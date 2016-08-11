#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

#include "../privsep.c"
#include "mock.h"

#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>

FILE *logfile = NULL;
int domid = 123;
const char *bios_dir = "/bios";

int crashdump_enabled(void)
{
    return 0;
}

void qemu_system_exit_request(void)
{
}

QEMUFile *qemu_fdopen(int fd, const char *mode)
{
    return (QEMUFile *) fdopen(fd, mode);
}

int xc_evtchn_fd(xc_interface *xc)
{
    return -1;
}

QEMUFile *qemu_fopen_ops(void *opaque, QEMUFilePutBufferFunc *put_buffer,
                         QEMUFileGetBufferFunc *get_buffer,
                         QEMUFileCloseFunc *close,
                         QEMUFileRateLimit *rate_limit)
{
    exit(1);
    return NULL;
}

static void
end_ping(int fd)
{
    unsigned n = 0xdeadbeef;
    must_write(fd, &n, sizeof(n));
    exit(0);
}
#define end_ping() end_ping(socks[1])

static void
end_test(int fd)
{
    int status;
    unsigned n;
    must_read(fd, &n, sizeof(n));
    fail_if(n != 0xdeadbeef);
    wait(&status);
    alarm(0);
}
#define end_test() do {\
	end_test(socks[0]); mark_point(); \
	} while(0)

/*
 * Base test for send/receive functions
 * Test send/receive functions sending data and expecting same
 * result. A child that does an echo is used.
 * Also data is appended to check all data are readed.
 */
START_TEST (sep_data)
{
    int socks[2], fd;
    char buf[10], *s;
    unsigned l;
    char *buf_list[3];

    if (socketpair(AF_LOCAL, SOCK_STREAM, PF_UNSPEC, socks) == -1)
        err(1, "socketpair() failed");

    /* send/receive bool */
    alarm(5);
    if (fork() == 0) {
        bool b = receive_bool_errno(socks[1]);
        send_bool_errno(socks[1], b, errno);
        end_ping();
    }
    send_bool_errno(socks[0], true, 123);
    fail_if(receive_bool_errno(socks[0]) != true);
    fail_if(errno != 123);
    end_test();

    if (fork() == 0) {
        bool b = receive_bool_errno(socks[1]);
        send_bool_errno(socks[1], b, errno);
        end_ping();
    }
    send_bool_errno(socks[0], false,321);
    fail_if(receive_bool_errno(socks[0]) != false);
    fail_if(errno != 321);
    end_test();

    /* send/receive a file */
    alarm(5);
    fd = open("out", O_CREAT|O_TRUNC|O_WRONLY, 0600);
    fail_if(fd < 0);
    if (fork() == 0) {
        send_fd(socks[1], receive_fd(socks[1]));
        end_ping();
    }
    send_fd(socks[0], fd);
    close(fd);
    fd = receive_fd(socks[0]);
    must_write(fd, "test", 4);
    close(fd);
    fd = open("out", O_RDONLY);
    fail_if(fd < 0);
    must_read(fd, buf, 4);
    buf[4] = 0;
    fail_if(strcmp(buf, "test") != 0);
    end_test();

    /* send/receive normal string with no terminator */
    alarm(5);
    if (fork() == 0) {
        s = receive_string(socks[1], NULL);
        send_string(socks[1], s);
        free(s);
        end_ping();
    }
    send_string(socks[0], "foo 123");
    s = receive_string(socks[0], &l);
    fail_if(strcmp(s, "foo 123") != 0);
    fail_if(l != 7);
    free(s);
    end_test();

    /* send/receive normal string with terminator */
    alarm(5);
    if (fork() == 0) {
        s = receive_string(socks[1], &l);
        send_buf(socks[1], s, l);
        free(s);
        end_ping();
    }
    send_buf(socks[0], "foo\0\0duck", 9);
    memset(buf, 0, sizeof(buf));
    s = receive_string(socks[0], &l);
    fail_if(memcmp(s, "foo\0\0duck\0", 10) != 0);
    fail_if(l != 9);
    free(s);
    end_test();

    /* send/receive NULL string. This happen if xs_read has not data */
    alarm(5);
    if (fork() == 0) {
        s = receive_string(socks[1], &l);
        send_buf(socks[1], s, l);
        free(s);
        end_ping();
    }
    send_buf(socks[0], NULL, 9);
    s = receive_string(socks[0], &l);
    fail_if(s != NULL);
    end_test();

    /* send/receive empty list */
    char **list = buf_list;
    alarm(5);
    if (fork() == 0) {
        l = -1u;
        list = receive_list(socks[1], &l);
        if (l != 0) exit(1);
        send_list(socks[1], list, l);
        free(list);
        end_ping();
    }
    send_list(socks[0], list, 0);
    list = receive_list(socks[0], &l);
    fail_if(list == NULL);
    fail_if(l != 0);
    free(list);
    end_test();

    /* send/receive two element list */
    alarm(5);
    buf_list[0] = "test string 1";
    buf_list[1] = "foo 654 ";
    list = buf_list;
    if (fork() == 0) {
        l = -1u;
        list = receive_list(socks[1], &l);
        if (l != 2) exit(1);
        send_list(socks[1], list, l);
        free(list);
        end_ping();
    }
    send_list(socks[0], list, 2);
    list = receive_list(socks[0], &l);
    fail_if(list == NULL);
    fail_if(l != 2);
    fail_if(strcmp(list[0], "test string 1") != 0, "string 0 %s", list[0]);
    fail_if(strcmp(list[1], "foo 654 ") != 0, "string 1 %s", list[1]);
    fail_if(list[2] != NULL);
    free(list);
    end_test();

    /* use build_watch_data */
    alarm(5);
    buf_list[0] = "test string 1";
    buf_list[1] = "foo 654 ";
    list = buf_list;
    if (fork() == 0) {
        l = -1u;
        list = receive_list(socks[1], &l);
        if (l != 2) exit(1);
        size_t len;
        unsigned char *buf = build_watch_data(list, &len);
        free(list);
        must_write(socks[1], buf, len);
        free(buf);
        end_ping();
    }
    send_list(socks[0], list, 2);
    list = receive_list(socks[0], &l);
    fail_if(list == NULL);
    fail_if(l != 2);
    fail_if(strcmp(list[0], "test string 1") != 0, "string 0 %s", list[0]);
    fail_if(strcmp(list[1], "foo 654 ") != 0, "string 1 %s", list[1]);
    fail_if(list[2] != NULL);
    free(list);
    end_test();


    /* send/receive NULL list */
    list = NULL;
    alarm(5);
    if (fork() == 0) {
        list = receive_list(socks[1], &l);
        send_list(socks[1], list, 10);
        free(list);
        end_ping();
    }
    send_list(socks[0], list, 9);
    list = receive_list(socks[0], &l);
    fail_if(list != NULL);
    end_test();

    exit(125);
}
END_TEST

static int watch_socks[2];

/*
 * Check separation code
 * Use privileged call and check the function we want are called.
 */
START_TEST (sep_test)
{
    static const char logdirty_ret[] = "/local/domain/0/device-model/123/logdirty/ret";
    static const char logdirty_cmd[] = "/local/domain/0/device-model/123/logdirty/cmd";

    if (socketpair(AF_LOCAL, SOCK_STREAM, PF_UNSPEC, watch_socks) < -1)
        err(1, "socketpair() failed");

    /* must be done before the prepare */
    with_return(xs_get_domain_path, strdup("/local/domain/123"));
    with_return(xs_read, NULL);
    with_return_num(xs_read, 12);
    with_return(xs_read, strdup("/vm/b78b8aba-9b19-1ce0-b977-3efb98a5fcbc"));

    with_return(xs_read, NULL);
    with_return_num(xs_read, 6);
    with_return(xs_read, strdup("foo123"));

    with_return(xs_write, "/test2");
    with_return(xs_write, NULL);
    with_return_num(xs_write, true);

    with_return_num(xs_watch, true);
    with_return_num(xs_watch, true);

    with_return(xs_unwatch, "foo2");
    with_return_num(xs_unwatch, true);

    with_return(xs_unwatch, "foo");
    with_return_num(xs_unwatch, true);

    with_return(xs_read, NULL);
    with_return_num(xs_read, 10);
    with_return(xs_read, strdup("test_watch"));

    with_return(xs_write, logdirty_ret);
    with_return(xs_write, "enable");
    with_return_num(xs_write, true);

    with_return(xs_read, logdirty_cmd);
    with_return_num(xs_read, 6);
    with_return(xs_read, strdup("state1"));

    with_return(xs_write, logdirty_ret);
    with_return(xs_write, "disable");
    with_return_num(xs_write, false);

    with_return(xs_read, logdirty_cmd);
    with_return_num(xs_read, 6);
    with_return(xs_read, strdup("state2"));

    with_return(xs_write, "/local/domain/0/device-model/123/state");
    with_return(xs_write, NULL);
    with_return_num(xs_write, true);

    with_return(xs_read, "/local/domain/0/device-model/123/xyz/etc");
    with_return_num(xs_read, 6);
    with_return(xs_read, strdup("state3"));

    with_return(xs_write, logdirty_ret);
    with_return(xs_write, "mock_check");
    with_return_num(xs_write, false);

    privsep_prepare();

    mark_point();
    struct xs_handle *xsh = privsep_daemon_open();

    mark_point();
    char *s = privsep_get_domain_path(xsh, domid);
    fail_if(strcmp(s, "/local/domain/123") != 0);
    free(s);

    mark_point();
    unsigned l;
    s = privsep_read(xsh, XBT_NULL, "/test1", &l);
    fail_if(strcmp(s, "foo123") != 0);
    free(s);

    mark_point();
    bool b = privsep_write(xsh, XBT_NULL, "/test2", "qemu-xen", 8);
    fail_if(!b);

    fail_if(privsep_watch(xsh, "/test3", "foo") == false);
    fail_if(privsep_watch(xsh, "/test4", "foo2") == false);

    int fd = privsep_fileno(xsh);
    fail_if(fd < 0);

    struct pollfd pfd = { fd, POLLIN, 0 };
    int rc;
    while ((rc=poll(&pfd, 1, 100)) < 0)
        fail_if(errno != EINTR);
    fail_if(rc != 0);

    /* send some data to other end */
    send_string(watch_socks[0], "foo_/test3/mao");

    /* now we should have data */
    pfd = (struct pollfd) { fd, POLLIN, 0 };
    while ((rc=poll(&pfd, 1, 100)) < 0)
        fail_if(errno != EINTR);
    fail_if(rc != 1);

    char **list = privsep_read_watch(xsh, &l);
    fail_if(list == NULL);
    fail_if(l != 2);
    fail_if(strcmp(list[XS_WATCH_TOKEN], "foo") != 0, "token '%s'", list[XS_WATCH_TOKEN]);
    fail_if(strncmp(list[XS_WATCH_PATH], "/test3", 5) != 0, "path '%s'", list[XS_WATCH_PATH]);

    /* these two should not call xs_watch */
    fail_if(privsep_unwatch(xsh, "/test5", "foo2"));
    fail_if(privsep_unwatch(xsh, "/test4", "foo"));

    fail_if(!privsep_unwatch(xsh, "/test4", "foo2"));

    /* close should delete automatically the remain watch */
    privsep_daemon_close(xsh);

    xsh = privsep_daemon_open();
    s = privsep_read(xsh, XBT_NULL, "/test1", &l);
    fail_if(strcmp(s, "test_watch") != 0);
    free(s);

    send_command(privsep_fd, privsep_op_restrict_paths);

    privsep_write(xsh, XBT_NULL, logdirty_ret, "enable", 6);
    fail_if(strcmp(s=privsep_read(xsh, XBT_NULL, logdirty_cmd, &l), "state1") != 0);
    free(s);
    privsep_write(xsh, XBT_NULL, logdirty_ret, "disable", 7);
    fail_if(strcmp(s=privsep_read(xsh, XBT_NULL, logdirty_cmd, &l), "state2") != 0);
    free(s);

    privsep_record_dm("a/b/c", "value");
    privsep_record_dm("state", "value");
    fail_if(strcmp(s=privsep_read_dm("xyz/etc"), "state3") != 0);
    free(s);

    /* check other process eat all data queued in mock */
    fail_if(!privsep_write(xsh, XBT_NULL, logdirty_ret, "mock_check", 10));
    privsep_daemon_close(xsh);
    close(privsep_fd);
    int status;
    wait(&status);
    fail_if(!WIFEXITED(status));
    fail_if(WEXITSTATUS(status) != 0);

    exit(125);
}
END_TEST

#define path_ok(path,ck) fail_if(!check_xs_path(path, CHECK_ ## ck))
#define path_fail(path,ck) fail_if(check_xs_path(path, CHECK_ ## ck))

START_TEST(sep_check_paths)
{
    domain_path = "/local/domain/123";
    vm_path = "/vm/vmpathX";

    privsep_state = privsep_started;

    path_fail("", READ);
    path_fail("", WRITE);

    path_fail("/", READ);
    path_fail("/", WRITE);

    path_fail("/test", READ);
    path_fail("/foo", WRITE);

    path_fail("test", READ);
    path_fail("foo", WRITE);

    path_ok  ("/local/domain/0/backend/vbd3/123/5696/params", READ);
    path_fail("/local/domain/0/backend/vbd3/1234/5696/params", READ);
    path_fail("/local/domain/0/backend/vbd3/123/5696/params", WRITE);

    path_ok  ("/local/domain/123/data/report_clipboard", READ);
    path_ok  ("/local/domain/123/data/report_clipboard", WRITE);
    path_ok  ("/local/domain/123/data/set_clipboard", READ);
    path_ok  ("/local/domain/123/data/set_clipboard", WRITE);

    path_ok  ("/local/domain/123/data/report_clipboard/x", READ);
    path_fail("/local/domain/123/data/report_clipboard/x", WRITE);
    path_ok  ("/local/domain/123/data/set_clipboard/x", READ);
    path_fail("/local/domain/123/data/set_clipboard/x", WRITE);

    path_fail("/local/domain/1231/data/report_clipboard", READ);
    path_fail("/local/domain/1231/data/report_clipboard", WRITE);
    path_fail("/local/domain/1231/data/set_clipboard", READ);
    path_fail("/local/domain/1231/data/set_clipboard", WRITE);

    path_fail("/local/domain/123", WRITE);
    path_fail("/local/domain/1234", WRITE);
    path_fail("/local/domain/123/", WRITE);
    path_fail("/local/domain/123/vm", WRITE);

    /* paths removed as used only by Qemu as backend (not used in XenServer) */
#if 0
    path_ok  ("/local/domain/123/device", WRITE);
    path_ok  ("/local/domain/123/device/", WRITE);
    path_ok  ("/local/domain/123/device/foo", WRITE);
#endif
    path_fail("/local/domain/1234/device", WRITE);
    path_fail("/local/domain/123/deviceX", WRITE);
    path_fail("/local/domain/1234/deviceX", WRITE);
    path_fail("/local/domain/1234/device/", WRITE);
    path_fail("/local/domain/1234/device/foo", WRITE);
    path_fail("/local/domain/12/device", WRITE);
    path_fail("/local/domain/12/deviceX", WRITE);
    path_fail("/local/domain/12/device/", WRITE);
    path_fail("/local/domain/12/device/foo", WRITE);

    /* backend */
    path_fail("/local/domain/0/backend", READ);
    path_fail("/local/domain/0/backend//123", READ);
    path_fail("/local/domain/0/backend//12", READ);
    path_fail("/local/domain/0/backend//1234", READ);
    path_ok  ("/local/domain/0/backend/x/123", READ);
    path_fail("/local/domain/0/backend/x/12", READ);
    path_fail("/local/domain/0/backend/x/1234", READ);
    path_fail("/local/domain/0/backend/x/ 123", READ);
    path_fail("/local/domain/0/backend/x/123 ", READ);

    path_fail("/local/domain/17/keymap", READ);
    path_ok  ("/local/domain/123/keymap", READ);

    path_ok  ("/mh/driver-blacklist/xensource-windows/86451", READ);
    path_fail("/mh/driver-blacklist/xensource-windows/86451", WRITE);
    path_ok  ("/mh/driver-blacklist", READ);
    path_fail("/mh/driver-blacklist", WRITE);
    path_fail("/mh/driver-blacklistX", READ);
    path_fail("/mh/driver-blacklistX", WRITE);
    path_fail("/mh/", READ);
    path_fail("/mh/", WRITE);
    path_fail("/mh", READ);
    path_fail("/mh", WRITE);
    path_fail("/m", READ);
    path_fail("/m", WRITE);

    path_ok  ("/vm/vmpathX", READ);
    path_fail("/vm/vmpathXY", READ);
    path_ok  ("/vm/vmpathX/x", READ);
    path_fail("/vm/vmpath", READ);
    path_ok  ("/vm/vmpathX/", READ);
    path_fail("/vm/vmpathXY/", READ);

    path_fail("/vm/vmpathX", WRITE);
    path_fail("/vm/vmpathXY", WRITE);
    path_fail("/vm/vmpathX/x", WRITE);
    path_fail("/vm/vmpath", WRITE);
    path_fail("/vm/vmpathX/", WRITE);
    path_fail("/vm/vmpathXY/", WRITE);

    path_ok  ("/local/logconsole", READ);
    path_ok  ("/local/logconsole/x", READ);
    path_ok  ("@releaseDomain", READ);

    path_ok  ("/local/domain/0/device-model/123/logdirty/ret", WRITE);
    path_ok  ("/local/domain/0/device-model/123/logdirty/cmd", WRITE);
    path_fail("/local/domain/0/device-model/123/a/b", WRITE);
}
END_TEST

struct xs_handle *xs_daemon_open(void)
{
    return (void *) (intptr_t) 0x1;
}

void xs_daemon_close(struct xs_handle *h)
{
    if ((void *) (intptr_t) 0x1 != h)
        exit(1);
}

char *xs_get_domain_path(struct xs_handle *xsh, unsigned int domid)
{
    return (char *) mock();
}

void *xs_read(struct xs_handle *h, xs_transaction_t t,
		   const char *path, unsigned int *len)
{
    char *s = (char *) mock();
    if (s && strcmp(s, path) != 0)
        exit(1);
    unsigned n = mock_num();
    if (len) *len = n;
    return (void*) mock();
}

bool xs_write(struct xs_handle *h, xs_transaction_t t,
		   const char *path, const void *data, unsigned int len)
{
    char *s = (char *) mock();
    if (s && strcmp(s, path) != 0)
        exit(1);
    s = (char *) mock();
    bool res = (bool) mock_num();
    if (s && strcmp(s, "mock_check") == 0)
        return mock_check_left();
    if (s && strcmp(s, data) != 0)
        exit(1);
    return res;
}

bool xs_rm(struct xs_handle *h, xs_transaction_t t,
		const char *path)
{
    return (bool) mock_num();
}

bool xs_watch(struct xs_handle *h, const char *path, const char *token)
{
    return (bool) mock_num();
}

bool xs_unwatch(struct xs_handle *h, const char *path, const char *token)
{
    printf("xs_unwatch %s %s\n", path, token);
    if (strcmp(token, (char *) mock()) != 0)
        exit(1);

    return (bool) mock_num();
}

char **xs_directory(struct xs_handle *h, xs_transaction_t t,
			 const char *path, unsigned int *num)
{
    *num = mock_num();
    return (char**) mock();
}

int xs_fileno(struct xs_handle *xsh)
{
    return watch_socks[1];
}

char **xs_read_watch(struct xs_handle *h, unsigned int *num)
{
    char *s = receive_string(watch_socks[1], NULL);
    if (!s) exit(1);

    size_t l = strlen(s);
    char **list = (char**) calloc(1, l + sizeof(char*) * 3 + 1);
    memcpy(list+3, s, l + 1);
    free(s);
    s = (char *) (list+3);
    char *p = strchr(s, '_');
    *p++ = 0;
    list[XS_WATCH_TOKEN] = s;
    list[XS_WATCH_PATH] = p;
    list[2] = NULL;
    *num = 2;
    return list;
}

TCase *
sep_tc (void)
{
    TCase *tc = tcase_create ("Privsep");
    tcase_add_exit_test(tc, sep_data, 125);
    tcase_add_exit_test(tc, sep_test, 125);
    tcase_add_test(tc, sep_check_paths);

    return tc;
}

