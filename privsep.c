/* Privilege separation.  Closely based on OpenBSD syslogd's
 * privsep, which is:
 *
 * Copyright (c) 2003 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *
 * We also use some utility functions from privsep_fdpass.c, which is:
 *
 *
 * Copyright 2001 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Copyright (c) 2002 Matthieu Herrb
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * Tests to do for this code (beside running the machine):
 * - suspend/resume
 * - insert a CD from XenCenter
 * - eject a CD from XenCenter
 * - eject a CD from the guest (ie right click on Windows)
 * - hotplug network device
 * - hotplug disk device
 * - kill parent, check child exit automatically
 * - kill parent with SEGV or ABRT signals, a core file should be generated
 * - writing enable/disable to /local/domain/0/device-model/<domid>/logdirty/cmd
 *   cause /local/domain/0/device-model/<domid>/logdirty/ret to be written
 *   with same value
 */

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <sys/stat.h>
#ifndef CONFIG_STUBDOM
#include <sys/prctl.h>
#endif
#include <dirent.h>
#include <sys/ioctl.h>
#include <dlfcn.h>
#include <poll.h>
#include <sched.h>

#include "qemu-common.h"
#include "hw/hw.h"
#include "sysemu.h"
#include "exec-all.h"
#include "privsep.h"
#include "qemu-xen.h"

#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif

#undef xs_get_domain_path
#undef xs_read
#undef xs_write
#undef xs_directory
#undef xs_watch
#undef xs_unwatch
#undef xs_rm
#undef xs_daemon_open
#undef xs_daemon_close
#undef xs_restrict
#undef xs_fileno
#undef xs_read_watch

enum {
    max_len_xs_path = 256,
    max_len_cd_path = 1024,
    max_len_privsep_state = 256,
    max_len_language = 256,
    max_len_subpath = 256,
    max_len_token = 256,
    /* define limit of the dump file */
    max_len_dump = (64*1024),
    /* define limit of data written by xs_write */
    max_len_xs_data = (64*1024),
    /* maximum length of log message */
    max_len_log = 1024,
};

int privileged = 0;
privsep_state_t privsep_state;

static int privsep_fd = -1;
static struct xs_handle * priv_xsh;
static int parent_fd = -1;
static int parent_pid;
static char root_directory[64];
static int termsig;
static char *domain_path = NULL;
static char *vm_path = NULL;
#define MAX_XS_CONN 4
static int xs_conns[MAX_XS_CONN] = { -1, -1, -1, -1 };

#undef  OPCODES
#define OPCODES \
    OPCODE(open_iso) \
    OPCODE(eject_cd) \
    OPCODE(lock_cd) \
    OPCODE(unlock_cd) \
    OPCODE(set_cd_backend) \
    OPCODE(set_rtc) \
    OPCODE(save_vm_dump) \
    OPCODE(open_keymap) \
    OPCODE(record_dm) \
    OPCODE(read_dm) \
    OPCODE(read_xs) \
    OPCODE(write_xs) \
    OPCODE(directory_xs) \
    OPCODE(watch_xs) \
    OPCODE(unwatch_xs) \
    OPCODE(rm_xs) \
    OPCODE(daemon_open_xs) \
    OPCODE(daemon_close_xs) \
    OPCODE(restrict_paths) \
    OPCODE(log_msg)

#undef  OPCODE
#define OPCODE(n) privsep_op_ ## n ,
enum privsep_opcode {
    OPCODES
    privsep_op_count
};

typedef void privsep_read_t(void);
#undef  OPCODE
#define OPCODE(n) static privsep_read_t n;
OPCODES

#undef  OPCODE
#define OPCODE(n) n ,
static privsep_read_t *privsep_opcode[] = {
    OPCODES
};

typedef enum {
    CHECK_READ = 1,
    CHECK_WRITE = 2,
} check_type_t;

static bool check_xs_path(const char *path, check_type_t check);

#define MAX_CDS (MAX_DRIVES+1)

#define LOG_LIMIT_BURST 10000
#define LOG_LIMIT_INTERVAL 60

/* store fake xs_handle structure to give to unprivileged
 * Qemu when we use privilege separation
 * This is required as watches are per-xs_handle
 * and to multiplex watches
 */
typedef struct privsep_handle {
    int watch_fd;
    unsigned priv_handle;
} privsep_handle_t;

/* We have a list of xenstore paths which correspond to CD backends,
   and we validate CD and ISO commands against that.  New backends can
   only be added to that list before you drop privileges.
*/
static char *
cd_backend_areas[MAX_CDS];

static int watches_find(const char *token);

static void
clean_exit(int ret)
{
    if (strcmp(root_directory, "/var/empty")) {
        char name[80];
        struct stat buf;
        strcpy(name, root_directory);
        strcat(name, "/etc/localtime");
        unlink(name);
        strcpy(name, root_directory);
        strcat(name, "/etc");
        rmdir(name);

        snprintf(name, 80, "%s/core.%d", root_directory, parent_pid);
        if (!stat(name, &buf) && !buf.st_size)
            unlink(name);

        rmdir(root_directory);
    }
    _exit(ret);
}

/* Read data with the assertion that it all must come through, or
 * else abort the process.  Based on atomicio() from openssh. */
static void
must_read(int fd, void *buf, size_t n)
{
        char *s = buf;
        ssize_t res, pos = 0;

        while (n > pos) {
                res = read(fd, s + pos, n - pos);
                switch (res) {
                case -1:
                        if (errno == EINTR || errno == EAGAIN)
                                continue;
                case 0:
                        clean_exit(fd == privsep_fd ? 1 : 0);
                default:
                        pos += res;
                }
        }
}

/* Write data with the assertion that it all has to be written, or
 * else abort the process.  Based on atomicio() from openssh. */
static ssize_t
write_all(int fd, const void *buf, size_t n)
{
        const char *s = buf;
        ssize_t res, pos = 0;

        while (n > pos) {
                res = write(fd, s + pos, n - pos);
                switch (res) {
                case -1:
                        if (errno == EINTR || errno == EAGAIN)
                                continue;
                case 0:
                        return -1;
                default:
                        pos += res;
                }
        }
        return pos;
}

static void
must_write(int fd, const void *buf, size_t n)
{
    if (write_all(fd, buf, n) < 0)
        clean_exit(0);
}

#ifndef CONFIG_STUBDOM
static void
send_fd(int sock, int fd)
{
        struct msghdr msg;
        char tmp[CMSG_SPACE(sizeof(int))];
        struct cmsghdr *cmsg;
        struct iovec vec;
        int result = 0;
        ssize_t n;

        memset(&msg, 0, sizeof(msg));

        if (fd >= 0) {
                msg.msg_control = (caddr_t)tmp;
                msg.msg_controllen = CMSG_LEN(sizeof(int));
                cmsg = CMSG_FIRSTHDR(&msg);
                cmsg->cmsg_len = CMSG_LEN(sizeof(int));
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                *(int *)CMSG_DATA(cmsg) = fd;
        } else {
                result = errno;
        }

        vec.iov_base = &result;
        vec.iov_len = sizeof(int);
        msg.msg_iov = &vec;
        msg.msg_iovlen = 1;

        while ((n = sendmsg(sock, &msg, 0)) == -1) {
                if (errno == EINTR) continue;
                warn("%s: sendmsg(%d)", "send_fd", sock);
                break;
        }
        if (n != sizeof(int))
                warnx("%s: sendmsg: expected sent 1 got %ld",
                    "send_fd", (long)n);
}
#endif

#ifndef CONFIG_STUBDOM
static int
receive_fd(int sock)
{
        struct msghdr msg;
        char tmp[CMSG_SPACE(sizeof(int))];
        struct cmsghdr *cmsg;
        struct iovec vec;
        ssize_t n;
        int result;
        int fd;

        memset(&msg, 0, sizeof(msg));
        vec.iov_base = &result;
        vec.iov_len = sizeof(int);
        msg.msg_iov = &vec;
        msg.msg_iovlen = 1;
        msg.msg_control = tmp;
        msg.msg_controllen = sizeof(tmp);

        while ((n = recvmsg(sock, &msg, 0)) == -1) {
                if (errno == EINTR) continue;
                warn("%s: recvmsg", "receive_fd");
                break;
        }
        if (n != sizeof(int))
                warnx("%s: recvmsg: expected received 1 got %zd",
                      "receive_fd", n);
        if (result == 0) {
                cmsg = CMSG_FIRSTHDR(&msg);
                if (cmsg == NULL) {
                        warnx("%s: no message header", "receive_fd");
                        return (-1);
                }
                if (cmsg->cmsg_type != SCM_RIGHTS)
                        warnx("%s: expected type %d got %d", "receive_fd",
                            SCM_RIGHTS, cmsg->cmsg_type);
                fd = (*(int *)CMSG_DATA(cmsg));
                return fd;
        } else {
                errno = result;
                return -1;
        }
}
#else

static int
receive_fd(int sock)
{
    return -1;
}
#endif

#define send_raw(fd, x) must_write(fd, &x, sizeof(x))

#define INVALID_SIZE (-(size_t)1)
static void
send_buf(int fd, const char *s, size_t len)
{
    if (!s) {
        len = INVALID_SIZE;
        send_raw(fd, len);
    } else {
        send_raw(fd, len);
        must_write(fd, s, len);
    }
}

static inline void
send_string(int fd, const char *s)
{
    send_buf(fd, s, s ? strlen(s) : 0);
}

static char*
receive_string_limited(int fd, unsigned int *p_len, size_t limit)
{
    size_t l;
    char *res;

    must_read(fd, &l, sizeof(l));
    if (l == INVALID_SIZE)
        return NULL;
    if (limit && l > limit)
        return NULL;

    res = malloc(l + 1);
    if (!res)
        return res;
    must_read(fd, res, l);
    res[l] = 0;
    if (p_len)
        *p_len = l;
    return res;
}

static char*
receive_string(int fd, unsigned int *p_len)
{
    return receive_string_limited(fd, p_len, 0);
}

static void
receive_string_buf_len(int fd, char *buf, unsigned len)
{
    size_t l;

    must_read(fd, &l, sizeof(l));
    if (l >= len)
        clean_exit(1);

    must_read(fd, buf, l);
    buf[l] = 0;
}
#define MAX_LEN(n) max_len_ ## n
#define check_len(n) (strlen(n) <= MAX_LEN(n))
#define receive_string_buf(f, b) char b[MAX_LEN(b)+1]; receive_string_buf_len(f, b, MAX_LEN(b)+1)

static inline void
send_command(int fd, enum privsep_opcode cmd)
{
    send_raw(fd, cmd);
}

static inline void
send_int(int fd, int i)
{
    send_raw(fd, i);
}

static inline int
receive_int(int fd)
{
    int i;
    must_read(fd, &i, sizeof(i));
    return i;
}

static void
send_list(int fd, char **list, unsigned num)
{
    size_t l;
    unsigned n;

    if (!list) {
        num = -1u;
        send_raw(fd, num);
        return;
    }

    send_raw(fd, num);

    l = 0;
    for (n = 0; n < num; ++n)
        l += strlen(list[n]);
    send_raw(fd, l);

    for (n = 0; n < num; ++n) {
        l = strlen(list[n]);
        send_raw(fd, l);
        must_write(fd, list[n], l);
    }
}

static char **
receive_list(int fd, unsigned *p_num)
{
    size_t l;
    unsigned n, num;
    char **res;
    char *p;

    must_read(fd, &num, sizeof(num));
    if (num == -1u) {
        *p_num = 0;
        return NULL;
    }
    *p_num = num;
    must_read(fd, &l, sizeof(l));
    res = (char **) malloc(l + num + sizeof(char*) * (num+1));
    if (!res)
        return NULL;

    p = (char*) (res+num+1);

    for (n = 0; n < num; ++n) {
        res[n] = p;
        must_read(fd, &l, sizeof(l));
        must_read(fd, p, l);
        p += l;
        *p++ = 0;
    }
    res[n] = NULL;
    return res;
}

typedef struct {
    bool b;
    int error;
} bool_errno_t;

static inline void
send_bool_errno(int fd, bool b, int error)
{
    bool_errno_t data = { b, error };
    send_raw(fd, data);
}

static inline bool
receive_bool_errno(int fd)
{
    bool_errno_t data;
    must_read(fd, &data, sizeof(data));
    errno = data.error;
    return data.b;
}

#ifndef CONFIG_STUBDOM
static void
open_iso(void)
{
    int i;
    char *params_path;
    char *allowed_path = NULL;
    unsigned len;
    int fd;

    /* This is a bit icky.  We get a path from the unprivileged qemu,
       and then scan the defined CD areas to make sure it matches.
       The internal structure of qemu means that by the time you do
       the open(), it's kind of hard to map back to the actual CD
       drive. */
    receive_string_buf(parent_fd, cd_path);

    /* Have a path.  Validate against xenstore. */
    for (i = 0; i < MAX_CDS; i++) {
        if (!cd_backend_areas[i]) continue;
        if (asprintf(&params_path, "%s/params", cd_backend_areas[i]) < 0) {
            /* Umm, not sure what to do now */
            continue;
        }
        free(allowed_path);
        allowed_path = xs_read(priv_xsh, XBT_NULL, params_path, &len);
        free(params_path);
        if (allowed_path && strcmp(allowed_path, cd_path) == 0)
            break;
    }
    free(allowed_path);
    if (i >= MAX_CDS) {
        errno = EPERM;
        fd = -1;
    } else {
        fd = open(cd_path, O_RDONLY|O_LARGEFILE|O_BINARY);
    }
    send_fd(parent_fd, fd);
    if (fd >= 0)
        close(fd);
}
#endif

static void
do_eject_cd(int id)
{
    char *param_path;
    if (cd_backend_areas[id]) {
        if (asprintf(&param_path, "%s/params", cd_backend_areas[id]) >= 0){
            xs_write(priv_xsh, XBT_NULL, param_path, "", 0);
            free(param_path);
        }
    }
}

static void
eject_cd(void)
{
    int id = receive_int(parent_fd);
    if (id >= 0 && id < MAX_CDS)
        do_eject_cd(id);
}

void
privsep_eject_cd(int id)
{
    if (privsep_fd < 0) {
        do_eject_cd(id);
    } else {
        send_command(privsep_fd, privsep_op_eject_cd);
        send_raw(privsep_fd, id);
    }
}

static void
set_cd_lock_state(int id, const char *state)
{
    char *locked_path;
    if (cd_backend_areas[id]) {
        if (asprintf(&locked_path, "%s/locked", cd_backend_areas[id]) >= 0) {
            xs_write(priv_xsh, XBT_NULL, locked_path, state, strlen(state));
            free(locked_path);
        }
    }
}

static void
lock_cd(void)
{
    int id = receive_int(parent_fd);
    if (id >= 0 && id < MAX_CDS)
        set_cd_lock_state(id, "true");
}

void
privsep_lock_cd(int id)
{
    if (privsep_fd < 0) {
        set_cd_lock_state(id, "true");
        return;
    }

    send_command(privsep_fd, privsep_op_lock_cd);
    send_raw(privsep_fd, id);
}

static void
unlock_cd(void)
{
    int id = receive_int(parent_fd);
    if (id >= 0 && id < MAX_CDS)
        set_cd_lock_state(id, "false");
}

void
privsep_unlock_cd(int id)
{
    if (privsep_fd < 0) {
        set_cd_lock_state(id, "false");
    } else {
        send_command(privsep_fd, privsep_op_unlock_cd);
        send_raw(privsep_fd, id);
    }
}

static int 
xenstore_vm_write(int domid, const char *key, const char *value)
{
    char *buf, *path;
    int rc;

    path = xs_get_domain_path(priv_xsh, domid);
    if (path == NULL) {
        return 0;
    }

    rc = asprintf(&buf, "%s/vm", path);
    free(path);
    if (rc < 0)
        return 0;

    path = xs_read(priv_xsh, XBT_NULL, buf, NULL);
    free(buf);
    if (path == NULL) {
        return 0;
    }

    rc = asprintf(&buf, "%s/%s", path, key);
    free(path);
    if (rc < 0)
        return 0;

    rc = xs_write(priv_xsh, XBT_NULL, buf, value, strlen(value));
    free(buf);
    return rc;
}

static void
do_set_rtc(long time_offset)
{
    char b[64];

    sprintf(b, "%ld", time_offset);
    xenstore_vm_write(domid, "rtc/timeoffset", b);
}

static void
set_rtc(void)
{
    long time_offset;

    must_read(parent_fd, &time_offset, sizeof(time_offset));
    do_set_rtc(time_offset);
}

void
privsep_set_rtc_timeoffset(long time_offset)
{
    if (privsep_fd < 0) {
        do_set_rtc(time_offset);
    } else {
        send_command(privsep_fd, privsep_op_set_rtc);
        send_raw(privsep_fd, time_offset);
    }
}

#ifndef CONFIG_STUBDOM
static void
save_vm_dump(void)
{
    int fd, e;
    char name[128];
    char *dump = NULL;
    unsigned len;

    sprintf(name, "/var/lib/xen/qemu-save.%d", domid);

    dump = receive_string_limited(parent_fd, &len, max_len_dump);
    if (!dump)
        clean_exit(1);

    fd = open(name, O_RDWR|O_CREAT|O_TRUNC, 0600);
    e = errno;
    if (fd < 0)
        goto done;

    if (write_all(fd, dump, len) >= 0) {
        e = 0;
    } else {
        e = errno;
        unlink(name);
    }

done:
    if (fd >= 0)
        close(fd);
    free(dump);
    send_int(parent_fd, e);
}
#endif

typedef struct {
    char *buf;
    uint32_t len, capacity;
    int has_error;
} vm_dump_t;

static int
dump_put_buffer(void *opaque, const uint8_t *buf,
                int64_t pos, int size)
{
    vm_dump_t *dump = (vm_dump_t *) opaque;

    if (pos < 0 || size < 0 || pos + size > max_len_dump)
        dump->has_error = 1;
    if (dump->has_error)
        return -1;

    /* resize buf if needed */
    uint32_t s = pos + size;
    s += 1023;
    s -= s % 1024;
    if (s > dump->capacity) {
        char *p = (char *) realloc(dump->buf, s);
        if (!p) {
            dump->has_error = 1;
            return -1;
        }
        dump->buf = p;
        dump->capacity = s;
    }

    memcpy(dump->buf + pos, buf, size);
    s = pos + size;
    if (s > dump->len)
        dump->len = s;
    return size;
}


static int
dump_close(void *opaque)
{
    vm_dump_t *dump = (vm_dump_t *) opaque;
    int ret = -1;

    if (dump->has_error || dump->len > max_len_dump || !dump->buf)
        goto cleanup;

    send_command(privsep_fd, privsep_op_save_vm_dump);
    send_buf(privsep_fd, dump->buf, dump->len);

    ret = receive_int(privsep_fd);

cleanup:
    free(dump->buf);
    free(dump);
    return ret;
}

QEMUFile *
privsep_open_vm_dump(const char *name)
{
    vm_dump_t *dump = (vm_dump_t *) calloc(1, sizeof(*dump));
    if (!dump)
        return NULL;

    QEMUFile *res = qemu_fopen_ops(dump, dump_put_buffer, NULL, dump_close, NULL);
    if (!res) {
        free(dump);
        return NULL;
    }
    return res;
}

static int
do_open_keymap(const char *language)
{
    int e;
    int fd;
    char *filename;
    int x;

    for (x = 0; language[x]; x++) {
        if (!isalnum(language[x]) && language[x] != '-') {
            errno = EPERM;
            return -1;
        }
    }

    if (asprintf(&filename, "%s/keymaps/%s", bios_dir, language) < 0)
        return -1;
    fd = open(filename, O_RDONLY);
    e = errno;
    free(filename);
    errno = e;
    return fd;
}

#ifndef CONFIG_STUBDOM
static void
open_keymap(void)
{
    int fd;

    receive_string_buf(parent_fd, language);

    fd = do_open_keymap(language);

    send_fd(parent_fd, fd);
    if (fd >= 0)
        close(fd);
}
#endif

FILE *
privsep_open_keymap(const char *language)
{
    int fd;
    FILE *res;
    int e;

    if (privsep_fd < 0) {
        fd = do_open_keymap(language);
    } else {
        if (!check_len(language)) {
            errno = EINVAL;
            return NULL;
        }
        send_command(privsep_fd, privsep_op_open_keymap);
        send_string(privsep_fd, language);
        fd = receive_fd(privsep_fd);
    }

    if (fd < 0)
        return NULL;
    res = fdopen(fd, "r");
    if (!res) {
        e = errno;
        close(fd);
        errno = e;
    }
    return res;
}

static void
do_record_dm(const char *subpath, const char *state)
{
    char *path = NULL;

    if (asprintf(&path, 
                "/local/domain/0/device-model/%u/%s", domid, subpath) < 0) {
        return;
    }
    xs_write(priv_xsh, XBT_NULL, path, state, strlen(state));
    free(path);
}

static void
record_dm(void)
{
    receive_string_buf(parent_fd, subpath);
    receive_string_buf(parent_fd, privsep_state);

    /* these are the only values allowed, return to avoid
     * filling xenstore */
    if (strcmp(subpath, "parameter") != 0 && strcmp(subpath, "state") != 0)
        return;

    do_record_dm(subpath, privsep_state);
}

static char *
do_read_dm(const char *subpath)
{
    unsigned int len;
    char *path = NULL, *res;
    int e;

    if (asprintf(&path, 
                "/local/domain/0/device-model/%u/%s", domid, subpath) < 0) {
        return NULL;
    }
    res = xs_read(priv_xsh, XBT_NULL, path, &len);
    e = errno;
    free(path);
    errno = e;
    return res;
}

static void
read_dm(void)
{
    char *value;

    receive_string_buf(parent_fd, subpath);

    value = do_read_dm(subpath);

    send_string(parent_fd, value);

    free(value);
}

static void
log_msg(void)
{
    char *msg;
    unsigned int len;
    static time_t last_time;
    static int count;

    msg = receive_string_limited(parent_fd, &len, max_len_log);
    if (msg) {
        time_t now;

        time(&now);
        if (now - last_time > LOG_LIMIT_INTERVAL) {
            count = 0;
            last_time = now;
        }

        if (count < LOG_LIMIT_BURST) {
            count++;
            syslog(LOG_DAEMON|LOG_INFO, "%s", msg);
        } else if (count == LOG_LIMIT_BURST) {
            count++;
            syslog(LOG_DAEMON|LOG_INFO, "Rate limited!");
        }
        free(msg);
    }
}

int privsep_vsyslog(const char *fmt, va_list ap)
{
    int res;
    char buf[max_len_log];

    res = vsnprintf(buf, max_len_log, fmt, ap);
    send_command(privsep_fd, privsep_op_log_msg);
    send_string(privsep_fd, buf);

    return res;
}

int privsep_syslog(const char *fmt, ...)
{
    va_list ap;
    int res;

    va_start(ap, fmt);
    res = privsep_vsyslog(fmt, ap);
    va_end(ap);

    return res;
}

#ifndef CONFIG_STUBDOM
static void
sigxfsz_handler_f(int num)
{
    struct rlimit rlim;

    getrlimit(RLIMIT_FSIZE, &rlim);
    rlim.rlim_cur = rlim.rlim_max;
    setrlimit(RLIMIT_FSIZE, &rlim);

    write(2, "SIGXFSZ received: exiting\n", 26);

    exit(1);
}

static void
sigterm_handler_f(int num)
{
    char buf[128];
    if (termsig) {
        /* Hmm, we got a exit signal before.  Still running.
         * Main loop is probably stuck somewhere ... */
        snprintf(buf, 128, "Termination signal %d received but we should already be exited, force exit now!\n", num);
        write(2, buf, strlen(buf));
        _exit(1);
    }
    snprintf(buf, 128, "Termination signal %d received, requesting clean shutdown\n", num);
    write(2, buf, strlen(buf));
    qemu_system_exit_request();
    termsig = num;
}

static void
create_localtime(void)
{
    int rd, wr, count;
    char name[80];
    char buf[256];

    strcpy(name, root_directory);
    strcat(name, "/etc");
    if (mkdir(name, 00755) < 0) {
        fprintf(stderr, "cannot create directory %s\n", name);
        return;
    }

    rd = open("/etc/localtime", O_RDONLY);
    if (rd < 0) {
        fprintf(stderr, "cannot open /etc/localtime\n");
        return;
    }
    strcat(name, "/localtime");
    wr = open(name, O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW, 0644);
    if (wr < 0) {
        fprintf(stderr, "cannot create %s\n", name);
        close(rd);
        return;
    }
    while ((count = read(rd, buf, 256)) > 0) {
        write(wr, buf, count);
    }
    close(rd);
    close(wr);
}

/* build same structure of send_list but in memory */
static unsigned char*
build_watch_data(char **list, size_t *watch_len)
{
    size_t l, ll[2];
    unsigned n;
    unsigned char *p;

    ll[0] = strlen(list[0]);
    ll[1] = strlen(list[1]);

#define ADD(x) do { memcpy(p, &x, sizeof(x)); p += sizeof(x); } while(0)
    l = sizeof(l) * 3 + sizeof(n) + ll[0] + ll[1];
    unsigned char *res = (unsigned char *) calloc(1, l);
    if (!res) return NULL;

    p = res;
    *watch_len = l;
    n = 2;
    ADD(n);
    l = ll[0] + ll[1];
    ADD(l);
    ADD(ll[0]);
    memcpy(p, list[0], ll[0]);
    p += ll[0];
    ADD(ll[1]);
    memcpy(p, list[1], ll[1]);
    p += ll[1];
    return res;
}

static void
privsep_loop(void)
{
    enum privsep_opcode opcode;
    struct pollfd fds[2] = {
        { parent_fd, POLLIN, 0 },
        { -1, 0 , 0 }
    };

    unsigned char *watch = NULL;
    size_t watch_len = 0, watch_pos = 0;
    int xs_conn = -1;

    while (1) {
        /* sanity check on watch connection */
        if (watch && (xs_conn < 0 || xs_conns[xs_conn] < 0 || watch_pos >= watch_len)) {
            free(watch);
            watch = NULL;
            continue;
        }

        /* watch for new events or send the old one */
        /* we avoid to do both to avoid dead locks or DoS */
        if (watch) {
            fds[1].fd = xs_conns[xs_conn];
            fds[1].events = POLLOUT;
        } else {
            fds[1].fd = xs_fileno(priv_xsh);
            fds[1].events = POLLIN;
        }

        int rc = poll(fds, 2, -1);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if ((fds[1].revents & POLLIN) != 0 && !watch) {
            unsigned num;
            char **list = xs_read_watch(priv_xsh, &num);
            if (!list) continue;
            xs_conn = watches_find(list[XS_WATCH_TOKEN]);
            if (xs_conn >= 0 && xs_conns[xs_conn] >= 0) {
                watch_pos = 0;
                watch = build_watch_data(list, &watch_len);
            }
            free(list);
        }

        if ((fds[1].revents & (POLLERR|POLLHUP|POLLNVAL)) != 0) {
            xs_conn = -1;
            continue;
        }

        if ((fds[1].revents & POLLOUT) != 0 && watch) {
            int rc = write(xs_conns[xs_conn], watch + watch_pos, watch_len - watch_pos);
            if (rc < 0) {
                if (errno == EINTR) continue;
                /* assume connection was closed */
                xs_conn = -1;
            }
            watch_pos += rc;
        }

        if (fds[0].revents & POLLIN) {
            must_read(parent_fd, &opcode, sizeof(opcode));
            if (opcode < 0 || opcode >= privsep_op_count)
                break;
            privsep_opcode[opcode]();
        }
    }
    clean_exit(0);
}

/**
 * Prepare privilege separation
 * - fork to have the other process
 * - privileged will connect to xenstore
 */
void
privsep_prepare(void)
{
    int socks[2];
    pid_t child;

    if (socketpair(AF_LOCAL, SOCK_STREAM, PF_UNSPEC, socks) == -1)
        err(1, "socketpair() failed");

    snprintf(root_directory, 64, "/var/xen/qemu/%d", getpid());
    if (mkdir(root_directory, 00755) < 0) {
        fprintf(stderr, "cannot create qemu scratch directory\n");
        strcpy(root_directory, "/var/empty");
    } else {
        /* directory have to be at least execute permission */
        chmod(root_directory, 0711);
        create_localtime();
    }

    parent_pid = getpid();

    child = fork();
    if (child < 0)
        err(1, "fork() failed");

    privsep_state = privsep_prepared;
    if (child == 0) {
        int i;
        struct rlimit limit;
        char *path;

        /* Child of privilege. */

        parent_fd = socks[0];
#ifdef QEMU_UNITEST
        close(socks[1]);
#endif

        if (getrlimit(RLIMIT_NOFILE, &limit) < 0)
            limit.rlim_max = 1024;

        /* The only file descriptor we really need is the socket to
           the parent.  Close everything else. */
        closelog();
        for (i = 0; i < limit.rlim_max; i++) {
#ifndef QEMU_UNITEST
            if (i != parent_fd)
                close(i);
#endif
        }

        /* Try to get something safe on to stdin, stdout, and stderr,
           to avoid embarrassing bugs if someone tries to fprintf to
           stderr and crashes xenstored. */
#ifndef QEMU_UNITEST
        open("/dev/null", O_RDONLY);
        open("/dev/null", O_WRONLY);
        open("/dev/null", O_WRONLY);
#endif

        logfile = stderr;

        priv_xsh = xs_daemon_open();
        if (!priv_xsh) {
            send_int(parent_fd, errno);
            exit(1);
        }

        domain_path = xs_get_domain_path(priv_xsh, domid);
        if (!domain_path) {
            send_int(parent_fd, errno);
            exit(1);
        }
        if (asprintf(&path, "%s/vm", domain_path) < 0) {
            send_int(parent_fd, ENOMEM);
            exit(1);
        }
        vm_path = xs_read(priv_xsh, XBT_NULL, path, NULL);
        if (!vm_path) {
            send_int(parent_fd, errno);
            exit(1);
        }
        free(path);

        send_int(parent_fd, 0);
        send_string(parent_fd, domain_path);

        privsep_loop();
    } else {
        /* We are the parent.  chroot and drop privileges. */
        close(socks[0]);
        privsep_fd = socks[1];

        /* wait privilege initialization */
        errno = receive_int(privsep_fd);
        if (errno)
            err(1, "privilege separation failure");

        /* read domain path */
        domain_path = receive_string(privsep_fd, NULL);
        if (!domain_path)
            err(1, "unable to read domain path");
    }
}

void
init_privsep(void)
{
    struct passwd *pw;
    struct group *gr;
    uid_t qemu_uid;
    gid_t qemu_gid;

    if (privsep_fd < 0 || privsep_state != privsep_prepared)
        err(1, "privilege separation not prepared");
    if (priv_xsh != NULL)
        err(1, "privilege separation not initialized properly");

    pw = getpwnam("qemu_base");
    if (!pw)
        err(1, "cannot get qemu user id");
    qemu_uid = pw->pw_uid + (unsigned short)domid;

    gr = getgrnam("qemu_base");
    if (!gr)
        err(1, "cannot get qemu group id");
    qemu_gid = gr->gr_gid + (unsigned short)domid;

    struct sigaction sigterm_handler, sigxfsz_handler;
    memset (&sigterm_handler, 0, sizeof(struct sigaction));
    memset (&sigxfsz_handler, 0, sizeof(struct sigaction));
    sigterm_handler.sa_handler = sigterm_handler_f;
    sigxfsz_handler.sa_handler = sigxfsz_handler_f;
    struct rlimit rlim;
    char name[64];
    int f;

    if (!crashdump_enabled()) {
        rlim.rlim_cur = 64 * 1024 * 1024;
        rlim.rlim_max = 64 * 1024 * 1024 + 64;
        setrlimit(RLIMIT_FSIZE, &rlim);
    }

    /* restrict network */
    if (unshare(CLONE_NEWNET))
        err(1, "unshare()");

    if (chdir(root_directory) < 0
        || chroot(root_directory) < 0
        || chdir("/") < 0)
        err(1, "cannot chroot");

    snprintf(name, 64, "core.%d", parent_pid);
    f = open(name, O_WRONLY|O_TRUNC|O_CREAT|O_NOFOLLOW, 0644);
    if (f > 0) {
        close(f);
        chown(name, qemu_uid, qemu_gid);
    }

    if (setgroups(0, NULL) < 0)
        err(1, "setgroups()");
    if (setgid(qemu_gid) < 0)
        err(1, "setgid()");
    if (setuid(qemu_uid) < 0)
        err(1, "setuid()");

    /* qemu core dumps are often useful; make sure they're allowed. */
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);

    /* handling termination signals */
    sigaction (SIGTERM, &sigterm_handler, NULL);
    sigaction (SIGINT, &sigterm_handler, NULL);
    sigaction (SIGHUP, &sigterm_handler, NULL);
    sigaction (SIGXFSZ, &sigxfsz_handler, NULL);

    closelog();

    privsep_state = privsep_started;
    send_command(privsep_fd, privsep_op_restrict_paths);
}
#endif

void
init_privxsh(void)
{
    if (privsep_state != privsep_not_initialized)
        return;

    priv_xsh = xs_daemon_open();
    if (!priv_xsh) {
        fprintf(logfile, "couldn't open privileged connection to xenstore\n");
        exit(0);
    }
}

int
privsep_open_ro(const char *cd_path)
{
    if (privsep_fd < 0)
        return open(cd_path, O_RDONLY|O_LARGEFILE|O_BINARY);

    if (!check_len(cd_path)) {
        errno = EINVAL;
        return -1;
    }
    send_command(privsep_fd, privsep_op_open_iso);
    send_string(privsep_fd, cd_path);

    return receive_fd(privsep_fd);
}

static void
do_set_cd_backend(int id, const char *path)
{
    if (cd_backend_areas[id]) return;

    cd_backend_areas[id] = strdup(path);
    if (!cd_backend_areas[id])
        err(1, "cloning cd backend path %s", path);
}

static void
set_cd_backend(void)
{
    int id = receive_int(parent_fd);
    receive_string_buf(parent_fd, cd_path);
    if (privsep_state == privsep_prepared && id >= 0 && id < MAX_CDS)
        do_set_cd_backend(id, cd_path);
}

void
privsep_set_cd_backend(int id, const char *cd_path)
{
    /* It's only meaningful to call this before we fork. */
    if (privsep_state == privsep_not_initialized)
        do_set_cd_backend(id, cd_path);

    if (privsep_state == privsep_prepared && check_len(cd_path)) {
        send_command(privsep_fd, privsep_op_set_cd_backend);
        send_int(privsep_fd, id);
        send_string(privsep_fd, cd_path);
    }
}

void
privsep_record_dm(const char *subpath, const char *privsep_state)
{
    if (privsep_fd < 0) {
        do_record_dm(subpath, privsep_state);
        return;
    }

    if (!check_len(subpath) || !check_len(privsep_state)) {
        errno = EINVAL;
        return;
    }
    send_command(privsep_fd, privsep_op_record_dm);
    send_string(privsep_fd, subpath);
    send_string(privsep_fd, privsep_state);
}

char*
privsep_read_dm(const char *subpath)
{
    if (privsep_fd < 0)
        return do_read_dm(subpath);

    if (!check_len(subpath)) {
        errno = EINVAL;
        return NULL;
    }

    send_command(privsep_fd, privsep_op_read_dm);
    send_string(privsep_fd, subpath);

    return receive_string(privsep_fd, NULL);
}

/*
 * Watches list
 */

typedef struct {
    char *path;
    char *token;
    unsigned int xs_conn;
} watch_t;

#define MAX_WATCHES 128
static watch_t watches[MAX_WATCHES];

static bool
watch_free(watch_t *w)
{
    if (!xs_unwatch(priv_xsh, w->path, w->token))
        return false;

    free(w->path);
    w->path = NULL;
    free(w->token);
    w->token = NULL;
    return true;
}

static bool
watches_add(unsigned int xs_conn, const char *path, const char *token)
{
    unsigned int n;
    char *p = strdup(path);
    char *t = strdup(token);
    int e = ENOMEM;
    if (!p || !t)
        goto cleanup;

    for (n = 0; n < MAX_WATCHES; ++n)
        if (!watches[n].path) {
            if (!xs_watch(priv_xsh, path, token)) {
                e = errno;
                goto cleanup;
            }
            watches[n].path = p;
            watches[n].token = t;
            watches[n].xs_conn = xs_conn;
            return true;
        }

cleanup:
    free(p);
    free(t);
    errno = e;
    return false;
}

static bool
watches_rm(unsigned int xs_conn, const char *path, const char *token)
{
    unsigned int n;
    for (n = 0; n < MAX_WATCHES; ++n) {
        /* skip invalid */
        if (!watches[n].path) continue;
        if (!watches[n].token) continue;

        /* skip not equal */
        if (watches[n].xs_conn != xs_conn) continue;
        if (strcmp(watches[n].path, path) != 0) continue;
        if (strcmp(watches[n].token, token) != 0) continue;

        return watch_free(&watches[n]);
    }
    errno = ENOENT;
    return false;
}

static void
watches_rm_conn(unsigned int xs_conn)
{
    unsigned int n;
    for (n = 0; n < MAX_WATCHES; ++n) {
        /* skip invalid */
        if (!watches[n].path) continue;
        if (!watches[n].token) continue;

        /* skip not equal */
        if (watches[n].xs_conn != xs_conn) continue;

        watch_free(&watches[n]);
    }
}

static int
watches_find(const char *token)
{
    unsigned int n;
    for (n = 0; n < MAX_WATCHES; ++n) {
        /* skip invalid */
        if (!watches[n].path) continue;
        if (!watches[n].token) continue;

        /* skip not equal */
        if (strcmp(watches[n].token, token) != 0) continue;

        return watches[n].xs_conn;
    }
    return -1;
}

/*
 * redirections
 */

static inline bool
xsh_valid(struct xs_handle *xsh)
{
    return xsh && ((privsep_handle_t*) xsh)->priv_handle < MAX_XS_CONN;
}

static inline void
send_xsh(struct xs_handle *xsh)
{
    privsep_handle_t *h = (privsep_handle_t *) xsh;
    send_raw(privsep_fd, h->priv_handle);
}

static inline unsigned
receive_xsh(void)
{
    unsigned n;
    must_read(parent_fd, &n, sizeof(n));
    if (n > MAX_XS_CONN)
        clean_exit(1);
    return n;
}

static inline bool
path_starts_with(const char *path, const char *s)
{
    size_t l = strlen(s);
    return strncmp(path, s, l) == 0 && (path[l] == 0 || path[l] == '/');
}

static bool
check_xs_path(const char *path, check_type_t check)
{
    static const char backend_d0[] = "/local/domain/0/backend";
    static const char dm_d0[] = "/local/domain/0/device-model";
    const char *s;
    char dom_num[64];

    if (privsep_state != privsep_started)
        return true;

    if (path_starts_with(path, domain_path)) {
        if (check == CHECK_READ)
            return true;
        if (check != CHECK_WRITE)
            goto fail;
        s = path + strlen(domain_path);
        if (*s++ != '/')
            return false;
        /*
         * removed "device" as used only by Qemu as backend
         * (not used in XenServer)
         */
        if (strcmp(s, "data/report_clipboard") == 0
            || strcmp(s, "data/set_clipboard") == 0
            || strcmp(s, "data/updated") == 0
            || strcmp(s, "console/vnc-port") == 0
            || strcmp(s, "device-misc/dm-ready") == 0
            || strcmp(s, "control/feature-suspend") == 0
            || strcmp(s, "control/feature-shutdown") == 0
            || strcmp(s, "control/feature-vcpu-hotplug") == 0)
            return true;
    }

    if (path_starts_with(path, dm_d0)) {
        s = path + strlen(dm_d0);
        sprintf(dom_num, "/%u", domid);
        if (!path_starts_with(s, dom_num))
            goto fail;
        if (check == CHECK_READ)
            return true;
        s += strlen(dom_num);
        if (*s++ != '/' || check != CHECK_WRITE)
            goto fail;
        if (strcmp(s, "logdirty/ret") == 0
            || strcmp(s, "logdirty/cmd") == 0
            || strcmp(s, "command") == 0
            || strcmp(s, "parameter") == 0
            || strcmp(s, "state") == 0)
            return true;
    }

    if (check != CHECK_READ)
        goto fail;

    if (path_starts_with(path, backend_d0)) {
        s = path + strlen(backend_d0);
        if (s[0] != '/' || s[1] == 0 || s[1] == '/')
            return false;
        s = strchr(s+2, '/');
        if (!s) goto fail;
        sprintf(dom_num, "%u", domid);
        if (path_starts_with(s+1, dom_num))
            return true;
    }

    if (vm_path && path_starts_with(path, vm_path))
        return true;

    if (path_starts_with(path, "/local/logconsole"))
        return true;

    if (path_starts_with(path, "/mh/driver-blacklist"))
        return true;

    if (strcmp(path, "@releaseDomain") == 0)
        return true;

fail:
    /* NOTE: if returns false should set errno to EACCES */
    errno = EACCES;
    return false;
}

char *
privsep_get_domain_path(struct xs_handle *xsh, unsigned int domid)
{
    char *path;

    if (asprintf(&path, "/local/domain/%u", domid) < 0)
        return NULL;
    return path;
}

void *privsep_read(struct xs_handle *xsh, xs_transaction_t t,
                   const char *xs_path, unsigned int *len)
{
    if (privsep_state == privsep_not_initialized)
        return xs_read(xsh, t, xs_path, len);

    if (!check_len(xs_path) || !xsh_valid(xsh)) {
        errno = EINVAL;
        return NULL;
    }
    send_command(privsep_fd, privsep_op_read_xs);
    send_string(privsep_fd, xs_path);

    char *res = receive_string(privsep_fd, len);
    errno = receive_int(privsep_fd);
    return res;
}

static void
read_xs(void)
{
    unsigned int len;

    receive_string_buf(parent_fd, xs_path);

    char *value = NULL;

    if (check_xs_path(xs_path, CHECK_READ))
        value = xs_read(priv_xsh, XBT_NULL, xs_path, &len);
    int error = errno;
    send_buf(parent_fd, value, len);
    free(value);
    send_int(parent_fd, error);
}

bool
privsep_write(struct xs_handle *xsh, xs_transaction_t t,
              const char *xs_path, const void *data, unsigned int len)
{
    if (privsep_state == privsep_not_initialized)
        return xs_write(xsh, t, xs_path, data, len);

    if (!check_len(xs_path) || len > max_len_xs_data || !xsh_valid(xsh)) {
        errno = EINVAL;
        return NULL;
    }
    send_command(privsep_fd, privsep_op_write_xs);
    send_string(privsep_fd, xs_path);
    send_buf(privsep_fd, data, len);

    return receive_bool_errno(privsep_fd);
}

static void
write_xs(void)
{
    receive_string_buf(parent_fd, xs_path);

    unsigned len;
    char *data = receive_string_limited(parent_fd, &len, max_len_xs_data);
    if (!data)
        clean_exit(1);

    bool res = check_xs_path(xs_path, CHECK_WRITE);
    int error = EACCES;

    if (res) {
        res = xs_write(priv_xsh, XBT_NULL, xs_path, data, len);
        error = errno;
    }
    free(data);
    send_bool_errno(parent_fd, res, error);
}

char **
privsep_directory(struct xs_handle *xsh, xs_transaction_t t,
                  const char *xs_path, unsigned int *num)
{
    if (privsep_state == privsep_not_initialized)
        return xs_directory(xsh, t, xs_path, num);

    if (!check_len(xs_path) || !xsh_valid(xsh)) {
        errno = EINVAL;
        return NULL;
    }
    send_command(privsep_fd, privsep_op_directory_xs);
    send_string(privsep_fd, xs_path);

    char **res = receive_list(privsep_fd, num);
    errno = receive_int(privsep_fd);
    return res;
}

static void
directory_xs(void)
{
    receive_string_buf(parent_fd, xs_path);

    unsigned num;
    char **list = NULL;

    if (check_xs_path(xs_path, CHECK_READ))
        list = xs_directory(priv_xsh, XBT_NULL, xs_path, &num);
    int error = errno;
    send_list(parent_fd, list, num);
    free(list);
    send_int(parent_fd, error);
}

bool
privsep_watch(struct xs_handle *xsh, const char *xs_path, const char *token)
{
    if (privsep_state == privsep_not_initialized)
        return xs_watch(xsh, xs_path, token);

    if (!check_len(xs_path) || !check_len(token) || !xsh_valid(xsh)) {
        errno = EINVAL;
        return NULL;
    }
    send_command(privsep_fd, privsep_op_watch_xs);
    send_xsh(xsh);
    send_string(privsep_fd, xs_path);
    send_string(privsep_fd, token);

    return receive_bool_errno(privsep_fd);
}

static void
watch_xs(void)
{
    unsigned xs_conn = receive_xsh();
    receive_string_buf(parent_fd, xs_path);
    receive_string_buf(parent_fd, token);

    /* check path, add to a list */
    bool res = check_xs_path(xs_path, CHECK_READ);
    if (res)
        res = watches_add(xs_conn, xs_path, token);
    send_bool_errno(parent_fd, res, errno);
}

bool
privsep_unwatch(struct xs_handle *xsh, const char *xs_path, const char *token)
{
    if (privsep_state == privsep_not_initialized)
        return xs_unwatch(xsh, xs_path, token);

    if (!check_len(xs_path) || !check_len(token) || !xsh_valid(xsh)) {
        errno = EINVAL;
        return NULL;
    }
    send_command(privsep_fd, privsep_op_unwatch_xs);
    send_xsh(xsh);
    send_string(privsep_fd, xs_path);
    send_string(privsep_fd, token);

    return receive_bool_errno(privsep_fd);
}

static void
unwatch_xs(void)
{
    unsigned xs_conn = receive_xsh();
    receive_string_buf(parent_fd, xs_path);
    receive_string_buf(parent_fd, token);

    /* delete from list */
    bool res = watches_rm(xs_conn, xs_path, token);
    send_bool_errno(parent_fd, res, errno);
}

bool
privsep_rm(struct xs_handle *xsh, xs_transaction_t t,
           const char *xs_path)
{
    if (privsep_state == privsep_not_initialized)
        return xs_rm(xsh, t, xs_path);

    if (!check_len(xs_path) || !xsh_valid(xsh)) {
        errno = EINVAL;
        return NULL;
    }
    send_command(privsep_fd, privsep_op_rm_xs);
    send_string(privsep_fd, xs_path);

    return receive_bool_errno(privsep_fd);
}

static void
rm_xs(void)
{
    receive_string_buf(parent_fd, xs_path);

    bool res = check_xs_path(xs_path, CHECK_WRITE);
    int error = EACCES;

    if (res) {
        res = xs_rm(priv_xsh, XBT_NULL, xs_path);
        error = errno;
    }
    send_bool_errno(parent_fd, res, error);
}

/**
 * privsep_daemon_open
 * wrapper for xs_daemon_open
 * We need to provide a dummy connection for every connection requested
 * to be able to send back watches on the appropriate connection.
 */
struct xs_handle *
privsep_daemon_open(void)
{
    if (privsep_state == privsep_not_initialized)
        return xs_daemon_open();

    privsep_handle_t *h = (privsep_handle_t*) calloc(1, sizeof(privsep_handle_t));
    if (!h)
        return NULL;

    send_command(privsep_fd, privsep_op_daemon_open_xs);

    must_read(privsep_fd, &h->priv_handle, sizeof(h->priv_handle));
    int fd = receive_fd(privsep_fd);
    if (fd < 0) {
        free(h);
        return NULL;
    }
    h->watch_fd = fd;
    return (struct xs_handle *) h;
}

static void
daemon_open_xs(void)
{
    int fds[2] = { -1, -1 };

    /* allocate a new connection */
    unsigned n;
    for (n = 0; n < MAX_XS_CONN; ++n) {
        if (xs_conns[n] < 0) {
            /* create a pipe for this connection */
            if (pipe(fds) < 0) {
                fds[0] = -1;
            } else {
                xs_conns[n] = fds[1];
            }
            break;
        }
    }

    /* return it */
    send_raw(parent_fd, n);
    send_fd(parent_fd, fds[0]);
    if (fds[0] >= 0)
        close(fds[0]);
}

void
privsep_daemon_close(struct xs_handle *xsh)
{
    if (privsep_state == privsep_not_initialized) {
        xs_daemon_close(xsh);
        return;
    }

    if (!xsh_valid(xsh))
        return;

    send_command(privsep_fd, privsep_op_daemon_close_xs);
    send_xsh(xsh);

    /* wait other end close */
    errno = receive_int(privsep_fd);

    privsep_handle_t *h = (privsep_handle_t*) xsh;
    close(h->watch_fd);
    free(h);
}

static void
daemon_close_xs(void)
{
    /* get connection */
    unsigned n = receive_xsh();

    /* on double free ignore */
    if (xs_conns[n] < 0)
        goto done;

    /* remove watches */
    watches_rm_conn(n);

    close(xs_conns[n]);
    xs_conns[n] = -1;

done:
    send_int(parent_fd, 0);
}

int
privsep_fileno(struct xs_handle *xsh)
{
    if (privsep_state == privsep_not_initialized)
        return xs_fileno(xsh);

    if (!xsh_valid(xsh))
        return -1;

    return ((privsep_handle_t*) xsh)->watch_fd;
}

char **
privsep_read_watch(struct xs_handle *xsh, unsigned int *num)
{
    if (privsep_state == privsep_not_initialized)
        return xs_read_watch(xsh, num);

    /* read from other end */
    if (!xsh_valid(xsh))
        return NULL;

    return receive_list(((privsep_handle_t*) xsh)->watch_fd, num);
}

static void
restrict_paths(void)
{
    privsep_state = privsep_started;
}

/* restriction functions */
#undef xc_interface_restrict
typedef int xc_interface_restrict_t(xc_interface *xc_handle, uint32_t domid);

int
xc_interface_restrict_qemu(xc_interface *xc_handle, int domid)
{
    xc_interface_restrict_t *p = (xc_interface_restrict_t*) dlsym(RTLD_DEFAULT, "xc_interface_restrict");
    if (!p)
        return -1;
    return p(xc_handle, domid);
}

#define IOCTL_EVTCHN_RESTRICT_DOMID                    \
    _IOC(_IOC_NONE, 'E', 100, sizeof(struct ioctl_evtchn_restrict_domid))
struct ioctl_evtchn_restrict_domid {
    domid_t domid;
};

int
xc_evtchn_restrict(xc_interface *xce_handle, int domid)
{
    int fd;
    struct ioctl_evtchn_restrict_domid restrict_domid = { domid };

    fd = xc_evtchn_fd(xce_handle);
    if (fd < 0)
        return -1;
    if (ioctl(fd, IOCTL_EVTCHN_RESTRICT_DOMID, &restrict_domid) < 0)
        return -1;
    return 0;
}

