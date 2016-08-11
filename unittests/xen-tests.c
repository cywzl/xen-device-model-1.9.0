#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <syslog.h>

#include <qemu-common.h>

static int  syslog_called = 0;
static char syslog_buf[512];

void __wrap_vsyslog(int priority, const char *format, va_list ap)
{
    memset(syslog_buf, 0, sizeof(syslog_buf));
    vsnprintf(syslog_buf, sizeof(syslog_buf), format, ap);
    ++syslog_called;
}

void __wrap_syslog(int priority, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    __wrap_vsyslog(LOG_INFO, format, ap);
    va_end(ap);
}

static void syslog_check(const char *expected)
{
    fail_if(syslog_called != use_syslog);
    if (use_syslog)
        fail_if(strstr(syslog_buf, expected) == NULL, "output: %s", syslog_buf);

    /* reset back to original state */
    syslog_called = 0;
    memset(syslog_buf, 0, sizeof(syslog_buf));
}

static void call_vfprintf(FILE *f, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vfprintf(f, format, ap);
    va_end(ap);
}

START_TEST (syslog_redirect)
{
    FILE *out = fopen("out.txt", "w+");
    fail_if(out == NULL);

    for (use_syslog = 0; use_syslog < 2; ++use_syslog) {

        /* for all these functions output should be
         * redirected to syslog
         */
        printf("check\n");
        syslog_check("check");

        errno = EINVAL;
        perror("errno");
        syslog_check(strerror(EINVAL));

        fprintf(stderr, "check %d\n", 7654);
        syslog_check("7654");

        fprintf(stdout, "check %d\n", 12345);
        syslog_check("12345");

        call_vfprintf(stdout, "%d\n", -456);
        syslog_check("-456");

        call_vfprintf(stderr, "%d\n", -62243);
        syslog_check("-62243");

        /* These functions should just write to the file
         * No output to syslog
         */
        fprintf(out, "line one\n");
        fail_if(syslog_called != 0);

        call_vfprintf(out, "line %d\n", 876);
        fail_if(syslog_called != 0);
    }

    /* check content of the file */
    fail_if(fseek(out, 0L, SEEK_SET) != 0);
    for (use_syslog = 0; use_syslog < 2; ++use_syslog) {
        fail_if(fgets(syslog_buf, sizeof(syslog_buf), out) == NULL);
        fail_if(strcmp(syslog_buf, "line one\n") != 0);

        fail_if(fgets(syslog_buf, sizeof(syslog_buf), out) == NULL);
        fail_if(strcmp(syslog_buf, "line 876\n") != 0);
    }
    fail_if(fgets(syslog_buf, sizeof(syslog_buf), out) != NULL);

    /* cleanup */
    fclose(out);
    unlink("out.txt");
}
END_TEST
 
TCase *sep_tc (void);

static Suite *
xen_suite (void)
{
    Suite *s = suite_create ("Xen");

    /* Core test case */
    TCase *tc_syslog = tcase_create ("Syslog");
    tcase_add_test (tc_syslog, syslog_redirect);
    suite_add_tcase (s, tc_syslog);
    suite_add_tcase (s, sep_tc());

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s = xen_suite ();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

