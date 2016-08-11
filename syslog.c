/*
 * Syslog redirection functions
 * 
 * Copyright (c) 2014 Citrix Systems Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "qemu-common.h"
#include "privsep.h"

#ifdef CONFIG_SYSLOG
#include <syslog.h>

#ifndef perror
#error perror should be defined
#endif

char use_syslog = 0;

#undef fprintf
#undef printf
#undef vfprintf
#undef perror

int log_vfprintf(FILE *f, const char *fmt, va_list ap)
{
    if (use_syslog && (f == stdout || f == stderr)) {
        if (privileged || privsep_state != privsep_started)
            vsyslog(LOG_DAEMON|LOG_INFO, fmt, ap);
        else
            privsep_vsyslog(fmt, ap);
        /* just return a value to make every caller happy */
        return 10;
    }

    return vfprintf(f, fmt, ap);
}

void log_perror(const char *s)
{
    if (!use_syslog) {
        perror(s);
        return;
    }

    char errbuf[256];
    int err = errno;

    errno = 0;
    strerror_r(err, errbuf, sizeof(errbuf));
    if (errno != 0)
       return;

    if (s && *s) {
        if (privileged || privsep_state != privsep_started)
            syslog(LOG_DAEMON|LOG_INFO, "%s: %s", s, errbuf);
        else
            privsep_syslog("%s: %s", s, errbuf);
    } else {
        if (privileged || privsep_state != privsep_started)
            syslog(LOG_DAEMON|LOG_INFO, "%s", errbuf);
        else
            privsep_syslog("%s", errbuf);
    }
}

int log_printf(const char *fmt, ...)
{
    va_list ap;
    int res;

    va_start(ap, fmt);
    res = log_vfprintf(stdout, fmt, ap);
    va_end(ap);

    return res;
}

int log_fprintf(FILE* f, const char *fmt, ...)
{
    va_list ap;
    int res;

    va_start(ap, fmt);
    res = log_vfprintf(f, fmt, ap);
    va_end(ap);

    return res;
}

#endif

