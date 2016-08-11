/* Stupid driver to make it easy to get kernel crashdumps out of
   Windows guests */
#include <sys/types.h>
#include <stdint.h>
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "cpu.h"
#include "exec-all.h"

#include "hw.h"
#include "pci.h"
#include "qemu-xen.h"

#define CRASHDUMP_CONTROL_PORT  0xeb
#define CRASHDUMP_DATA_PORT     0xec

#define CRASHDUMP_VERSION       1

static const char *crashdump_dir;
static char *crashdump_path;
static long long crashdump_quota;
static int crashdump_fd = -1;
static int crashdump_failed;
static int crashdump_registered;

static void
open_crashdump(void)
{
    DIR *d = NULL;
    struct dirent *de;
    char *path = NULL;
    int nr_files;
    int e;
    int fd = -1;

    d = opendir(crashdump_dir);
    if (d == NULL) {
        fprintf(logfile, "cannot open %s: %s\n", crashdump_dir,
                strerror(errno));
        goto fail;
    }

    nr_files = 0;
    while ((de = readdir(d))) {
        struct stat sb;

        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;

        if (asprintf(&path, "%s/%s", crashdump_dir, de->d_name) == -1) {
            fprintf(logfile, "cannot allocate memory\n");
            goto fail;
        }

        if (stat(path, &sb) < 0) {
            fprintf(logfile, "cannot stat %s: %s\n", path, strerror(errno));
            goto fail;
        }
        if (sb.st_size != 0) {
            crashdump_quota -= sb.st_size;
            nr_files++;
        }

        free(path);
        path = NULL;
    }
    closedir(d);
    d = NULL;

    /* If we run below 64k, give up, since we won't even be able to
       get a minidump out. */
    if (crashdump_quota < 65536) {
        fprintf(logfile, "out of quota\n");
        goto fail;
    }

    fprintf(logfile, "available crashdump quota = %lldk\n",
            crashdump_quota / 1024);

    /* Create the dump file */
    for (e = nr_files; e < nr_files * 2 + 1; e++) {
        if (asprintf(&path, "%s/%d", crashdump_dir, e) < 0) {
            fprintf(logfile, "allocating memory: %s\n", strerror(errno));
            goto fail;
        }

        fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) /* success */
            break;

        if (errno != EEXIST) {
            fprintf(logfile, "openning %s: %s\n", path, strerror(errno));
            goto fail;
        }

        free(path);
        path = NULL;
    }

    if (e == nr_files * 2 + 1) {
        fprintf(logfile, "cannot find a place to dump to in %s\n",
                crashdump_dir);
        goto fail;
    }

    crashdump_path = path;
    crashdump_fd = fd;
    return;

fail:
    if (path != NULL) {
        free(path);
        path = NULL;
    }

    if (d != NULL) {
        closedir(d);
        d = NULL;
    }
}

int
crashdump_enabled(void)
{
    return (crashdump_fd >= 0);
}

static void
close_crashdump(void)
{
    /* Leave incomplete crash dumps tp be tidied up */
    if (crashdump_failed)
        return;

    close(crashdump_fd);
    crashdump_fd = -1;

    free(crashdump_path);
    crashdump_path = NULL;
}

static int
write_crashdump_page(target_phys_addr_t addr)
{
    char buf[TARGET_PAGE_SIZE];
    int count;
    int rc;

    if (crashdump_fd < 0)
        return -1;

    if (crashdump_quota < 0) {
        fprintf(logfile, "out of quota\n");
        return -1;
    }

    cpu_physical_memory_rw(addr, buf, TARGET_PAGE_SIZE, 0);

    for (count = 0; count < TARGET_PAGE_SIZE; count += rc) {
        rc = write(crashdump_fd, buf, TARGET_PAGE_SIZE);
        if (rc <= 0) {
            fprintf(logfile, "failed to write to dump file (%d, %s)\n",
                    rc, strerror(errno));
            return -1;
        }
    }

    crashdump_quota -= TARGET_PAGE_SIZE;
    return 0;
}

static uint32_t
control_port_read(void *ign, uint32_t ign2)
{
    unsigned char version = CRASHDUMP_VERSION;

    fprintf(logfile, "Crashdump version (%02x).\n", version);

    return (uint32_t)version;
}

static uint32_t
data_port_read(void *ign, uint32_t ign2)
{
    return (uint32_t)((crashdump_registered) ? 0x00 : 0xff);
}

static void
control_port_write(void *ign, uint32_t ign2, uint32_t data)
{
    switch ((unsigned char)data) {
    case 0x00:
        fprintf(logfile, "Crashdump callback is registered.\n");
        crashdump_registered = 1;
        break;
    case 0x01:
        fprintf(logfile, "Starting crashdump.\n");
        break;
    case 0x02:
        fprintf(logfile, "Completing crashdump (%s).\n", crashdump_path);
        close_crashdump();
        break;
    default:
        fprintf(logfile, "unknown crashdump control port write (%02x)\n",
                (unsigned char)data);
        break;
    }
}

static void
data_port_write(void *ign, uint32_t ign2, uint32_t data)
{
    target_phys_addr_t addr = data;

    if (crashdump_failed)
        return;

    addr <<= TARGET_PAGE_BITS;

    if (write_crashdump_page(addr) < 0)
        crashdump_failed = 1;
}

static void
tidy_up(void)
{
    if (crashdump_fd < 0)
        return;

    /* The crashdump did not terminate cleanly */
    close(crashdump_fd);

    fprintf(logfile, "Cleaning up failed crashdump: %s\n", crashdump_path);
    unlink(crashdump_path);
    free(crashdump_path);
}

void register_crashdump(void)
{
    if (crashdump_dir == NULL)
        return;

    register_ioport_read(CRASHDUMP_CONTROL_PORT, 1, 1,
                         control_port_read, NULL);
    register_ioport_read(CRASHDUMP_DATA_PORT, 1, 1,
                         data_port_read, NULL);

    register_ioport_write(CRASHDUMP_CONTROL_PORT, 1, 1,
                          control_port_write, NULL);
    register_ioport_write(CRASHDUMP_DATA_PORT, 4, 4,
                          data_port_write, NULL);

    fprintf(logfile, "crashdump ports enabled\n");
}

void provision_crashdump(const char *dir, long long quota)
{
    crashdump_dir = dir;

    /* Set an initial value for available crashdump quota */
    crashdump_quota = (quota > 0) ?
                      quota * 1024 * 1024 :
                      LONG_LONG_MAX;

    open_crashdump();

    atexit(tidy_up);
}
