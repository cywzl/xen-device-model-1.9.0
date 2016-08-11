#ifndef PRIVSEP_H
#define PRIVSEP_H

#include <stdarg.h>

/* privsep.c */
void privsep_prepare(void);
void init_privsep(void);
void init_privxsh(void);
int privsep_open_ro(const char *path);
void privsep_eject_cd(int id);
void privsep_lock_cd(int id);
void privsep_unlock_cd(int id);
void privsep_set_rtc_timeoffset(long offset);
void privsep_set_cd_backend(int id, const char *path);
QEMUFile* privsep_open_vm_dump(const char *name);
FILE* privsep_open_keymap(const char *language);
void privsep_record_dm(const char *subpath, const char *state);
char* privsep_read_dm(const char *subpath);
int privsep_vsyslog(const char *fmt, va_list ap);
int privsep_syslog(const char *fmt, ...);

/* redirections */
char *privsep_get_domain_path(struct xs_handle *xsh, unsigned int domid);
#define xs_get_domain_path(h, domid) privsep_get_domain_path(h, domid)
void *privsep_read(struct xs_handle *h, xs_transaction_t t,
		   const char *path, unsigned int *len);
#define xs_read(h, t, p, l) privsep_read(h, t, p, l)
bool privsep_write(struct xs_handle *h, xs_transaction_t t,
		   const char *path, const void *data, unsigned int len);
#define xs_write(h, t, p, d, l) privsep_write(h, t, p, d, l)
char **privsep_directory(struct xs_handle *h, xs_transaction_t t,
			 const char *path, unsigned int *num);
#define xs_directory(h, t, p, n) privsep_directory(h, t, p, n)
bool privsep_watch(struct xs_handle *h, const char *path, const char *token);
#define xs_watch(h, p, t) privsep_watch(h, p, t)
bool privsep_unwatch(struct xs_handle *h, const char *path, const char *token);
#define xs_unwatch(h, p, t) privsep_unwatch(h, p, t)
bool privsep_rm(struct xs_handle *h, xs_transaction_t t,
		const char *path);
#define xs_rm(h, t, p) privsep_rm(h, t, p)
struct xs_handle *privsep_daemon_open(void);
#define xs_daemon_open() privsep_daemon_open()
void privsep_daemon_close(struct xs_handle *h);
#define xs_daemon_close(h) privsep_daemon_close(h)
int privsep_fileno(struct xs_handle *xsh);
#define xs_fileno(h) privsep_fileno(h)
char **privsep_read_watch(struct xs_handle *h, unsigned int *num);
#define xs_read_watch(h, n) privsep_read_watch(h, n)

int xc_interface_restrict_qemu(xc_interface *xc_handle, int domid);
#define xc_interface_restrict(h,d) xc_interface_restrict_qemu(h,d)
int xc_evtchn_restrict(xc_interface *xce_handle, int domid);

typedef enum {
    /** not initialized at all, call privsep_prepare */
    privsep_not_initialized = 0,
    /** prepared but xenstore is not restricted */
    privsep_prepared,
    privsep_started,
} privsep_state_t;

extern int privileged;
extern privsep_state_t privsep_state;

#endif
