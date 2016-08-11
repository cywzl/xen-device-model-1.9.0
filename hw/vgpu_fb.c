#include "hw.h"
#include "console.h"
#include "pc.h"
#include "pci.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <sys/mman.h>
#include "sysemu.h"
#include "qemu-xen.h"
#include "exec-all.h"

#include "qemu-timer.h"

#pragma pack(1)

typedef struct shared_surface {
    uint32_t    offset;
    uint32_t    linesize;
    uint32_t    width;
    uint32_t    height;
    uint32_t    depth;
    uint32_t    update;
    uint16_t    port;
} shared_surface_t;

#pragma pack(0)

typedef struct vgpu_fb_state {
    DisplayState *ds;
    shared_surface_t *shared;

    uint32_t surface_offset;
    uint32_t surface_linesize;
    uint32_t surface_width;
    uint32_t surface_height;
    uint32_t surface_depth;
    uint32_t surface_update;

    uint8_t *surface_buffer;

    struct sockaddr_in server;
    int surface_fd;
} vgpu_fb_state;

#define	P2ROUNDUP(_x, _a) -(-(_x) & -(_a))

static void vgpu_fb_update(void *opaque)
{
    vgpu_fb_state *s = (vgpu_fb_state *)opaque;
    char buf = 'S';

    sendto(s->surface_fd, &buf, 1, MSG_DONTWAIT, &s->server, sizeof (s->server));

    if (s->surface_offset != s->shared->offset ||
        s->surface_linesize != s->shared->linesize ||
        s->surface_width != s->shared->width ||
        s->surface_height != s->shared->height ||
        s->surface_depth != s->shared->depth) {
        if (s->ds->surface != NULL)
            qemu_free_displaysurface(s->ds);

        s->surface_offset = s->shared->offset;
        s->surface_linesize = s->shared->linesize;
        s->surface_width = s->shared->width;
        s->surface_height = s->shared->height;
        s->surface_depth = s->shared->depth;

        fprintf(stderr, "%s: %dx%dx%d @ %x (linesize = %x)\n", __func__,
                s->surface_width, s->surface_height, s->surface_depth,
                s->surface_offset, s->surface_linesize);

        s->ds->surface = qemu_create_displaysurface_from(s->surface_width,
                                                         s->surface_height,
                                                         s->surface_depth,
                                                         s->surface_linesize,
                                                         s->surface_buffer + s->surface_offset);
        dpy_resize(s->ds);
    }

    if (s->surface_update != s->shared->update) {
        s->surface_update = s->shared->update;

        dpy_update(s->ds, 0, 0,
                   s->surface_width, s->surface_height);
    }
}

#define SURFACE_RESERVED_ADDRESS    0xff000000
#define SURFACE_RESERVED_SIZE       0x01000000

void
vgpu_fb_init(void)
{
    const int n = SURFACE_RESERVED_SIZE >> TARGET_PAGE_BITS;
    xen_pfn_t pfn[n];
    int i;
    vgpu_fb_state *s;
    int fd;

    s = qemu_mallocz(sizeof(vgpu_fb_state));
    if (!s)
        return;

    s->ds = graphic_console_init(vgpu_fb_update,
                                 NULL,
                                 NULL,
                                 NULL,
                                 s);

    for (i = 0; i < n; i++)
        pfn[i] = (SURFACE_RESERVED_ADDRESS >> TARGET_PAGE_BITS) + i;

    s->surface_buffer = xc_map_foreign_pages(xc_handle, domid,
                                             PROT_READ | PROT_WRITE,
                                             pfn, n);
    if (s->surface_buffer == NULL) {
        fprintf(stderr, "mmap failed\n");
        exit(1);
    }

    s->shared = (shared_surface_t *)(s->surface_buffer +
                                     SURFACE_RESERVED_SIZE -
                                     TARGET_PAGE_SIZE);

    fprintf(stderr, "vgpu: port = %u\n", s->shared->port);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "socket failed\n");
        exit(1);
    }

    s->surface_fd = fd;

    s->server.sin_family = AF_INET;
    s->server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    s->server.sin_port = htons(s->shared->port);
}
