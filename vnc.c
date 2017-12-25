/*
 * QEMU VNC display driver
 *
 * Copyright (C) 2006 Anthony Liguori <anthony@codemonkey.ws>
 * Copyright (C) 2006 Fabrice Bellard
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

#include "qemu-common.h"
#include "console.h"
#include "sysemu.h"
#include "qemu_socket.h"
#include "qemu-timer.h"
#include "audio/audio.h"
#include <zlib.h>
#include <sys/mman.h>

/* output limit to stop handling requests */
#define VNC_OUTPUT_LIMIT (2u*1024u*1024u)

#define VNC_REFRESH_INTERVAL_BASE 30
#define VNC_REFRESH_INTERVAL_INC  50
#define VNC_REFRESH_INTERVAL_MAX  2000

#include "vnc.h"
#include "vnc_keysym.h"
#include "keymaps.c"
#include "d3des.h"

void xenstore_set_guest_clipboard(const char *text, size_t len);

#ifdef CONFIG_VNC_TLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#endif /* CONFIG_VNC_TLS */

// #define _VNC_DEBUG 1

#ifdef _VNC_DEBUG
#define VNC_DEBUG(fmt, ...) do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)

#if defined(CONFIG_VNC_TLS) && _VNC_DEBUG >= 2
/* Very verbose, so only enabled for _VNC_DEBUG >= 2 */
static void vnc_debug_gnutls_log(int level, const char* str) {
    VNC_DEBUG("%d %s", level, str);
}
#endif /* CONFIG_VNC_TLS && _VNC_DEBUG */
#else
#define VNC_DEBUG(fmt, ...) do { } while (0)
#endif

#define count_bits(c, v) { \
    for (c = 0; v; v >>= 1) \
    { \
        c += v & 1; \
    } \
}

/*
 * maximum buffer size, if bigger is requested a failure is returned.
 * This is actually sufficient and should at least contains enough memory
 * to handle a full screen frame.
 */
#define VNC_BUFFER_MAX_SIZE ((size_t) 32*1024*1024)
/* minimum size, buffer is not shrunk below this limit */
#define VNC_BUFFER_MIN_SIZE ((size_t) 64*1024)

static size_t host_page_size = 4096;

typedef struct Buffer
{
    size_t capacity;
    size_t offset;
    uint8_t *buffer;
} Buffer;

typedef struct VncState VncState;

typedef int VncReadEvent(VncState *vs, uint8_t *data, size_t len);

typedef void VncWritePixels(VncState *vs, void *data, int size);

typedef void VncSendHextileTile(VncState *vs,
                                int x, int y, int w, int h,
                                void *last_bg,
                                void *last_fg,
                                int *has_bg, int *has_fg);

#define VNC_AUTH_CHALLENGE_SIZE 16

typedef struct VncDisplay VncDisplay;

#define VNC_PIXELS_PER_DIRTY_BIT 16
#define VNC_PIXELS_PER_DIRTY_WORD (VNC_PIXELS_PER_DIRTY_BIT * 8 * sizeof(uint32_t))

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

struct VncDirtyBuffer {
    uint32_t *bits;
    uint32_t width;
    uint32_t height;
    uint32_t line_words;
};

static void dirty_resize(struct VncDirtyBuffer *dbuf, uint32_t w, uint32_t h)
{
    uint32_t lw;

    lw = DIV_ROUND_UP(w, VNC_PIXELS_PER_DIRTY_WORD);

    if (dbuf->bits)
        qemu_free(dbuf->bits);

    dbuf->bits = qemu_mallocz(sizeof(*dbuf->bits) * h * lw);

    dbuf->height = h;
    dbuf->width = w;
    dbuf->line_words = lw;
}

static uint32_t *dirty_line(struct VncDirtyBuffer *dbuf, uint32_t y)
{
    return dbuf->bits + dbuf->line_words * y;
}

static void dirty_set_bit(struct VncDirtyBuffer *dbuf, uint32_t x, uint32_t y)
{
    uint32_t *line;

    line = dirty_line(dbuf, y);
    line[x >> 5] |= 1 << (x & 0x1f);
}

static inline void dirty_clear_bit(struct VncDirtyBuffer *dbuf, uint32_t x, uint32_t y)
{
    uint32_t *line = dirty_line(dbuf, y);

    line[x >> 5] &= ~(1 << (x & 0x1f));
}

static inline int dirty_get_bit(struct VncDirtyBuffer *dbuf, uint32_t x, uint32_t y)
{
    uint32_t *line = dirty_line(dbuf, y);

    return (line[x >> 5] >> (x & 0x1f)) & 1;
}

static void dirty_set_segment(struct VncDirtyBuffer *dbuf, uint32_t y,
                              uint32_t x, uint32_t w)
{
    uint32_t *line = dirty_line(dbuf, y);
    uint32_t *word;
    uint32_t i;
    uint32_t b, e; /* begin and end bit offsets */

    b = x / 16;
    e = DIV_ROUND_UP(x + w, 16);

    /*
     * This is equivalent to:
     *
     * for (i = b; i < e; i++)
     *     dirty_set_bit(b, i, y);
     */

    word = line + b / 32;

    if (b & 31) {
        *word++ |= 0xffffffff << (b & 31);
        b += 32 - (b & 31);
    }

    while (e - b >= 32) {
        *word++ = 0xffffffff;
        b += 32;
    }

    if (e > b)
        *word++ |= (1 << (e - b)) - 1;
}

static void dirty_set_region(struct VncDirtyBuffer *dbuf,
                             uint32_t x, uint32_t y,
                             uint32_t w, uint32_t h)
{
    for (; y < dbuf->height; y++)
        dirty_set_segment(dbuf, y, x, w);
}

static void dirty_set_all(struct VncDirtyBuffer *dbuf)
{
    dirty_set_region(dbuf, 0, 0, dbuf->width, dbuf->height);
}

static inline int line_is_dirty(struct VncDirtyBuffer *dbuf, uint32_t y)
{
    uint32_t *line = dirty_line(dbuf, y);
    unsigned int w;

    for (w = 0; w < dbuf->line_words; w++)
        if (line[w] != 0)
            return 1;
    return 0;
}

struct VncSurface
{
    struct VncDirtyBuffer dirty;
    DisplaySurface *ds;
};

struct VncDisplay
{
    QEMUTimer *timer;
    int timer_interval;
    int lsock;
    DisplayState *ds;
    VncState *clients;
    kbd_layout_t *kbd_layout;

    struct VncSurface guest;   /* guest visible surface (aka ds->surface) */
    DisplaySurface *server;  /* vnc server surface */

    char *display;
    char *password;
    int auth;
#ifdef CONFIG_VNC_TLS
    int subauth;
    int x509verify;

    char *x509cacert;
    char *x509cacrl;
    char *x509cert;
    char *x509key;
#endif
};

struct VncState
{
    int csock;
    DisplayState *ds;
    struct VncDirtyBuffer dirty;
    VncDisplay *vd;
    int need_update;
    int force_update;
    int missed_update;
    uint32_t features;
    int absolute;
    int last_x;
    int last_y;

    uint32_t vnc_encoding;
    uint8_t tight_quality;
    uint8_t tight_compression;

    int major;
    int minor;

    char challenge[VNC_AUTH_CHALLENGE_SIZE];

#ifdef CONFIG_VNC_TLS
    int wiremode;
    gnutls_session_t tls_session;
#endif

    Buffer output;
    Buffer input;
    /* current output mode information */
    VncWritePixels *write_pixels;
    VncSendHextileTile *send_hextile_tile;
    DisplaySurface clientds;

    CaptureVoiceOut *audio_cap;
    struct audsettings as;

    VncReadEvent *read_handler;
    size_t read_handler_expect;
    /* input */
    uint8_t modifiers_state[256];

    Buffer zlib;
    z_stream zlib_stream;

    VncState *next;
};

static VncDisplay *vnc_display; /* needed for info vnc */
static DisplayChangeListener *dcl;

void do_info_vnc(void)
{
    if (vnc_display == NULL || vnc_display->display == NULL)
	term_printf("VNC server disabled\n");
    else {
	term_printf("VNC server active on: ");
	term_print_filename(vnc_display->display);
	term_printf("\n");

	if (vnc_display->clients == NULL)
	    term_printf("No client connected\n");
	else
	    term_printf("Client connected\n");
    }
}

static inline uint32_t vnc_has_feature(VncState *vs, int feature) {
    return (vs->features & (1 << feature));
}

/* TODO
   1) Get the queue working for IO.
   2) there is some weirdness when using the -S option (the screen is grey
      and not totally invalidated
   3) resolutions > 1024
*/

static void vnc_write(VncState *vs, const void *data, size_t len);
static void vnc_write_u32(VncState *vs, uint32_t value);
static void vnc_write_s32(VncState *vs, int32_t value);
static void vnc_write_u16(VncState *vs, uint16_t value);
static void vnc_write_u8(VncState *vs, uint8_t value);
static void vnc_flush(VncState *vs);
static int vnc_update_client(VncState *vs, int has_dirty);
static void vnc_client_read(void *opaque);
static void vnc_disconnect_start(VncState *vs);
static void vnc_disconnect_finish(VncState *vs);
static void vnc_init_timer(VncDisplay *vd);
static void vnc_remove_timer(VncDisplay *vd);

static void vnc_colordepth(VncState *vs);
//skylark
//extern char domain_name[64];
static void framebuffer_update_request(VncState *vs, int incremental,
                                       int x_position, int y_position,
                                       int w, int h);
static void vnc_refresh(void *opaque);
static int vnc_refresh_server_surface(VncDisplay *vd);

static void vnc_dpy_update(DisplayState *ds, int x, int y, int w, int h)
{
    int i;
    VncDisplay *vd = ds->opaque;
    struct VncSurface *s = &vd->guest;

    if (!vd->server)
        return;

    h += y;

    /* round x down to ensure the loop only spans one 16-pixel block per,
       iteration.  otherwise, if (x % 16) != 0, the last iteration may span
       two 16-pixel blocks but we only mark the first as dirty
    */
    w += (x % 16);
    x -= (x % 16);

    x = MIN(x, s->ds->width);
    y = MIN(y, s->ds->height);
    w = MIN(x + w, s->ds->width) - x;
    h = MIN(h, s->ds->height);

    for (; y < h; y++)
	for (i = 0; i < w; i += 16)
            dirty_set_bit(&s->dirty, (x + i) / 16, y);
}

static void vnc_framebuffer_update(VncState *vs, int x, int y, int w, int h,
				   int32_t encoding)
{
    vnc_write_u16(vs, x);
    vnc_write_u16(vs, y);
    vnc_write_u16(vs, w);
    vnc_write_u16(vs, h);

    vnc_write_s32(vs, encoding);
}

static bool buffer_reserve(Buffer *buffer, size_t len)
{
    uint8_t *p;
    size_t s;

    if ((buffer->capacity - buffer->offset) >= len)
        return true;

    s = buffer->capacity + len;
    s += host_page_size - 1;
    s &= -host_page_size;

    /* too much */
    if (s > VNC_BUFFER_MAX_SIZE) {
        buffer->offset = 0;
        return false;
    }

    p = buffer->buffer;
    /* allocate virtual space if not allocated before */
    if (!p) {
        p = mmap(NULL, VNC_BUFFER_MAX_SIZE, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            goto fail;
        buffer->buffer = p;
    }

    /* allocate real memory */
    p = mmap(p + buffer->capacity, s - buffer->capacity, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    if (p == MAP_FAILED)
        goto fail;

    buffer->capacity = s;
    return true;

fail:
    if (buffer->capacity < VNC_BUFFER_MIN_SIZE) {
        fprintf(stderr, "vnc: out of memory\n");
        exit(1);
    }
    buffer->offset = 0;
    return false;
}

static void buffer_free(Buffer *buffer)
{
    if (buffer->buffer)
        munmap(buffer->buffer, VNC_BUFFER_MAX_SIZE);
    buffer->buffer = NULL;
    buffer->capacity = 0;
    buffer->offset = 0;
}

static int buffer_empty(Buffer *buffer)
{
    return buffer->offset == 0;
}

static uint8_t *buffer_end(Buffer *buffer)
{
    return buffer->buffer + buffer->offset;
}

static void buffer_reset(Buffer *buffer)
{
    buffer->offset = 0;
    if (buffer->capacity > VNC_BUFFER_MIN_SIZE) {
        if (mmap(buffer->buffer + VNC_BUFFER_MIN_SIZE, buffer->capacity - VNC_BUFFER_MIN_SIZE, PROT_NONE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) != MAP_FAILED)
            buffer->capacity = VNC_BUFFER_MIN_SIZE;
    }
}

static void buffer_append(Buffer *buffer, const void *data, size_t len)
{
    memcpy(buffer->buffer + buffer->offset, data, len);
    buffer->offset += len;
}

static void vnc_clean_surface(VncDisplay *vd, int data)
{
    if (vd->server) {
        qemu_free(vd->server->data);
        qemu_free(vd->server);
        vd->server = NULL;
    }

    qemu_free(vd->guest.ds);
    vd->guest.ds = NULL;

    /* if we are using the default allocator and buffer is allocated
     * free and allocate lazily
     */
    if (data && (vd->ds->surface->flags & (QEMU_ALLOCATED_FLAG|QEMU_LAZY_FLAG|QEMU_REALPIXELS_FLAG))
        == (QEMU_ALLOCATED_FLAG|QEMU_LAZY_FLAG)) {
        qemu_free(vd->ds->surface->data);
        vd->ds->surface->data = NULL;
        vd->ds->surface->flags &= ~QEMU_ALLOCATED_FLAG;
    }

    /* deactivate console to avoid buffer to be created again */
    console_unselect();
}

static int vnc_update_surface(VncDisplay *vd)
{
    int size_changed;
    DisplayState *ds = vd->ds;

    /* assure we have data */
    ds_get_data(ds);

    /* server surface */
    if (!vd->server)
        vd->server = qemu_mallocz(sizeof(*vd->server));
    if (vd->server->data)
        qemu_free(vd->server->data);
    *(vd->server) = *(ds->surface);
    vd->server->data = qemu_mallocz(vd->server->linesize *
                                    vd->server->height);

    /* guest surface */
    if (!vd->guest.ds)
        vd->guest.ds = qemu_mallocz(sizeof(*vd->guest.ds));
    if (ds_get_bytes_per_pixel(ds) != vd->guest.ds->pf.bytes_per_pixel)
        console_color_init(ds);
    size_changed = ds_get_width(ds) != vd->guest.ds->width ||
                   ds_get_height(ds) != vd->guest.ds->height;
    *(vd->guest.ds) = *(ds->surface);
    dirty_resize(&vd->guest.dirty, ds_get_width(ds), ds_get_height(ds));
    dirty_set_all(&vd->guest.dirty);

    return size_changed;
}

static inline void vnc_create_surface(VncDisplay *vd)
{
    if (!vd->server)
        vnc_update_surface(vd);
}

static void vnc_dpy_resize(DisplayState *ds)
{
    int size_changed;
    VncDisplay *vd = ds->opaque;
    VncState *vs;

    if (!vd->server)
        return;

    size_changed = vnc_update_surface(vd);

    vs = vd->clients;
    while (vs != NULL) {
        vnc_colordepth(vs);
        if (size_changed) {
            if (vs->csock != -1 && vnc_has_feature(vs, VNC_FEATURE_RESIZE)) {
                vnc_write_u8(vs, 0);  /* msg id */
                vnc_write_u8(vs, 0);
                vnc_write_u16(vs, 1); /* number of rects */
                vnc_framebuffer_update(vs, 0, 0, ds_get_width(ds), ds_get_height(ds),
                        VNC_ENCODING_DESKTOPRESIZE);
                vnc_flush(vs);
            }
        }
        dirty_resize(&vs->dirty, ds_get_width(ds), ds_get_height(ds));
        dirty_set_all(&vs->dirty);
        vs = vs->next;
    }
}

/* fastest code */
static void vnc_write_pixels_copy(VncState *vs, void *pixels, int size)
{
    vnc_write(vs, pixels, size);
}

/* slowest but generic code. */
static void vnc_convert_pixel(VncState *vs, uint8_t *buf, uint32_t v)
{
    uint8_t r, g, b;
    VncDisplay *vd = vs->vd;

    r = ((((v & vd->server->pf.rmask) >> vd->server->pf.rshift) << vs->clientds.pf.rbits) >>
        vd->server->pf.rbits);
    g = ((((v & vd->server->pf.gmask) >> vd->server->pf.gshift) << vs->clientds.pf.gbits) >>
        vd->server->pf.gbits);
    b = ((((v & vd->server->pf.bmask) >> vd->server->pf.bshift) << vs->clientds.pf.bbits) >>
        vd->server->pf.bbits);
    v = (r << vs->clientds.pf.rshift) |
        (g << vs->clientds.pf.gshift) |
        (b << vs->clientds.pf.bshift);
    switch(vs->clientds.pf.bytes_per_pixel) {
    case 1:
        buf[0] = v;
        break;
    case 2:
        if (vs->clientds.flags & QEMU_BIG_ENDIAN_FLAG) {
            buf[0] = v >> 8;
            buf[1] = v;
        } else {
            buf[1] = v >> 8;
            buf[0] = v;
        }
        break;
    default:
    case 4:
        if (vs->clientds.flags & QEMU_BIG_ENDIAN_FLAG) {
            buf[0] = v >> 24;
            buf[1] = v >> 16;
            buf[2] = v >> 8;
            buf[3] = v;
        } else {
            buf[3] = v >> 24;
            buf[2] = v >> 16;
            buf[1] = v >> 8;
            buf[0] = v;
        }
        break;
    }
}

static void vnc_write_pixels_generic(VncState *vs, void *pixels1, int size)
{
    uint8_t buf[4];
    VncDisplay *vd = vs->vd;

    if (vd->server->pf.bytes_per_pixel == 4) {
        uint32_t *pixels = pixels1;
        int n, i;
        n = size >> 2;
        for(i = 0; i < n; i++) {
            vnc_convert_pixel(vs, buf, pixels[i]);
            vnc_write(vs, buf, vs->clientds.pf.bytes_per_pixel);
        }
    } else if (vd->server->pf.bytes_per_pixel == 2) {
        uint16_t *pixels = pixels1;
        int n, i;
        n = size >> 1;
        for(i = 0; i < n; i++) {
            vnc_convert_pixel(vs, buf, pixels[i]);
            vnc_write(vs, buf, vs->clientds.pf.bytes_per_pixel);
        }
    } else if (vd->server->pf.bytes_per_pixel == 1) {
        uint8_t *pixels = pixels1;
        int n, i;
        n = size;
        for(i = 0; i < n; i++) {
            vnc_convert_pixel(vs, buf, pixels[i]);
            vnc_write(vs, buf, vs->clientds.pf.bytes_per_pixel);
        }
    } else {
        fprintf(stderr, "vnc_write_pixels_generic: VncState color depth not supported\n");
    }
}

static void send_framebuffer_update_raw(VncState *vs, int x, int y, int w, int h)
{
    int i;
    uint8_t *row;
    VncDisplay *vd = vs->vd;

    row = vd->server->data + y * ds_get_linesize(vs->ds) + x * ds_get_bytes_per_pixel(vs->ds);
    for (i = 0; i < h; i++) {
	vs->write_pixels(vs, row, w * ds_get_bytes_per_pixel(vs->ds));
	row += ds_get_linesize(vs->ds);
    }
}

static void hextile_enc_cord(uint8_t *ptr, int x, int y, int w, int h)
{
    ptr[0] = ((x & 0x0F) << 4) | (y & 0x0F);
    ptr[1] = (((w - 1) & 0x0F) << 4) | ((h - 1) & 0x0F);
}

#define BPP 8
#include "vnchextile.h"
#undef BPP

#define BPP 16
#include "vnchextile.h"
#undef BPP

#define BPP 32
#include "vnchextile.h"
#undef BPP

#define GENERIC
#define BPP 8
#include "vnchextile.h"
#undef BPP
#undef GENERIC

#define GENERIC
#define BPP 16
#include "vnchextile.h"
#undef BPP
#undef GENERIC

#define GENERIC
#define BPP 32
#include "vnchextile.h"
#undef BPP
#undef GENERIC

static void send_framebuffer_update_hextile(VncState *vs, int x, int y, int w, int h)
{
    int i, j;
    int has_fg, has_bg;
    uint8_t *last_fg, *last_bg;
    VncDisplay *vd = vs->vd;

    last_fg = (uint8_t *) qemu_malloc(vd->server->pf.bytes_per_pixel);
    last_bg = (uint8_t *) qemu_malloc(vd->server->pf.bytes_per_pixel);
    has_fg = has_bg = 0;
    for (j = y; j < (y + h); j += 16) {
	for (i = x; i < (x + w); i += 16) {
            vs->send_hextile_tile(vs, i, j,
                                  MIN(16, x + w - i), MIN(16, y + h - j),
                                  last_bg, last_fg, &has_bg, &has_fg);
	}
    }
    free(last_fg);
    free(last_bg);

}

static void vnc_zlib_init(VncState *vs)
{
    vs->zlib_stream.opaque = NULL;
}

static void vnc_zlib_clear(VncState *vs)
{
    if (vs->zlib_stream.opaque != NULL) {
        deflateEnd(&vs->zlib_stream);
        vs->zlib_stream.opaque = NULL;
    }
    buffer_free(&vs->zlib);
}

static void vnc_zlib_start(VncState *vs)
{
    Buffer zlib_tmp;
    buffer_reset(&vs->zlib);

    // make the output buffer be the zlib buffer, so we can compress it later
    zlib_tmp = vs->output;
    vs->output = vs->zlib;
    vs->zlib = zlib_tmp;
}

static int vnc_zlib_stop(VncState *vs)
{
    z_streamp zstream = &vs->zlib_stream;
    int previous_out;
    Buffer zlib_tmp;

    // switch back to normal output/zlib buffers
    zlib_tmp = vs->output;
    vs->output = vs->zlib;
    vs->zlib = zlib_tmp;

    // compress the zlib buffer

    // initialize the stream
    if (zstream->opaque != vs) {
        int err;

        VNC_DEBUG("VNC: initializing zlib stream %d\n", stream_id);
        VNC_DEBUG("VNC: opaque = %p | vs = %p\n", zstream->opaque, vs);
        zstream->zalloc = Z_NULL;
        zstream->zfree = Z_NULL;

        err = deflateInit2(zstream, vs->tight_compression, Z_DEFLATED, MAX_WBITS,
                           MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);

        if (err != Z_OK) {
            fprintf(stderr, "VNC: error initializing zlib\n");
            return -1;
        }

        zstream->opaque = vs;
    }

    // reserve memory in output buffer
    if (!buffer_reserve(&vs->output, vs->zlib.offset + 64))
        vnc_disconnect_start(vs);

    // set pointers
    zstream->next_in = vs->zlib.buffer;
    zstream->avail_in = vs->zlib.offset;
    zstream->next_out = vs->output.buffer + vs->output.offset;
    zstream->avail_out = vs->output.capacity - vs->output.offset;
    previous_out = zstream->avail_out;
    zstream->data_type = Z_BINARY;

    // start encoding
    if (deflate(zstream, Z_SYNC_FLUSH) != Z_OK) {
        fprintf(stderr, "VNC: error during zlib compression\n");
        return -1;
    }

    vs->output.offset = vs->output.capacity - zstream->avail_out;
    return previous_out - zstream->avail_out;
}

static void send_framebuffer_update_zlib(VncState *vs, int x, int y, int w, int h)
{
    int old_offset, new_offset, bytes_written;

    vnc_framebuffer_update(vs, x, y, w, h, VNC_ENCODING_ZLIB);

    // remember where we put in the follow-up size
    old_offset = vs->output.offset;
    vnc_write_s32(vs, 0);

    // compress the stream
    vnc_zlib_start(vs);
    send_framebuffer_update_raw(vs, x, y, w, h);
    bytes_written = vnc_zlib_stop(vs);

    if (bytes_written == -1)
        return;

    // hack in the size
    new_offset = vs->output.offset;
    vs->output.offset = old_offset;
    vnc_write_u32(vs, bytes_written);
    vs->output.offset = new_offset;
}

static void send_framebuffer_update(VncState *vs, int x, int y, int w, int h)
{
    switch(vs->vnc_encoding) {
	case VNC_ENCODING_ZLIB:
	    send_framebuffer_update_zlib(vs, x, y, w, h);
	    break;
	case VNC_ENCODING_HEXTILE:
	    vnc_framebuffer_update(vs, x, y, w, h, VNC_ENCODING_HEXTILE);
	    send_framebuffer_update_hextile(vs, x, y, w, h);
	    break;
	default:
	    vnc_framebuffer_update(vs, x, y, w, h, VNC_ENCODING_RAW);
	    send_framebuffer_update_raw(vs, x, y, w, h);
	    break;
    }
}

static void vnc_copy(VncState *vs, int src_x, int src_y, int dst_x, int dst_y, int w, int h)
{
    /* send bitblit op to the vnc client */
    vnc_write_u8(vs, 0);  /* msg id */
    vnc_write_u8(vs, 0);
    vnc_write_u16(vs, 1); /* number of rects */
    vnc_framebuffer_update(vs, dst_x, dst_y, w, h, VNC_ENCODING_COPYRECT);
    vnc_write_u16(vs, src_x);
    vnc_write_u16(vs, src_y);
    vnc_flush(vs);
}

static void vnc_dpy_copy(DisplayState *ds, int src_x, int src_y, int dst_x, int dst_y, int w, int h)
{
    VncDisplay *vd = ds->opaque;
    VncState *vs, *vn;
    uint8_t *src_row;
    uint8_t *dst_row;
    int i,x,y,pitch,depth,inc,w_lim,s;
    int cmp_bytes;

    if (!vd->server)
        return;

    vnc_refresh_server_surface(vd);
    for (vs = vd->clients; vs != NULL; vs = vn) {
        vn = vs->next;
        if (vnc_has_feature(vs, VNC_FEATURE_COPYRECT)) {
            if (!vs->need_update)
                vs->need_update++;
            vs->force_update = 1;
            vnc_update_client(vs, 1);
            /* vs might be free()ed here */
        }
    }

    /* vd->server could be NULL now if the last client disconnected. */
    if (!vd->server)
        return;
    
    /* do bitblit op on the local surface too */
    pitch = ds_get_linesize(vd->ds);
    depth = ds_get_bytes_per_pixel(vd->ds);
    src_row = vd->server->data + pitch * src_y + depth * src_x;
    dst_row = vd->server->data + pitch * dst_y + depth * dst_x;
    y = dst_y;
    inc = 1;
    if (dst_y > src_y) {
        /* copy backwards */
        src_row += pitch * (h-1);
        dst_row += pitch * (h-1);
        pitch = -pitch;
        y = dst_y + h - 1;
        inc = -1;
    }
    w_lim = w - (16 - (dst_x % 16));
    if (w_lim < 0)
        w_lim = w;
    else
        w_lim = w - (w_lim % 16);
    for (i = 0; i < h; i++) {
        for (x = 0; x <= w_lim;
                x += s, src_row += cmp_bytes, dst_row += cmp_bytes) {
            if (x == w_lim) {
                if ((s = w - w_lim) == 0)
                    break;
            } else if (!x) {
                s = (16 - (dst_x % 16));
                s = MIN(s, w_lim);
            } else {
                s = 16;
            }
            cmp_bytes = s * depth;
            if (memcmp(src_row, dst_row, cmp_bytes) == 0)
                continue;
            memmove(dst_row, src_row, cmp_bytes);
            vs = vd->clients;
            while (vs != NULL) {
                if (!vnc_has_feature(vs, VNC_FEATURE_COPYRECT))
                    dirty_set_bit(&vs->dirty, (x + dst_x) / 16, y);
                vs = vs->next;
            }
        }
        src_row += pitch - w * depth;
        dst_row += pitch - w * depth;
        y += inc;
    }

    for (vs = vd->clients; vs != NULL; vs = vs->next) {
        if (vnc_has_feature(vs, VNC_FEATURE_COPYRECT))
            vnc_copy(vs, src_x, src_y, dst_x, dst_y, w, h);
    }
}

static int find_and_clear_dirty_height(struct VncState *vs,
                                       int y, int last_x, int x)
{
    int h;
    VncDisplay *vd = vs->vd;

    for (h = 1; h < (vd->server->height - y); h++) {
	int tmp_x;
        if (!dirty_get_bit(&vs->dirty, last_x, y + h))
	    break;
	for (tmp_x = last_x; tmp_x < x; tmp_x++)
            dirty_clear_bit(&vs->dirty, tmp_x, y + h);
    }

    return h;
}

static int vnc_update_client(VncState *vs, int has_dirty)
{
    if (has_dirty)
        vs->missed_update = 1;

    if (vs->need_update > 0 && vs->csock != -1) {
        VncDisplay *vd = vs->vd;
	int y;
	int n_rectangles;
	int saved_offset;

        if (vs->output.offset && !vs->audio_cap && !vs->force_update)
            /* kernel send buffers are full -> drop frames to throttle */
            return 0;

        if (!has_dirty && !vs->missed_update && !vs->audio_cap &&
                !vs->force_update)
	    return 0;

        /*
         * Send screen updates to the vnc client using the server
         * surface and server dirty map.  guest surface updates
         * happening in parallel don't disturb us, the next pass will
         * send them to the client.
         */
	n_rectangles = 0;
	vnc_write_u8(vs, 0);  /* msg id */
	vnc_write_u8(vs, 0);
	saved_offset = vs->output.offset;
	vnc_write_u16(vs, 0);

        for (y = 0; y < vd->server->height; y++) {
	    int x;
	    int last_x = -1;
            for (x = 0; x < vd->server->width / 16; x++) {
                if (dirty_get_bit(&vs->dirty, x, y)) {
		    if (last_x == -1) {
			last_x = x;
		    }
                    dirty_clear_bit(&vs->dirty, x, y);
		} else {
		    if (last_x != -1) {
                        int h = find_and_clear_dirty_height(vs, y, last_x, x);
			send_framebuffer_update(vs, last_x * 16, y, (x - last_x) * 16, h);
			n_rectangles++;
		    }
		    last_x = -1;
		}
	    }
	    if (last_x != -1) {
                int h = find_and_clear_dirty_height(vs, y, last_x, x);
		send_framebuffer_update(vs, last_x * 16, y, (x - last_x) * 16, h);
		n_rectangles++;
	    }
	}
	vs->output.buffer[saved_offset] = (n_rectangles >> 8) & 0xFF;
	vs->output.buffer[saved_offset + 1] = n_rectangles & 0xFF;
	vnc_flush(vs);
        vs->missed_update = 0;
        vs->force_update = 0;
        vs->need_update--;
        if (vs->need_update < 0)
            vs->need_update = 0;

        return n_rectangles;
    }

    if (vs->csock == -1)
        vnc_disconnect_finish(vs);

    return 0;
}

/* audio */
static void audio_capture_notify(void *opaque, audcnotification_e cmd)
{
    VncState *vs = opaque;

    switch (cmd) {
    case AUD_CNOTIFY_DISABLE:
        vnc_write_u8(vs, 255);
        vnc_write_u8(vs, 1);
        vnc_write_u16(vs, 0);
        vnc_flush(vs);
        break;

    case AUD_CNOTIFY_ENABLE:
        vnc_write_u8(vs, 255);
        vnc_write_u8(vs, 1);
        vnc_write_u16(vs, 1);
        vnc_flush(vs);
        break;
    }
}

static void audio_capture_destroy(void *opaque)
{
}

static void audio_capture(void *opaque, void *buf, int size)
{
    VncState *vs = opaque;

    vnc_write_u8(vs, 255);
    vnc_write_u8(vs, 1);
    vnc_write_u16(vs, 2);
    vnc_write_u32(vs, size);
    vnc_write(vs, buf, size);
    vnc_flush(vs);
}

static void audio_add(VncState *vs)
{
    struct audio_capture_ops ops;

    if (vs->audio_cap) {
        term_printf ("audio already running\n");
        return;
    }

    ops.notify = audio_capture_notify;
    ops.destroy = audio_capture_destroy;
    ops.capture = audio_capture;

    vs->audio_cap = AUD_add_capture(NULL, &vs->as, &ops, vs);
    if (!vs->audio_cap) {
        term_printf ("Failed to add audio capture\n");
    }
}

static void audio_del(VncState *vs)
{
    if (vs->audio_cap) {
        AUD_del_capture(vs->audio_cap, vs);
        vs->audio_cap = NULL;
    }
}

static int vnc_client_io_error(VncState *vs, int ret, int last_errno)
{
    if (ret == 0 || ret == -1) {
        if (ret == -1) {
            switch (last_errno) {
                case EINTR:
                case EAGAIN:
#ifdef _WIN32
                case WSAEWOULDBLOCK:
#endif
                    return 0;
                default:
                    break;
            }
        }

        VNC_DEBUG("Closing down client sock: ret %d, errno %d\n",
                  ret, ret < 0 ? last_errno : 0);
        vnc_disconnect_start(vs);

	return 0;
    }
    return ret;
}

static void vnc_client_error(VncState *vs)
{
    VNC_DEBUG("Closing down client sock: protocol error\n");
    vnc_disconnect_start(vs);
}

static void vnc_client_write(void *opaque)
{
    long ret;
    VncState *vs = opaque;
    size_t orig_offset = vs->output.offset;

#ifdef CONFIG_VNC_TLS
    if (vs->tls_session) {
	ret = gnutls_write(vs->tls_session, vs->output.buffer, vs->output.offset);
	if (ret < 0) {
	    if (ret == GNUTLS_E_AGAIN)
		errno = EAGAIN;
	    else
		errno = EIO;
	    ret = -1;
	}
    } else
#endif /* CONFIG_VNC_TLS */
	ret = send(vs->csock, vs->output.buffer, vs->output.offset, 0);
    ret = vnc_client_io_error(vs, ret, socket_error());
    if (!ret)
	return;

    memmove(vs->output.buffer, vs->output.buffer + ret, (vs->output.offset - ret));
    vs->output.offset -= ret;

    if (vs->output.offset == 0) {
        buffer_reset(&vs->output);
        qemu_set_fd_handler2(vs->csock, NULL, vnc_client_read, NULL, vs);
    } else if (orig_offset >= VNC_OUTPUT_LIMIT && vs->output.offset < VNC_OUTPUT_LIMIT) {
        qemu_set_fd_handler2(vs->csock, NULL, vnc_client_read, vnc_client_write, vs);
    }
}

static void vnc_read_when(VncState *vs, VncReadEvent *func, size_t expecting)
{
    vs->read_handler = func;
    vs->read_handler_expect = expecting;
}

static bool vnc_consume_input(VncState *vs)
{
    bool res = false;

    while (vs->read_handler && vs->input.offset >= vs->read_handler_expect) {
        size_t len = vs->read_handler_expect;
        int ret;

        res = true;
        ret = vs->read_handler(vs, vs->input.buffer, len);
        if (vs->csock == -1) {
            vnc_disconnect_finish(vs);
            break;
        }

        if (!ret) {
            memmove(vs->input.buffer, vs->input.buffer + len, (vs->input.offset - len));
            vs->input.offset -= len;
        } else {
            vs->read_handler_expect = ret;
        }

        // check output buffer for limit
        if (vs->output.offset >= VNC_OUTPUT_LIMIT) {
            qemu_set_fd_handler2(vs->csock, NULL, NULL, vnc_client_write, vs);
            break;
        }
    }
    return res;
}

static void vnc_client_read(void *opaque)
{
    VncState *vs = opaque;
    long ret;

    // consume input if possible and exit if consumed
    if (vnc_consume_input(vs))
        return;

    if (!buffer_reserve(&vs->input, 4096))
        vnc_disconnect_start(vs);

#ifdef CONFIG_VNC_TLS
    if (vs->tls_session) {
	ret = gnutls_read(vs->tls_session, buffer_end(&vs->input), 4096);
	if (ret < 0) {
	    if (ret == GNUTLS_E_AGAIN)
		errno = EAGAIN;
	    else
		errno = EIO;
	    ret = -1;
	}
    } else
#endif /* CONFIG_VNC_TLS */
	ret = recv(vs->csock, buffer_end(&vs->input), 4096, 0);
    ret = vnc_client_io_error(vs, ret, socket_error());
    if (!ret) {
        if (vs->csock == -1)
            vnc_disconnect_finish(vs);
	return;
    }

    vs->input.offset += ret;

    vnc_consume_input(vs);
}

static void vnc_write(VncState *vs, const void *data, size_t len)
{
    if (!buffer_reserve(&vs->output, len))
        vnc_disconnect_start(vs);

    if (vs->csock != -1 && buffer_empty(&vs->output)) {
	qemu_set_fd_handler2(vs->csock, NULL, vnc_client_read, vnc_client_write, vs);
    }

    buffer_append(&vs->output, data, len);
}

static void vnc_write_s32(VncState *vs, int32_t value)
{
    vnc_write_u32(vs, *(uint32_t *)&value);
}

static void vnc_write_u32(VncState *vs, uint32_t value)
{
    uint8_t buf[4];

    buf[0] = (value >> 24) & 0xFF;
    buf[1] = (value >> 16) & 0xFF;
    buf[2] = (value >>  8) & 0xFF;
    buf[3] = value & 0xFF;

    vnc_write(vs, buf, 4);
}

static void vnc_write_u16(VncState *vs, uint16_t value)
{
    uint8_t buf[2];

    buf[0] = (value >> 8) & 0xFF;
    buf[1] = value & 0xFF;

    vnc_write(vs, buf, 2);
}

static void vnc_write_u8(VncState *vs, uint8_t value)
{
    vnc_write(vs, (char *)&value, 1);
}

static void vnc_flush(VncState *vs)
{
    if (vs->csock != -1 && vs->output.offset)
	vnc_client_write(vs);
}

static uint8_t read_u8(uint8_t *data, size_t offset)
{
    return data[offset];
}

static uint16_t read_u16(uint8_t *data, size_t offset)
{
    return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
}

static int32_t read_s32(uint8_t *data, size_t offset)
{
    return (int32_t)((data[offset] << 24) | (data[offset + 1] << 16) |
		     (data[offset + 2] << 8) | data[offset + 3]);
}

static uint32_t read_u32(uint8_t *data, size_t offset)
{
    return ((data[offset] << 24) | (data[offset + 1] << 16) |
	    (data[offset + 2] << 8) | data[offset + 3]);
}

static void vnc_disconnect_start(VncState *vs)
{
    if (vs->csock == -1)
        return;
    qemu_set_fd_handler2(vs->csock, NULL, NULL, NULL, NULL);
    closesocket(vs->csock);
    vs->csock = -1;
}

static void vnc_disconnect_finish(VncState *vs)
{
    VncDisplay *vd = vs->vd;

    VncState *p, *parent = NULL;
    for (p = vs->vd->clients; p != NULL; p = p->next) {
        if (p == vs) {
            if (parent)
                parent->next = p->next;
            else
                vs->vd->clients = p->next;
            break;
        }
        parent = p;
    }
    if (!vd->clients)
        dcl->idle = 1;

    buffer_free(&vs->input);
    buffer_free(&vs->output);
    audio_del(vs);

    vnc_remove_timer(vd);
    vnc_zlib_clear(vs);
    qemu_free(vs->dirty.bits);
    qemu_free(vs);

    if (!vd->clients)
        vnc_clean_surface(vd, 1);
}

#ifdef CONFIG_VNC_TLS
static ssize_t vnc_tls_push(gnutls_transport_ptr_t transport,
                            const void *data,
                            size_t len) {
    struct VncState *vs = (struct VncState *)transport;
    int ret;

 retry:
    ret = send(vs->csock, data, len, 0);
    if (ret < 0) {
	if (errno == EINTR)
	    goto retry;
	return -1;
    }
    return ret;
}

static ssize_t vnc_tls_pull(gnutls_transport_ptr_t transport,
                            void *data,
                            size_t len) {
    struct VncState *vs = (struct VncState *)transport;
    int ret;

 retry:
    ret = recv(vs->csock, data, len, 0);
    if (ret < 0) {
	if (errno == EINTR)
	    goto retry;
	return -1;
    }
    return ret;
}
#endif /* CONFIG_VNC_TLS */

static void client_cut_text(VncState *vs, size_t len, uint8_t *text)
{
    xenstore_set_guest_clipboard(text, len);
}

static void vnc_set_clipboard(VncState *vs, char *text)
{
    char pad[3] = { 0, 0, 0 };
    vnc_write_u8(vs, 3);	/* ServerCutText */
    vnc_write(vs, pad, 3);	/* padding */
    vnc_write_u32(vs, strlen(text));	/* length */
    vnc_write(vs, text, strlen(text));  /* text */
    vnc_flush(vs);
}

void vnc_dpy_set_clipboard(char *text)
{
    VncState *vs = vnc_display->clients;
    while (vs != NULL) {
        vnc_set_clipboard(vs, text);
        vs = vs->next;
    }
}

static void check_pointer_type_change(VncState *vs, int absolute)
{
    if (vnc_has_feature(vs, VNC_FEATURE_POINTER_TYPE_CHANGE) && vs->absolute != absolute) {
	vnc_write_u8(vs, 0);
	vnc_write_u8(vs, 0);
	vnc_write_u16(vs, 1);
	vnc_framebuffer_update(vs, absolute, 0,
			       ds_get_width(vs->ds), ds_get_height(vs->ds),
                               VNC_ENCODING_POINTER_TYPE_CHANGE);
	vnc_flush(vs);
    }
    vs->absolute = absolute;
}

static void pointer_event(VncState *vs, int button_mask, int x, int y)
{
    int buttons = 0;
    int dz = 0;

    if (button_mask & 0x01)
	buttons |= MOUSE_EVENT_LBUTTON;
    if (button_mask & 0x02)
	buttons |= MOUSE_EVENT_MBUTTON;
    if (button_mask & 0x04)
	buttons |= MOUSE_EVENT_RBUTTON;
    if (button_mask & 0x08)
	dz = -1;
    if (button_mask & 0x10)
	dz = 1;

    if (vs->absolute) {
	kbd_mouse_event(x * 0x7FFF / (ds_get_width(vs->ds) - 1),
			y * 0x7FFF / (ds_get_height(vs->ds) - 1),
			dz, buttons);
    } else if (vnc_has_feature(vs, VNC_FEATURE_POINTER_TYPE_CHANGE)) {
	x -= 0x7FFF;
	y -= 0x7FFF;

	kbd_mouse_event(x, y, dz, buttons);
    } else {
	if (vs->last_x != -1)
	    kbd_mouse_event(x - vs->last_x,
			    y - vs->last_y,
			    dz, buttons);
	vs->last_x = x;
	vs->last_y = y;
    }

    check_pointer_type_change(vs, kbd_mouse_is_absolute());
}

static void reset_keys(VncState *vs)
{
    int i;
    for(i = 0; i < 256; i++) {
        if (vs->modifiers_state[i]) {
            if (i & 0x80)
                kbd_put_keycode(0xe0);
            kbd_put_keycode(i | 0x80);
            vs->modifiers_state[i] = 0;
        }
    }
}

static void press_key(VncState *vs, int keysym)
{
    kbd_put_keycode(keysym2scancode(vs->vd->kbd_layout, keysym) & 0x7f);
    kbd_put_keycode(keysym2scancode(vs->vd->kbd_layout, keysym) | 0x80);
}

static void do_key_event(VncState *vs, int down, int keycode, int sym)
{
    /* QEMU console switch */
    switch(keycode) {
    case 0x2a:                          /* Left Shift */
    case 0x36:                          /* Right Shift */
    case 0x1d:                          /* Left CTRL */
    case 0x9d:                          /* Right CTRL */
    case 0x38:                          /* Left ALT */
    case 0xb8:                          /* Right ALT */
        if (down)
            vs->modifiers_state[keycode] = 1;
        else
            vs->modifiers_state[keycode] = 0;
        break;
    case 0x02 ... 0x0a: /* '1' to '9' keys */
        if (down && vs->modifiers_state[0x1d] && vs->modifiers_state[0x38]) {
            /* Reset the modifiers sent to the current console */
            reset_keys(vs);
            console_select(keycode - 0x02);
            return;
        }
        break;
    case 0x3a:			/* CapsLock */
    case 0x45:			/* NumLock */
        if (!down)
            vs->modifiers_state[keycode] ^= 1;
        break;
    }

    if (keycode_is_keypad(vs->vd->kbd_layout, keycode)) {
        /* If the numlock state needs to change then simulate an additional
           keypress before sending this one.  This will happen if the user
           toggles numlock away from the VNC window.
        */
        if (keysym_is_numlock(vs->vd->kbd_layout, sym & 0xFFFF)) {
            if (!vs->modifiers_state[0x45]) {
                vs->modifiers_state[0x45] = 1;
                press_key(vs, 0xff7f);
            }
        } else {
            if (vs->modifiers_state[0x45]) {
                vs->modifiers_state[0x45] = 0;
                press_key(vs, 0xff7f);
            }
        }
    }

    if (is_graphic_console()) {
        if (keycode & 0x80)
            kbd_put_keycode(0xe0);
        if (down)
            kbd_put_keycode(keycode & 0x7f);
        else
            kbd_put_keycode(keycode | 0x80);
    } else {
        /* QEMU console emulation */
        if (down) {
            switch (keycode) {
            case 0x2a:                          /* Left Shift */
            case 0x36:                          /* Right Shift */
            case 0x1d:                          /* Left CTRL */
            case 0x9d:                          /* Right CTRL */
            case 0x38:                          /* Left ALT */
            case 0xb8:                          /* Right ALT */
                break;
            case 0xc8:
            case 0x48:
                kbd_put_keysym(QEMU_KEY_UP);
                break;
            case 0xd0:
            case 0x50:
                kbd_put_keysym(QEMU_KEY_DOWN);
                break;
            case 0xcb:
            case 0x4b:
                kbd_put_keysym(QEMU_KEY_LEFT);
                break;
            case 0xcd:
            case 0x4d:
                kbd_put_keysym(QEMU_KEY_RIGHT);
                break;
            case 0xd3:
            case 0x53:
                kbd_put_keysym(QEMU_KEY_DELETE);
                break;
            case 0xc7:
            case 0x47:
                kbd_put_keysym(QEMU_KEY_HOME);
                break;
            case 0xcf:
            case 0x4f:
                kbd_put_keysym(QEMU_KEY_END);
                break;
            case 0xc9:
            case 0x49:
                kbd_put_keysym(QEMU_KEY_PAGEUP);
                break;
            case 0xd1:
            case 0x51:
                kbd_put_keysym(QEMU_KEY_PAGEDOWN);
                break;
            default:
                kbd_put_keysym(sym);
                break;
            }
        }
    }
}

static void key_event(VncState *vs, int down, uint32_t sym)
{
    int keycode;

    if (sym >= 'A' && sym <= 'Z' && is_graphic_console())
	sym = sym - 'A' + 'a';

    keycode = keysym2scancode(vs->vd->kbd_layout, sym & 0xFFFF);
    do_key_event(vs, down, keycode, sym);
}

static void ext_key_event(VncState *vs, int down,
                          uint32_t sym, uint16_t keycode)
{
    /* if the user specifies a keyboard layout, always use it */
    if (keyboard_layout)
        key_event(vs, down, sym);
    else
        do_key_event(vs, down, keycode, sym);
}

static void scan_event(VncState *vs, int down, uint32_t code)
{

    /* Prefix with 0xe0 if high bit set, except for NumLock key. */
    if (code & 0x80 && code != 0xc5)
	kbd_put_keycode(0xe0);
    if (down)
	kbd_put_keycode(code & 0x7f);
    else
	kbd_put_keycode(code | 0x80);
}

static void framebuffer_update_request(VncState *vs, int incremental,
				       int x_position, int y_position,
				       int w, int h)
{
    if (x_position > ds_get_width(vs->ds))
        x_position = ds_get_width(vs->ds);
    if (y_position > ds_get_height(vs->ds))
        y_position = ds_get_height(vs->ds);
    if (x_position + w >= ds_get_width(vs->ds))
        w = ds_get_width(vs->ds)  - x_position;
    if (y_position + h >= ds_get_height(vs->ds))
        h = ds_get_height(vs->ds) - y_position;

    int i;
    vs->need_update++;
    if (!incremental) {
        vs->force_update = 1;
        dirty_set_region(&vs->dirty, x_position, y_position, w, h);
    }
}

static void send_ext_key_event_ack(VncState *vs)
{
    vnc_write_u8(vs, 0);
    vnc_write_u8(vs, 0);
    vnc_write_u16(vs, 1);
    vnc_framebuffer_update(vs, 0, 0, ds_get_width(vs->ds), ds_get_height(vs->ds),
                           VNC_ENCODING_EXT_KEY_EVENT);
    vnc_flush(vs);
}

static void send_ext_audio_ack(VncState *vs)
{
    vnc_write_u8(vs, 0);
    vnc_write_u8(vs, 0);
    vnc_write_u16(vs, 1);
    vnc_framebuffer_update(vs, 0, 0, ds_get_width(vs->ds), ds_get_height(vs->ds),
                           VNC_ENCODING_AUDIO);
    vnc_flush(vs);
}

static void set_encodings(VncState *vs, int32_t *encodings, size_t n_encodings)
{
    int i;
    unsigned int enc = 0;
    int is_xencenter = 0;

    vnc_zlib_clear(vs);
    vs->features = 0;
    vs->vnc_encoding = 0;
    vs->tight_compression = 9;
    vs->tight_quality = 9;
    vs->absolute = -1;

    for (i = n_encodings - 1; i >= 0; i--) {
        enc = encodings[i];
        switch (enc) {
        case VNC_ENCODING_RAW:
            vs->vnc_encoding = enc;
            break;
        case VNC_ENCODING_COPYRECT:
            vs->features |= VNC_FEATURE_COPYRECT_MASK;
            break;
        case VNC_ENCODING_HEXTILE:
            vs->features |= VNC_FEATURE_HEXTILE_MASK;
            vs->vnc_encoding = enc;
            break;
        case VNC_ENCODING_ZLIB:
            vs->features |= VNC_FEATURE_ZLIB_MASK;
            vs->vnc_encoding = enc;
            break;
        case VNC_ENCODING_DESKTOPRESIZE:
            vs->features |= VNC_FEATURE_RESIZE_MASK;
            break;
        case VNC_ENCODING_POINTER_TYPE_CHANGE:
            vs->features |= VNC_FEATURE_POINTER_TYPE_CHANGE_MASK;
            break;
        case VNC_ENCODING_EXT_KEY_EVENT:
            send_ext_key_event_ack(vs);
            break;
        case VNC_ENCODING_AUDIO:
            send_ext_audio_ack(vs);
            break;
        case VNC_ENCODING_WMVi:
            vs->features |= VNC_FEATURE_WMVI_MASK;
            break;
        case VNC_ENCODING_XENCENTER:
            is_xencenter = 1;
            break;
        case VNC_ENCODING_COMPRESSLEVEL0:
        case VNC_ENCODING_COMPRESSLEVEL0 + 1:
        case VNC_ENCODING_COMPRESSLEVEL0 + 3 ... VNC_ENCODING_COMPRESSLEVEL0 + 9:
            vs->tight_compression = (enc & 0x0F);
            break;
        case VNC_ENCODING_QUALITYLEVEL0 ... VNC_ENCODING_QUALITYLEVEL0 + 9:
            vs->tight_quality = (enc & 0x0F);
            break;
        default:
            VNC_DEBUG("Unknown encoding: %d (0x%.8x): %d\n", i, enc, enc);
            break;
        }
    }
    /* disable copyrect for xencenter */
    if (is_xencenter)
        vs->features &= ~VNC_FEATURE_COPYRECT_MASK;

    check_pointer_type_change(vs, kbd_mouse_is_absolute());
}

static void set_pixel_conversion(VncState *vs)
{
    if ((vs->clientds.flags & QEMU_BIG_ENDIAN_FLAG) ==
        (vs->ds->surface->flags & QEMU_BIG_ENDIAN_FLAG) && 
        !memcmp(&(vs->clientds.pf), &(vs->ds->surface->pf), sizeof(PixelFormat))) {
        vs->write_pixels = vnc_write_pixels_copy;
        switch (vs->ds->surface->pf.bits_per_pixel) {
            case 8:
                vs->send_hextile_tile = send_hextile_tile_8;
                break;
            case 16:
                vs->send_hextile_tile = send_hextile_tile_16;
                break;
            case 32:
                vs->send_hextile_tile = send_hextile_tile_32;
                break;
        }
    } else {
        vs->write_pixels = vnc_write_pixels_generic;
        switch (vs->ds->surface->pf.bits_per_pixel) {
            case 8:
                vs->send_hextile_tile = send_hextile_tile_generic_8;
                break;
            case 16:
                vs->send_hextile_tile = send_hextile_tile_generic_16;
                break;
            case 32:
                vs->send_hextile_tile = send_hextile_tile_generic_32;
                break;
        }
    }
}

static void set_pixel_format(VncState *vs,
			     int bits_per_pixel, int depth,
			     int big_endian_flag, int true_color_flag,
			     int red_max, int green_max, int blue_max,
			     int red_shift, int green_shift, int blue_shift)
{
    if (!true_color_flag) {
	vnc_client_error(vs);
        return;
    }

    vs->clientds = *(vs->vd->guest.ds);
    vs->clientds.pf.rmax = red_max;
    count_bits(vs->clientds.pf.rbits, red_max);
    vs->clientds.pf.rshift = red_shift;
    vs->clientds.pf.rmask = red_max << red_shift;
    vs->clientds.pf.gmax = green_max;
    count_bits(vs->clientds.pf.gbits, green_max);
    vs->clientds.pf.gshift = green_shift;
    vs->clientds.pf.gmask = green_max << green_shift;
    vs->clientds.pf.bmax = blue_max;
    count_bits(vs->clientds.pf.bbits, blue_max);
    vs->clientds.pf.bshift = blue_shift;
    vs->clientds.pf.bmask = blue_max << blue_shift;
    vs->clientds.pf.bits_per_pixel = bits_per_pixel;
    vs->clientds.pf.bytes_per_pixel = bits_per_pixel / 8;
    vs->clientds.pf.depth = bits_per_pixel == 32 ? 24 : bits_per_pixel;
    vs->clientds.flags = big_endian_flag ? QEMU_BIG_ENDIAN_FLAG : 0x00;

    set_pixel_conversion(vs);

    vga_hw_invalidate();
    vga_hw_update();
}

static void pixel_format_message (VncState *vs) {
    char pad[3] = { 0, 0, 0 };

    vnc_write_u8(vs, vs->ds->surface->pf.bits_per_pixel); /* bits-per-pixel */
    vnc_write_u8(vs, vs->ds->surface->pf.depth); /* depth */

#ifdef WORDS_BIGENDIAN
    vnc_write_u8(vs, 1);             /* big-endian-flag */
#else
    vnc_write_u8(vs, 0);             /* big-endian-flag */
#endif
    vnc_write_u8(vs, 1);             /* true-color-flag */
    vnc_write_u16(vs, vs->ds->surface->pf.rmax);     /* red-max */
    vnc_write_u16(vs, vs->ds->surface->pf.gmax);     /* green-max */
    vnc_write_u16(vs, vs->ds->surface->pf.bmax);     /* blue-max */
    vnc_write_u8(vs, vs->ds->surface->pf.rshift);    /* red-shift */
    vnc_write_u8(vs, vs->ds->surface->pf.gshift);    /* green-shift */
    vnc_write_u8(vs, vs->ds->surface->pf.bshift);    /* blue-shift */
    if (vs->ds->surface->pf.bits_per_pixel == 32)
        vs->send_hextile_tile = send_hextile_tile_32;
    else if (vs->ds->surface->pf.bits_per_pixel == 16)
        vs->send_hextile_tile = send_hextile_tile_16;
    else if (vs->ds->surface->pf.bits_per_pixel == 8)
        vs->send_hextile_tile = send_hextile_tile_8;
    vs->clientds = *(vs->ds->surface);
    vs->clientds.flags &= ~QEMU_ALLOCATED_FLAG;
    vs->write_pixels = vnc_write_pixels_copy;

    vnc_write(vs, pad, 3);           /* padding */
}

static void vnc_dpy_setdata(DisplayState *ds)
{
    /* We don't have to do anything */
}

static void vnc_colordepth(VncState *vs)
{
    if (vnc_has_feature(vs, VNC_FEATURE_WMVI)) {
        /* Sending a WMVi message to notify the client*/
        vnc_write_u8(vs, 0);  /* msg id */
        vnc_write_u8(vs, 0);
        vnc_write_u16(vs, 1); /* number of rects */
        vnc_framebuffer_update(vs, 0, 0, ds_get_width(vs->ds),
                               ds_get_height(vs->ds), VNC_ENCODING_WMVi);
        pixel_format_message(vs);
        vnc_flush(vs);
    } else {
        set_pixel_conversion(vs);
    }
}

static int protocol_client_msg(VncState *vs, uint8_t *data, size_t len)
{
    int i;
    uint16_t limit;
    VncDisplay *vd = vs->vd;

    if (data[0] > 3) {
        vd->timer_interval = VNC_REFRESH_INTERVAL_BASE;
        if (!qemu_timer_expired(vd->timer, qemu_get_clock(rt_clock) + vd->timer_interval))
            qemu_mod_timer(vd->timer, qemu_get_clock(rt_clock) + vd->timer_interval);
    }

    switch (data[0]) {
    case 0:
	if (len == 1)
	    return 20;

	set_pixel_format(vs, read_u8(data, 4), read_u8(data, 5),
			 read_u8(data, 6), read_u8(data, 7),
			 read_u16(data, 8), read_u16(data, 10),
			 read_u16(data, 12), read_u8(data, 14),
			 read_u8(data, 15), read_u8(data, 16));
	break;
    case 2:
	if (len == 1)
	    return 4;

	if (len == 4) {
            limit = read_u16(data, 2);
            if (limit > 0)
                return 4 + (limit * 4);
        } else
            limit = read_u16(data, 2);

	for (i = 0; i < limit; i++) {
	    int32_t val = read_s32(data, 4 + (i * 4));
	    memcpy(data + 4 + (i * 4), &val, sizeof(val));
	}

	set_encodings(vs, (int32_t *)(data + 4), limit);
	break;
    case 3:
	if (len == 1)
	    return 10;

	framebuffer_update_request(vs,
				   read_u8(data, 1), read_u16(data, 2), read_u16(data, 4),
				   read_u16(data, 6), read_u16(data, 8));
	break;
    case 4:
	if (len == 1)
	    return 8;

	key_event(vs, read_u8(data, 1), read_u32(data, 4));
	break;
    case 5:
	if (len == 1)
	    return 6;

	pointer_event(vs, read_u8(data, 1), read_u16(data, 2), read_u16(data, 4));
	break;
    case 6:
	if (len == 1)
	    return 8;

	if (len == 8) {
            uint32_t dlen = read_u32(data, 4);
            if (dlen > 0)
                return 8 + dlen;
        }

	client_cut_text(vs, read_u32(data, 4), data + 8);
	break;
    case 254:
        if (len == 1)
	    return 8;

        scan_event(vs, read_u8(data, 1), read_u32(data, 4));
        break;
    case 255:
        if (len == 1)
            return 2;

        switch (read_u8(data, 1)) {
        case 0:
            if (len == 2)
                return 12;

            ext_key_event(vs, read_u16(data, 2),
                          read_u32(data, 4), read_u32(data, 8));
            break;
        case 1:
            if (len == 2)
                return 4;

            switch (read_u16 (data, 2)) {
            case 0:
                audio_add(vs);
                break;
            case 1:
                audio_del(vs);
                break;
            case 2:
                if (len == 4)
                    return 10;
                switch (read_u8(data, 4)) {
                case 0: vs->as.fmt = AUD_FMT_U8; break;
                case 1: vs->as.fmt = AUD_FMT_S8; break;
                case 2: vs->as.fmt = AUD_FMT_U16; break;
                case 3: vs->as.fmt = AUD_FMT_S16; break;
                case 4: vs->as.fmt = AUD_FMT_U32; break;
                case 5: vs->as.fmt = AUD_FMT_S32; break;
                default:
                    printf("Invalid audio format %d\n", read_u8(data, 4));
                    vnc_client_error(vs);
                    break;
                }
                vs->as.nchannels = read_u8(data, 5);
                if (vs->as.nchannels != 1 && vs->as.nchannels != 2) {
                    printf("Invalid audio channel coount %d\n",
                           read_u8(data, 5));
                    vnc_client_error(vs);
                    break;
                }
                vs->as.freq = read_u32(data, 6);
                break;
            default:
                printf ("Invalid audio message %d\n", read_u8(data, 4));
                vnc_client_error(vs);
                break;
            }
            break;

        default:
            printf("Msg: %d\n", read_u16(data, 0));
            vnc_client_error(vs);
            break;
        }
        break;
    default:
	printf("Msg: %d\n", data[0]);
	vnc_client_error(vs);
	break;
    }

    vnc_read_when(vs, protocol_client_msg, 1);
    return 0;
}

static int protocol_client_init(VncState *vs, uint8_t *data, size_t len)
{
    char buf[1024];
    int size;

    vnc_write_u16(vs, ds_get_width(vs->ds));
    vnc_write_u16(vs, ds_get_height(vs->ds));

    pixel_format_message(vs);

    if (qemu_name)
        size = snprintf(buf, sizeof(buf), "QEMU (%s)", qemu_name);
    else
        size = snprintf(buf, sizeof(buf), "QEMU");

    vnc_write_u32(vs, size);
    vnc_write(vs, buf, size);
    vnc_flush(vs);

    vnc_read_when(vs, protocol_client_msg, 1);

    return 0;
}

static void make_challenge(VncState *vs)
{
    int i;

    srand(time(NULL)+getpid()+getpid()*987654+rand());

    for (i = 0 ; i < sizeof(vs->challenge) ; i++)
        vs->challenge[i] = (int) (256.0*rand()/(RAND_MAX+1.0));
}

static int protocol_client_auth_vnc(VncState *vs, uint8_t *data, size_t len)
{
    unsigned char response[VNC_AUTH_CHALLENGE_SIZE];
    int i, j, pwlen;
    unsigned char key[8];

    if (!vs->vd->password || !vs->vd->password[0]) {
	VNC_DEBUG("No password configured on server");
	vnc_write_u32(vs, 1); /* Reject auth */
	if (vs->minor >= 8) {
	    static const char err[] = "Authentication failed";
	    vnc_write_u32(vs, sizeof(err));
	    vnc_write(vs, err, sizeof(err));
	}
	vnc_flush(vs);
	vnc_client_error(vs);
	return 0;
    }

    memcpy(response, vs->challenge, VNC_AUTH_CHALLENGE_SIZE);

    /* Calculate the expected challenge response */
    pwlen = strlen(vs->vd->password);
    for (i=0; i<sizeof(key); i++)
        key[i] = i<pwlen ? vs->vd->password[i] : 0;
    deskey(key, EN0);
    for (j = 0; j < VNC_AUTH_CHALLENGE_SIZE; j += 8)
        des(response+j, response+j);

    /* Compare expected vs actual challenge response */
    if (memcmp(response, data, VNC_AUTH_CHALLENGE_SIZE) != 0) {
	VNC_DEBUG("Client challenge reponse did not match\n");
	vnc_write_u32(vs, 1); /* Reject auth */
	if (vs->minor >= 8) {
	    static const char err[] = "Authentication failed";
	    vnc_write_u32(vs, sizeof(err));
	    vnc_write(vs, err, sizeof(err));
	}
	vnc_flush(vs);
	vnc_client_error(vs);
    } else {
	VNC_DEBUG("Accepting VNC challenge response\n");
	vnc_write_u32(vs, 0); /* Accept auth */
	vnc_flush(vs);

	vnc_read_when(vs, protocol_client_init, 1);
    }
    return 0;
}

static int start_auth_vnc(VncState *vs)
{
    make_challenge(vs);
    /* Send client a 'random' challenge */
    vnc_write(vs, vs->challenge, sizeof(vs->challenge));
    vnc_flush(vs);

    vnc_read_when(vs, protocol_client_auth_vnc, sizeof(vs->challenge));
    return 0;
}


#ifdef CONFIG_VNC_TLS
#define DH_BITS 1024
static gnutls_dh_params_t dh_params;

static int vnc_tls_initialize(void)
{
    static int tlsinitialized = 0;

    if (tlsinitialized)
	return 1;

    if (gnutls_global_init () < 0)
	return 0;

    /* XXX ought to re-generate diffie-hellmen params periodically */
    if (gnutls_dh_params_init (&dh_params) < 0)
	return 0;
    if (gnutls_dh_params_generate2 (dh_params, DH_BITS) < 0)
	return 0;

#if defined(_VNC_DEBUG) && _VNC_DEBUG >= 2
    gnutls_global_set_log_level(10);
    gnutls_global_set_log_function(vnc_debug_gnutls_log);
#endif

    tlsinitialized = 1;

    return 1;
}

static gnutls_anon_server_credentials vnc_tls_initialize_anon_cred(void)
{
    gnutls_anon_server_credentials anon_cred;
    int ret;

    if ((ret = gnutls_anon_allocate_server_credentials(&anon_cred)) < 0) {
	VNC_DEBUG("Cannot allocate credentials %s\n", gnutls_strerror(ret));
	return NULL;
    }

    gnutls_anon_set_server_dh_params(anon_cred, dh_params);

    return anon_cred;
}


static gnutls_certificate_credentials_t vnc_tls_initialize_x509_cred(VncState *vs)
{
    gnutls_certificate_credentials_t x509_cred;
    int ret;

    if (!vs->vd->x509cacert) {
	VNC_DEBUG("No CA x509 certificate specified\n");
	return NULL;
    }
    if (!vs->vd->x509cert) {
	VNC_DEBUG("No server x509 certificate specified\n");
	return NULL;
    }
    if (!vs->vd->x509key) {
	VNC_DEBUG("No server private key specified\n");
	return NULL;
    }

    if ((ret = gnutls_certificate_allocate_credentials(&x509_cred)) < 0) {
	VNC_DEBUG("Cannot allocate credentials %s\n", gnutls_strerror(ret));
	return NULL;
    }
    if ((ret = gnutls_certificate_set_x509_trust_file(x509_cred,
						      vs->vd->x509cacert,
						      GNUTLS_X509_FMT_PEM)) < 0) {
	VNC_DEBUG("Cannot load CA certificate %s\n", gnutls_strerror(ret));
	gnutls_certificate_free_credentials(x509_cred);
	return NULL;
    }

    if ((ret = gnutls_certificate_set_x509_key_file (x509_cred,
						     vs->vd->x509cert,
						     vs->vd->x509key,
						     GNUTLS_X509_FMT_PEM)) < 0) {
	VNC_DEBUG("Cannot load certificate & key %s\n", gnutls_strerror(ret));
	gnutls_certificate_free_credentials(x509_cred);
	return NULL;
    }

    if (vs->vd->x509cacrl) {
	if ((ret = gnutls_certificate_set_x509_crl_file(x509_cred,
							vs->vd->x509cacrl,
							GNUTLS_X509_FMT_PEM)) < 0) {
	    VNC_DEBUG("Cannot load CRL %s\n", gnutls_strerror(ret));
	    gnutls_certificate_free_credentials(x509_cred);
	    return NULL;
	}
    }

    gnutls_certificate_set_dh_params (x509_cred, dh_params);

    return x509_cred;
}

static int vnc_validate_certificate(struct VncState *vs)
{
    int ret;
    unsigned int status;
    const gnutls_datum_t *certs;
    unsigned int nCerts, i;
    time_t now;

    VNC_DEBUG("Validating client certificate\n");
    if ((ret = gnutls_certificate_verify_peers2 (vs->tls_session, &status)) < 0) {
	VNC_DEBUG("Verify failed %s\n", gnutls_strerror(ret));
	return -1;
    }

    if ((now = time(NULL)) == ((time_t)-1)) {
	return -1;
    }

    if (status != 0) {
	if (status & GNUTLS_CERT_INVALID)
	    VNC_DEBUG("The certificate is not trusted.\n");

	if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
	    VNC_DEBUG("The certificate hasn't got a known issuer.\n");

	if (status & GNUTLS_CERT_REVOKED)
	    VNC_DEBUG("The certificate has been revoked.\n");

	if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
	    VNC_DEBUG("The certificate uses an insecure algorithm\n");

	return -1;
    } else {
	VNC_DEBUG("Certificate is valid!\n");
    }

    /* Only support x509 for now */
    if (gnutls_certificate_type_get(vs->tls_session) != GNUTLS_CRT_X509)
	return -1;

    if (!(certs = gnutls_certificate_get_peers(vs->tls_session, &nCerts)))
	return -1;

    for (i = 0 ; i < nCerts ; i++) {
	gnutls_x509_crt_t cert;
	VNC_DEBUG ("Checking certificate chain %d\n", i);
	if (gnutls_x509_crt_init (&cert) < 0)
	    return -1;

	if (gnutls_x509_crt_import(cert, &certs[i], GNUTLS_X509_FMT_DER) < 0) {
	    gnutls_x509_crt_deinit (cert);
	    return -1;
	}

	if (gnutls_x509_crt_get_expiration_time (cert) < now) {
	    VNC_DEBUG("The certificate has expired\n");
	    gnutls_x509_crt_deinit (cert);
	    return -1;
	}

	if (gnutls_x509_crt_get_activation_time (cert) > now) {
	    VNC_DEBUG("The certificate is not yet activated\n");
	    gnutls_x509_crt_deinit (cert);
	    return -1;
	}

	if (gnutls_x509_crt_get_activation_time (cert) > now) {
	    VNC_DEBUG("The certificate is not yet activated\n");
	    gnutls_x509_crt_deinit (cert);
	    return -1;
	}

	gnutls_x509_crt_deinit (cert);
    }

    return 0;
}


static int start_auth_vencrypt_subauth(VncState *vs)
{
    switch (vs->vd->subauth) {
    case VNC_AUTH_VENCRYPT_TLSNONE:
    case VNC_AUTH_VENCRYPT_X509NONE:
       VNC_DEBUG("Accept TLS auth none\n");
       vnc_write_u32(vs, 0); /* Accept auth completion */
       vnc_read_when(vs, protocol_client_init, 1);
       break;

    case VNC_AUTH_VENCRYPT_TLSVNC:
    case VNC_AUTH_VENCRYPT_X509VNC:
       VNC_DEBUG("Start TLS auth VNC\n");
       return start_auth_vnc(vs);

    default: /* Should not be possible, but just in case */
       VNC_DEBUG("Reject auth %d\n", vs->vd->auth);
       vnc_write_u8(vs, 1);
       if (vs->minor >= 8) {
           static const char err[] = "Unsupported authentication type";
           vnc_write_u32(vs, sizeof(err));
           vnc_write(vs, err, sizeof(err));
       }
       vnc_client_error(vs);
    }

    return 0;
}

static void vnc_handshake_io(void *opaque);

static int vnc_continue_handshake(struct VncState *vs) {
    int ret;

    if ((ret = gnutls_handshake(vs->tls_session)) < 0) {
       if (!gnutls_error_is_fatal(ret)) {
           VNC_DEBUG("Handshake interrupted (blocking)\n");
           if (!gnutls_record_get_direction(vs->tls_session))
               qemu_set_fd_handler(vs->csock, vnc_handshake_io, NULL, vs);
           else
               qemu_set_fd_handler(vs->csock, NULL, vnc_handshake_io, vs);
           return 0;
       }
       VNC_DEBUG("Handshake failed %s\n", gnutls_strerror(ret));
       vnc_client_error(vs);
       return -1;
    }

    if (vs->vd->x509verify) {
	if (vnc_validate_certificate(vs) < 0) {
	    VNC_DEBUG("Client verification failed\n");
	    vnc_client_error(vs);
	    return -1;
	} else {
	    VNC_DEBUG("Client verification passed\n");
	}
    }

    VNC_DEBUG("Handshake done, switching to TLS data mode\n");
    vs->wiremode = VNC_WIREMODE_TLS;
    qemu_set_fd_handler2(vs->csock, NULL, vnc_client_read, vnc_client_write, vs);

    return start_auth_vencrypt_subauth(vs);
}

static void vnc_handshake_io(void *opaque) {
    struct VncState *vs = (struct VncState *)opaque;

    VNC_DEBUG("Handshake IO continue\n");
    vnc_continue_handshake(vs);
}

#define NEED_X509_AUTH(vs)			      \
    ((vs)->vd->subauth == VNC_AUTH_VENCRYPT_X509NONE ||   \
     (vs)->vd->subauth == VNC_AUTH_VENCRYPT_X509VNC ||    \
     (vs)->vd->subauth == VNC_AUTH_VENCRYPT_X509PLAIN)


static int vnc_start_tls(struct VncState *vs) {
    static const int cert_type_priority[] = { GNUTLS_CRT_X509, 0 };
    static const int protocol_priority[]= { GNUTLS_TLS1_1, GNUTLS_TLS1_0, GNUTLS_SSL3, 0 };
    static const int kx_anon[] = {GNUTLS_KX_ANON_DH, 0};
    static const int kx_x509[] = {GNUTLS_KX_DHE_DSS, GNUTLS_KX_RSA, GNUTLS_KX_DHE_RSA, GNUTLS_KX_SRP, 0};

    VNC_DEBUG("Do TLS setup\n");
    if (vnc_tls_initialize() < 0) {
	VNC_DEBUG("Failed to init TLS\n");
	vnc_client_error(vs);
	return -1;
    }
    if (vs->tls_session == NULL) {
	if (gnutls_init(&vs->tls_session, GNUTLS_SERVER) < 0) {
	    vnc_client_error(vs);
	    return -1;
	}

	if (gnutls_set_default_priority(vs->tls_session) < 0) {
	    gnutls_deinit(vs->tls_session);
	    vs->tls_session = NULL;
	    vnc_client_error(vs);
	    return -1;
	}

	if (gnutls_kx_set_priority(vs->tls_session, NEED_X509_AUTH(vs) ? kx_x509 : kx_anon) < 0) {
	    gnutls_deinit(vs->tls_session);
	    vs->tls_session = NULL;
	    vnc_client_error(vs);
	    return -1;
	}

	if (gnutls_certificate_type_set_priority(vs->tls_session, cert_type_priority) < 0) {
	    gnutls_deinit(vs->tls_session);
	    vs->tls_session = NULL;
	    vnc_client_error(vs);
	    return -1;
	}

	if (gnutls_protocol_set_priority(vs->tls_session, protocol_priority) < 0) {
	    gnutls_deinit(vs->tls_session);
	    vs->tls_session = NULL;
	    vnc_client_error(vs);
	    return -1;
	}

	if (NEED_X509_AUTH(vs)) {
	    gnutls_certificate_server_credentials x509_cred = vnc_tls_initialize_x509_cred(vs);
	    if (!x509_cred) {
		gnutls_deinit(vs->tls_session);
		vs->tls_session = NULL;
		vnc_client_error(vs);
		return -1;
	    }
	    if (gnutls_credentials_set(vs->tls_session, GNUTLS_CRD_CERTIFICATE, x509_cred) < 0) {
		gnutls_deinit(vs->tls_session);
		vs->tls_session = NULL;
		gnutls_certificate_free_credentials(x509_cred);
		vnc_client_error(vs);
		return -1;
	    }
	    if (vs->vd->x509verify) {
		VNC_DEBUG("Requesting a client certificate\n");
		gnutls_certificate_server_set_request (vs->tls_session, GNUTLS_CERT_REQUEST);
	    }

	} else {
	    gnutls_anon_server_credentials anon_cred = vnc_tls_initialize_anon_cred();
	    if (!anon_cred) {
		gnutls_deinit(vs->tls_session);
		vs->tls_session = NULL;
		vnc_client_error(vs);
		return -1;
	    }
	    if (gnutls_credentials_set(vs->tls_session, GNUTLS_CRD_ANON, anon_cred) < 0) {
		gnutls_deinit(vs->tls_session);
		vs->tls_session = NULL;
		gnutls_anon_free_server_credentials(anon_cred);
		vnc_client_error(vs);
		return -1;
	    }
	}

	gnutls_transport_set_ptr(vs->tls_session, (gnutls_transport_ptr_t)vs);
	gnutls_transport_set_push_function(vs->tls_session, vnc_tls_push);
	gnutls_transport_set_pull_function(vs->tls_session, vnc_tls_pull);
    }

    VNC_DEBUG("Start TLS handshake process\n");
    return vnc_continue_handshake(vs);
}

static int protocol_client_vencrypt_auth(VncState *vs, uint8_t *data, size_t len)
{
    int auth = read_u32(data, 0);

    if (auth != vs->vd->subauth) {
	VNC_DEBUG("Rejecting auth %d\n", auth);
	vnc_write_u8(vs, 0); /* Reject auth */
	vnc_flush(vs);
	vnc_client_error(vs);
    } else {
	VNC_DEBUG("Accepting auth %d, starting handshake\n", auth);
	vnc_write_u8(vs, 1); /* Accept auth */
	vnc_flush(vs);

	if (vnc_start_tls(vs) < 0) {
	    VNC_DEBUG("Failed to complete TLS\n");
	    return 0;
	}

	if (vs->wiremode == VNC_WIREMODE_TLS) {
	    VNC_DEBUG("Starting VeNCrypt subauth\n");
	    return start_auth_vencrypt_subauth(vs);
	} else {
	    VNC_DEBUG("TLS handshake blocked\n");
	    return 0;
	}
    }
    return 0;
}

static int protocol_client_vencrypt_init(VncState *vs, uint8_t *data, size_t len)
{
    if (data[0] != 0 ||
	data[1] != 2) {
	VNC_DEBUG("Unsupported VeNCrypt protocol %d.%d\n", (int)data[0], (int)data[1]);
	vnc_write_u8(vs, 1); /* Reject version */
	vnc_flush(vs);
	vnc_client_error(vs);
    } else {
	VNC_DEBUG("Sending allowed auth %d\n", vs->vd->subauth);
	vnc_write_u8(vs, 0); /* Accept version */
	vnc_write_u8(vs, 1); /* Number of sub-auths */
	vnc_write_u32(vs, vs->vd->subauth); /* The supported auth */
	vnc_flush(vs);
	vnc_read_when(vs, protocol_client_vencrypt_auth, 4);
    }
    return 0;
}

static int start_auth_vencrypt(VncState *vs)
{
    /* Send VeNCrypt version 0.2 */
    vnc_write_u8(vs, 0);
    vnc_write_u8(vs, 2);

    vnc_read_when(vs, protocol_client_vencrypt_init, 2);
    return 0;
}
#endif /* CONFIG_VNC_TLS */

static int protocol_client_auth(VncState *vs, uint8_t *data, size_t len)
{
    /* We only advertise 1 auth scheme at a time, so client
     * must pick the one we sent. Verify this */
    if (data[0] != vs->vd->auth) { /* Reject auth */
       VNC_DEBUG("Reject auth %d\n", (int)data[0]);
       vnc_write_u32(vs, 1);
       if (vs->minor >= 8) {
           static const char err[] = "Authentication failed";
           vnc_write_u32(vs, sizeof(err));
           vnc_write(vs, err, sizeof(err));
       }
       vnc_client_error(vs);
    } else { /* Accept requested auth */
       VNC_DEBUG("Client requested auth %d\n", (int)data[0]);
       switch (vs->vd->auth) {
       case VNC_AUTH_NONE:
           VNC_DEBUG("Accept auth none\n");
           if (vs->minor >= 8) {
               vnc_write_u32(vs, 0); /* Accept auth completion */
               vnc_flush(vs);
           }
           vnc_read_when(vs, protocol_client_init, 1);
           break;

       case VNC_AUTH_VNC:
           VNC_DEBUG("Start VNC auth\n");
           return start_auth_vnc(vs);

#ifdef CONFIG_VNC_TLS
       case VNC_AUTH_VENCRYPT:
           VNC_DEBUG("Accept VeNCrypt auth\n");;
           return start_auth_vencrypt(vs);
#endif /* CONFIG_VNC_TLS */

       default: /* Should not be possible, but just in case */
           VNC_DEBUG("Reject auth %d\n", vs->vd->auth);
           vnc_write_u8(vs, 1);
           if (vs->minor >= 8) {
               static const char err[] = "Authentication failed";
               vnc_write_u32(vs, sizeof(err));
               vnc_write(vs, err, sizeof(err));
           }
           vnc_client_error(vs);
       }
    }
    return 0;
}

static int protocol_version(VncState *vs, uint8_t *version, size_t len)
{
    char local[13];

    memcpy(local, version, 12);
    local[12] = 0;

    if (sscanf(local, "RFB %03d.%03d\n", &vs->major, &vs->minor) != 2) {
	VNC_DEBUG("Malformed protocol version %s\n", local);
	vnc_client_error(vs);
	return 0;
    }
    VNC_DEBUG("Client request protocol version %d.%d\n", vs->major, vs->minor);
    if (vs->major != 3 ||
	(vs->minor != 3 &&
	 vs->minor != 4 &&
	 vs->minor != 5 &&
	 vs->minor != 7 &&
	 vs->minor != 8)) {
	VNC_DEBUG("Unsupported client version\n");
	vnc_write_u32(vs, VNC_AUTH_INVALID);
	vnc_flush(vs);
	vnc_client_error(vs);
	return 0;
    }
    /* Some broken clients report v3.4 or v3.5, which spec requires to be treated
     * as equivalent to v3.3 by servers
     */
    if (vs->minor == 4 || vs->minor == 5)
	vs->minor = 3;

    if (vs->minor == 3) {
	if (vs->vd->auth == VNC_AUTH_NONE) {
            VNC_DEBUG("Tell client auth none\n");
            vnc_write_u32(vs, vs->vd->auth);
            vnc_flush(vs);
            vnc_read_when(vs, protocol_client_init, 1);
       } else if (vs->vd->auth == VNC_AUTH_VNC) {
            VNC_DEBUG("Tell client VNC auth\n");
            vnc_write_u32(vs, vs->vd->auth);
            vnc_flush(vs);
            start_auth_vnc(vs);
       } else {
            VNC_DEBUG("Unsupported auth %d for protocol 3.3\n", vs->vd->auth);
            vnc_write_u32(vs, VNC_AUTH_INVALID);
            vnc_flush(vs);
            vnc_client_error(vs);
       }
    } else {
	VNC_DEBUG("Telling client we support auth %d\n", vs->vd->auth);
	vnc_write_u8(vs, 1); /* num auth */
	vnc_write_u8(vs, vs->vd->auth);
	vnc_read_when(vs, protocol_client_auth, 1);
	vnc_flush(vs);
    }

    return 0;
}

static int vnc_refresh_server_surface(VncDisplay *vd)
{
    int y;
    uint8_t *guest_row;
    uint8_t *server_row;
    int cmp_bytes;
    VncState *vs = NULL;
    int has_dirty = 0;

    if (!vd->server)
        return 0;

    /*
     * Walk through the guest dirty map.
     * Check and copy modified bits from guest to server surface.
     * Update server dirty map.
     */
    cmp_bytes = 16 * ds_get_bytes_per_pixel(vd->ds);
    guest_row  = vd->guest.ds->data;
    server_row = vd->server->data;
    for (y = 0; y < vd->guest.ds->height; y++) {
        if (line_is_dirty(&vd->guest.dirty, y)) {
            int x;
            uint8_t *guest_ptr;
            uint8_t *server_ptr;

            guest_ptr  = guest_row;
            server_ptr = server_row;

            for (x = 0; x < vd->guest.ds->width;
                    x += 16, guest_ptr += cmp_bytes, server_ptr += cmp_bytes) {
                if (!dirty_get_bit(&vd->guest.dirty, x / 16, y))
                    continue;
                dirty_clear_bit(&vd->guest.dirty, x / 16, y);
                if (memcmp(server_ptr, guest_ptr, cmp_bytes) == 0)
                    continue;
                memcpy(server_ptr, guest_ptr, cmp_bytes);
                vs = vd->clients;
                while (vs != NULL) {
                    dirty_set_bit(&vs->dirty, x / 16, y);
                    vs = vs->next;
                }
                has_dirty++;
            }
        }
        guest_row  += ds_get_linesize(vd->ds);
        server_row += ds_get_linesize(vd->ds);
    }
    return has_dirty;
}

static void vnc_refresh(void *opaque)
{
    VncDisplay *vd = opaque;
    VncState *vs = NULL, *vn = NULL;
    int has_dirty = 0, rects = 0;

    if (!vd->server)
        return;

    vga_hw_update();

    has_dirty = vnc_refresh_server_surface(vd);

    vs = vd->clients;
    while (vs != NULL) {
        vn = vs->next;
        rects += vnc_update_client(vs, has_dirty);
        /* vs might be free()ed here */
        vs = vn;
    }
    /* vd->timer could be NULL now if the last client disconnected,
     * in this case don't update the timer */
    if (vd->timer == NULL)
        return;

    if (has_dirty && rects) {
        vd->timer_interval /= 2;
        if (vd->timer_interval < VNC_REFRESH_INTERVAL_BASE)
            vd->timer_interval = VNC_REFRESH_INTERVAL_BASE;
    } else {
        vd->timer_interval += VNC_REFRESH_INTERVAL_INC;
        if (vd->timer_interval > VNC_REFRESH_INTERVAL_MAX)
            vd->timer_interval = VNC_REFRESH_INTERVAL_MAX;
    }
    qemu_mod_timer(vd->timer, qemu_get_clock(rt_clock) + vd->timer_interval);
}

static void vnc_init_timer(VncDisplay *vd)
{
    vd->timer_interval = VNC_REFRESH_INTERVAL_BASE;
    if (vd->timer == NULL && vd->clients != NULL) {
        vd->timer = qemu_new_timer(rt_clock, vnc_refresh, vd);
        vnc_refresh(vd);
    }
}

static void vnc_remove_timer(VncDisplay *vd)
{
    if (vd->timer != NULL && vd->clients == NULL) {
        qemu_del_timer(vd->timer);
        qemu_free_timer(vd->timer);
        vd->timer = NULL;
    }
}

static void vnc_connect(VncDisplay *vd, int csock)
{
    VncState *vs = qemu_mallocz(sizeof(VncState));
    if (!vs) {
        closesocket(csock);
        return;
    }
    vnc_zlib_init(vs);
    vs->csock = csock;

    VNC_DEBUG("New client on socket %d\n", csock);
    dcl->idle = 0;
    socket_set_nonblock(vs->csock);
    qemu_set_fd_handler2(vs->csock, NULL, vnc_client_read, NULL, vs);

    /* assure we have a console */
    if (!is_console_selected())
        console_select(0);

    /* here we must be sure we have a surface */
    vnc_create_surface(vd);

    vs->vd = vd;
    vs->ds = vd->ds;
    vs->last_x = -1;
    vs->last_y = -1;

    vs->as.freq = 44100;
    vs->as.nchannels = 2;
    vs->as.fmt = AUD_FMT_S16;
    vs->as.endianness = 0;

    dirty_resize(&vs->dirty, ds_get_width(vs->ds), ds_get_height(vs->ds));

    vs->next = vd->clients;
    vd->clients = vs;

    vga_hw_update();

    vnc_write(vs, "RFB 003.008\n", 12);
    vnc_flush(vs);
    vnc_read_when(vs, protocol_version, 12);
    reset_keys(vs);

    vnc_init_timer(vd);

    /* vs might be free()ed here */
}

static void vnc_listen_read(void *opaque)
{
    VncDisplay *vs = opaque;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    /* Catch-up */
    if (vs->server)
       vga_hw_update();

    int csock = accept(vs->lsock, (struct sockaddr *)&addr, &addrlen);
    if (csock != -1) {
        vnc_connect(vs, csock);
    }
}

void vnc_keymap_change(char *keymap)
{
    kbd_layout_t *new_layout;

    if (keyboard_layout && !strcmp(keymap, keyboard_layout))
        return;

    new_layout = init_keyboard_layout(keymap);
    if (!new_layout) {
        fprintf(stderr, "Failed to initialise new keyboard layout\n");
        return;
    }

    fprintf(stderr, "Initialise new keyboard layout %s\n", keymap);

    qemu_free(keyboard_layout);
    qemu_free(vnc_display->kbd_layout);

    keyboard_layout = strdup(keymap);
    vnc_display->kbd_layout = new_layout;
}

void vnc_display_init(DisplayState *ds)
{
    VncDisplay *vs = qemu_mallocz(sizeof(*vs));

    host_page_size = sysconf(_SC_PAGESIZE);

    dcl = qemu_mallocz(sizeof(DisplayChangeListener));

    ds->opaque = vs;
    dcl->idle = 1;
    vnc_display = vs;

    vs->lsock = -1;

    vs->ds = ds;

    if (keyboard_layout)
        vs->kbd_layout = init_keyboard_layout(keyboard_layout);
    else
        vs->kbd_layout = init_keyboard_layout("en-us");

    if (!vs->kbd_layout)
	exit(1);

    dcl->dpy_copy = vnc_dpy_copy;
    dcl->dpy_update = vnc_dpy_update;
    dcl->dpy_resize = vnc_dpy_resize;
    dcl->dpy_setdata = vnc_dpy_setdata;
    register_displaychangelistener(ds, dcl);

    vnc_clean_surface(vs, 1);
}

#ifdef CONFIG_VNC_TLS
static int vnc_set_x509_credential(VncDisplay *vs,
				   const char *certdir,
				   const char *filename,
				   char **cred,
				   int ignoreMissing)
{
    struct stat sb;

    if (*cred) {
	qemu_free(*cred);
	*cred = NULL;
    }

    *cred = qemu_malloc(strlen(certdir) + strlen(filename) + 2);

    strcpy(*cred, certdir);
    strcat(*cred, "/");
    strcat(*cred, filename);

    VNC_DEBUG("Check %s\n", *cred);
    if (stat(*cred, &sb) < 0) {
	qemu_free(*cred);
	*cred = NULL;
	if (ignoreMissing && errno == ENOENT)
	    return 0;
	return -1;
    }

    return 0;
}

static int vnc_set_x509_credential_dir(VncDisplay *vs,
				       const char *certdir)
{
    if (vnc_set_x509_credential(vs, certdir, X509_CA_CERT_FILE, &vs->x509cacert, 0) < 0)
	goto cleanup;
    if (vnc_set_x509_credential(vs, certdir, X509_CA_CRL_FILE, &vs->x509cacrl, 1) < 0)
	goto cleanup;
    if (vnc_set_x509_credential(vs, certdir, X509_SERVER_CERT_FILE, &vs->x509cert, 0) < 0)
	goto cleanup;
    if (vnc_set_x509_credential(vs, certdir, X509_SERVER_KEY_FILE, &vs->x509key, 0) < 0)
	goto cleanup;

    return 0;

 cleanup:
    qemu_free(vs->x509cacert);
    qemu_free(vs->x509cacrl);
    qemu_free(vs->x509cert);
    qemu_free(vs->x509key);
    vs->x509cacert = vs->x509cacrl = vs->x509cert = vs->x509key = NULL;
    return -1;
}
#endif /* CONFIG_VNC_TLS */

void vnc_display_close(DisplayState *ds)
{
    VncDisplay *vs = ds ? (VncDisplay *)ds->opaque : vnc_display;

    if (!vs)
        return;
    if (vs->display) {
	qemu_free(vs->display);
	vs->display = NULL;
    }
    if (vs->lsock != -1) {
	qemu_set_fd_handler2(vs->lsock, NULL, NULL, NULL, NULL);
	close(vs->lsock);
	vs->lsock = -1;
    }
    vs->auth = VNC_AUTH_INVALID;
#ifdef CONFIG_VNC_TLS
    vs->subauth = VNC_AUTH_INVALID;
    vs->x509verify = 0;
#endif
}

int vnc_display_password(DisplayState *ds, const char *password)
{
    VncDisplay *vs = ds ? (VncDisplay *)ds->opaque : vnc_display;

    if (vs->password) {
	qemu_free(vs->password);
	vs->password = NULL;
    }
    if (password && password[0]) {
	if (!(vs->password = qemu_strdup(password)))
	    return -1;
    }

    return 0;
}

int vnc_display_open(DisplayState *ds, const char *display)
{
    VncDisplay *vs = ds ? (VncDisplay *)ds->opaque : vnc_display;
    const char *options;
    int password = 0;
    int reverse = 0;
    int to_port = 0;
#ifdef CONFIG_VNC_TLS
    int tls = 0, x509 = 0;
#endif

    if (!vnc_display)
        return -1;
    vnc_display_close(ds);
    if (strcmp(display, "none") == 0)
	return 0;

    if (!(vs->display = strdup(display)))
	return -1;

    options = display;
    while ((options = strchr(options, ','))) {
	options++;
	if (strncmp(options, "password", 8) == 0) {
	    password = 1; /* Require password auth */
	} else if (strncmp(options, "reverse", 7) == 0) {
	    reverse = 1;
	} else if (strncmp(options, "to=", 3) == 0) {
            to_port = atoi(options+3) + 5900;
#ifdef CONFIG_VNC_TLS
	} else if (strncmp(options, "tls", 3) == 0) {
	    tls = 1; /* Require TLS */
	} else if (strncmp(options, "x509", 4) == 0) {
	    char *start, *end;
	    x509 = 1; /* Require x509 certificates */
	    if (strncmp(options, "x509verify", 10) == 0)
	        vs->x509verify = 1; /* ...and verify client certs */

	    /* Now check for 'x509=/some/path' postfix
	     * and use that to setup x509 certificate/key paths */
	    start = strchr(options, '=');
	    end = strchr(options, ',');
	    if (start && (!end || (start < end))) {
		int len = end ? end-(start+1) : strlen(start+1);
		char *path = qemu_strndup(start + 1, len);

		VNC_DEBUG("Trying certificate path '%s'\n", path);
		if (vnc_set_x509_credential_dir(vs, path) < 0) {
		    fprintf(stderr, "Failed to find x509 certificates/keys in %s\n", path);
		    qemu_free(path);
		    qemu_free(vs->display);
		    vs->display = NULL;
		    return -1;
		}
		qemu_free(path);
	    } else {
		fprintf(stderr, "No certificate path provided\n");
		qemu_free(vs->display);
		vs->display = NULL;
		return -1;
	    }
#endif
	}
    }

    if (password) {
#ifdef CONFIG_VNC_TLS
	if (tls) {
	    vs->auth = VNC_AUTH_VENCRYPT;
	    if (x509) {
		VNC_DEBUG("Initializing VNC server with x509 password auth\n");
		vs->subauth = VNC_AUTH_VENCRYPT_X509VNC;
	    } else {
		VNC_DEBUG("Initializing VNC server with TLS password auth\n");
		vs->subauth = VNC_AUTH_VENCRYPT_TLSVNC;
	    }
	} else {
#endif
	    VNC_DEBUG("Initializing VNC server with password auth\n");
	    vs->auth = VNC_AUTH_VNC;
#ifdef CONFIG_VNC_TLS
	    vs->subauth = VNC_AUTH_INVALID;
	}
#endif
    } else {
#ifdef CONFIG_VNC_TLS
	if (tls) {
	    vs->auth = VNC_AUTH_VENCRYPT;
	    if (x509) {
		VNC_DEBUG("Initializing VNC server with x509 no auth\n");
		vs->subauth = VNC_AUTH_VENCRYPT_X509NONE;
	    } else {
		VNC_DEBUG("Initializing VNC server with TLS no auth\n");
		vs->subauth = VNC_AUTH_VENCRYPT_TLSNONE;
	    }
	} else {
#endif
	    VNC_DEBUG("Initializing VNC server with no auth\n");
	    vs->auth = VNC_AUTH_NONE;
#ifdef CONFIG_VNC_TLS
	    vs->subauth = VNC_AUTH_INVALID;
	}
#endif
    }

    if (reverse) {
        /* connect to viewer */
        if (strncmp(display, "unix:", 5) == 0)
            vs->lsock = unix_connect(display+5);
        else
            vs->lsock = inet_connect(display, SOCK_STREAM);
        if (-1 == vs->lsock) {
            free(vs->display);
            vs->display = NULL;
            return -1;
        } else {
            int csock = vs->lsock;
            vs->lsock = -1;
            vnc_connect(vs, csock);
        }
        return 0;

    } else {
        /* listen for connects */
        char *dpy;
        dpy = qemu_malloc(256);
        if (strncmp(display, "unix:", 5) == 0) {
            pstrcpy(dpy, 256, "unix:");
            vs->lsock = unix_listen(display+5, dpy+5, 256-5);
        } else {
            vs->lsock = inet_listen(display, dpy, 256, SOCK_STREAM, 5900);
        }
        if (-1 == vs->lsock) {
            free(dpy);
            return -1;
        } else {
            free(vs->display);
            vs->display = dpy;
        }
    }
    qemu_set_fd_handler2(vs->lsock, NULL, vnc_listen_read, NULL, vs);
    if (!vs->display) {
        return -1;
    } else {
        char port[5];
        char *start, *end;
        int n;
        start = strchr(vs->display, ':');
        if (!start) return -1;
        start++;
        end = strchr(start, ',');
        if (!end)
            n = 4;
        else
            n = (int) (end - start);
        strncpy(port, start, n);
        port[n] = '\0';
        return (5900 + atoi(port));
    }
}
