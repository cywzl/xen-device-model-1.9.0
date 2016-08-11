/*
 * SDL_zoom - surface scaling
 *
 * Derived from: SDL_rotozoom,  LGPL (c) A. Schiffler
 * from the SDL_gfx library.
 *
 * Modifications by Stefano Stabellini and Christopher Clark
 * Copyright (c) 2009 Citrix Systems, Inc.
 */

#include "sdl_zoom.h"
#include <stdint.h>

typedef struct tColorRGBA {
    Uint8 r;
    Uint8 g;
    Uint8 b;
    Uint8 a;
} tColorRGBA;

static Uint16 getRed16(Uint16 color)
{
    return (color >> 11);
}

static Uint16 getGreen16(Uint16 color)
{
    return ((color >> 5) & 0x003f);
}

static Uint16 getBlue16(Uint16 color)
{
    return (color &  0x001f);
}

static void setRed16(Uint16 r, Uint16* color)
{
    *color = ((*color) & 0x07ff) + ((r & 0x001f) << 11);
}

static void setGreen16(Uint16 g, Uint16* color)
{
    *color = ((*color) & 0xf81f) + ((g & 0x003f) << 5);
}

static void setBlue16(Uint16 b, Uint16* color)
{
    *color = ((*color) & 0xffe0) + (b & 0x001f);
}

static int sdl_zoom_rgb16(SDL_Surface *src, SDL_Surface *dst, int smooth,
                          SDL_Rect *src_rect, SDL_Rect *dst_rect, int dst_h, int dst_w)
{
    int x, y, sx, sy, *sax, *say, *csax, *csay, csx, csy, ex, ey, t1, t2, sstep, sstep_jump;
    Uint16 *c00, *c01, *c10, *c11, *sp, *csp, *dp;
    int d_gap;

    if (smooth) {
        /* For interpolation: assume source dimension is one pixel.
         * Smaller here to avoid overflow on right and bottom edge.
         */
        sx = (int) (65536.0 * (float) (src->w - 1) / (float) dst_w);
        sy = (int) (65536.0 * (float) (src->h - 1) / (float) dst_h);
    } else {
        sx = (int) (65536.0 * (float) src->w / (float) dst_w);
        sy = (int) (65536.0 * (float) src->h / (float) dst_h);
    }

    if ((sax = (int *) malloc((dst_w + 1) * sizeof(Uint32))) == NULL) {
        return (-1);
    }
    if ((say = (int *) malloc((dst_h + 1) * sizeof(Uint32))) == NULL) {
        free(sax);
        return (-1);
    }

    sp = csp = (Uint16 *) src->pixels;
    dp = (Uint16 *) dst->pixels;

    csx = 0;
    csax = sax;
    for (x = 0; x <= dst_w; x++) {
        *csax = csx;
        csax++;
        csx &= 0xffff;
        csx += sx;
    }
    csy = 0;
    csay = say;
    for (y = 0; y <= dst_h; y++) {
        *csay = csy;
        csay++;
        csy &= 0xffff;
        csy += sy;
    }

    d_gap = dst->pitch - dst->w * dst->format->BytesPerPixel;

    if (smooth) {
        csay = say;
        for (y = 0; y < dst_rect->y; y++) {
            csay++;
            sstep = (*csay >> 16) * src->pitch;
            csp = (Uint16 *) ((Uint8 *) csp + sstep);
        }

        /* Calculate sstep_jump */
        csax = sax;
        sstep_jump = 0;
        for (x = 0; x < dst_rect->x; x++) {
            csax++;
            sstep = (*csax >> 16);
            sstep_jump += sstep;
        }

        for (y = 0; y < dst->h ; y++) {
            /* Setup colour source pointers */
            c00 = csp + sstep_jump;
            c01 = c00 + 1;
            c10 = (Uint16 *) ((Uint8 *) csp + src->pitch) + sstep_jump;
            c11 = c10 + 1;
            csax = sax + dst_rect->x;

            for (x = 0; x < dst->w; x++) {

                /* Interpolate colours */
                ex = (*csax & 0xffff);
                ey = (*csay & 0xffff);
                t1 = ((((getRed16(*c01) - getRed16(*c00)) * ex) >> 16) + getRed16(*c00)) & 0x1f;
                t2 = ((((getRed16(*c11) - getRed16(*c10)) * ex) >> 16) + getRed16(*c10)) & 0x1f;
                setRed16((((t2 - t1) * ey) >> 16) + t1, dp);
                t1 = ((((getGreen16(*c01) - getGreen16(*c00)) * ex) >> 16) + getGreen16(*c00)) & 0x3f;
                t2 = ((((getGreen16(*c11) - getGreen16(*c10)) * ex) >> 16) + getGreen16(*c10)) & 0x3f;
                setGreen16((((t2 - t1) * ey) >> 16) + t1, dp);
                t1 = ((((getBlue16(*c01) - getBlue16(*c00)) * ex) >> 16) + getBlue16(*c00)) & 0x1f;
                t2 = ((((getBlue16(*c11) - getBlue16(*c10)) * ex) >> 16) + getBlue16(*c10)) & 0x1f;
                setBlue16((((t2 - t1) * ey) >> 16) + t1, dp);

                /* Advance source pointers */
                csax++;
                sstep = (*csax >> 16);
                c00 += sstep;
                c01 += sstep;
                c10 += sstep;
                c11 += sstep;
                /* Advance destination pointer */
                dp++;
            }
            /* Advance source pointer */
            csay++;
            csp = (Uint16 *) ((Uint8 *) csp + (*csay >> 16) * src->pitch);
            /* Advance destination pointers */
            dp = (Uint16 *) ((Uint8 *) dp + d_gap);
        }


    } else {
        csay = say;

        for (y = 0; y < dst_rect->y; y++) {
            csay++;
            sstep = (*csay >> 16) * src->pitch;
            csp = (Uint16 *) ((Uint8 *) csp + sstep);
        }

        /* Calculate sstep_jump */
        csax = sax;
        sstep_jump = 0;
        for (x = 0; x < dst_rect->x; x++) {
            csax++;
            sstep = (*csax >> 16);
            sstep_jump += sstep;
        }

        for (y = 0 ; y < dst->h ; y++) {
            sp = csp + sstep_jump;
            csax = sax + dst_rect->x;

            for (x = 0; x < dst->w; x++) {

                /* Draw */
                *dp = *sp;

                /* Advance source pointers */
                csax++;
                sstep = (*csax >> 16);
                sp += sstep;

                /* Advance destination pointer */
                dp++;
            }
            /* Advance source pointers */
            csay++;
            sstep = (*csay >> 16) * src->pitch;
            csp = (Uint16 *) ((Uint8 *) csp + sstep);

            /* Advance destination pointer */
            dp = (Uint16 *) ((Uint8 *) dp + d_gap);
        }
    }

    free(sax);
    free(say);
    return (0);
}

static int sdl_zoom_rgba32(SDL_Surface *src, SDL_Surface *dst, int smooth,
                           SDL_Rect *src_rect, SDL_Rect *dst_rect, int dst_h, int dst_w)
{
    int x, y, sx, sy, *sax, *say, *csax, *csay, csx, csy, ex, ey, t1, t2, sstep, sstep_jump;
    tColorRGBA *c00, *c01, *c10, *c11, *sp, *csp, *dp;
    int d_gap;

    if (smooth) {
        /* For interpolation: assume source dimension is one pixel.
         * Smaller here to avoid overflow on right and bottom edge.
         */
        sx = (int) (65536.0 * (float) (src->w - 1) / (float) dst_w);
        sy = (int) (65536.0 * (float) (src->h - 1) / (float) dst_h);
    } else {
        sx = (int) (65536.0 * (float) src->w / (float) dst_w);
        sy = (int) (65536.0 * (float) src->h / (float) dst_h);
    }

    if ((sax = (int *) malloc((dst_w + 1) * sizeof(Uint32))) == NULL) {
	return (-1);
    }
    if ((say = (int *) malloc((dst_h + 1) * sizeof(Uint32))) == NULL) {
	free(sax);
	return (-1);
    }

    sp = csp = (tColorRGBA *) src->pixels;
    dp = (tColorRGBA *) dst->pixels;

    csx = 0;
    csax = sax;
    for (x = 0; x <= dst_w; x++) {
	*csax = csx;
	csax++;
	csx &= 0xffff;
	csx += sx;
    }
    csy = 0;
    csay = say;
    for (y = 0; y <= dst_h; y++) {
	*csay = csy;
	csay++;
	csy &= 0xffff;
	csy += sy;
    }

    d_gap = dst->pitch - dst->w * 4;

    if (smooth) {
        csay = say;
        for (y = 0; y < dst_rect->y; y++) {
            csay++;
            sstep = (*csay >> 16) * src->pitch;
            csp = (tColorRGBA *) ((Uint8 *) csp + sstep);
        }

        /* Calculate sstep_jump */
        csax = sax;
        sstep_jump = 0;
        for (x = 0; x < dst_rect->x; x++) {
            csax++;
            sstep = (*csax >> 16);
            sstep_jump += sstep;
        }

        for (y = 0; y < dst->h ; y++) {
            /* Setup colour source pointers */
            c00 = csp + sstep_jump;
            c01 = c00 + 1;
            c10 = (tColorRGBA *) ((Uint8 *) csp + src->pitch) + sstep_jump;
            c11 = c10 + 1;
            csax = sax + dst_rect->x;

            for (x = 0; x < dst->w; x++) {

                /* Interpolate colours */
                ex = (*csax & 0xffff);
                ey = (*csay & 0xffff);
                t1 = ((((c01->r - c00->r) * ex) >> 16) + c00->r) & 0xff;
                t2 = ((((c11->r - c10->r) * ex) >> 16) + c10->r) & 0xff;
                dp->r = (((t2 - t1) * ey) >> 16) + t1;
                t1 = ((((c01->g - c00->g) * ex) >> 16) + c00->g) & 0xff;
                t2 = ((((c11->g - c10->g) * ex) >> 16) + c10->g) & 0xff;
                dp->g = (((t2 - t1) * ey) >> 16) + t1;
                t1 = ((((c01->b - c00->b) * ex) >> 16) + c00->b) & 0xff;
                t2 = ((((c11->b - c10->b) * ex) >> 16) + c10->b) & 0xff;
                dp->b = (((t2 - t1) * ey) >> 16) + t1;
                t1 = ((((c01->a - c00->a) * ex) >> 16) + c00->a) & 0xff;
                t2 = ((((c11->a - c10->a) * ex) >> 16) + c10->a) & 0xff;
                dp->a = (((t2 - t1) * ey) >> 16) + t1;

                /* Advance source pointers */
                csax++;
                sstep = (*csax >> 16);
                c00 += sstep;
                c01 += sstep;
                c10 += sstep;
                c11 += sstep;
                /* Advance destination pointer */
                dp++;
            }
            /* Advance source pointer */
            csay++;
            csp = (tColorRGBA *) ((Uint8 *) csp + (*csay >> 16) * src->pitch);
            /* Advance destination pointers */
            dp = (tColorRGBA *) ((Uint8 *) dp + d_gap);
        }


    } else {
        csay = say;

        for (y = 0; y < dst_rect->y; y++) {
            csay++;
            sstep = (*csay >> 16) * src->pitch;
            csp = (tColorRGBA *) ((Uint8 *) csp + sstep);
        }

        /* Calculate sstep_jump */
        csax = sax;
        sstep_jump = 0;
        for (x = 0; x < dst_rect->x; x++) {
            csax++;
            sstep = (*csax >> 16);
            sstep_jump += sstep;
        }

        for (y = 0 ; y < dst->h ; y++) {
            sp = csp + sstep_jump;
            csax = sax + dst_rect->x;

            for (x = 0; x < dst->w; x++) {

                /* Draw */
                *dp = *sp;

                /* Advance source pointers */
                csax++;
                sstep = (*csax >> 16);
                sp += sstep;

                /* Advance destination pointer */
                dp++;
            }
            /* Advance source pointers */
            csay++;
            sstep = (*csay >> 16) * src->pitch;
            csp = (tColorRGBA *) ((Uint8 *) csp + sstep);

            /* Advance destination pointer */
            dp = (tColorRGBA *) ((Uint8 *) dp + d_gap);
        }
    }

    free(sax);
    free(say);
    return (0);
}

int sdl_zoom_blit(SDL_Surface *src_sfc, SDL_Surface *dst_sfc, int smooth,
                  SDL_Rect *in_rect)
{
    SDL_Surface *zoom_sfc;
    SDL_Rect zoom, src_rect;
    int ret, extra;

    /* Grow the size of the modified rectangle to avoid edge artefacts */
    src_rect.x = (in_rect->x > 0) ? (in_rect->x - 1) : 0;
    src_rect.y = (in_rect->y > 0) ? (in_rect->y - 1) : 0;

    src_rect.w = in_rect->w + 1;
    if (src_rect.x + src_rect.w > src_sfc->w)
        src_rect.w = src_sfc->w - src_rect.x;

    src_rect.h = in_rect->h + 1;
    if (src_rect.y + src_rect.h > src_sfc->h)
        src_rect.h = src_sfc->h - src_rect.y;

    /* (x,y) : round down */
    zoom.x = (int)(((float)(src_rect.x * dst_sfc->w)) / (float)(src_sfc->w));
    zoom.y = (int)(((float)(src_rect.y * dst_sfc->h)) / (float)(src_sfc->h));

    /* (w,h) : round up */
    zoom.w = (int)( ((double)((src_rect.w * dst_sfc->w) + (src_sfc->w - 1))) /
                     (double)(src_sfc->w));

    zoom.h = (int)( ((double)((src_rect.h * dst_sfc->h) + (src_sfc->h - 1))) /
                     (double)(src_sfc->h));

    /* Account for any (x,y) rounding by adding one-source-pixel's worth
     * of destination pixels and then edge checking.
     */

    extra = ((dst_sfc->w-1) / src_sfc->w) + 1;

    if ((zoom.x + zoom.w) < (dst_sfc->w - extra))
        zoom.w += extra;
    else
        zoom.w = dst_sfc->w - zoom.x;

    extra = ((dst_sfc->h-1) / src_sfc->h) + 1;

    if ((zoom.y + zoom.h) < (dst_sfc->h - extra))
        zoom.h += extra;
    else
        zoom.h = dst_sfc->h - zoom.y;

    /* The rectangle (zoom.x, zoom.y, zoom.w, zoom.h) is the area on the
     * destination surface that needs to be updated.
     */

    zoom_sfc = SDL_CreateRGBSurface(SDL_SWSURFACE, zoom.w, zoom.h, dst_sfc->format->BitsPerPixel,
                             src_sfc->format->Rmask, src_sfc->format->Gmask,
                             src_sfc->format->Bmask, src_sfc->format->Amask);

    SDL_LockSurface(src_sfc);

    if (zoom_sfc->format->BitsPerPixel == 32)
        sdl_zoom_rgba32(src_sfc, zoom_sfc, smooth, &src_rect, &zoom, dst_sfc->h, dst_sfc->w);
    else if (zoom_sfc->format->BitsPerPixel == 16)
        sdl_zoom_rgb16(src_sfc, zoom_sfc, smooth, &src_rect, &zoom, dst_sfc->h, dst_sfc->w);
    else {
        fprintf(stderr, "pixel format not supported\n");
        return -1;
    }

    SDL_UnlockSurface(src_sfc);

    SDL_SetAlpha(zoom_sfc, SDL_SRCALPHA, 255);

    ret = SDL_BlitSurface(zoom_sfc, 0, dst_sfc, &zoom);

    /* Return the rectangle of the update to the caller */
    if (ret == 0)
        *in_rect = zoom;

    SDL_FreeSurface(zoom_sfc);

    return ret;
}

