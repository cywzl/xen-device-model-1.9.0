/*
 * SDL_zoom - surface scaling
 *
 * Derived from: SDL_rotozoom,  LGPL (c) A. Schiffler
 * from the SDL_gfx library.
 *
 * Modifications by Stefano Stabellini and Christopher Clark
 * Copyright (c) 2009 Citrix Systems, Inc.
 */

#ifndef _SDL_zoom_h
#define _SDL_zoom_h

#include <SDL/SDL.h>

#define SMOOTHING_OFF		0
#define SMOOTHING_ON		1

int sdl_zoom_blit(SDL_Surface *src_sfc, SDL_Surface *dst_sfc,
                  int smooth, SDL_Rect *src_rect);

#endif /* _SDL_zoom_h */
