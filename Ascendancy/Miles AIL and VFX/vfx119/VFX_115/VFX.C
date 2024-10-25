//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл  VFX.C                                                                 лл
//лл                                                                        лл
//лл  386FX VFX API support routines                                        лл
//лл                                                                        лл
//лл  Version 1.00 of 23-Aug-93: Initial                                    лл
//лл  Version 1.10 of 13-Mar-94: Moved from PSpace to VFX                   лл
//лл                                                                        лл
//лл  Project: 386FX Sound & Light(TM)                                      лл
//лл  Authors: John Lemberger, John Miles                                   лл
//лл                                                                        лл
//лл  80386 C source compatible with WATCOM C v9.0 or later                 лл
//лл                                                                        лл
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл  Copyright (C) 1992-1994 Non-Linear Arts, Inc.                         лл
//лл                                                                        лл
//лл  Non-Linear Arts, Inc.                                                 лл
//лл  3415 Greystone #200                                                   лл
//лл  Austin, TX 78731                                                      лл
//лл                                                                        лл
//лл  (512) 346-9595 / FAX (512) 346-9596 / BBS (512) 454-9990              лл
//лл                                                                        лл
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

#include <string.h>
#include <malloc.h>
#include <stdlib.h>

#include "vfx.h"

//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл Pane/window management                                                 лл
//лл                                                                        лл
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

WINDOW *VFX_window_construct(LONG width, LONG height)
{
   WINDOW *window;

   if (width < 1 || height < 1)
      return(NULL);

   if ((window = (WINDOW *) malloc(sizeof(WINDOW))) == NULL)
      return(NULL);

   if ((window->buffer = (UBYTE *) malloc(width * height)) == NULL)
      {
      free(window);
      return(NULL);
      }

   window->x_max = width  - 1;
   window->y_max = height - 1;

   window->stencil = NULL;
   window->shadow  = NULL;

   return window;
}

void VFX_window_destroy(WINDOW *window)
{
   free(window->buffer);
   free(window);
}

PANE *VFX_pane_construct(WINDOW *window, LONG x0, LONG y0, LONG x1, LONG y1)
{
   PANE *pane;

   if (abs(x1 - x0) < 1 || abs(y1 - y0) < 1)
      return NULL;

   if ((pane = (PANE *) malloc(sizeof(PANE))) == NULL)
      return NULL;

   pane->window = window;
   pane->x0 = x0;
   pane->y0 = y0;
   pane->x1 = x1;
   pane->y1 = y1;

   return pane;
}

void VFX_pane_destroy(PANE *pane)
{
   free(pane);
}

//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл Pane list management                                                   лл
//лл                                                                        лл
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

static ULONG a_contained_by_b(PANE *a, PANE *b)
{
   //
   // Panes in different windows can't be compared
   //

   if (a->window != b->window)
      return 0;

   //
   // Trivial rejection: if a is entirely above, below, left, or right
   // of b, a cannot be contained by b
   //

   if (a->y1 < b->y0)
      return 0;

   if (a->y0 > b->y1)
      return 0;

   if (a->x1 < b->x0)
      return 0;

   if (a->x0 > b->x1)
      return 0;

   //
   // a and b are known to overlap: check for X and Y containment
   //

   if (a->x0 < b->x0)
      return 0;

   if (a->x1 > b->x1)
      return 0;

   if (a->y0 < b->y0)
      return 0;

   if (a->y1 > b->y1)
      return 0;

   //
   // No edge of b is outside a, so return TRUE
   //

   return 1;
}

PANE_LIST *VFX_pane_list_construct(LONG n_entries)
{
   PANE_LIST *list;

   if ((list = (PANE_LIST *) malloc(sizeof(PANE_LIST))) == NULL)
      return NULL;

   list->flags = calloc(n_entries,sizeof(ULONG));

   if (list->flags == NULL)
      {
      free(list);
      return NULL;
      }

   list->array = calloc(n_entries,sizeof(PANE));

   if (list->array == NULL)
      {
      free(list->flags);
      free(list);
      return NULL;
      }
   
   list->size = n_entries;

   VFX_pane_list_clear(list);

   return list;
}

void VFX_pane_list_destroy(PANE_LIST *list)
{
   free(list->array);
   free(list->flags);
   free(list);
}

void VFX_pane_list_clear(PANE_LIST *list)
{
   ULONG i;

   for (i=0;i<list->size;i++)
      {
      list->flags[i] = PL_FREE;
      }
}

LONG VFX_pane_list_add(PANE_LIST *list, PANE *target)
{
   return VFX_pane_list_add_area(list,target->window,
                                      target->x0,
                                      target->y0,
                                      target->x1,
                                      target->y1);
}

LONG VFX_pane_list_add_area(PANE_LIST *list, WINDOW *window,//)
                            LONG x0, LONG y0, LONG x1, LONG y1)
{
   ULONG i,j;
   PANE *a,*b;

   for (i=0;i<list->size;i++)
      {
      if (list->flags[i] == PL_FREE)
         break;
      }

   if (i==list->size)
      {
      return -1;
      }

   list->flags[i] = PL_VALID;

   a = &list->array[i];

   a->window = window;
   a->x0     = x0;
   a->y0     = y0;
   a->x1     = x1;
   a->y1     = y1;

   for (j=0,b=&list->array[0]; j<list->size; j++,b++)
      {
      if ((list->flags[j] == PL_FREE) || (a == b))
         continue;

      if (a_contained_by_b(a,b))
         {
         list->flags[i] = PL_CONTAINED;
         break;
         }
      }

   return i;
}

void VFX_pane_list_delete_entry(PANE_LIST *list, LONG entry_num)
{
   ULONG i,j;
   PANE *a,*b,*c;

   if (list->flags[entry_num] == PL_FREE)
      return;

   b = &list->array[entry_num];

   //
   // See if entry_num contains any panes (a)
   //

   for (i=0,a=&list->array[0]; i<list->size; i++,a++)
      {
      if ((list->flags[i] == PL_FREE) || (b == a))
         continue;

      if (a_contained_by_b(a,b))
         {
         //
         // Pane (a) is contained by entry_num (b)
         //
         // If no other pane (c) contains pane (a), then mark pane (a)
         // as PL_VALID
         //

         for (j=0,c=&list->array[0]; j<list->size; j++,c++)
            {
            if ((list->flags[j] == PL_FREE) || (c == a) || (c == b))
               continue;

            if (a_contained_by_b(a,c))
               break;
            }

         if (j==list->size)
            {
            list->flags[i] = PL_VALID;
            }
         }
      }

   list->flags[entry_num] = PL_FREE;
}

void VFX_pane_list_refresh(PANE_LIST *list)
{
   ULONG i;
   PANE *a;

   for (i=0; i<list->size; i++)
      {
      if (list->flags[i] == PL_VALID)
         {
         a = &list->array[i];

         VFX_pane_refresh(a,a->x0,a->y0,a->x1,a->y1);
         }
      }
}

//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл Stencil management                                                     лл
//лл                                                                        лл
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

ULONG VFX_stencil_size(WINDOW *source, ULONG transparent_color)
{
   ULONG  w,h;
   ULONG  x,y;
   ULONG  next;
   ULONG  runtype;
   ULONG  runcnt;
   ULONG  bytes;
   UBYTE *in;

   w = source->x_max + 1;
   h = source->y_max + 1;

   bytes = (sizeof(ULONG) * h);

   for (y = 0; y < h; y++)
      {
      in = ((UBYTE *) source->buffer) + (w * y);

      x = 0;

      while (x < w)
         {
         runtype = (*in == transparent_color);

         for (next = x+1; next < w; next++)
            {   
            if ((*++in == transparent_color) != runtype)
               break;
            }

         runcnt = next-x;

         while (runcnt > 127)
            {
            bytes++;
            runcnt -= 127;
            }

         bytes++;

         x = next;
         }
      }

   return bytes;
}

STENCIL *VFX_stencil_construct(WINDOW *source, void *dest,//)
                               ULONG transparent_color)
{
   ULONG  w,h;
   ULONG  x,y;
   ULONG  next;
   ULONG  runtype;
   ULONG  runcnt;
   UBYTE *in,*out;
   ULONG *dir;

   w = source->x_max + 1;
   h = source->y_max + 1;

   if (dest == source->buffer)
      {
      if (VFX_stencil_size(source,transparent_color) > (w*h))
         return NULL;
      }
   else if (dest == NULL)
      {
      dest = malloc(VFX_stencil_size(source,transparent_color));

      if (dest == NULL)
         return NULL;
      }

   dir = malloc(sizeof(ULONG) * h);

   if (dir == NULL)
      return NULL;

   out = dest;

   for (y = 0; y < h; y++)
      {
      in = ((UBYTE *) source->buffer) + (w * y);

      dir[y] = (((ULONG) out) - ((ULONG) dest)) + (sizeof(ULONG) * h);

      x = 0;

      while (x < w)
         {
         runtype = (*in == transparent_color);

         for (next = x+1; next < w; next++)
            {   
            if ((*++in == transparent_color) != runtype)
               break;
            }

         runtype <<= 7;
         runcnt    = next-x;

         while (runcnt > 127)
            {
            *out++  = runtype | 127;
            runcnt -= 127;
            }

         *out++ = runtype | runcnt;

         x = next;
         }
      }

   memmove((UBYTE *) dest + (h * sizeof(ULONG)),dest,(ULONG) out - (ULONG) dest);
   memmove((UBYTE *) dest, dir, (h * sizeof(ULONG)));

   free(dir);

   return dest;
}

void VFX_stencil_destroy(STENCIL *stencil)
{
   free(stencil);
}

