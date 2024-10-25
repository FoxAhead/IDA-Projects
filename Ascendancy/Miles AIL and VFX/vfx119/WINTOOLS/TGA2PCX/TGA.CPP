//
// 16/24/32-bit .TGA parser
//
// jmiles@pop.net
//

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>

#include "mmsystem.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <io.h>
#include <fcntl.h>
#include <float.h>

#define WRITE_COMPRESSED_FILE 1     // 0=uncompressed, 1=RLE compressed

#include "tga.h"

#pragma pack(1)  // Do NOT allow compiler to reorder structs!

struct TGA_HDR
{
   U8    len_image_ID;
   U8    color_map_present;
   U8    image_type;
   S16   color_map_origin;
   S16   color_map_len;
   U8    color_map_entry_size;
   S16   X_origin;
   S16   Y_origin;
   S16   pixel_width;
   S16   pixel_height;
   U8    bits_per_pixel;
   U8    image_descriptor_flags;
};

#define TGA_INTERLEAVE_4 0x80
#define TGA_INTERLEAVE_2 0x40
#define TGA_ORIGIN_TOP   0x20
#define TGA_ORIGIN_RIGHT 0x10
#define TGA_ATTRIB_MASK  0x0F

#define TGA_FORMAT_RGB_UNCOMPRESSED 2
#define TGA_FORMAT_RGB_RLE          10

#pragma pack()

//****************************************************************************
//
// Parse memory-resident copy of .TGA file, returning dimensions and pointer
// to decoded pixel block
//
//****************************************************************************

VFX_RGB * __cdecl TGA_parse(void *TGA_image, //)
                            S32  *x_res, 
                            S32  *y_res)
{
   //
   // Acquire header pointer and validate file type
   //

   TGA_HDR *file = (TGA_HDR *) TGA_image;

   switch (file->image_type)
      {
      case 0:
         SAL_alert_box("Error","No image data in file\n");
         return NULL;

      case TGA_FORMAT_RGB_UNCOMPRESSED:
      case TGA_FORMAT_RGB_RLE:
         break;

      default:
         SAL_alert_box("Error","Unrecognized image format %d -- 16-, 24- or 32-bpp uncompressed or RLE file required\n",
            file->image_type);
         return NULL;
      }

   //
   // Require 16-bit, 24-bit, or 32-bit files
   //

   S32 BPP = file->bits_per_pixel / 8;

   if ((BPP != 3) && 
       (BPP != 4) &&
       (BPP != 2))
      {
      SAL_alert_box("Error","File has %d bits per pixel -- 16-, 24-, or 32-bpp file required\n",
         file->bits_per_pixel);
      return NULL;
      }

   //
   // We don't support interleaved files or files with weird origins...
   //

   if (file->image_descriptor_flags & (TGA_INTERLEAVE_2 | 
                                       TGA_INTERLEAVE_4 |
                                       TGA_ORIGIN_RIGHT))
      {
      SAL_alert_box("Error","Unrecognized image descriptor %X\n",
         file->image_descriptor_flags);
      return NULL;
      }

   //
   // Input pointer follows header
   //

   U8 *in = ((U8 *) file) + sizeof(TGA_HDR);

   //
   // Skip image ID field, if present
   //

   in += file->len_image_ID;

   //
   // Skip color map, if present
   //

   if (file->color_map_present)
      {
      in += (((file->color_map_entry_size) / 8) * file->color_map_len);
      }

   //
   // Allocate memory for output RGB data
   //

   VFX_RGB *out = (VFX_RGB *) malloc(sizeof(VFX_RGB) * 
                                     file->pixel_width *
                                     file->pixel_height);
   if (out == NULL)
      {
      SAL_alert_box("Error","Could not allocate output data block\n");
      return NULL;
      }

   //
   // Set up Y origin and increment
   //

   S32 y,dy,ylim;

   if (file->image_descriptor_flags & TGA_ORIGIN_TOP)
      {
      y    =  0;
      dy   =  1;
      ylim =  file->pixel_height;
      }
   else
      {
      y    =  file->pixel_height-1;
      dy   = -1;
      ylim = -1;
      }       

   //
   // Unpack file to output RGB buffer
   // 

   S32 w = file->pixel_width;

   switch (file->image_type)
      {
      //
      // Uncompressed RGB data
      //

      case TGA_FORMAT_RGB_UNCOMPRESSED:
         {
         while (y != ylim)
            {
            for (S32 x=0; x < w; x++)
               {
               VFX_RGB RGB;

               if (BPP == 2)
                  {
                  RGB.r = ((in[1] >> 2) & 31) << 3;
                  RGB.g = (((in[0] & 0xe0) >> 5) | ((in[1] & 0x03) << 3)) << 3;
                  RGB.b = (in[0] & 0x1f) << 3;
                  }
               else
                  {
                  RGB.r = in[2];
                  RGB.g = in[1];
                  RGB.b = in[0];
                  }

               in += BPP;

               out[(y * w) + x] = RGB;
               }

            y += dy;
            }
         break;
         }

      //
      // RLE-encoded RGB data
      //

      case TGA_FORMAT_RGB_RLE:
         {
         enum {rep,raw};
         S32  state;
         S32  cnt;
         U8  *val;

         state = (*in & 0x80) ? rep : raw;
         cnt   = (*in & 0x7f);
         val   = &in[1];

         while (y != ylim)
            {
            for (S32 x=0; x < w; x++)
               {
               VFX_RGB RGB;

               if (BPP == 2)
                  {
                  RGB.r = ((val[1] >> 2) & 31) << 3;
                  RGB.g = (((val[0] & 0xe0) >> 5) | ((val[1] & 0x03) << 3)) << 3;
                  RGB.b = (val[0] & 0x1f) << 3;
                  }
               else
                  {
                  RGB.r = val[2];
                  RGB.g = val[1];
                  RGB.b = val[0];
                  }

               if (state == raw)
                  {
                  val += BPP;
                  }

               if (!cnt--)
                  {
                  in    = &val[(state == rep) * BPP];
                  state =  (*in & 0x80) ? rep : raw;
                  cnt   =  (*in & 0x7f);
                  val   = &in[1];
                  }

               out[(y * w) + x] = RGB;
               }

            y += dy;
            }

         break;
         }
      }
 
   //
   // Return file location and size to caller
   //

   if (x_res != NULL)
      {
      *x_res = file->pixel_width;
      }

   if (y_res != NULL)
      {
      *y_res = file->pixel_height;
      }

   return out;
}

//****************************************************************************
//
// Write contents of VFX pane to .TGA file, returning 1 if OK or 0 on error 
//
//****************************************************************************

S32 __cdecl TGA_write_16bpp  (PANE *src, //)
                              C8   *filename)
{
   //
   // Open output file
   //

   FILE *out = fopen(filename,"w+b");
   
   if (out == NULL)
      {
      return 0;
      }

   //
   // Get pane dimensions
   //

   S32 w = (src->x1 - src->x0) + 1;
   S32 h = (src->y1 - src->y0) + 1;

   //
   // Compose and write TGA header
   //

   TGA_HDR TGA;

   TGA.len_image_ID           = 0;
   TGA.color_map_present      = 0;

#if WRITE_COMPRESSED_FILE
   TGA.image_type             = TGA_FORMAT_RGB_RLE;
#else
   TGA.image_type             = TGA_FORMAT_RGB_UNCOMPRESSED;
#endif

   TGA.color_map_origin       = 0;
   TGA.color_map_len          = 0;
   TGA.color_map_entry_size   = 0;
   TGA.X_origin               = 0;
   TGA.Y_origin               = 0;
   TGA.pixel_width            = (S16) w;
   TGA.pixel_height           = (S16) h;
   TGA.bits_per_pixel         = 16;
   TGA.image_descriptor_flags = TGA_ORIGIN_TOP;

   if (fwrite(&TGA,
               sizeof(TGA),
               1,
               out) != 1)
      {
      fclose(out);
      return 0;
      }

   //
   // Write pixel data
   //

#if WRITE_COMPRESSED_FILE

   U16 raw_data_record[128];
   U32 raw_data_len = 0;

   for (S32 y=0; y < h; y++)
      {
      for (S32 x=0; x < w; x++)
         {
         //
         // Read pixel at (x,y)
         //

         VFX_RGB *RGB = VFX_RGB_value(VFX_pixel_read(src, x, y));

         U16 out_word = ((RGB->r >> 3) << 10) |
                        ((RGB->g >> 3) << 5 ) |
                        ((RGB->b >> 3) << 0 );

         //
         // Count # of successive occurrences of this pixel, up to 128 in a row
         //

         S32 n = 1;

         for (S32 r=x+1; r < w; r++)
            {
            VFX_RGB *RGB = VFX_RGB_value(VFX_pixel_read(src, r, y));

            U16 test_word = ((RGB->r >> 3) << 10) |
                            ((RGB->g >> 3) << 5 ) |
                            ((RGB->b >> 3) << 0 );

            if (test_word != out_word)
               {
               --r;
               break;
               }
            else
               {
               ++n;

               if (n == 128)
                  {
                  break;
                  }
               }
            }

         x = r;

         //
         // If we have more than one repetition, write RLE record
         // (0x80 | n-1 followed by word to repeat), then continue
         //

         if (n > 1)
            {
            //
            // First, flush any raw data we have buffered
            //

            if (raw_data_len > 0)
               {
               U8 raw_byte = (U8) (raw_data_len - 1);

               if (fwrite(&raw_byte,
                           sizeof(raw_byte),
                           1,
                           out) != 1)
                  {
                  fclose(out);
                  return 0;
                  }

               if (fwrite(&raw_data_record,
                           sizeof(raw_data_record[0]),
                           raw_data_len,
                           out) != raw_data_len)
                  {
                  fclose(out);
                  return 0;
                  }

               raw_data_len = 0;
               }

            //
            // Finally, write RLE record
            //

            U8 RLE_byte = (U8) (0x80 | (n - 1));

            if (fwrite(&RLE_byte,
                        sizeof(RLE_byte),
                        1,
                        out) != 1)
               {
               fclose(out);
               return 0;
               }

            if (fwrite(&out_word,
                        sizeof(out_word),
                        1,
                        out) != 1)
               {
               fclose(out);
               return 0;
               }

            //
            // Continue with next pixel in line
            //

            continue;
            }

         //
         // Current pixel is not repeated, so add it to the raw-data-record
         // buffer and continue
         //

         raw_data_record[raw_data_len++] = out_word;

         //
         // If raw data record full, flush it
         //

         if (raw_data_len == 128)
            {
            U8 raw_byte = (U8) (raw_data_len - 1);

            if (fwrite(&raw_byte,
                        sizeof(raw_byte),
                        1,
                        out) != 1)
               {
               fclose(out);
               return 0;
               }

            if (fwrite(&raw_data_record,
                        sizeof(raw_data_record[0]),
                        raw_data_len,
                        out) != raw_data_len)
               {
               fclose(out);
               return 0;
               }

            raw_data_len = 0;
            }
         }

      //
      // Flush raw data buffer, if not empty
      //

      if (raw_data_len > 0)
         {
         U8 raw_byte = (U8) (raw_data_len - 1);

         if (fwrite(&raw_byte,
                     sizeof(raw_byte),
                     1,
                     out) != 1)
            {
            fclose(out);
            return 0;
            }

         if (fwrite(&raw_data_record,
                     sizeof(raw_data_record[0]),
                     raw_data_len,
                     out) != raw_data_len)
            {
            fclose(out);
            return 0;
            }

         raw_data_len = 0;
         }

      //
      // Continue with next row of pixels
      //
      }

#else

   for (S32 y=0; y < h; y++)
      {
      for (S32 x=0; x < w; x++)
         {
         VFX_RGB *RGB = VFX_RGB_value(VFX_pixel_read(src, x, y));

         U16 out_word = ((RGB->r >> 3) << 10) |
                        ((RGB->g >> 3) << 5 ) |
                        ((RGB->b >> 3) << 0 );

         if (fwrite(&out_word,
                     sizeof(out_word),
                     1,
                     out) != 1)
            {
            fclose(out);
            return 0;
            }
         }
      }

#endif

   //
   // Close output file and return success
   //

   fclose(out);

   return 1;
}


