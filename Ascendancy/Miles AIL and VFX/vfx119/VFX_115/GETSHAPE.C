//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл  GETSHAPE.C                                                            лл
//лл                                                                        лл
//лл  386FX shape table creation utility                                    лл
//лл                                                                        лл
//лл  Version 0.10 of 10-Dec-92: Created                                    лл
//лл          1.00 of  1-Mar-93: Initial release                            лл
//лл          1.01 of 19-May-93: PCX files require tc parameter             лл
//лл          1.02 of  5-Sep-93: Bkgnd color derived from 2nd-last .LBM     лл
//лл          1.03 of 19-Nov-93: New shape format for expanded functions    лл
//лл  Version 1.10 of  3-Dec-93: Updated to use new WINDOW structure        лл
//лл  Version 1.20 of 16-Feb-94: Added .FLI & .FLC support                  лл
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

#include <stdio.h>
#include <malloc.h>
#include <dos.h>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>

#include "vfx.h"
#include "flic.h"

#define SOURCE             1
#define TOP_LEFT           2
#define BOTTOM_RIGHT       3
#define HOT_SPOT           4
#define TRANSPARENT_COLOR  5
#define SHAPE              6
#define SAVE_COLORS        7
#define FRAME              8

typedef struct
{
   UBYTE keyword;
   BYTE keystr[32];
}
KEYWORD;

KEYWORD keywords[] =
{
   { SOURCE,            "source_file=\0"        }, //  0
   { SOURCE,            "sf=\0"                 }, //  1
   { SHAPE,             "shape_number=\0"       }, //  2
   { SHAPE,             "sn=\0"                 }, //  3
   { TOP_LEFT,          "top_left=\0"           }, //  4
   { TOP_LEFT,          "tl=\0"                 }, //  5
   { BOTTOM_RIGHT,      "bottom_right=\0"       }, //  6
   { BOTTOM_RIGHT,      "br=\0"                 }, //  7
   { HOT_SPOT,          "hot_spot=\0"           }, //  8
   { HOT_SPOT,          "hs=\0"                 }, //  9
   { TRANSPARENT_COLOR, "transparent_color=\0"  }, // 10
   { TRANSPARENT_COLOR, "tc=\0"                 }, // 11
   { SAVE_COLORS,       "save_colors\0"         }, // 12
   { SAVE_COLORS,       "sc\0"                  }, // 13
   { FRAME,             "frame_number=\0"       }, // 14
   { FRAME,             "fn=\0"                 }, // 15
   { 0,                 "\0"                    }  // 16
};


#define LBM 1
#define PCX 2
#define GIF 3
#define SHP 4

typedef struct
{
   LONG  shape;
   LONG  colors;
}
OFFSET;

typedef struct
{
   char  source[256];
   LONG  x0;
   LONG  y0;
   LONG  x1;
   LONG  y1;
   LONG  origin_x;
   LONG  origin_y;
   LONG  transparent;
   LONG  save_colors;
   LONG  shape;
   ULONG  first_frame;
   ULONG  last_frame;
}
GETSHAPE;

ULONG shape_version = SHAPE_FILE_VERSION;

LONG bkgnd=0;  
UBYTE *fpic;
LONG fpic_type;
FILE *outfile,*rf,*pf;
RGB palette[256], new_palette[256];
LONG file_length;

OFFSET *offsets;
LONG output_shape_number = 0;
LONG color_first_shape = 0;

ULONG colors[256];
CRGB  rgbcolors[256];
ULONG rgb_color_count=0;

LONG entry_count=0, shape_count=0, offset_fptr;

/************************************************************/
void fail(int errcode)
{
   static BYTE errmsgs[][128] =
     {{"Error: Input file must be in .LBM, .PCX, .GIF, or .SHP format"      },
      {"Error: Insufficient memory available"                               },  
      {"Error: Could not open input file"                                   },
      {"Error: Could not open output file"                                  },
      {"Error: Could not write to output file"                              },
      {"Error: Shape number does not exist in shape file"                   },
      {"Error: Could not read response file"                                },
      {"Error: Could not open palette file"                                 },
      {"Error: Coordinate must lie within source image"                     },
      {"Error: Invalid directive in response file"                          },
      {"Error: Transparent color must be given for PCX|FLI|FLC or SHP files"},
      {"Error: Bad frame in .FLI or .FLC"                                   },
      {"Error: Frame number out of range or not specified in .FLI or .FLC"  }


   };

   printf("%s\n",errmsgs[errcode]);

   fcloseall();
   exit(errcode+1);
}

/******************************************/
void palette_copy(RGB *source, RGB *dest)
{
   ULONG i;

   for (i=0; i<256; i++)
      *(dest++) = *(source++);
}
/******************************************/
LONG palette_compare(RGB *source, RGB *dest)
{
   ULONG i;

   for (i=0; i<256; i++)
      {
      if ( source[i].r != dest[i].r )
         return 1;

      if ( source[i].g != dest[i].g )
         return 1;

      if ( source[i].b != dest[i].b )
         return 1;
      }

   return 0;
}

/******************************************/
LONG store_colors(ULONG shape_number)
{
   if (rgb_color_count > 0)
      {
      offsets[shape_number].colors = ftell(outfile);
      if (fwrite(&rgb_color_count,sizeof(rgb_color_count),1,outfile) < 1)
         fail(4);

      if (fwrite(rgbcolors,sizeof(CRGB),rgb_color_count,outfile) < rgb_color_count)
         fail(4);
      }
   else
      offsets[shape_number].colors = 0;

   return ( (LONG) (offsets[shape_number].colors) );
}

/******************************************/
void flush_colors()
{
   LONG i;
   LONG colors_offset;

   if (output_shape_number > color_first_shape)
      {
      colors_offset = store_colors(color_first_shape);

      for(i=color_first_shape+1; i<output_shape_number; i++)
         offsets[i].colors = colors_offset;

      color_first_shape = output_shape_number;
      rgb_color_count   = 0;
      }
}

/******************************************/
void check_palette_and_store_colors(RGB *palette, RGB *new_palette)
{
   if ( palette_compare(palette, new_palette) )
      {
      flush_colors();

      palette_copy(new_palette, palette);
      }
}

/******************************************/
ULONG rgb_color_add(ULONG color)
{
   ULONG i;   

   for (i=0; i<rgb_color_count; i++)
      if ( rgbcolors[i].color == color )
         return rgb_color_count;

   rgbcolors[rgb_color_count].color = color;
   rgbcolors[rgb_color_count].rgb.r = palette[color].r;
   rgbcolors[rgb_color_count].rgb.g = palette[color].g;
   rgbcolors[rgb_color_count].rgb.b = palette[color].b;

   return ++rgb_color_count;
}


/******************************************/
void get_colors(GETSHAPE *shape, WINDOW *window, LONG max_x, LONG max_y)
{
   LONG i;
   PANE pane;
   ULONG color_count=0;

   if (shape->x0<0 || shape->y0<0 || shape->x1>max_x || shape->y1>max_y)
      fail(8);

   if (shape->x0==0 && shape->y0==0 && shape->x1==0 && shape->y1==0)
      {
      shape->x1=max_x;
      shape->y1=max_y;
      }

   pane.window = window;
   pane.x0 = shape->x0;
   pane.y0 = shape->y0;
   pane.x1 = shape->x1;
   pane.y1 = shape->y1;

   color_count = VFX_color_scan(&pane,colors);

   if (shape->transparent != -1)
      bkgnd = shape->transparent;

   for (i=0; i<color_count; i++)
      {
      if (colors[i] != bkgnd)
         {
         rgb_color_count = rgb_color_add( colors[i] );
         }
      }
}

/************************************************************/
void get_shape(GETSHAPE *shape, ULONG shape_number, WINDOW *window,     //)
               LONG max_x, LONG max_y)
{
   PANE pane;
   void *shape_buffer;
   LONG shape_size;
   LONG *size_ptr;

   if (shape->transparent != -1)
      bkgnd = shape->transparent;

   //
   // Scan shape from bitmap pane
   //

   if (shape->x0<0 || shape->y0<0 || shape->x1>max_x || shape->y1>max_y)
      fail(8);

   if (shape->x0==0 && shape->y0==0 && shape->x1==0 && shape->y1==0)
      {
      shape->x1=max_x;
      shape->y1=max_y;
      }

   pane.window = window;
   pane.x0 = shape->x0;
   pane.y0 = shape->y0;
   pane.x1 = shape->x1;
   pane.y1 = shape->y1;

   shape_size=VFX_shape_scan(&pane, bkgnd,
      shape->origin_x, shape->origin_y, NULL);

   if ((shape_buffer=malloc(shape_size))==NULL)
      fail(1);

   shape_size=VFX_shape_scan(&pane, bkgnd,
      shape->origin_x, shape->origin_y, shape_buffer);

   size_ptr=(LONG *)shape_buffer;

   //
   // Copy shape buffer to shape file
   //

   offsets[shape_number].shape=ftell(outfile);

   if (fwrite(shape_buffer, sizeof(UBYTE), shape_size, outfile)
         < shape_size)
      fail(4);

   fflush(outfile);

   free(shape_buffer);

   shape_count++;
}

/************************************************************/
long shape_compare(GETSHAPE *A, GETSHAPE *B)
{
   if (A->first_frame != B->first_frame)
      return 0;
   if (A->last_frame != B->last_frame)
      return 0;

   if ( strcmpi(A->source, B->source) )
      return 0;

   if (A->x0 != B->x0)
      return 0;
   if (A->y0 != B->y0)
      return 0;

   if (A->x1 != B->x1)
      return 0;
   if (A->y1 != B->y1)
      return 0;

   if (A->origin_x != B->origin_x)
      return 0;
   if (A->origin_y != B->origin_y)
      return 0;

   if (A->save_colors != B->save_colors)
      return 0;

   if (A->shape != B->shape)
      return 0;

   if (A->transparent != B->transparent)
      return 0;

   return 1;
}  

/******************************************/
void *load_file(BYTE *filename)
{
   LONG file_handle;
   void *buffer;

   if ( (file_handle=open(filename,O_RDONLY|O_BINARY))==-1L )
      return NULL;
   if ( (file_length=filelength(file_handle))==-1L )
      return NULL;
   if ( (buffer = malloc(file_length))==NULL )
      return NULL;
   if ( read(file_handle,buffer,file_length)==-1L )
      return NULL;
   close(file_handle);

   return buffer;
}

/************************************************************/
LONG parse_rsp_entry(char *lbuffer, GETSHAPE *shape)
{
   BYTE *token;
   BYTE *ptr;
   LONG i;

   if ((ptr = strstr(lbuffer,"\n")) != NULL)
      *ptr='\0';

   if ((ptr = strstr(lbuffer,"//")) != NULL)
      *ptr='\0';

   strlwr(lbuffer);
   if ((strstr(lbuffer,keywords[0].keystr)!=NULL) ||
         (strstr(lbuffer,keywords[1].keystr)!=NULL))
      {
      shape->x0 = shape->y0 = shape->x1 = shape->y1=0;
      shape->origin_x = shape->origin_y = 0;
      shape->transparent = -1;
      shape->save_colors = 0;
      shape->shape = 0;
      shape->first_frame = shape->last_frame = 0;

      token=strtok(lbuffer,";");
      while (token != NULL)
         {
         while (isspace(*token))
            token++;
         if (*token == '\0')
            break;

         for (i=0;keywords[i].keyword;i++)
            if (strstr(token,keywords[i].keystr) != NULL)
               break;

         if (keywords[i].keyword)
            {
            token=strstr(token,"=")+1;
            switch (keywords[i].keyword)
               {
               case SOURCE:
                  strcpy(shape->source, token);
                  break;

               case SHAPE:
                  if ( sscanf(token,"%d",&shape->shape) != 1 )
                     fail(9);
                  break;

               case FRAME:
                  if ( sscanf(token,"%d,%d",&shape->first_frame,
                              &shape->last_frame) != 2 )
                     fail(9);
                  break;

               case TOP_LEFT:
                  if ( sscanf(token,"%d,%d",&shape->x0,&shape->y0) != 2 )
                     fail(9);
                  break;

               case BOTTOM_RIGHT:
                  if ( sscanf(token,"%d,%d",&shape->x1,&shape->y1) != 2 )
                     fail(9);
                  break;

               case HOT_SPOT:
                  if ( sscanf(token,"%d,%d",&shape->origin_x,
                                          &shape->origin_y) != 2 )
                     fail(9);
                  break;

               case TRANSPARENT_COLOR:
                  shape->transparent=strtol(token,NULL,10);
                  break;

               case SAVE_COLORS:
                  shape->save_colors=TRUE;
                  break;

               default:
                  fail(9);
               }
            }
         else
            fail(9);
      
         token=strtok(NULL,";");
         } // while token != NULL
      return (shape->last_frame - shape->first_frame + 1);
      }
   else
      return 0;
}

/************************************************************/
void main(int argc, BYTE *argv[])
{
   LONG resolution,max_x,max_y,minxy,counter,dup_shape,duplicate;
	UBYTE *window_buffer;
   void *GIF_scratch, *rf;
   BYTE lbuffer[255];
   BYTE last_filename[256];
   LONG flic_status;
   ULONG frame_count=0;
   FLIC flic;
   GETSHAPE *shape_refs, *shape, *shape_ptr;
   WINDOW window;
   PANE pane;


   printf("GETSHAPE V1.20                    Copyright (C) 1992-1994 Non-Linear Arts, Inc.\n\n");

   if (argc < 2)
      {
      printf("Usage: GETSHAPE rspfile outfile\n\n");

      printf("where: rspfile = response file\n");
      printf("       outfile = 386FX standard binary shape table file\n\n");

      printf("Response file directives (* = optional):\n");
      printf("   source_filename=xxx .... .PCX|LBM|GIF|FLI|FLC or .SHP file ('sf')\n");
      printf(" * shape_number=n ......... Shape # in .SHP source image      ('sn')\n");
      printf(" * frame_number=f,l ........Frame # range in .FLI or .FLC     ('fn')\n");
      printf("   top_left=x,y ........... Upper-left corner of image area   ('tl')\n");
      printf("   bottom_right=x,y ....... Bottom-right corner of image area ('br')\n");
      printf(" * hot_spot=x,y ........... Logical 'handle' for shape        ('hs')\n");
      printf(" * transparent_color=n .... Transparent color for shape       ('tc')\n");
      printf(" * save_colors ............ If present, record shape's colors ('sc')\n");
      printf(" * // ..................... Begins comment\n\n");

      printf("Sample response file:\n");
      printf("       sf=frotz.pcx;  tl=0,0; br=20,20; tc=255;   hs=10,10\n");
      printf("       sf=ozmoo.gif;  tl=5,5; br=80,80; tc=128;\n");
      printf("       sf=rezrov.shp; sn=69;  tl=15,35; br=80,80; tc=128;\n");

      exit(1);
      }

   //
   // Open response file, count number of shapes and malloc mem for offsets
   //

   if ((rf = fopen(argv[1],"rt")) == NULL)
      fail(6);

   if ((shape=malloc(sizeof(GETSHAPE))) == NULL)
      fail(1);
   entry_count=0;
   while ( fgets(lbuffer, 255, rf) != NULL )
      entry_count += parse_rsp_entry(lbuffer, shape);
   free(shape);

   //
   // Allocate memory for GETSHAPE structures and shape & palette offsets
   //

   if ((shape_refs=malloc(entry_count*sizeof(GETSHAPE))) == NULL)
      fail(1);
   shape = shape_refs;

   if ((offsets=malloc(entry_count*sizeof(OFFSET))) == NULL)
      fail(1);

   fseek(rf, 0L, SEEK_SET);

   //
   // Open output file and initialize header information
   //

   if ((outfile = fopen(argv[2],"w+b")) == NULL) fail(3);

   if ( fwrite(&shape_version, sizeof(long), 1, outfile) < 1)
      fail(4);

   if ( fwrite(&entry_count, sizeof(long), 1, outfile) < 1)
      fail(4);

   offset_fptr=ftell(outfile);

   if (fwrite(offsets, sizeof(OFFSET), entry_count, outfile) < entry_count)
      fail(4);

   //
   // Parse response File
   //

   window_buffer=NULL;
   fpic=NULL;

   max_x = max_y = 0;

   while (fgets(lbuffer, 255, rf) != NULL )
      {
      printf("Compiling shape %u of %u shape(s) referenced in '%s'       \r",
              output_shape_number+1, entry_count, argv[1]);

      if ( parse_rsp_entry(lbuffer, shape) )
         {
         //
         // Search list of shape references for a duplicate
         //

         for (shape_ptr=shape_refs, counter=0, dup_shape=0, duplicate=0;
              shape_ptr < shape;  shape_ptr++, counter++)
            {
            if ( shape_compare(shape, shape_ptr) )
               {
               duplicate = 1;
               dup_shape = counter;
               break;
               }
            }

         if ( duplicate )
            {
            //
            // Store a duplicate pointer
            //

            offsets[output_shape_number  ].colors = offsets[dup_shape].colors;
            offsets[output_shape_number++].shape  = offsets[dup_shape].shape;
            }
         else
            {
            // Check if this shape refers to same file as last entry

            if (stricmp(last_filename,shape->source) != 0)
               {
               //
               // Not same file as last entry
               //

               strcpy(last_filename,shape->source);

               if (window_buffer != NULL)
                  {
                  free(window_buffer);
                  window_buffer=NULL;
                  }

               if (fpic != NULL)
                  {
                  free(fpic);
                  fpic=NULL;
                  }

               //
               // Check for .LBM or .PCX extension
               //

               if ( stricmp(".LBM",&shape->source[strlen(shape->source)-4]) == 0 )
                  fpic_type=LBM;
               else if ( stricmp(".PCX",&shape->source[strlen(shape->source)-4]) == 0 )
                  fpic_type=PCX;
               else if ( stricmp(".GIF",&shape->source[strlen(shape->source)-4]) == 0 )
                  fpic_type=GIF;
               else if ( stricmp(".SHP",&shape->source[strlen(shape->source)-4]) == 0 )
                  fpic_type=SHP;
               else if ( stricmp(".FLI",&shape->source[strlen(shape->source)-4]) == 0 )
                  fpic_type=FLI;
               else if ( stricmp(".FLC",&shape->source[strlen(shape->source)-4]) == 0 )
                  fpic_type=FLC;
               else
                  fail(0);
            
               //
               // Load file
               //

               if ((fpic=load_file(shape->source)) == NULL) fail(2);
            
               //
               // Get resolution of image
               //

               switch (fpic_type)
                  {
                  case LBM:
                     resolution = VFX_ILBM_resolution(fpic);
                     VFX_ILBM_palette(fpic, new_palette);
                     check_palette_and_store_colors(palette, new_palette);
                     break;

                  case PCX:
                     resolution = VFX_PCX_resolution(fpic);
                     VFX_PCX_palette(fpic, file_length, new_palette);
                     check_palette_and_store_colors(palette, new_palette);
                     break;

                  case GIF:
                     resolution = VFX_GIF_resolution(fpic);
                     VFX_GIF_palette(fpic, new_palette);
                     check_palette_and_store_colors(palette, new_palette);
                     break;

                  case SHP:
                     if ( (ULONG) (*(fpic+4)) <= shape->shape )
                        fail(5);

                     resolution = VFX_shape_resolution(fpic, shape->shape);
                     if (VFX_shape_colors(fpic, shape->shape ,NULL) > 0)
                        {
                        VFX_shape_palette(fpic, shape->shape, new_palette);
                        check_palette_and_store_colors(palette, new_palette);
                        }
                     break;

                  case FLI:
                  case FLC:
                     flic.header = (FLIC_HEADER *)fpic;
                     flic.frame  = NULL;
                     flic.chunk  = NULL;

                     if ((shape->first_frame > flic.header->frames) ||
                         (shape->last_frame  > flic.header->frames) ||
                         (shape->first_frame==0 || shape->last_frame==0))
                        fail(12);

                     resolution = (flic.header->width<<16) | flic.header->height;
                     break;

                  default:
                     resolution = 0;
                     fail(0);
                  }

               max_x=(resolution>>16)-1;
               max_y=(resolution&0x0ffff)-1;

               //
               // Set up pane and window
               //

			      if ((window_buffer=
                  calloc((resolution>>16)*(resolution&0x0ffff),1)) == NULL)
                     fail(1);

			      window.buffer = window_buffer;
               window.stencil = window.shadow = NULL;
			      pane.x0= 0;
			      pane.y0= 0;
			      pane.x1=window.x_max = max_x;
			      pane.y1=window.y_max = max_y;
			      pane.window = &window;

               if (fpic_type != FLI && fpic_type != FLC)
                  {
                  //
                  // Draw image
                  //

                  switch (fpic_type)
                     {
                     case LBM:
                        bkgnd = VFX_ILBM_draw(&pane,fpic);
                        break;

                     case PCX:
                        if (shape->transparent == -1)
                           fail(10);

                        VFX_PCX_draw(&pane,fpic);
                        break;

                     case GIF:
                        if ( (GIF_scratch=malloc(GIF_SCRATCH_SIZE))==NULL )
                           fail(3);
                        bkgnd = VFX_GIF_draw(&pane,fpic,GIF_scratch);
                        free(GIF_scratch);
                        break;

                     case SHP:
                        if (shape->transparent == -1)
                           fail(10);

                        minxy=VFX_shape_minxy(fpic, shape->shape);
                        VFX_pane_wipe(&pane,shape->transparent);
                        VFX_shape_draw(&pane,fpic,shape->shape,-(minxy>>16),-(minxy<<16>>16));
                        break;

                     default:
                        fail(0);
                     }
                  } // if not an animation file

               } // if !same file


            //
            // Get shape from pane
            //

            if (fpic_type == FLI || fpic_type == FLC)
               {
               if (shape->transparent == -1)
                  fail(10);

               // Reset animation to first frame

               flic.frame = NULL;
               flic.chunk = NULL;
               frame_count = 0;

               while ( frame_count < shape->last_frame )
                  {
                  if ( (flic_status=FLIC_frame_draw(&pane,&flic,&new_palette[0]))==-1 )
                     fail(11);

                  ++frame_count;

                  if ( flic_status == FLIC_NEW_COLORS )
                     check_palette_and_store_colors(palette, new_palette);

                  if ( frame_count >= shape->first_frame &&
                       frame_count <= shape->last_frame     )
                     {
                     if (shape->save_colors)
                        get_colors(shape, &window, max_x, max_y);

                     get_shape(shape, output_shape_number++, &window,
                               max_x, max_y);
                     }
                  }
               }
            else
               {
               if (shape->save_colors)
                  get_colors(shape, &window, max_x, max_y);

               get_shape(shape, output_shape_number++, &window, max_x, max_y);
               }

            } // else not duplicate shape

         shape++;

         } // if response file line contains a shape description

      } // while not end of response file

   flush_colors();

   //
   // Write shape file header to output file
   //

   if (fseek(outfile, offset_fptr, SEEK_SET) != 0)
      fail(4);

   if (fwrite(offsets, sizeof(OFFSET), entry_count, outfile) < entry_count)
      fail(4);

   fflush(outfile);

   free(shape_refs);
   free(offsets);
   free(fpic);
   free(window_buffer);

   printf("Finished: %u shape(s) written to %u entry(s) in '%s'          \n",
      shape_count, entry_count, argv[2]);

   exit(0);
}








