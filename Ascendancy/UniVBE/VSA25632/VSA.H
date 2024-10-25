/*.................................. VSA.H ................. 8-3-95 ........*/
/* This file declares the VSA256 Graphics Library functions and global      */
/* parameters used throughout the graphics routines.                        */
/*                                                                          */
/*                               VERSION 3.2                                */
/*                                                                          */
/*         Copyright Spyro Gumas, 1992 - 1995.  All Rights Reserved.        */
/*..........................................................................*/

/*..........................................................................*/
/*                    External Function Prototypes                          */
/*..........................................................................*/

extern unsigned  far cdecl vsa_set_svga_mode( unsigned );
extern unsigned  far cdecl vsa_get_svga_mode( unsigned far * );
extern unsigned  far cdecl vsa_set_display_start( unsigned, unsigned );
extern unsigned  far cdecl vsa_get_display_start( unsigned far *,
														unsigned far * );
extern unsigned  far cdecl vsa_init( unsigned );
extern void far cdecl vsa_set_color( unsigned );
extern void far cdecl vsa_set_text_color( unsigned );
extern void far cdecl vsa_set_text_cursor_mode( unsigned );
extern void far cdecl vsa_set_text_cursor( int, int);
extern void far cdecl vsa_get_text_cursor( int far *, int far *);
extern void far cdecl vsa_set_text_scale(float,float);
extern void far cdecl vsa_set_viewport( int, int, int, int);
extern void far cdecl vsa_set_clip_mode(  unsigned );
extern void far cdecl vsa_write_string( int, int, int, char far * );
extern void far cdecl vsa_write_string_alt( char far * );
extern void far cdecl vsa_read_color_register( unsigned, unsigned char far *,
								 unsigned char far *, unsigned char far *);
extern void far cdecl vsa_write_color_register( unsigned, unsigned char,
								 unsigned char, unsigned char );
extern void far cdecl vsa_read_color_block( unsigned, unsigned,
								 unsigned char far * );
extern void far cdecl vsa_write_color_block( unsigned, unsigned,
								 unsigned char far * );
extern void far cdecl vsa_move_to( int, int);
extern void far cdecl vsa_set_pixel( int, int);
extern unsigned far cdecl vsa_get_pixel( int, int);
extern void far cdecl vsa_line_to( int, int);
extern void far cdecl vsa_triangle_fill( int, int, int, int, int, int);
extern void far cdecl vsa_rect_fill( int, int);
extern void far cdecl vsa_rect( int, int);
extern unsigned long far cdecl vsa_image_size( int, int, int, int);
extern void far cdecl vsa_get_image( int, int, int, int,unsigned char huge * );
extern void far cdecl vsa_put_image( int, int,unsigned char huge *, unsigned);
extern void far cdecl vsa_h_line( int, int, int);
extern void far cdecl vsa_v_line( int, int, int);
extern void far cdecl vsa_raster_line( int, int, int, unsigned char far *);
extern void far cdecl vsa_get_raster_line( int, int, int,unsigned char far *);
extern void far cdecl vsa_gouraud_line( int, int, int, int, int);
extern void far cdecl vsa_shaded_triangle( int, int, int, int, int, int,
																					 int, int, int);
extern void far cdecl vsa_wait_hsync( void );
extern void far cdecl vsa_wait_vsync( void );
extern void far cdecl vsa_about( void );

/*..........................................................................*/
/*                    External Parameter Declarations                       */
/*..........................................................................*/
extern unsigned far XResolution, far YResolution;
extern unsigned far XCharResolution, far YCharResolution;
extern unsigned char far XCharSize, far YCharSize;
extern unsigned char far BitsPerPixel;
extern int far XLeft, far XRight, far YTop, far YBottom;
extern float far Text_X_Scale, far Text_Y_Scale;
extern int VSA_ATI_COLOR;

