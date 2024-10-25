/*..........................................................................*/
/*                               VSA_DEMO.C              8-3-95             */
/*                                                                          */
/*  This is the "C" source code for the VSA_DEMO.EXE program.  This program */
/*  demonstrates the usage of the VSA256 Graphics Library, Version 3.2      */
/*  functions.                                                              */
/*                                                                          */
/*            Note: Set STACK SIZE to approx 10000 bytes.                   */
/*            Note: For BORLAND compilers, use -Fs flag (SS = DS)!          */
/*                                                                          */
/*         Copyright Spyro Gumas, 1992 - 1995.  All Rights Reserved.        */
/*..........................................................................*/

#include<dos.h>
#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include<limits.h>
#include<bios.h>
#include<conio.h>
#include<time.h>

#include <vsa.h>            /* Required to support VSA256 Graphics Library  */
#include <vsa_font.h>       /* Required to support VSA256 Graphics Library  */
#include <tiff.h>           /* Required to support TIFF256 Graphics Library */

#ifndef _MSC_VER
/*.....                  This is for Borland C Only !                  .....*/
extern unsigned _stklen = 10000;
#endif

void cube(int,int,int);
void cubes(int,int,int);
void rainbow_lut(void);
void color_bar(int,int);
void banner(int,int);
void image(int,int);
void obj_3d(int,int);
void cube_3d(int,int);
int  any_key(void);
void delay(unsigned);
void color_effect(void);
void vsa_get_input(char *);
void vsa_setup(void);

float SIN_LUT[1024];

void main()
{
	int i,k,l,ty,tx;
	unsigned xx,yy,a,b,c,d,m,n,oldm,oldn,image_size;
	char your_name[80];
	unsigned char *pict1;
	float x_scale,y_scale;
	srand(1);
/*..........................................................................*/
/* If demo locks up during color cycling, or color mods crash for whatever  */
/* reason, set the global parameter VSA_ATI_COLOR = 1.                      */
/*..........................................................................*/
//	VSA_ATI_COLOR = 1;
/*..........................................................................*/
/*                      Initialize sin look up table.                       */
/*  Index 'i' goes from 0 to 1023 and is equivalent to 0 to 360 degrees.    */
/*..........................................................................*/
	for(i=0;i<1024;i++)
		SIN_LUT[i] = sin(i*6.28/1024.0);

	vsa_setup();
	xx = XResolution;
	yy = YResolution;
	x_scale = XResolution/640.0;
	y_scale = YResolution/480.0;
	vsa_set_text_scale(x_scale,y_scale);
	vsa_set_color(1);
	vsa_move_to(0,0);
	vsa_rect(xx-1,yy-1);
/*..........................................................................*/
/*             Draw color look up table at bottom of screen.                */
/*..........................................................................*/
	rainbow_lut();
	a = .125*xx;
	b = .83*yy;
	color_bar(a,b);
/*..........................................................................*/
/*            Draw "random" cubes enclosed by rectangle                     */
/*..........................................................................*/
	a = .6*xx;
	b = .4*yy;
	c = .88*xx;
	d = .72*yy;
	tx = (a+(c-a)/2) - 12*XCharSize;
	ty = d + 0.01*yy;
	vsa_write_string(tx,ty,250,"Lines using `vsa_line_to'");
	vsa_write_string(tx,ty+YCharSize,64,"Clipping with `vsa_set_viewport'");
	vsa_move_to(a,b);
	vsa_set_color(180);
	vsa_rect(c,d);
	vsa_move_to(a+1,b+1);
	vsa_set_color(20);
	vsa_rect_fill(c-1,d-1);
	vsa_set_viewport(a+1,b+1,c-1,d-1);
	cubes(a,b,1);
/*..........................................................................*/
/*                          Draw a banner                                   */
/*..........................................................................*/
	vsa_set_viewport(0,0,xx,yy);
	a = .55*xx;
	b = .06*yy;
	banner(a,b);
/*..........................................................................*/
/*                    Draw 2D sine-cosine image                             */
/*..........................................................................*/
	a = .08*xx;
	b = .15*yy;
	image(a,b);
/*..........................................................................*/
/*                    Draw a 3-D shaded object                              */
/*..........................................................................*/
	a = .08*xx;
	b = .5*yy;
	obj_3d(a,b);
/*..........................................................................*/
/*                    Draw a 3-D shaded Cube                                */
/*..........................................................................*/
	a = .5*xx;
	b = .35*yy;
	cube_3d(a,b);
/*..........................................................................*/
/*                        Using Text Cursor Mode 1.                         */
/*..........................................................................*/
	ty = .05*yy;
	tx = .05*xx;
	vsa_set_text_cursor_mode(1);
	vsa_write_string(tx,ty,250,"Please Enter Your Name: ");
	vsa_get_input(your_name);

	vsa_set_text_cursor(tx,ty+YCharSize);
	vsa_set_text_color(200);
	vsa_write_string_alt("Hello ");
	vsa_write_string_alt(your_name);
	vsa_write_string_alt(", Hit any key to bail.");

/*..........................................................................*/
/* NOTE: TIFF256 requires Large MEM Model if you uncomment following lines! */
/*..........................................................................*/
/*.....
	printf("Input Full file name for TIFF file to be saved: ");
	scanf("%s",filename);
	tf_save_file(0,YResolution-1,XResolution-1,0,filename);
.....*/
/*..........................................................................*/
/*    Now do moving clipped cubes effect until someone presses a key.       */
/*..........................................................................*/
	k = 0;
	l = 256;
	a = .6*xx;
	b = .4*yy;
	c = .88*xx;
	d = .72*yy;
	oldm = a;
	oldn = b;
	vsa_set_viewport(a+1,b+1,c-1,d-1);
	while(!any_key())
		{
			m = a + xx*0.1*SIN_LUT[k];
			n = b + yy*0.1*SIN_LUT[l];
			vsa_wait_vsync();
			vsa_wait_vsync();
			cubes(oldm,oldn,0);     /* Clear last cube draw */
			cubes(m,n,1);           /* Draw New cubes       */
			k+=4;
			l+=4;
			k=k & 0x3ff;
			l=l & 0x3ff;
			oldm = m;
			oldn = n;
		}
	ty = YResolution/2;
	tx = XResolution/2;
/*..........................................................................*/
/*    Now do sliding blue color effect until someone presses a key.         */
/*..........................................................................*/
	color_effect();
/*..........................................................................*/
/*    Now BitBLT in SPRITE mode with vsa_get_image and vsa_put_image        */
/*..........................................................................*/
	vsa_set_viewport(0,0,xx-1,yy-1);
	i = 0;
	k = 0;
	l = 256;
	a = .495*xx;
	b = .295*yy;
	c = .09*xx;
	d = .12*yy;
	image_size = vsa_image_size(a,b,a+c,b+d);
	if((pict1 = malloc(image_size)) == NULL)
		{
			vsa_write_string(0,0,31,"Error allocating memory for IMAGE");
			getch();
			goto BAIL;
		}
	vsa_get_image(a,b,a+c,b+d,pict1);
	vsa_set_color(255);
	vsa_move_to(a,b);
	vsa_rect(a+c,b+d);
	while(!any_key())
		{
			m = xx/2 - c/2 + (i)*0.3*SIN_LUT[k];
			n = yy/2 - d/2 + (i)*0.3*SIN_LUT[l];
			vsa_put_image(m,n,pict1,6);
			k-=4;
			l-=4;
			k=k & 0x3ff;
			l=l & 0x3ff;
			i++;
		}
	free(pict1);
	vsa_set_color(20);
	vsa_move_to(tx-15*XCharSize,ty-2*YCharSize);
	vsa_rect_fill(tx+15*XCharSize,ty+3*YCharSize);
	vsa_set_color(31);
	vsa_move_to(tx-15*XCharSize,ty-2*YCharSize);
	vsa_rect(tx+15*XCharSize,ty+3*YCharSize);
	vsa_write_string(tx-14*XCharSize,ty-YCharSize,200,"BitBlt Using: vsa_image_size");
	vsa_write_string(tx-14*XCharSize,ty          ,200," (Sprites!)   vsa_get_image ");
	vsa_write_string(tx-14*XCharSize,ty+YCharSize,200,"              vsa_put_image ");
/*..........................................................................*/
/*  Now do sliding blue color effect (again) until someone presses a key.   */
/*..........................................................................*/
	color_effect();
/*..........................................................................*/
/*           Restore text video mode and print information.                 */
/*..........................................................................*/
BAIL:
	vsa_set_viewport(0,0,xx-1,yy-1);
	vsa_about();
	getch();
	vsa_init(0x3);
	return;
}

void cube(int x,int y,int size)
{
	int sizeb;
	sizeb = size/2;
	vsa_move_to(x,y);
	vsa_rect(x+size,y+size);
	vsa_move_to(x+sizeb,y+sizeb);
	vsa_rect(x+sizeb+size,y+sizeb+size);
	vsa_move_to(x,y);
	vsa_line_to(x+sizeb,y+sizeb);
	vsa_move_to(x+size,y);
	vsa_line_to(x+sizeb+size,y+sizeb);
	vsa_move_to(x+size,y+size);
	vsa_line_to(x+sizeb+size,y+sizeb+size);
	vsa_move_to(x,y+size);
	vsa_line_to(x+sizeb,y+sizeb+size);
	return;
}

void cubes(int m,int n,int draw)
{
	int i,x,y,size;
	float xfact,yfact,sfact;
	srand(1);
	vsa_set_color(20);
	xfact = .23*XResolution/(float)RAND_MAX;
	yfact = .23*YResolution/(float)RAND_MAX;
	sfact = .05*xfact/.23;
	for(i=0;i<16;i++)
		{
			x = m+5+xfact*rand();
			y = n+5+yfact*rand();
			size = sfact*rand();
			if(draw)
				vsa_set_color(i);
			cube(x,y,size);
		}
	return;
}

void rainbow_lut()
{
	int i,start,count;
	unsigned char color_array[768];
	for(i=0;i<224;i++)
		{
			color_array[3*i+2]=0;
			color_array[3*i+1]=0;
			color_array[3*i]=0;
		}
/*................................ RED .....................................*/
	for(i=0;i<56;i++)
		{
				color_array[3*i] = 63*sin((i*6.28)/112.0);
		}
/*............................... BLUE .....................................*/
	for(i=20;i<146;i++)
		{
				color_array[3*i+2] = 63*sin(((i-20)*6.28)/252.0);
		}
/*............................... GREEN ....................................*/
	for(i=90;i<216;i++)
		{
				color_array[3*i+1] = 63*sin(((i-90)*6.28)/252.0);
		}
/*................................ RED .....................................*/
	for(i=140;i<224;i++)
		{
				color_array[3*i]   = 63*sin(((i-140)*6.28)/280.0);
		}
	start = 32;
	count = 224;
	vsa_write_color_block(start,count,color_array);
	return;
}

void color_bar(x0,y0)
int x0,y0;
{
	int i,ty,tx;
	unsigned xx,yy,a,b;
	float c;
	xx = XResolution;
	yy = YResolution;
/*..........................................................................*/
/*     Draw outline for color bar.                                          */
/*..........................................................................*/
	vsa_set_color(15);
	vsa_move_to(x0-1,y0-1);
	a = .75*xx;
	b = .065*yy;
	vsa_rect(x0+a+1,y0+b+1);
	c = (float)a/256;
	for(i=0;i<256;i++)
		{
			vsa_set_color((unsigned char)i);
			vsa_move_to(x0+(unsigned)(i*c),y0);
			vsa_rect_fill(x0+(unsigned)(c+i*c),y0+b);
		}
	ty = (y0+b+1) + 0.01*YResolution;
	tx = (x0+a/2) - 31*XCharSize;
	vsa_write_string(tx,ty,63,"Color Look Up Table Manipulation using");
	vsa_write_string(tx+38*XCharSize,ty,63," `vsa_write_color_block'");
	vsa_write_string(tx,ty+YCharSize,63,"'vsa_read_color_register' and");
	vsa_write_string(tx+31*XCharSize,ty+YCharSize,63,"`vsa_write_color_register'.");
	return;
}

void banner(int x,int y)
{
	int ty,tx;
	unsigned xx,yy,a,b;
	xx = XResolution;
	yy = YResolution;
	a = .40*xx;
	b = .17*yy;
	vsa_move_to(x,y);
	vsa_set_color(1);
	vsa_rect_fill(x+a,y+b);
	vsa_move_to(x+5,y+5);
	vsa_set_color(22);
	vsa_rect_fill(x+a-5,y+b-5);
	tx = (x+5) + 0.08*a;
	ty = (y+6) + 0.15*b;
	vsa_write_string(tx,ty,200,"VSA256 GRAPHICS LIBRARY");
	vsa_write_string(tx,ty+YCharSize,200,"for C Programmers");
	vsa_write_string(tx+18*XCharSize,ty+YCharSize,255,"V3.2 ");
	vsa_write_string(tx,ty+2*YCharSize,200,"Copyright Spyro Gumas 92-95");
	ty = (y+b) + 0.01*YResolution;
	tx = (x+(a+5)/2) - 16*XCharSize;
	vsa_write_string(tx,ty,2            ,"Text using 'vsa_set_text_scale'  ");
	vsa_write_string(tx,ty+YCharSize,2  ,"           'vsa_write_string'    ");
	vsa_write_string(tx,ty+2*YCharSize,2,"           'vsa_write_string_alt'");
	return;
}

void image(int x,int y)
{
	int i,j,ty,tx;
	long ii,jj,z1,z2;
	unsigned char array[1024];
	unsigned xx,yy,a,b;
	xx = XResolution;
	yy = YResolution;
	a = .4*xx;
	b = .26*yy;
	z1 = 2*1024L/a;
	z2 = 1024L/b;
	vsa_move_to(x-2,y-2);
	vsa_set_color(250);
	vsa_rect(x+a+1,y+b+1);
	for(j=0;j<b;j++)
		{
			for(i=0;i<a;i++)
				{
					ii = (i*z1) & 0x000003ff;
					jj = (j*z2+256) & 0x000003ff;
/*.....
					array[i] = 144+112*sin(i*6.28/c)*cos(j*6.28/c);
.....*/
					array[i] = 144+112.0*(SIN_LUT[ii]*SIN_LUT[jj]);
				}
			vsa_raster_line(x,x+a-1,y+j,array);
		}
	ty = (y+b+1) + 0.01*YResolution;
	tx = (x+a/2) - 17*XCharSize;
	vsa_write_string(tx,ty,100,"2D Images Using `vsa_raster_line'");
	return;
}

void obj_3d(int x,int y)
{
	int rim1,rim2,tip1,tip2,ty,tx;
	unsigned xx,yy,a,b;
	xx = XResolution;
	yy = YResolution;
	a = .4*xx;
	b = .2*yy;
	vsa_move_to(x-2,y-2);
	vsa_set_color(255);
	vsa_rect(x+a+1,y+b+1);
	vsa_move_to(x,y);
	vsa_set_color(38);
	vsa_rect_fill(x+a,y+b);
	rim1 = 145;
	tip1 = 255;
	tip2 = 32;
	rim2 = 155;
vsa_shaded_triangle((int)(.35*a+x),(int)(.8*b+y),rim1,(int)(.25*a+x),(int)(.8*b+y),rim1,(int)(.9*a+x),(int)(.1*b+y),tip1);
vsa_shaded_triangle((int)(.25*a+x),(int)(.8*b+y),rim1,(int)(.15*a+x),(int)(.6*b+y),rim1,(int)(.9*a+x),(int)(.1*b+y),tip1);
vsa_shaded_triangle((int)(.15*a+x),(int)(.6*b+y),rim1,(int)(.15*a+x),(int)(.4*b+y),rim1,(int)(.9*a+x),(int)(.1*b+y),tip1);
vsa_shaded_triangle((int)(.15*a+x),(int)(.4*b+y),rim1,(int)(.25*a+x),(int)(.2*b+y),rim1,(int)(.9*a+x),(int)(.1*b+y),tip1);
vsa_shaded_triangle((int)(.25*a+x),(int)(.2*b+y),rim1,(int)(.35*a+x),(int)(.2*b+y),rim1,(int)(.9*a+x),(int)(.1*b+y),tip1);
vsa_set_color(32);
vsa_move_to((int)(.3*a+x),(int)(.5*b+y));
vsa_line_to((int)(.9*a+x),(int)(.1*b+y));
vsa_shaded_triangle((int)(.35*a+x),(int)(.2*b+y),rim1,(int)(.45*a+x),(int)(.4*b+y),rim1,(int)(.9*a+x),(int)(.1*b+y),tip1);
vsa_shaded_triangle((int)(.45*a+x),(int)(.4*b+y),rim1,(int)(.45*a+x),(int)(.6*b+y),rim1,(int)(.9*a+x),(int)(.1*b+y),tip1);
vsa_shaded_triangle((int)(.45*a+x),(int)(.6*b+y),rim1,(int)(.35*a+x),(int)(.8*b+y),rim1,(int)(.9*a+x),(int)(.1*b+y),tip1);

vsa_shaded_triangle((int)(.80*a+x),(int)(.75*b+y),rim2,(int)(.75*a+x),(int)(.9*b+y),rim2,(int)(.9*a+x),(int)(.1*b+y),tip2);
vsa_shaded_triangle((int)(.75*a+x),(int)(.9*b+y),rim2,(int)(.65*a+x),(int)(.9*b+y),rim2,(int)(.9*a+x),(int)(.1*b+y),tip2);
vsa_shaded_triangle((int)(.65*a+x),(int)(.9*b+y),rim2,(int)(.60*a+x),(int)(.75*b+y),rim2,(int)(.9*a+x),(int)(.1*b+y),tip2);
vsa_shaded_triangle((int)(.60*a+x),(int)(.75*b+y),rim2,(int)(.60*a+x),(int)(.65*b+y),rim2,(int)(.9*a+x),(int)(.1*b+y),tip2);
vsa_shaded_triangle((int)(.60*a+x),(int)(.65*b+y),rim2,(int)(.65*a+x),(int)(.5*b+y),rim2,(int)(.9*a+x),(int)(.1*b+y),tip2);
vsa_set_color(32);
vsa_move_to((int)(.7*a+x),(int)(.7*b+y));
vsa_line_to((int)(.9*a+x),(int)(.1*b+y));
vsa_shaded_triangle((int)(.65*a+x),(int)(.5*b+y),rim2,(int)(.75*a+x),(int)(.5*b+y),rim2,(int)(.9*a+x),(int)(.1*b+y),tip2);
vsa_shaded_triangle((int)(.75*a+x),(int)(.5*b+y),rim2,(int)(.80*a+x),(int)(.65*b+y),rim2,(int)(.9*a+x),(int)(.1*b+y),tip2);
vsa_shaded_triangle((int)(.80*a+x),(int)(.65*b+y),rim2,(int)(.80*a+x),(int)(.75*b+y),rim2,(int)(.9*a+x),(int)(.1*b+y),tip2);

	ty = (y+b+1) + 0.01*YResolution;
	tx = (x+a/2) - 19*XCharSize;
	vsa_write_string(tx,ty,14,"3D Objects Using `vsa_shaded_triangle'");
	return;
}

void cube_3d(int a,int b)
{
	int dy,dx,dd;
	dx = .045*XResolution;
	dy = .06*YResolution;
	dd = .5*dx;
	vsa_shaded_triangle(a,b,75,a+dx,b,91,a+dx,b+dy,75);
	vsa_shaded_triangle(a,b,75,a,b+dy,49,a+dx,b+dy,75);
	a+= 0.05*dx;
	b-= 0.2*dy;
	vsa_shaded_triangle(a,b,75,a+dx,b,91,a+3*dd,b-dd,75);
	vsa_shaded_triangle(a,b,75,a+dd,b-dd,49,a+3*dd,b-dd,75);
	a+= 0.15*dx;
	b+= 0.15*dy;
	vsa_shaded_triangle(a+dx,b+dy,75,a+dx,b,91,a+3*dd,b-dd,75);
	vsa_shaded_triangle(a+dx,b+dy,75,a+3*dd,b+dy-dd,49,a+3*dd,b-dd,75);
	vsa_write_string((int)(a-0.3*dx),(int)(b+1.2*dy),240,"Sprites");
	return;
}

void color_effect(void)
{
	int i;
	unsigned char save_color_array[768],j,jj;
	unsigned char red[256],green[256],blue[256];
	vsa_read_color_block(251,5,save_color_array);
	for(j=0;j<5;j++)
		{
			red[j+251]   = save_color_array[3*j];
			green[j+251] = save_color_array[3*j+1];
			blue[j+251]  = save_color_array[3*j+2];
		}
	while(1)
		for(i=32;i<256;i++)
			{
				vsa_wait_vsync();
				j = (unsigned char) i;
				vsa_read_color_register(j,&red[j],&green[j],&blue[j]);
				vsa_write_color_register(j,0,0,63);
				if(j <= 36)
					jj = (unsigned char)(j-37);
				else
					jj = (unsigned char)(j-5);
				vsa_write_color_register(jj,red[jj],green[jj],blue[jj]);
				if(any_key())
					return;
			}
}

int any_key(void)
{
	int result=0;
#ifdef _MSC_VER
/*.....             For Microsoft C, Use this line.                    .....*/
	if(_bios_keybrd(_KEYBRD_READY))
		result = _bios_keybrd(_KEYBRD_READ);
#else
/*.....             For Borland C, Use this line instead.              .....*/
	if(bioskey(1))
		result = bioskey(0);
#endif
	return result;
}

/*.......................... VSA_GET_INPUT .................... 6-25-94 ....*/
/*  This routine reads the keyboard input and echos it to the screen until  */
/* a carriage return is entered. Then the whole text string is returned     */
/* via 'text'.                                                              */
/*..........................................................................*/
void vsa_get_input(char *text)
{
	int i,x,y;
	char key;
	vsa_get_text_cursor(&x,&y);
	i=0;
	text[0] = 0;
	while((key = getch()) != 13)               /*  Do until a return is hit.  */
		{
			if(key != 8)
				{                                    /*  If not a back space        */
					text[i] = key;                     /*  add key entry to string.   */
					text[i+1] = 0;
					vsa_write_string(x,y,255,text);    /*  Echo the updated string.   */
					i++;
				}
			else
				{                                    /*  If a back space            */
					if(i > 0) i --;                    /*  delete last key entry.     */
					text[i] = 92;
					vsa_write_string(x,y,255,text);    /*  Echo the updated string.   */
					text[i] = 0;
				}
		}
	return;
}

/*.............................. VSA_SETUP .................... 6-6-95 .....*/
/*  This routine goes through the video mode set up stuff.                  */
/*..........................................................................*/
void vsa_setup(void)
{
	int i,vmode;
/*..........................................................................*/
/*               Initialize video mode and VSA256 environment.              */
/*               Valid modes are: 100h, 101h, 103h, and 105h.               */
/*..........................................................................*/
	printf("\n");
	printf("\n");
	printf("VESA standard Video Modes  =>   Mode | Resolution\n");
	printf("              (256 color)       -----|-----------\n");
	printf("                                100  |  640 x 400\n");
	printf("                                101  |  640 x 480\n");
	printf("                                103  |  800 x 600\n");
	printf("                                105  | 1024 x 768\n");
	printf("                                107  | 1280 x 1024\n");
	printf("Input Mode: ");
	scanf("%x",&vmode);
	if((i = vsa_init(vmode)) != 0)
		{
			printf("Error Initializing Requested Video Mode!\n");
			if(i==1) printf("  - Did You Load Correct VESA Driver (TSR) ??\n");
			if(i==2) printf("  - VESA BIOS Extensions (Driver) Not Loaded !!\n");
			if(i==3) printf("  - Requested Video Mode Not Supported by this Card!\n");
			if(i==4) printf("  - Mode Not an SVGA Mode Supported by this Card!\n");
			if(i==5) printf("  - VESA Driver Not Returning Mode Information!\n");
			exit(0);
		}
	return;
}
