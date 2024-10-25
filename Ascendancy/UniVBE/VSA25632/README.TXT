	README.TXT for VSA256 Graphics Library Version 3.2    
																	12-16-94

-------------------- FILES IN VSA256.ZIP DISTRIBUTION -----------------

	The distribution of the VSA256 Graphics Library Version 3.2
consists of the 13 files listed below.  These files are archived in the
file VSA256.ZIP.  To extract, just type 'PKUNZIP VSA256' in the
directory that you want the files extracted to.

VSA_DEMO.C         VSA256 Demonstration program (Source Code).
VSA_DEMO.EXE       VSA256 Demonstration program (Executable).
VSA256MS.LIB       VSA256 Graphics Library (Microsoft C compatible).
VSA256BC.LIB       VSA256 Graphics Library (Borland C Compatible).
VSA.H              VSA256 Include file required in your program.
VSA_FONT.H         VSA256 Include file required in your program.
VSA_DEMO.MAK       Make File for Microsoft Quick C V2.5 (IDE).
VSA_DEMO.PRJ       Project file for Borland C/C++ V3.1 (IDE).
VSA_DEMO.IDE       Project file for Borland C/C++ V4.0 (IDE).
VSA256.TXT         The VSA256 Users Manual.
ORDER.TXT          A text file order form for registration and upgrades.
README.TXT         This Document
DRIVERS2.EXE       A self extracting archive of VESA BIOS TSRs.


-------------- WHATS NEW IN VSA256 GRAPHICS LIBRARY V3.2 ---------------

- Added Viewport Clipping to all drawing functions.
- Added BitBLT drawing functions.
- Added Vector Text: Infinitely scalable, positionable to nearest
	pixel, fonts are fully user definable!                                   
- Now works with Small, Medium, Compact Large memory
	models with Borland (Already did so with Microsoft).
- Fixed "unresolved external _fstrlen" linker error with Turbo C.
- Fixed "Text I/O Functions Not Supported" problem.                   
- Made all functions in VSA.H external, no more "Multiple
	Declaration" warnings.
- Added Global Parameter VSA_ATI_COLOR to work with some ATI cards. 
- New routine, vsa_set_clip_mode.
- New routine, vsa_set_viewport.
- New routine, vsa_image_size.
- New routine, vsa_get_image.
- New routine, vsa_put_image.
- New routine, vsa_get_pixel.   
- New routine, vsa_get_text_cursor.
- New routine, vsa_set_text_scale.
- New routine, vsa_wait_vsync.

-------------- Compatibility With Previous VSA256 Version -------------

VSA256 text support has been REVAMPED!  I no longer rely on the 
video card manufacturers BIOS to get text support.  Instead I draw
each character using 2D vector strokes.  The advantages are as follows:

	- Text now works with ALL video cards!
	- Now text is Infinitely scaleable.
	- Text positioning resolution is down to 1 pixel.
	- Background color is preserved.
	- The programmer can define his own fonts in VSA_FONT.H.

Some minor incompatibilities with VSA256 version 2.0 were introduced 
due to the changes and they are as follows:

-  vsa_write_string now takes x,y (in pixel coordinates) instead of 
	 row,col (in character coordinates) as the first two parameters.
-  The first two parameters of vsa_write_string (x,y) are now int
	 instead of unsigned char.
-  The vsa_write_char function was deleted.
-  The supported ASCII characters are the printable characters 
	from ASCII code 32 to ASCII code 127.

Your existing code should take very little editing to make these
changes, especially if you write a macro to edit all occurances of
vsa_write_string as follows:

OLD - vsa_write_string(row,col,color,text);

NEW - vsa_write_string(col*XCharSize,row*YCharSize,color,text);


---------------- INSTALLING VESA BIOS EXTENSION DRIVERS ---------------

DRIVERS2.EXE is a self extracting archive file which contains the 
VESA BIOS Extensions.  When executed, it will create subdirectories for 
each of the video adapter manufacturers.  Within each subdirectory, it
will place the respective VESA driver.  To execute:

	1. Get into the directory where you want the subdirectories 
	to be created.
			
	2. Copy the file DRIVERS2.EXE into this directory.
			
	3. type drivers2 -d  (the -d tells it to create subdirectories).

--------------------------- Trouble Shooting --------------------------

1.) Please read the VSA256.TXT document, at least sections 1 and 2, to
make sure you are setting things up right.

2.) If Turbo C says "Undefined Symbol ___brklvl in module vsa_all0",
add the following line to the top of your main program file:
		
	unsigned __brklvl;

3.) This version of the VSA256 Graphics Library has a fix in it to 
support ATI color palettes.  Going from 2.0 to 3.0, I switched the way 
I handled color palettes so that it  would work with Diamond Vipers.  
Unbeknownst (cool word) to me, this fix wiped out some ATI cards.  So,
now I give you a global parameter called: 

                           VSA_ATI_COLOR

When you call vsa_init(), VSA_ATI_COLOR  defaults to 0, which  means it 
is set up  for the  Diamond  Viper, NOT for ATI.  Note that this is the 
preferred mode since palette updates in this mode are much, much faster.
Right after your vsa_init() call, slip in VSA_ATI_COLOR = 1; and you'll 
be  swimming with  ATI.  This mode relies on BIOS calls for the palette 
updates, so its slower ... but it will get ATI users up and running.

4.) Tell me if there are any unresolved problems.


------------------------- Assist for 3 Compilers ----------------------
		
To help get you started, I have provided the "project" files for three 
different compiler Integrated Development Environments (IDEs).  

Microsoft Quick C, Version 2.5  ----> VSA_DEMO.MAK
Borland C/C++, Version 3.1      ----> VSA_DEMO.PRJ
Borland C/C++, Version 4.0      ----> VSA_DEMO.IDE

Get in the respective IDE and just select/load the appropriate project
file for your compiler.
