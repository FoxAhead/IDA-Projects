###############################################################
#                                                             #
#  MAKEFILE for WinVFX                                        #             
#                                                             #
#  MSVC 4.0                                                   #
#                                                             #
#  Execute with Microsoft (or compatible) NMAKE               #
#                                                             #
###############################################################

CPU = i386
TARGETOS = WIN95

!include <ntwin32.mak>

all: winvfx16.dll

#
# 16-bit WinVFX DLL
#

winvfx16.dll: winvfxhc.obj winvfx16.obj w32sal.lib
   $(link) $(lcommon) $(dlllflags) -LINK50COMPAT -map -out:winvfx16.dll -def:winvfx.def winvfxhc.obj winvfx16.obj w32sal.lib $(guilibs)
   del winvfx16.exp

#
# C++ support routines for all high-color modes
#

winvfxhc.obj: winvfxhc.cpp winvfx.h
   $(cc) $(cflags) $(cvars) -DBUILD_VFX -Ox -G6 $*.cpp
   del winvfx16.dll

#
# Assembly-language header file
#

winvfx.inc: winvfx.h
   h2inc /WIN32 winvfx.h

#
# Assembly primitives for 16-bit color
#

winvfx16.obj: winvfx16.asm winvfx.inc
   ml /Cp /c /coff /W2 /Zi /DWIN32 /D_WIN32 $*.asm
