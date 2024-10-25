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

all: winvfx8.dll

#
# 8-bit WinVFX DLL
#

winvfx8.dll: winvfx.obj winvfx8.obj w32sal.lib
   $(link) $(lcommon) $(dlllflags) -LINK50COMPAT -out:winvfx8.dll -def:winvfx.def winvfx.obj winvfx8.obj w32sal.lib $(guilibs)
   del winvfx8.exp

#
# C++ support routines for 8-bit color
#

winvfx.obj: winvfx.cpp winvfx.h
   $(cc) $(cflags) $(cvars) -DBUILD_VFX $*.cpp
   del winvfx8.dll

#
# Assembly-language header file
#

winvfx.inc: winvfx.h
   h2inc /WIN32 winvfx.h

#
# Assembly primitives for 8-bit color
#

winvfx8.obj: winvfx8.asm winvfx.inc
   ml /Cp /c /coff /W2 /Zi /DWIN32 /D_WIN32 $*.asm

