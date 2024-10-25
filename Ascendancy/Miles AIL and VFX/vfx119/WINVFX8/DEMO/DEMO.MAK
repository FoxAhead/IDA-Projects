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

all: demo.exe

#
# Test app for WinVFX / SAL (8bpp version)
#

demo.exe: demo.obj winvfx8.lib w32sal.lib 
    $(link) $(ldebug) $(guiflags) -out:demo.exe demo.obj w32sal.lib winvfx8.lib $(guilibs)

demo.obj: demo.cpp sal.h winvfx.h
    $(cc) $(cdebug) $(cflags) $(cvars) demo.cpp
