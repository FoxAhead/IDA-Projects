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

all: tga2pcx.exe

#
# TGA2PCX
#

tga2pcx.exe: tga2pcx.obj tga.obj pcx.obj winvfx16.lib w32sal.lib 
    $(link) $(ldebug) $(guiflags) -out:tga2pcx.exe tga2pcx.obj tga.obj pcx.obj w32sal.lib winvfx16.lib $(guilibs)

tga2pcx.obj: tga2pcx.cpp sal.h winvfx.h rgbutils.h
    $(cc) $(cdebug) $(cflags) $(cvars) tga2pcx.cpp

pcx.obj: pcx.cpp
    $(cc) $(cdebug) $(cflags) $(cvars) pcx.cpp

tga.obj: tga.cpp
    $(cc) $(cdebug) $(cflags) $(cvars) tga.cpp
