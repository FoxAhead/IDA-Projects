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

all: tga2shp.exe

#
# TGA2SHP
#

tga2shp.exe: tga2shp.obj tga.obj w32sal.lib
    $(link) $(ldebug) $(guiflags) -out:tga2shp.exe tga2shp.obj tga.obj w32sal.lib winvfx16.lib $(guilibs)

tga2shp.obj: tga2shp.cpp winvfx.h tga.h
    $(cc) $(cdebug) $(cflags) $(cvars) tga2shp.cpp

tga.obj: tga.cpp
   $(cc) $(cdebug) $(cflags) $(cvars) tga.cpp
