###############################################################
#                                                             #
#  MAKEFILE for SAL                                           #
#                                                             #
#  MSVC 4.0                                                   #
#                                                             #
#  Execute with Microsoft (or compatible) NMAKE               #
#                                                             #
###############################################################

CPU = i386
TARGETOS = WIN95

!include <ntwin32.mak>

all: w32sal.dll

#
# System Abstraction Layer library for Win32
#

w32sal.dll: w32sal.obj w32sal.obj
   $(link) $(lcommon) $(dlllflags) -LINK50COMPAT -debug -map -out:w32sal.dll -def:w32sal.def w32sal.obj $(guilibs) ddraw.lib winmm.lib
   del w32sal.exp

#
# C++ support routines for all high-color modes
#

w32sal.obj: w32sal.cpp sal.h
   $(cc) -Zi $(cflags) $(cvars) -DBUILD_SAL $*.cpp
   del w32sal.dll

