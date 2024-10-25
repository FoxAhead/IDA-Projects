###############################################################
#                                                             #
#  MAKEFILE for VFXRend development                           #             
#  16-Sep-92 John Miles                                       #
#  21-Jan-94 John Lemberger                                   #
#                                                             #
#  Execute with Microsoft MAKE                                #
#                                                             #
###############################################################

#
# Polygon clipping and rendering primitives
#

vfxrend.obj: vfxrend.asm rendopts.inc
   ml /c /DMASM /DFLAT_MODEL /I..\..\release.115 $*.asm

#
# Test bed
#

t.exe: t.c vfxrend.obj vfxrend.h
   wcc386 /s /d2 /i=..\..\release.115 t
   wlink n t f t,vfxrend system dos4g
