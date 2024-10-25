@echo off

rem Configure environment to run command-line compiler/linker
call setset c12

nmake /f winvfx.mak

copy winvfx16.dll demo
copy winvfx16.lib demo
copy winvfx.h     demo
copy winvfx16.dll ..\wintools\tga2pcx
copy winvfx16.lib ..\wintools\tga2pcx
copy winvfx.h     ..\wintools\tga2pcx
copy winvfx16.dll ..\wintools\tga2shp
copy winvfx.h     ..\wintools\tga2shp
