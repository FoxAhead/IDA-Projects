@echo off

rem Configure environment to run command-line compiler/linker
call setset c12

nmake /f winvfx.mak

copy winvfx8.dll ..\wintools\tga2shp
copy winvfx8.dll demo
copy winvfx8.lib demo
copy winvfx.h    demo
