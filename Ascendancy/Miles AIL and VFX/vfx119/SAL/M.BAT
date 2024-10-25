@echo off

rem Configure environment for MSVC 6.0 command-line compiler/linker
call setset c12

NMAKE /f "w32sal.mak" CFG="w32Sal - Win32 Debug"

if exist c:\util\w32sal.dll copy w32sal.dll c:\util

copy w32sal.lib ..\winvfx16
copy sal.h      ..\winvfx16
copy w32sal.dll ..\winvfx16\demo
copy w32sal.lib ..\winvfx16\demo
copy sal.h      ..\winvfx16\demo

copy w32sal.lib ..\winvfx8
copy sal.h      ..\winvfx8
copy w32sal.dll ..\winvfx8\demo
copy w32sal.lib ..\winvfx8\demo
copy sal.h      ..\winvfx8\demo

copy w32sal.dll ..\wintools\tga2shp
copy w32sal.lib ..\wintools\tga2shp
copy sal.h      ..\wintools\tga2shp

copy w32sal.dll ..\wintools\tga2pcx
copy w32sal.lib ..\wintools\tga2pcx
copy sal.h      ..\wintools\tga2pcx
