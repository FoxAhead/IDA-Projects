@echo off

rem Configure environment to run command-line compiler/linker
call setset c12

nmake /f demo.mak
