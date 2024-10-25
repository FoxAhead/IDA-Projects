@echo off
REM Batch file to profile all 320x200, 640x350, 640x400 and 640x480 resolutions

REM Profile all modes without Cache thrashing
profile 12 %1
profile 13 %1
profile 101 %1
profile 110 %1
profile 111 %1
profile 112 %1
profile 128 %1
profile 4101 %1
profile 4110 %1
profile 4111 %1
profile 4112 %1
profile 4128 %1

REM Profile all modes with Cache thrashing
profile -t 12 %1
profile -t 13 %1
profile -t 101 %1
profile -t 110 %1
profile -t 111 %1
profile -t 112 %1
profile -t 128 %1
profile -t 4101 %1
profile -t 4110 %1
profile -t 4111 %1
profile -t 4112 %1
profile -t 4128 %1

