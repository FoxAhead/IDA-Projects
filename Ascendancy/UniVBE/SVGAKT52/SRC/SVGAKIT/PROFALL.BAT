@echo off
REM Batch file to profile all modes and log to a file

if %1==%1 goto start
echo Usage: PROFALL card_name
echo.
echo This batch file will run the PROFILE.EXE program for Standard VGA
echo 320x200x256 (13h), UniVBE SuperVGA 320x200x256 (143h) and all
echo 640x480 modes (8,15,16,24 and 32 bits per pixel).
goto end

:start
REM Create the initial log file with header
if not exist ALLMODES.LOG profile 13 baseline ALLMODES.LOG

REM Profile all modes
profile 13 %1 ALLMODES.LOG
profile 143 %1 ALLMODES.LOG
profile 101 %1 ALLMODES.LOG
profile 110 %1 ALLMODES.LOG
profile 111 %1 ALLMODES.LOG
profile 112 %1 ALLMODES.LOG
profile 128 %1 ALLMODES.LOG
profile 4143 %1 ALLMODES.LOG
profile 4101 %1 ALLMODES.LOG
profile 4110 %1 ALLMODES.LOG
profile 4111 %1 ALLMODES.LOG
profile 4112 %1 ALLMODES.LOG
profile 4128 %1 ALLMODES.LOG

:end
