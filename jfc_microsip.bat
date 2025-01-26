@echo off

:: Get the directory of the current script
set "SCRIPT_DIR=%~dp0"

:: Check if JFC_CONFIG_DONE exists in the script directory
if exist "%SCRIPT_DIR%JFC_CONFIG_DONE" (
    echo JFC_CONFIG_DONE file found. Launching microsip.exe...
    start "" "%SCRIPT_DIR%microsip.exe"
) else (
    echo JFC_CONFIG_DONE file not found. Launching jfc_configure.exe...
    start "" "%SCRIPT_DIR%jfc_configure.exe"
)
