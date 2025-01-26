::[Bat To Exe Converter]
::
::YAwzoRdxOk+EWAjk
::fBw5plQjdCyDJGyX8VAjFBJAXx2NKXm7Fok47fvw++WXnmgtd94tfZzUz6aNJfMv50znZ5k+32oUkcgDbA==
::YAwzuBVtJxjWCl3EqQJgSA==
::ZR4luwNxJguZRRnk
::Yhs/ulQjdF+5
::cxAkpRVqdFKZSzk=
::cBs/ulQjdF+5
::ZR41oxFsdFKZSDk=
::eBoioBt6dFKZSDk=
::cRo6pxp7LAbNWATEpCI=
::egkzugNsPRvcWATEpCI=
::dAsiuh18IRvcCxnZtBJQ
::cRYluBh/LU+EWAnk
::YxY4rhs+aU+IeA==
::cxY6rQJ7JhzQF1fEqQJhSA==
::ZQ05rAF9IBncCkqN+0xwdVsFLA==
::ZQ05rAF9IAHYFVzEqQIaDjgUYQ2BLmSJL4V8
::eg0/rx1wNQPfEVWB+kM9LVsJDA6EP1S3D7YO5/vy/6SFo1l9
::fBEirQZwNQPfEVWB+kM9LVsJDGQ=
::cRolqwZ3JBvQF1fEqQIDASsUbwiLOWWuRrMT+qjR5uWhq08YRq0ecZ3907aLMqAG+UD2ZvY=
::dhA7uBVwLU+EWHOi1wIXOhRBXGQ=
::YQ03rBFzNR3SWATE3mQTaDxGQxGSXA==
::dhAmsQZ3MwfNWATE3mQTaDxGQxGSXA==
::ZQ0/vhVqMQ3MEVWAtB9wSA==
::Zg8zqx1/OA3MEVWAtB9wSA==
::dhA7pRFwIByZRRnk
::Zh4grVQjdCyDJGyX8VAjFBJAXx2NKXm7Fok47fvw++WXnmc7d68ScYzJ1YenEK4W8kCE
::YB416Ek+ZG8=
::
::
::978f952a14a936cc963da21a135fa983
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

exit