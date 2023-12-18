@echo off
call opensslstart.bat && openssl version
if %errorlevel%==0 (
    echo Both commands executed successfully.
) else (
    echo Failed to execute one or both commands.
)
pause

