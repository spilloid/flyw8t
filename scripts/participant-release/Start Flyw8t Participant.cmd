@echo off
setlocal DisableDelayedExpansion
set "NODE_OPTIONS="
set "NODE_PATH="
set "NODE_EXTRA_CA_CERTS="
set "NODE_TLS_REJECT_UNAUTHORIZED="
"%~dp0runtime\node.exe" "%~dp0app\public-participant.mjs"
set "FLYW8T_RESULT=%ERRORLEVEL%"
if not "%FLYW8T_RESULT%"=="0" pause
exit /b %FLYW8T_RESULT%
