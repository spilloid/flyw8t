@echo off
setlocal
set "program_files=%ProgramW6432%"
if not defined program_files set "program_files=%ProgramFiles%"
"%program_files%\flyw8t\flyw8t-agent.exe" service uninstall
exit /b %errorlevel%
