@echo off
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0diagnose-windows.ps1" -Launched
if errorlevel 1 (
  echo Diagnostics did not complete. Check the message above.
  pause
  exit /b 1
)
exit /b 0
