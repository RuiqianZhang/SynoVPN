@echo off
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-windows.ps1" -Launched
if errorlevel 1 (
  echo Setup did not complete. Check the message above.
  pause
  exit /b 1
)
exit /b 0
