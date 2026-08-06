@echo off
REM VADREX one-click bootstrap. Arguments are passed through to scripts\reproduce.ps1.
REM   reproduce.cmd              normal start (a second run reuses the existing state)
REM   reproduce.cmd -Reset       destructive reset, then start
REM   reproduce.cmd -SkipE2E     skip the end-to-end scenarios
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\reproduce.ps1" %*
exit /b %ERRORLEVEL%
