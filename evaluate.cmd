@echo off
REM VADREX evaluation entry point. Arguments are passed through to scripts\evaluate.ps1.
REM   evaluate.cmd quick            pipeline check (a few minutes)
REM   evaluate.cmd full             regression check before a paper run (about 20 minutes)
REM   evaluate.cmd paper            reproduce the paper evaluation (about 10.7 hours)
REM   evaluate.cmd paper -Detach    run in the background; prints the run directory and returns
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\evaluate.ps1" %*
exit /b %ERRORLEVEL%
