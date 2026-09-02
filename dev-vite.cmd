@echo off
REM ============================================================
REM  Vite dev server with auto-restart watchdog
REM
REM  P2-28: this file was corrupted - the whole script had been
REM  collapsed into a single line, so "@echo off npx vite ..." was
REM  parsed as one ECHO command. It only turned off command echo and
REM  exited immediately; the dev server never started and the restart
REM  loop never existed. Rewritten with real line breaks.
REM
REM  Comments are ASCII-only on purpose: .cmd files are read with the
REM  console codepage (GBK on zh-CN Windows), and UTF-8 Chinese text
REM  shows up as mojibake there.
REM
REM  Note: web-admin\dev-vite.cmd is the one launched by start.bat and
REM  has no restart loop. Use this script when you want the watchdog.
REM ============================================================

setlocal
REM cd failure must abort: without this check the script keeps going and
REM runs npx vite in whatever directory it happens to be in, which picks up
REM the wrong vite.config.js (or none at all). Observed during verification:
REM "The system cannot find the path specified." followed by a normal start.
cd /d "%~dp0web-admin" || (
  echo [dev-vite] cannot enter "%~dp0web-admin", aborting.
  exit /b 1
)

if not exist "node_modules" (
  echo [dev-vite] node_modules not found in web-admin, running npm install...
  call npm install || (
    echo [dev-vite] npm install failed, aborting.
    exit /b 1
  )
)

:loop
echo [dev-vite] starting Vite on port 3001 ...
REM --strictPort: fail fast when the port is taken instead of silently
REM moving to another port (the backend CORS whitelist pins 3001).
call npx vite --port 3001 --strictPort

REM Exit code 0 means a deliberate shutdown (Ctrl-C / q+Enter): stop here,
REM otherwise the watchdog would fight the user trying to quit.
if "%errorlevel%"=="0" (
  echo [dev-vite] Vite exited normally, watchdog stopped.
  goto end
)

echo [dev-vite] Vite exited (code=%errorlevel%), restarting in 3s ...
REM ping as a portable sleep: -n 4 waits about 3 seconds.
ping -n 4 127.0.0.1 >nul
goto loop

:end
endlocal
