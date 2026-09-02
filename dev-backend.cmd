@echo off
REM ============================================================
REM  Backend dev server with crash auto-restart.
REM
REM  P3-47: the original implementation was an unconditional
REM  "restart after 3 seconds" infinite loop. When the backend fails
REM  during startup (port already in use, missing JWT_SECRET,
REM  MongoDB unreachable) that turns into a permanent busy loop:
REM  the same error floods the console every 3 seconds, CPU stays
REM  busy, and the actual root cause scrolls out of the buffer.
REM
REM  Now:
REM   1. Exponential backoff 3 -> 6 -> 12 -> 24 -> 48 -> 60s (capped).
REM   2. Stop after MAX_FAST_FAILS consecutive fast failures. A process
REM      that dies within FAST_FAIL_SECONDS is a config/environment
REM      problem; retrying it forever will never fix it.
REM   3. Surviving longer than RESET_SECONDS counts as a genuine runtime
REM      crash: reset backoff and the fast-failure counter, because
REM      restarting in that case IS the useful behaviour.
REM   4. Exit code 0 means a clean shutdown - do not restart.
REM
REM  This file is intentionally ASCII-only. A .cmd file is decoded using
REM  the active console code page, and this script is launched as a child
REM  process by start.bat with its output redirected, so it must not run
REM  chcp itself (that would change the parent console). Non-ASCII text
REM  would therefore render as mojibake on some machines.
REM ============================================================
setlocal EnableDelayedExpansion

cd /d "%~dp0" || (echo [FATAL] Cannot enter script directory: %~dp0 & exit /b 1)

set "NODE_ENV=development"
set /a DELAY=3
set /a MAX_DELAY=60
set /a FAST_FAILS=0
set /a MAX_FAST_FAILS=5
set /a FAST_FAIL_SECONDS=10
set /a RESET_SECONDS=60

:loop
call :seconds_since_midnight START_TS

node src\index.js
set /a EXIT_CODE=%errorlevel%

call :seconds_since_midnight END_TS
set /a UPTIME=END_TS-START_TS
REM Midnight rollover: a negative delta means the day wrapped.
if !UPTIME! lss 0 set /a UPTIME=UPTIME+86400

if !EXIT_CODE! equ 0 (
    echo [INFO] Backend exited normally ^(code=0^), not restarting.
    exit /b 0
)

if !UPTIME! geq !RESET_SECONDS! (
    set /a FAST_FAILS=0
    set /a DELAY=3
    echo [WARN] Backend crashed after !UPTIME!s ^(code=!EXIT_CODE!^). Restarting in !DELAY!s ...
) else if !UPTIME! lss !FAST_FAIL_SECONDS! (
    set /a FAST_FAILS+=1
    echo [WARN] Backend exited after !UPTIME!s ^(code=!EXIT_CODE!^) - fast failure !FAST_FAILS!/!MAX_FAST_FAILS!.
    REM Bail out via goto rather than "exit /b" from inside this nested block:
    REM measured on this machine, "exit /b !VAR!" nested two levels deep inside
    REM an if/else-if chain in a goto-driven loop returns 0 to the caller,
    REM silently losing the failure code. Exiting from top level works reliably.
    if !FAST_FAILS! geq !MAX_FAST_FAILS! goto fatal
    echo        Restarting in !DELAY!s ...
) else (
    echo [WARN] Backend exited after !UPTIME!s ^(code=!EXIT_CODE!^). Restarting in !DELAY!s ...
)

REM "ping -n N" waits N-1 seconds. timeout.exe cannot be used here:
REM it aborts with "input redirection is not supported" when stdout/stdin
REM are redirected, which is exactly how start.bat launches this script.
set /a PING_COUNT=DELAY+1
ping -n !PING_COUNT! 127.0.0.1 >nul

set /a DELAY=DELAY*2
if !DELAY! gtr !MAX_DELAY! set /a DELAY=MAX_DELAY

goto loop

:fatal
echo.
echo [FATAL] Backend failed !MAX_FAST_FAILS! times, each within !FAST_FAIL_SECONDS!s.
echo         This is almost certainly a configuration or environment problem,
echo         not a transient crash. The restart loop has been stopped.
echo         Check the error above - common causes: port 3000 already in use,
echo         missing JWT_SECRET / AES_SECRET_KEY, MongoDB unreachable.
echo.
exit /b !EXIT_CODE!

REM ------------------------------------------------------------
REM  Subroutine: store seconds-since-midnight into the variable
REM  named by %1.
REM
REM  Two traps handled here:
REM   - %TIME% pads hours below 10 with a space (" 9:05:03.12"),
REM     so spaces are replaced with zeros first.
REM   - "set /a 08" is parsed as invalid octal, hence the classic
REM     1%%var%%-100 trick to force base 10.
REM   - setlocal/endlocal pair is required: "endlocal & set" without a
REM     matching setlocal inside this subroutine would pop the OUTER
REM     setlocal and silently disable delayed expansion for the whole
REM     script, making every !VAR! read as literal text.
REM ------------------------------------------------------------
:seconds_since_midnight
setlocal
set "T=%TIME: =0%"
set /a _H=1%T:~0,2%-100
set /a _M=1%T:~3,2%-100
set /a _S=1%T:~6,2%-100
set /a _TOTAL=_H*3600+_M*60+_S
endlocal & set "%~1=%_TOTAL%"
exit /b 0
