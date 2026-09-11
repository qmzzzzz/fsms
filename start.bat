@echo off
REM ============================================================
REM  消防安全管理系统 - 一键启动脚本（Windows）
REM
REM  P3-47 修复要点：
REM   1. 编码：本文件为 UTF-8 无 BOM，首行 chcp 65001 切到 UTF-8 代码页。
REM      原文件是 GBK 编码，在 UTF-8 控制台（Win10 1903+ 与 Terminal 默认）
REM      下全部中文显示为乱码。实测四种组合后选定此方案：
REM        UTF8 文件 + chcp 65001  -> 正常
REM        UTF8 文件 + 不改代码页  -> 乱码（控制台按 GBK 解字节）
REM        GBK  文件 + 不改代码页  -> 乱码
REM        GBK  文件 + chcp 936    -> 正常，但会把用户控制台改成 GBK
REM      选前者：UTF-8 是当前 Windows 的默认方向，且不劣化调用方环境。
REM   2. 清理端口时校验进程映像名，只结束 node.exe。原实现按端口无条件
REM      taskkill，会误杀占用 3000/3001 的任何进程（Docker 端口转发、
REM      其他项目的 dev server、甚至系统服务）。
REM ============================================================
chcp 65001 >nul
setlocal

title 消防安全管理系统

echo ========================================
echo     消防安全管理系统 - 启动脚本
echo ========================================
echo.

REM ========== 0. 环境自检 ==========
where node >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Node.js，请先安装 Node.js
    pause
    exit /b 1
)
where npx >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 npx，请检查 Node.js 安装是否完整
    pause
    exit /b 1
)

REM ========== 1. 清理旧进程 ==========
echo [1/5] 清理旧进程...
call :kill_port_node 3000
call :kill_port_node 3001
REM 用 ping 计时代替 timeout：timeout 在输出被重定向/非交互环境下会直接报错
ping -n 3 127.0.0.1 >nul

REM ========== 2. 检查 MongoDB ==========
echo [2/5] 检查 MongoDB...
netstat -ano | findstr /R /C:":27017 .*LISTENING" >nul 2>&1
if errorlevel 1 (
    echo [错误] MongoDB 未运行！
    echo         请先启动 MongoDB 服务，例如：net start MongoDB
    pause
    exit /b 1
)
echo [MongoDB 运行正常]

REM ========== 3. 启动后端并等待就绪 ==========
echo [3/5] 启动后端服务...
cd /d "%~dp0"
start "消防系统-后端" /B cmd /c "%~dp0dev-backend.cmd"

REM 不做盲等固定秒数，而是轮询 /health 探活（实际约 30 秒超时上限）
REM 后端在端口占用/配置校验/数据库连接失败都会立刻退出，明确报错优于假装成功
set /a BACKEND_TRIES=0
:wait_backend
powershell -NoProfile -Command "try{Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://127.0.0.1:3000/health|Out-Null;exit 0}catch{exit 1}" >nul 2>&1
if not errorlevel 1 goto backend_ready
set /a BACKEND_TRIES+=1
if %BACKEND_TRIES% geq 15 (
    echo [错误] 后端启动失败（30 秒内未通过健康检查）
    echo        请查看后端控制台窗口定位原因（端口占用 / 密钥未配置 / 数据库连不上等）
    pause
    exit /b 1
)
ping -n 3 127.0.0.1 >nul
goto wait_backend
:backend_ready
echo [后端已就绪] http://localhost:3000

REM ========== 4. 启动前端并等待就绪 ==========
echo [4/5] 启动前端开发服务器...
if not exist "%~dp0web-admin\" (
    echo [错误] 未找到前端目录：%~dp0web-admin
    pause
    exit /b 1
)
cd /d "%~dp0web-admin"

if not exist "node_modules\" (
    echo [提示] 首次运行，安装前端依赖（可能需要几分钟）...
    call npm install
    if errorlevel 1 (
        echo [错误] 前端依赖安装失败，请检查网络后手动执行 npm install
        pause
        exit /b 1
    )
)

REM --strictPort：端口被占用时直接报错退出，而不是静默换端口
REM （否则浏览器会按硬编码的 3001 打开一个不存在的服务）
start "消防系统-前端" /B cmd /c "%~dp0web-admin\dev-vite.cmd"

REM 同样轮询真实监听状态，替代原来的盲等 8 秒（约 60 秒超时上限）
set /a FRONTEND_TRIES=0
:wait_frontend
netstat -ano | findstr /R /C:":3001 .*LISTENING" >nul 2>&1
if not errorlevel 1 goto frontend_ready
set /a FRONTEND_TRIES+=1
if %FRONTEND_TRIES% geq 30 (
    echo [错误] 前端启动失败（60 秒内未开始监听 3001 端口）
    echo        请查看前端控制台窗口定位原因
    pause
    exit /b 1
)
ping -n 3 127.0.0.1 >nul
goto wait_frontend
:frontend_ready
echo [前端已就绪] http://localhost:3001

echo.
echo ========================================
echo     启动完成！
echo.
echo     后端地址：http://localhost:3000
echo     前端地址：http://localhost:3001
echo     登录页面：http://localhost:3001/login
echo.
echo     默认账号：admin
echo ========================================
echo.

REM ========== 5. 打开浏览器 ==========
echo 正在打开浏览器...
start "" "http://localhost:3001/login"

endlocal
exit /b 0

REM ============================================================
REM  子过程：结束占用指定端口的 node 进程
REM
REM  只结束 node.exe：本脚本无法区分「上次没关干净的本项目进程」与
REM  「恰好占用同一端口的别人的进程」，但至少能保证不去动非 node 的进程。
REM  若端口被非 node 进程占用，打印警告让人自行处置——静默杀掉别人的
REM  数据库/容器/IDE 服务，代价远高于让启动失败一次。
REM
REM  正则要求端口号后跟空格，精确匹配 :3000 而非前缀：
REM  否则 ":3000" 会连带命中 :30000~:30099 等无关端口。
REM ============================================================
:kill_port_node
for /f "tokens=5" %%a in ('netstat -ano ^| findstr /R /C:":%~1 .*LISTENING"') do call :kill_if_node %%a %~1
exit /b 0

:kill_if_node
REM %1 = PID，%2 = 端口号
REM 去重：同一进程会因 IPv4/IPv6 双栈在 netstat 中出现两行（0.0.0.0:3000 与 [::]:3000），
REM 不去重会对同一 PID 调用两次 taskkill——第二次必然失败（进程已不存在），
REM 错误虽被 >nul 吞掉，但屏幕上会打印两条"已结束"，让人误以为杀了两个进程
if defined KILLED_%~1 exit /b 0

set "IMAGE_NAME="
for /f "tokens=1 delims=," %%n in ('tasklist /FI "PID eq %~1" /FO CSV /NH 2^>nul') do set "IMAGE_NAME=%%~n"
if not defined IMAGE_NAME (
    REM 进程已自行退出（netstat 快照与 tasklist 之间存在时间差），无需处理
    exit /b 0
)
if /I "%IMAGE_NAME%"=="node.exe" (
    taskkill /F /PID %~1 >nul 2>&1
    set "KILLED_%~1=1"
    echo   已结束占用 %~2 端口的 node 进程 ^(PID=%~1^)
) else (
    set "KILLED_%~1=1"
    echo   [警告] %~2 端口被非 node 进程占用：%IMAGE_NAME% ^(PID=%~1^)
    echo          未结束该进程，请自行确认后处理，否则本次启动会失败
)
exit /b 0
