@echo off
setlocal
title Purpose-2-Tool Launcher

echo ===============================================================================
echo            PURPOSE-2-TOOL : OPERATIONAL CYBERSECURITY ARSENAL
echo               4,261+ Tools ^| 12 Semantic Domains ^| Live Upstream
echo ===============================================================================
echo.

:: 1. Verify Python Installation
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Error: Python 3 is not installed or not in your system PATH.
    echo [*] Download Python 3.9+ from https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

:: 2. Check and Install Missing Python Packages
python -c "import fastapi, uvicorn, requests, pydantic" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Installing required Python dependencies [fastapi, uvicorn, requests, pydantic]...
    pip install fastapi uvicorn requests pydantic
    echo.
)

:: 3. Check if Server is Already Running on Port 8080
python -c "import subprocess, sys; out = subprocess.check_output('netstat -ano', shell=True).decode(); pids = [l.strip().split()[-1] for l in out.splitlines() if ':8080' in l and 'LISTENING' in l and int(l.strip().split()[-1]) > 4]; sys.exit(0 if pids else 1)" >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Purpose-2-Tool server is ALREADY ACTIVE on http://localhost:8080
    echo [*] Opening dashboard in your default browser...
    start http://localhost:8080
    ping 127.0.0.1 -n 2 >nul
    exit /b 0
)

:: 4. Start Server in Dedicated Background Process
echo [*] Launching Purpose-2-Tool Federated Server on port 8080...
start "Purpose-2-Tool Server [Port 8080]" /min python server.py

:: 5. Wait for Initialization
ping 127.0.0.1 -n 3 >nul

:: 6. Confirm Server Status and Open Browser
python -c "import subprocess, sys; out = subprocess.check_output('netstat -ano', shell=True).decode(); pids = [l.strip().split()[-1] for l in out.splitlines() if ':8080' in l and 'LISTENING' in l and int(l.strip().split()[-1]) > 4]; sys.exit(0 if pids else 1)" >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Server Status          : ONLINE
    echo [+] Local API Base         : http://localhost:8080
    echo [+] In-Memory Cache        : ACTIVE [Sub-0.1ms retrieval]
    echo [+] Semantic Classifier    : 12 Operational Domains
    echo [+] Indexed Cybersecurity  : 4,261 Tools ^& Resources
    echo.
    echo [*] Launching web browser...
    start http://localhost:8080
) else (
    echo [*] Server is initializing. Opening browser at http://localhost:8080
    start http://localhost:8080
)

echo.
echo ===============================================================================
echo  Dashboard is live! To stop the background server at any time, run 'stop.bat'.
echo ===============================================================================
ping 127.0.0.1 -n 3 >nul
