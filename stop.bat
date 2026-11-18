@echo off
setlocal
title Purpose-2-Tool Shutdown

echo ===============================================================================
echo            PURPOSE-2-TOOL : STOPPING SERVER SERVICES
echo ===============================================================================
echo.

python -c "import subprocess, os, signal; out = subprocess.check_output('netstat -ano', shell=True).decode(); pids = set([l.strip().split()[-1] for l in out.splitlines() if ':8080' in l and 'LISTENING' in l and int(l.strip().split()[-1]) > 4]); [os.kill(int(p), signal.SIGTERM) for p in pids]; print(f'[✓] Terminated {len(pids)} active process(es) on port 8080.') if pids else print('[-] No active Purpose-2-Tool server found on port 8080.')"

echo.
echo ===============================================================================
echo  Purpose-2-Tool server has been halted. Run 'start.bat' to restart anytime.
echo ===============================================================================
ping 127.0.0.1 -n 2 >nul
