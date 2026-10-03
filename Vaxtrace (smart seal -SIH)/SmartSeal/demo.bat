@echo off
setlocal
cd /d "%~dp0"
echo.
echo [1/6] Checking Docker...
docker version >nul 2>&1
if errorlevel 1 (
  echo     Docker is not running. Start Docker Desktop, or run demo_nodocker.bat instead.
  exit /b 1
)
echo [2/6] Python environment...
if not exist .venv (
  python -m venv .venv
  call .venv\Scripts\activate.bat
  pip install -r requirements.txt
) else (
  call .venv\Scripts\activate.bat
)
echo [3/6] Besu network (4 validators)...
call blockchain\start_network.bat
if errorlevel 1 (
  echo     The network did not start. See blockchain\README.md, "Troubleshooting".
  exit /b 1
)
echo [4/6] Smart contracts...
if not exist blockchain\deployment.json (
  call blockchain\deploy.bat
  if errorlevel 1 exit /b 1
) else (
  echo     deployment.json already exists. After reset_network.bat it is removed automatically.
)
echo [5/6] Starting gateway (8000) and verifier (8100) in their own windows...
start "SmartSeal gateway" cmd /k "cd /d %~dp0gateway && call ..\.venv\Scripts\activate.bat && python -m uvicorn app:create_app --factory --port 8000"
start "SmartSeal verifier" cmd /k "cd /d %~dp0verifier && call ..\.venv\Scripts\activate.bat && python -m uvicorn app:create_app --factory --port 8100"
timeout /t 8 /nobreak >nul
echo [6/6] Seeding a demo shipment and opening the dashboard...
python integration\live_demo.py seed --shipment SHP-DEMO --seal SEAL-DEMO
start "" "%~dp0dashboard\index.html"
echo.
echo ============================================================
echo  Gateway      http://127.0.0.1:8000   (API docs: /docs)
echo  Verifier     http://127.0.0.1:8100
echo  Besu RPC     http://127.0.0.1:8545 to 8548 (one per validator)
echo  Dashboard    dashboard\index.html  -^>  "Real backend"
echo  API key      demo-only-change-me
echo ------------------------------------------------------------
echo  Try (new terminal, after: call .venv\Scripts\activate.bat):
echo   python integration\live_demo.py verify --shipment SHP-DEMO --finalize
echo   python integration\live_demo.py seed   --shipment SHP-HOT --seal SEAL-HOT --hot 5,6
echo   python integration\live_demo.py attack edit --shipment SHP-HOT
echo   python integration\live_demo.py verify --shipment SHP-HOT
echo   python integration\attack_tests\harness.py   (all attack scenarios)
echo  Quorum demo: docker stop smartseal-node4   (3 of 4 still commits)
echo               docker stop smartseal-node3   (2 of 4: no quorum, queue holds)
echo ============================================================
