@echo off
cd /d "%~dp0"
docker version >nul 2>&1
if errorlevel 1 (
  echo Docker is not running. Start Docker Desktop and try again.
  exit /b 1
)
if not exist nodes\network.json (
  echo First run: generating validator keys and the QBFT genesis with Besu...
  python scripts\prepare_network.py
  if errorlevel 1 exit /b 1
)
docker compose up -d
if errorlevel 1 exit /b 1
echo Waiting for the validators to start sealing blocks...
python scripts\wait_for_chain.py
exit /b %errorlevel%
