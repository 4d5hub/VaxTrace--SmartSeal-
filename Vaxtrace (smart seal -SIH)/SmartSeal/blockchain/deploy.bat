@echo off
cd /d "%~dp0"
python scripts\deploy.py --rpc http://127.0.0.1:8545
