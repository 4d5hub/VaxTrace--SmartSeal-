@echo off
cd /d "%~dp0"
if not exist .venv (
  python -m venv .venv
  call .venv\Scripts\activate.bat
  pip install -r requirements-dev.txt
) else (
  call .venv\Scripts\activate.bat
)
echo === gateway ===
cd gateway && python -m pytest -q && cd ..
if errorlevel 1 exit /b 1
echo === smart contracts (real Solidity, in-process EVM) ===
cd blockchain\tests && python -m pytest -q && cd ..\..
if errorlevel 1 exit /b 1
echo === integration: verifier, custody, 15 attack scenarios, end to end ===
cd integration && python -m pytest -q && cd ..
exit /b %errorlevel%
