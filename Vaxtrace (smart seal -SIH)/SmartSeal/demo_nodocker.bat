@echo off
setlocal
cd /d "%~dp0"
if not exist .venv (
  python -m venv .venv
  call .venv\Scripts\activate.bat
  pip install -r requirements-dev.txt
) else (
  call .venv\Scripts\activate.bat
)
start "" "%~dp0dashboard\index.html"
python integration\serve_stack.py --seed
