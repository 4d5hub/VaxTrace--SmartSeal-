@echo off
cd /d "%~dp0"
docker compose down -v
if exist nodes rmdir /s /q nodes
if exist genesis\networkFiles rmdir /s /q genesis\networkFiles
if exist genesis\genesis.json del genesis\genesis.json
if exist deployment.json del deployment.json
if exist .env del .env
mkdir nodes
echo Network reset.
