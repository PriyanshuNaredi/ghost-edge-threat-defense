@echo off
rem Start the HUD dev server. Calls vite directly: the '^&' in the parent folder
rem name breaks `npm run` under cmd.exe on Windows.
setlocal
cd /d "%~dp0.."
node node_modules\vite\bin\vite.js %*
