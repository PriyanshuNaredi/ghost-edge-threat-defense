@echo off
rem Build and run the Ghost gateway (default :8090, simulator ON).
setlocal
cd /d "%~dp0.."
go build -o ghost.exe .
ghost.exe %*
