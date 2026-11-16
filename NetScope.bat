@echo off
rem NetScope - lanzador
cd /d "%~dp0"
py -3.11 main.py
if errorlevel 1 pause
