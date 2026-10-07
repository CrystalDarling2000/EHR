@echo off
rem Start the HyL-EHR demo console on Windows. Needs Python 3.10+ and:  pip install cryptography
cd /d "%~dp0"
python demo_app\app.py
pause
