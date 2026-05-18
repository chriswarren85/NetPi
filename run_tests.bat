@echo off
REM Run the NetPi regression test suite on Windows
cd /d "%~dp0"
python -m pytest %*
