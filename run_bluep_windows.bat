@echo off
echo Starting Bluep Collaborative Editor for Windows...
echo.
cd /d "%~dp0"
call .venv\Scripts\activate.bat
python -c "from bluep.bluep_windows import main; main()"
