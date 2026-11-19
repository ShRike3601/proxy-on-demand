@echo off
rem Installs the one Python dependency (first run only), then opens the app.
cd /d "%~dp0"
where python >nul 2>nul || (
  echo Python is not installed. Get Python 3.11 or newer from https://www.python.org/downloads/windows/
  echo During setup, tick "Add python.exe to PATH". Then run this file again.
  pause
  exit /b 1
)
python -m pip install --user --quiet --disable-pip-version-check -r requirements.txt || (
  echo Could not install the requirements. Check your internet connection and try again.
  pause
  exit /b 1
)
start "" pythonw proxy_app.py
