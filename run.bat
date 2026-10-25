@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo   CyberShield: Firewall & Intrusion Detection System
echo   Academic Prototype Launcher
echo =======================================================
echo.

:: 1. Check if Python is installed and accessible
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python is not found on your system PATH!
    echo Please install Python 3.10+ from python.org and add it to PATH.
    echo.
    pause
    exit /b 1
)

echo [OK] Python detected.

:: 2. Create virtual environment if it doesn't exist
if not exist ".venv\Scripts\python.exe" (
    echo [*] Creating local virtual environment in .venv ...
    python -m venv .venv
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to create virtual environment!
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created.
) else (
    echo [OK] Existing virtual environment found.
)

:: 3. Install/verify requirements
echo [*] Checking dependencies from requirements.txt ...
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to install required packages!
    pause
    exit /b 1
)
echo [OK] Dependencies verified.

:: 4. Launch Streamlit Application
echo.
echo =======================================================
echo   Starting CyberShield Streamlit App...
echo   Open your browser at http://localhost:8501
echo =======================================================
echo.

.\.venv\Scripts\streamlit.exe run app.py

:: 5. Keep terminal open if execution terminates or errors
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Application exited with error code %ERRORLEVEL%.
    pause
)
