@echo off
REM NRP32 Renderer Environment Setup
REM This script sets up a 32-bit Python environment for DLL calls

echo ============================================
echo NRP32 Native Renderer - Environment Setup
echo ============================================
echo.

REM Check if 32-bit Python is installed
set PYTHON32=

REM Try common 32-bit Python locations
if exist "C:\Python312-32\python.exe" set PYTHON32=C:\Python312-32\python.exe
if exist "C:\Python311-32\python.exe" set PYTHON32=C:\Python311-32\python.exe
if exist "C:\Python310-32\python.exe" set PYTHON32=C:\Python310-32\python.exe
if exist "%LOCALAPPDATA%\Programs\Python\Python312-32\python.exe" set PYTHON32=%LOCALAPPDATA%\Programs\Python\Python312-32\python.exe
if exist "%LOCALAPPDATA%\Programs\Python\Python311-32\python.exe" set PYTHON32=%LOCALAPPDATA%\Programs\Python\Python311-32\python.exe

if "%PYTHON32%"=="" (
    echo ERROR: 32-bit Python not found!
    echo.
    echo Please install 32-bit Python:
    echo 1. Go to https://www.python.org/downloads/
    echo 2. Click "Download Python 3.12.x"
    echo 3. Scroll down and select "Windows installer (32-bit)"
    echo 4. Run the installer
    echo 5. IMPORTANT: Check "Add Python to PATH"
    echo 6. Run this script again
    echo.
    pause
    exit /b 1
)

echo Found 32-bit Python: %PYTHON32%
echo.

REM Check Python architecture
"%PYTHON32%" -c "import struct; print('Python is', struct.calcsize('P')*8, 'bit')"
echo.

REM Create virtual environment
echo Creating virtual environment...
"%PYTHON32%" -m venv .venv32
if errorlevel 1 (
    echo Failed to create virtual environment
    pause
    exit /b 1
)

REM Activate and install dependencies
echo Installing dependencies...
call .venv32\Scripts\activate.bat
pip install pywin32
if errorlevel 1 (
    echo Failed to install pywin32
    pause
    exit /b 1
)

echo.
echo ============================================
echo Setup complete!
echo ============================================
echo.
echo To use the renderer:
echo   1. Activate environment: .venv32\Scripts\activate.bat
echo   2. Run: python nrp32_renderer.py input.tmp output.pdf
echo.
echo Or use render.bat for quick rendering.
echo.
pause
