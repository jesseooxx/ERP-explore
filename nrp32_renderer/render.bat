@echo off
REM Quick render script - uses the 32-bit Python environment
REM Usage: render.bat input.tmp [output.pdf]

if "%1"=="" (
    echo Usage: render.bat input.tmp [output.pdf]
    exit /b 1
)

REM Activate virtual environment and run
call "%~dp0.venv32\Scripts\activate.bat" 2>nul
if errorlevel 1 (
    echo Virtual environment not found. Run setup_env.bat first.
    exit /b 1
)

python "%~dp0nrp32_renderer.py" %*
