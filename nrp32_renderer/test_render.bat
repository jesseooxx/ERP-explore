@echo off
REM Test script for render_to_pdf_enhanced.py
REM This demonstrates how to use the renderer

echo ========================================
echo Testing Enhanced TMP to PDF Renderer
echo ========================================
echo.

REM Check if test.tmp exists
if not exist "C:\temp\test.tmp" (
    echo ERROR: Test file not found: C:\temp\test.tmp
    echo Please create a test .tmp file first
    pause
    exit /b 1
)

REM Create output directory
if not exist "C:\temp\output" mkdir "C:\temp\output"

echo Input file: C:\temp\test.tmp
echo Output file: C:\temp\output\test_rendered.pdf
echo.

REM Run the enhanced renderer (with bitmap capture)
echo Running enhanced renderer...
py -3.12-32 render_to_pdf_enhanced.py C:\temp\test.tmp C:\temp\output\test_rendered.pdf 150

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo SUCCESS!
    echo ========================================
    echo.
    echo Opening PDF...
    start C:\temp\output\test_rendered.pdf
) else (
    echo.
    echo ========================================
    echo FAILED!
    echo ========================================
)

pause
