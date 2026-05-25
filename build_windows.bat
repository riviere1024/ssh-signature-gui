@echo off
REM Build the Windows .exe via PyInstaller.
REM
REM Prereqs (one-time setup on Windows):
REM   1. Install uv:  https://docs.astral.sh/uv/getting-started/installation/
REM   2. cd into the project root, then:  uv sync
REM
REM Usage:
REM   build_windows.bat

setlocal
cd /d "%~dp0"

set "APP_NAME=SSH Signature"
set "VERSION=0.1.0"

echo ==^> Cleaning previous build artifacts
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo ==^> Building .exe with PyInstaller
uv run pyinstaller ^
  --name "%APP_NAME%" ^
  --windowed ^
  --onefile ^
  --noconfirm ^
  --clean ^
  main.py

if not exist "dist\%APP_NAME%.exe" (
  echo.
  echo ERROR: build failed - dist\%APP_NAME%.exe not found
  exit /b 1
)

echo.
echo ============================================================
echo Build complete.
echo   .exe: dist\%APP_NAME%.exe
echo ============================================================
echo To run: double-click dist\%APP_NAME%.exe in File Explorer
