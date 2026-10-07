@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if errorlevel 1 (
    echo Python 3 bulunamadi. Once Windows icin Python 3 yukleyin.
    pause
    exit /b 1
)

py -3 -m venv .venv
if errorlevel 1 (
    echo Sanal Python ortami olusturulamadi.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" -m pip install -r requirements.txt pyinstaller
if errorlevel 1 (
    echo Gerekli paketler yuklenemedi.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name WhatsAppAramaRaporu --collect-all frida --hidden-import wa_peer ^
    wa_peer_gui.pyw
if errorlevel 1 (
    echo EXE olusturulamadi.
    pause
    exit /b 1
)

copy /Y "..\LICENSE" "dist\LICENSE.txt" >nul
echo.
echo Uygulama hazir: %~dp0dist\WhatsAppAramaRaporu.exe
echo Windows uzerinde gercek bir aramayla test edin.
pause
