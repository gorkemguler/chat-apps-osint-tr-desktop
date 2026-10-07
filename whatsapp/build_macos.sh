#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "Bu paket macOS üzerinde oluşturulmalıdır." >&2
    exit 1
fi

BUILD_PYTHON="${BUILD_PYTHON:-python3}"
if ! command -v "$BUILD_PYTHON" >/dev/null 2>&1; then
    echo "Python 3 bulunamadı. Python ve Tk 8.6+ kurun." >&2
    exit 1
fi

if ! "$BUILD_PYTHON" - <<'PY'
import sys
try:
    import tkinter
except ImportError:
    sys.exit("Tkinter bulunamadı. Tk desteği olan bir Python kurulumu seçin.")
if sys.version_info < (3, 10):
    sys.exit("Python 3.10 veya üzeri gereklidir.")
if tkinter.TkVersion < 8.6:
    sys.exit("Tk 8.6 veya üzeri gereklidir. Tk desteği olan güncel bir Python seçin.")
PY
then
    exit 1
fi

"$BUILD_PYTHON" -m venv .venv-macos
.venv-macos/bin/python -m pip install --disable-pip-version-check 'pyinstaller>=6,<7'
.venv-macos/bin/python -m PyInstaller --noconfirm --clean --onedir --windowed \
    --name WhatsAppRaporGoruntuleyici \
    --hidden-import wa_peer \
    --add-data '../LICENSE:.' \
    wa_peer_gui.py

echo
echo "macOS uygulaması: $(pwd)/dist/WhatsAppRaporGoruntuleyici.app"
echo "Bu sürüm mevcut raporları görüntüler; macOS üzerinde canlı yakalama desteklenmez."
