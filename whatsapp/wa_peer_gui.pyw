"""Windows'ta çift tıklayarak konsolsuz arayüzü açar."""

import sys


if __name__ == "__main__":
    try:
        from wa_peer_gui import main
        main()
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        if sys.platform == "win32":
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                None, detail, "WhatsApp Arama Raporu başlatılamadı", 0x10)
        else:
            print(detail, file=sys.stderr)
        raise SystemExit(1)
