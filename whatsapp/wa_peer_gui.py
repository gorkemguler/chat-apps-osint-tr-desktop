"""Windows yakalama ve tüm sistemlerde rapor inceleme masaüstü arayüzü."""

from __future__ import annotations

import datetime as dt
import json
import math
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk


MAX_IMPORT_BYTES = 50 * 1024 * 1024
MAX_RAW_EVENTS = 100_000
MAX_RAW_LINE_BYTES = 1024 * 1024


class ReportInputError(ValueError):
    """Kullanıcıya gösterilecek, içe aktarma dosyasıyla ilgili hata."""


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Geçersiz sayı: {value}")


def _valid_number(value: object) -> bool:
    return (not isinstance(value, bool) and isinstance(value, (int, float))
            and abs(value) <= 10**18 and math.isfinite(value))


def _read_limited(path: Path) -> bytes:
    try:
        if not path.is_file():
            raise ReportInputError("Seçilen dosya bulunamadı.")
        if path.stat().st_size > MAX_IMPORT_BYTES:
            raise ReportInputError("Dosya 50 MB sınırını aşıyor.")
        with path.open("rb") as stream:
            data = stream.read(MAX_IMPORT_BYTES + 1)
    except OSError as exc:
        raise ReportInputError(f"Dosya okunamadı: {exc}") from exc
    if len(data) > MAX_IMPORT_BYTES:
        raise ReportInputError("Dosya 50 MB sınırını aşıyor.")
    if not data:
        raise ReportInputError("Seçilen dosya boş.")
    return data


def _validate_report(report: object) -> dict:
    """HTML üreticisinin beklediği rapor yapısını denetle."""
    if not isinstance(report, dict):
        raise ReportInputError("JSON dosyası bir rapor nesnesi içermiyor.")
    if not isinstance(report.get("capture"), dict) or not isinstance(report.get("peer"), dict):
        raise ReportInputError("JSON dosyasında capture veya peer bölümü yok.")
    peer = report["peer"]
    for key in ("identity", "network", "relays", "behaviour", "fingerprint", "correlation"):
        if key in peer and not isinstance(peer[key], dict):
            raise ReportInputError(f"Rapordaki peer.{key} bölümü geçersiz.")
    network = peer.get("network", {})
    for key in ("telemetry_view", "medium", "nat"):
        if key in network and not isinstance(network[key], dict):
            raise ReportInputError(f"Rapordaki network.{key} bölümü geçersiz.")
    if network.get("geolocation") is not None and not isinstance(network["geolocation"], dict):
        raise ReportInputError("Rapordaki konum bölümü geçersiz.")
    for key in ("public_endpoints", "private_endpoints"):
        value = network.get(key, [])
        if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
            raise ReportInputError(f"Rapordaki network.{key} listesi geçersiz.")
    relays = peer.get("relays", {})
    if "servers" in relays and (not isinstance(relays["servers"], list)
                                or not all(isinstance(item, str) for item in relays["servers"])):
        raise ReportInputError("Rapordaki aktarma sunucuları listesi geçersiz.")
    latency = relays.get("latency", [])
    if not isinstance(latency, list) or not all(isinstance(item, dict) for item in latency):
        raise ReportInputError("Rapordaki gecikme listesi geçersiz.")
    for row in latency:
        delta = row.get("delta_ms")
        if delta is not None and not _valid_number(delta):
            raise ReportInputError("Rapordaki gecikme değeri geçersiz.")
    geo = network.get("geolocation") or {}
    for key, limit in (("lat", 90), ("lon", 180)):
        value = geo.get(key)
        if value is not None and (not _valid_number(value) or abs(value) > limit):
            raise ReportInputError(f"Rapordaki {key} koordinatı geçersiz.")
    behaviour = peer.get("behaviour", {})
    if behaviour.get("speech_activity") is not None and not isinstance(behaviour["speech_activity"], dict):
        raise ReportInputError("Rapordaki konuşma etkinliği bölümü geçersiz.")
    correlation = peer.get("correlation", {})
    if "call_ids" in correlation and (not isinstance(correlation["call_ids"], list)
                                      or not all(isinstance(item, str) for item in correlation["call_ids"])):
        raise ReportInputError("Rapordaki arama kimlikleri listesi geçersiz.")
    if "self" in report and not isinstance(report["self"], dict):
        raise ReportInputError("Rapordaki self bölümü geçersiz.")
    if "caveats" in report and not isinstance(report["caveats"], list):
        raise ReportInputError("Rapordaki uyarılar listesi geçersiz.")
    return report


def load_report_json(path: Path) -> dict:
    """Sınırlı boyuttaki Windows rapor JSON'unu aç ve denetle."""
    data = _read_limited(path)
    try:
        report = json.loads(data.decode("utf-8-sig"), parse_constant=_reject_json_constant)
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ReportInputError(f"JSON raporu okunamadı: {exc}") from exc
    return _validate_report(report)


def load_raw_events(path: Path) -> list[dict]:
    """Ham JSONL olaylarını boyut ve temel alan denetimleriyle oku."""
    data = _read_limited(path)
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError as exc:
        raise ReportInputError("JSONL dosyası UTF-8 biçiminde değil.") from exc
    events = []
    for number, line in enumerate(text.splitlines(), 1):
        if len(line.encode("utf-8")) > MAX_RAW_LINE_BYTES:
            raise ReportInputError(f"{number}. satır 1 MB sınırını aşıyor.")
        if not line.strip():
            continue
        if len(events) >= MAX_RAW_EVENTS:
            raise ReportInputError("JSONL dosyası 100.000 olay sınırını aşıyor.")
        try:
            event = json.loads(line, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise ReportInputError(f"JSONL dosyasının {number}. satırı geçersiz: {exc}") from exc
        if not isinstance(event, dict) or not isinstance(event.get("event"), str):
            raise ReportInputError(f"{number}. satırda geçerli bir olay türü yok.")
        ts = event.get("ts")
        if not _valid_number(ts):
            raise ReportInputError(f"{number}. satırda geçerli bir zaman damgası yok.")
        if "ctx" in event and not isinstance(event["ctx"], str):
            raise ReportInputError(f"{number}. satırdaki bağlam değeri geçersiz.")
        kind = event["event"]
        if kind in ("field_stat", "field_stat_str"):
            if not isinstance(event.get("name"), str):
                raise ReportInputError(f"{number}. satırdaki alan adı geçersiz.")
            value = event.get("value")
            if kind == "field_stat" and value is not None and not _valid_number(value):
                raise ReportInputError(f"{number}. satırdaki sayısal değer geçersiz.")
            if kind == "field_stat_str" and value is not None and not isinstance(value, str):
                raise ReportInputError(f"{number}. satırdaki metin değeri geçersiz.")
        elif kind == "endpoint":
            for key in ("ipv4", "ipv6"):
                if event.get(key) is not None and not isinstance(event[key], str):
                    raise ReportInputError(f"{number}. satırdaki {key} adresi geçersiz.")
            for key in ("ipv4_port", "ipv6_port"):
                value = event.get(key)
                if value is not None and (isinstance(value, bool) or not isinstance(value, int)
                                          or not 0 <= value <= 65535):
                    raise ReportInputError(f"{number}. satırdaki bağlantı noktası geçersiz.")
        elif kind == "peer_audio_level":
            value = event.get("level")
            if value is not None and not _valid_number(value):
                raise ReportInputError(f"{number}. satırdaki ses düzeyi geçersiz.")
        elif kind == "peer_device_count":
            value = event.get("device_count")
            if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
                raise ReportInputError(f"{number}. satırdaki cihaz sayısı geçersiz.")
        elif kind == "peer_offer_msg":
            values = event.get("strings", [])
            if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                raise ReportInputError(f"{number}. satırdaki arama dizeleri geçersiz.")
        events.append(event)
    if not events:
        raise ReportInputError("JSONL dosyasında olay bulunamadı.")
    return events


def default_report_dir() -> Path:
    documents = Path.home() / "Documents"
    return (documents if documents.is_dir() else Path.home()) / "WhatsApp Raporları"


def has_peer_data(report: dict) -> bool:
    """Yalnızca karşı tarafa ait alanları yakalama verisi olarak say."""
    def present(value) -> bool:
        if isinstance(value, dict):
            return any(present(item) for key, item in value.items()
                       if not str(key).startswith("_"))
        if isinstance(value, (list, tuple)):
            return any(present(item) for item in value)
        return value is not None and value != ""

    peer = report.get("peer", {})
    identity = peer.get("identity", {})
    network = peer.get("network", {})
    medium = network.get("medium", {})
    nat = network.get("nat", {})
    behaviour = peer.get("behaviour", {})
    fingerprint = peer.get("fingerprint", {})
    correlation = peer.get("correlation", {})
    peer_fields = (
        {key: value for key, value in identity.items() if key != "_note"},
        network.get("public_endpoints"),
        network.get("private_endpoints"),
        network.get("telemetry_view", {}).get("peer_public_ip_masked"),
        network.get("telemetry_view", {}).get("peer_lan_prefix_masked"),
        medium.get("peer"),
        nat.get("symmetric"),
        nat.get("ipv6_capable"),
        nat.get("p2p_disabled"),
        {key: value for key, value in behaviour.items() if key != "_note"},
        {key: value for key, value in fingerprint.items() if key != "_note"},
        {key: value for key, value in correlation.items() if key != "_note"},
    )
    return any(present(field) for field in peer_fields)


def open_local_path(path: Path) -> None:
    if sys.platform == "win32":
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


class WhatsAppCaptureApp:
    def __init__(self, root: tk.Tk, initial_source: Path | None = None) -> None:
        self.root = root
        self.capture_supported = sys.platform == "win32"
        self.root.title("WhatsApp Arama Raporu")
        self.root.geometry("800x720" if self.capture_supported else "800x560")
        self.root.minsize(650, 610 if self.capture_supported else 480)

        self.messages: queue.Queue[tuple[str, object]] = queue.Queue()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.worker_kind: str | None = None
        self.active = False
        self.closing = False
        self.destroyed = False
        self.hooks_ready = threading.Event()
        self.last_html: Path | None = None
        self.last_folder: Path | None = None
        self.current_raw: Path | None = None

        self.source_var = tk.StringVar()
        self.summary_var = tk.StringVar(value="Henüz rapor seçilmedi.")
        self.process_var = tk.StringVar(value="WhatsApp.Root.exe")
        self.seconds_var = tk.StringVar(value="0")
        self.outdir_var = tk.StringVar(value=str(default_report_dir()))
        self.lookup_var = tk.BooleanVar(value=False)
        self.import_lookup_var = tk.BooleanVar(value=False)
        self.raw_var = tk.BooleanVar(value=False)
        self.open_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Hazır")

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.after(100, self._poll_messages)
        if initial_source is not None:
            self.source_var.set(str(initial_source))
            if self.capture_supported:
                self.notebook.select(self.report_page)
            self.root.after(200, self._start_report_import)

    def _build_ui(self) -> None:
        style = ttk.Style(self.root)
        title_font = "Segoe UI" if self.capture_supported else "Helvetica"
        style.configure("Title.TLabel", font=(title_font, 19, "bold"))
        style.configure("Note.TLabel", foreground="#585e67")
        style.configure("Status.TLabel", font=(title_font, 10, "bold"))

        outer = ttk.Frame(self.root, padding=18)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="WhatsApp Arama Raporu",
                  style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text=("Yalnızca kendi hesaplarınızda, açık rızayla veya yetkili bir çalışma kapsamında kullanın."
                  if self.capture_supported else
                  "Windows'ta oluşturulan raporları açın veya ham olaylardan yeni rapor üretin."),
            style="Note.TLabel", wraplength=740,
        ).pack(anchor="w", pady=(4, 16))

        if self.capture_supported:
            self.notebook = ttk.Notebook(outer)
            self.notebook.pack(fill="x")
            capture_parent = ttk.Frame(self.notebook, padding=(0, 10, 0, 0))
            self.report_page = ttk.Frame(self.notebook, padding=(0, 10, 0, 0))
            self.notebook.add(capture_parent, text="Canlı yakalama")
            self.notebook.add(self.report_page, text="Rapor inceleme")
        else:
            self._build_report_controls(outer)
            self._build_footer(outer)
            return

        settings = ttk.LabelFrame(capture_parent, text="Yakalama ayarları", padding=12)
        settings.pack(fill="x")
        settings.columnconfigure(1, weight=1)

        ttk.Label(settings, text="WhatsApp işlemi").grid(
            row=0, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Entry(settings, textvariable=self.process_var).grid(
            row=0, column=1, sticky="ew", columnspan=2, pady=5)

        ttk.Label(settings, text="Rapor klasörü").grid(
            row=1, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Entry(settings, textvariable=self.outdir_var).grid(
            row=1, column=1, sticky="ew", pady=5)
        ttk.Button(settings, text="Gözat…", command=self._browse).grid(
            row=1, column=2, padx=(8, 0), pady=5)

        ttk.Label(settings, text="Süre (saniye)").grid(
            row=2, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Entry(settings, textvariable=self.seconds_var, width=12).grid(
            row=2, column=1, sticky="w", pady=5)
        ttk.Label(settings, text="0 = Durdur'a basılana kadar",
                  style="Note.TLabel").grid(row=2, column=2, sticky="w", padx=(8, 0))

        ttk.Checkbutton(
            settings, variable=self.lookup_var,
            text="IP konumunu çevrim içi sorgula (ipwho.is)",
        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(10, 2))
        ttk.Label(
            settings,
            text="Açılırsa karşı tarafın genel IP adresi HTTPS ile ipwho.is servisine gönderilir. Harita açıldığında OpenStreetMap'e döşeme istekleri yapılır.",
            style="Note.TLabel", wraplength=700,
        ).grid(row=4, column=0, columnspan=3, sticky="w", pady=(0, 6))
        ttk.Checkbutton(
            settings, variable=self.raw_var,
            text="Ham olay akışını ayrıca kaydet (JSONL)",
        ).grid(row=5, column=0, columnspan=3, sticky="w", pady=2)
        ttk.Checkbutton(
            settings, variable=self.open_var,
            text="Bitince HTML raporunu aç",
        ).grid(row=6, column=0, columnspan=3, sticky="w", pady=2)

        actions = ttk.Frame(capture_parent)
        actions.pack(fill="x", pady=(16, 8))
        self.start_button = ttk.Button(actions, text="Yakalamayı başlat",
                                       command=self._start)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(actions, text="Durdur ve rapor oluştur",
                                      command=self._stop, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))
        self.progress = ttk.Progressbar(actions, mode="indeterminate", length=140)
        self.progress.pack(side="right")

        ttk.Label(
            capture_parent,
            text="Eksik kalmaması için önce aramayı WhatsApp içinde bitirin; sonra yakalamayı durdurun.",
            style="Note.TLabel", wraplength=740,
        ).pack(anchor="w", pady=(0, 8))

        self._build_report_controls(self.report_page)
        self._build_footer(outer)

    def _build_report_controls(self, outer: ttk.Frame) -> None:
        settings = ttk.LabelFrame(outer, text="Rapor inceleme", padding=12)
        settings.pack(fill="x")
        settings.columnconfigure(1, weight=1)

        ttk.Label(settings, text="Rapor dosyası").grid(
            row=0, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Entry(settings, textvariable=self.source_var).grid(
            row=0, column=1, sticky="ew", pady=5)
        ttk.Button(settings, text="Dosya seç…", command=self._pick_source).grid(
            row=0, column=2, padx=(8, 0), pady=5)

        ttk.Label(settings, text="Rapor klasörü").grid(
            row=1, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Entry(settings, textvariable=self.outdir_var).grid(
            row=1, column=1, sticky="ew", pady=5)
        ttk.Button(settings, text="Gözat…", command=self._browse).grid(
            row=1, column=2, padx=(8, 0), pady=5)

        ttk.Label(
            settings,
            text="JSON ve JSONL'den yeni JSON/HTML raporu üretilir; HTML dosyası doğrudan açılır.",
            style="Note.TLabel", wraplength=700,
        ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 2))
        ttk.Checkbutton(
            settings, variable=self.import_lookup_var,
            text="JSONL'den rapor üretirken IP konumunu çevrim içi sorgula (ipwho.is)",
        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(6, 2))
        ttk.Label(
            settings,
            text="Açılırsa rapordaki genel IP adresi HTTPS ile ipwho.is servisine gönderilir. Varsayılan: kapalı.",
            style="Note.TLabel", wraplength=700,
        ).grid(row=4, column=0, columnspan=3, sticky="w", pady=(0, 2))

        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=(16, 8))
        self.import_button = ttk.Button(
            actions, text="Raporu incele", command=self._start_report_import)
        self.import_button.pack(side="left")
        self.import_progress = ttk.Progressbar(actions, mode="indeterminate", length=140)
        self.import_progress.pack(side="right")

        summary = ttk.LabelFrame(outer, text="Rapor özeti", padding=10)
        summary.pack(fill="x", pady=(4, 8))
        ttk.Label(summary, textvariable=self.summary_var,
                  wraplength=720).pack(anchor="w")

    def _build_footer(self, outer: ttk.Frame) -> None:
        ttk.Label(outer, textvariable=self.status_var,
                  style="Status.TLabel").pack(anchor="w", pady=(0, 8))

        log_frame = ttk.LabelFrame(outer, text="Durum günlüğü", padding=8)
        log_frame.pack(fill="both", expand=True)
        self.log = scrolledtext.ScrolledText(
            log_frame, height=9, state="disabled", wrap="word",
            font=("Consolas" if self.capture_supported else "monospace", 10))
        self.log.pack(fill="both", expand=True)

        outputs = ttk.Frame(outer)
        outputs.pack(fill="x", pady=(12, 0))
        self.report_button = ttk.Button(
            outputs, text="Son raporu aç", command=self._open_report,
            state="disabled")
        self.report_button.pack(side="left")
        self.folder_button = ttk.Button(
            outputs, text="Rapor klasörünü aç", command=self._open_folder,
            state="disabled")
        self.folder_button.pack(side="left", padx=(8, 0))

    def _browse(self) -> None:
        selected = filedialog.askdirectory(
            parent=self.root,
            initialdir=self.outdir_var.get() or str(Path.home()),
            title="Rapor klasörünü seçin",
        )
        if selected:
            self.outdir_var.set(selected)

    def _pick_source(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self.root,
            initialdir=str(Path.home()),
            title="Rapor dosyası seçin",
            filetypes=[("WhatsApp raporları", "*.json *.jsonl *.html"),
                       ("JSON raporu", "*.json"),
                       ("Ham olaylar", "*.jsonl"),
                       ("HTML raporu", "*.html")],
        )
        if selected:
            self.source_var.set(selected)

    def _start_report_import(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("İşlem sürüyor", "Önce devam eden işlemi tamamlayın.",
                                parent=self.root)
            return
        source_text = self.source_var.get().strip()
        if not source_text:
            messagebox.showerror("Eksik bilgi", "Önce bir rapor dosyası seçin.",
                                 parent=self.root)
            return
        try:
            source = Path(source_text).expanduser().resolve()
        except (OSError, RuntimeError) as exc:
            messagebox.showerror("Rapor dosyası açılamadı", str(exc), parent=self.root)
            return
        if source.suffix.lower() not in (".json", ".jsonl", ".html"):
            messagebox.showerror("Desteklenmeyen dosya",
                                 "JSON, JSONL veya HTML raporu seçin.", parent=self.root)
            return

        outdir = None
        if source.suffix.lower() != ".html":
            outdir_text = self.outdir_var.get().strip()
            if not outdir_text:
                messagebox.showerror("Eksik bilgi", "Rapor klasörünü seçin.",
                                     parent=self.root)
                return
            try:
                outdir = Path(outdir_text).expanduser().resolve()
                outdir.mkdir(parents=True, exist_ok=True)
                if not outdir.is_dir():
                    raise NotADirectoryError(str(outdir))
            except (OSError, RuntimeError) as exc:
                messagebox.showerror("Rapor klasörü açılamadı", str(exc),
                                     parent=self.root)
                return

        self.last_html = None
        self.last_folder = None
        self.report_button.configure(state="disabled")
        self.folder_button.configure(state="disabled")
        self.import_button.configure(state="disabled")
        self.import_progress.start(12)
        self.active = True
        self.worker_kind = "report"
        self.status_var.set("Rapor işleniyor…")
        self.summary_var.set("Dosya inceleniyor…")
        self._append_log(f"Dosya seçildi: {source.name}")
        self.worker = threading.Thread(
            target=self._run_report_import,
            args=(source, outdir, self.import_lookup_var.get()),
            name="wa-peer-report-import", daemon=True)
        self.worker.start()

    def _run_report_import(self, source: Path, outdir: Path | None,
                           geo_lookup: bool) -> None:
        try:
            suffix = source.suffix.lower()
            if suffix == ".html":
                _read_limited(source)
                report, json_path, html_path = None, None, source
            else:
                import wa_peer
                if suffix == ".json":
                    report = load_report_json(source)
                else:
                    events = load_raw_events(source)
                    report = wa_peer.build_report(events, geo_lookup=geo_lookup)
                json_path_text, html_path_text = wa_peer.write_outputs(
                    report, outdir=str(outdir), open_browser=False)
                json_path, html_path = Path(json_path_text), Path(html_path_text)
        except ReportInputError as exc:
            self.messages.put(("report_error", str(exc)))
        except (OSError, TypeError, ValueError, KeyError, RecursionError) as exc:
            self.messages.put(("report_error", f"Rapor işlenemedi: {exc}"))
        except Exception as exc:
            self.messages.put(("report_error", f"Rapor oluşturulamadı: {type(exc).__name__}: {exc}"))
        else:
            self.messages.put(("report_done", (report, json_path, html_path)))

    def _report_done(self, report: dict | None, json_path: Path | None,
                     html_path: Path) -> None:
        self.active = False
        self.worker_kind = None
        self.import_progress.stop()
        self.import_button.configure(state="normal")
        self.last_html = html_path.resolve()
        self.last_folder = self.last_html.parent
        self.report_button.configure(state="normal")
        self.folder_button.configure(state="normal")
        if json_path is not None:
            self._append_log(f"JSON: {json_path.resolve()}")
        self._append_log(f"HTML: {self.last_html}")
        if report is None:
            self.summary_var.set("Mevcut HTML raporu açılmaya hazır.")
            self.status_var.set("HTML raporu hazır.")
        else:
            capture = report.get("capture", {})
            events = capture.get("events", "?")
            duration = capture.get("duration_s", "?")
            peer_state = ("Karşı taraf verisi var." if has_peer_data(report)
                          else "Karşı taraf verisi bulunamadı.")
            self.summary_var.set(f"{events} olay · {duration} saniye · {peer_state}")
            self.status_var.set("Rapor hazır.")
        if self.closing:
            self._destroy()
        else:
            self._open_report()

    def _report_error(self, message: str) -> None:
        self.active = False
        self.worker_kind = None
        self.import_progress.stop()
        self.import_button.configure(state="normal")
        self.status_var.set("Rapor açılamadı.")
        self.summary_var.set("Dosya biçimini ve boyutunu kontrol edin.")
        self._append_log(message)
        if self.closing:
            self._destroy()
        else:
            messagebox.showerror("Rapor hatası", message, parent=self.root)

    def _append_log(self, message: str) -> None:
        when = dt.datetime.now().strftime("%H:%M:%S")
        self.log.configure(state="normal")
        self.log.insert("end", f"[{when}] {message}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _start(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("İşlem sürüyor", "Önce devam eden işlemi tamamlayın.",
                                parent=self.root)
            return
        process = self.process_var.get().strip()
        if not process:
            messagebox.showerror("Eksik bilgi", "WhatsApp işlem adını girin.",
                                 parent=self.root)
            return
        try:
            seconds = float(self.seconds_var.get().strip())
            if not math.isfinite(seconds) or seconds < 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Geçersiz süre",
                                 "Süre için 0 veya pozitif bir sayı girin.",
                                 parent=self.root)
            return
        outdir_text = self.outdir_var.get().strip()
        if not outdir_text:
            messagebox.showerror("Eksik bilgi", "Rapor klasörünü seçin.",
                                 parent=self.root)
            return
        outdir = Path(outdir_text).expanduser().resolve()
        try:
            outdir.mkdir(parents=True, exist_ok=True)
            if not outdir.is_dir():
                raise NotADirectoryError(str(outdir))
        except OSError as exc:
            messagebox.showerror("Rapor klasörü açılamadı", str(exc),
                                 parent=self.root)
            return

        self.last_html = None
        self.last_folder = None
        self.hooks_ready.clear()
        self.report_button.configure(state="disabled")
        self.folder_button.configure(state="disabled")
        self.stop_event = threading.Event()
        self.active = True
        self.worker_kind = "capture"
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.progress.start(12)
        self.status_var.set("WhatsApp işlemine bağlanılıyor…")
        self._append_log("Yakalama başlatıldı. Aramayı WhatsApp içinde başlatın veya kabul edin.")

        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        raw_path = str(outdir / f"wa_peer_raw_{stamp}.jsonl") if self.raw_var.get() else None
        self.current_raw = Path(raw_path) if raw_path else None
        options = {
            "process": process,
            "seconds": seconds,
            "raw": raw_path,
            "outdir": str(outdir),
            "no_geo": not self.lookup_var.get(),
            "no_browser": True,
            "stop_event": self.stop_event,
            "status_callback": lambda text: self.messages.put(("log", str(text))),
            "event_callback": self._on_agent_event,
        }
        should_open = self.open_var.get()
        self.worker = threading.Thread(
            target=self._run_capture, args=(options, should_open),
            name="wa-peer-capture", daemon=True)
        self.worker.start()

    def _run_capture(self, options: dict, should_open: bool) -> None:
        try:
            import wa_peer
            report, json_path, html_path = wa_peer.run_capture(**options)
        except SystemExit:
            self.messages.put((
                "error",
                "Frida yüklenemedi. Bu klasördeki requirements.txt bağımlılıklarını kurun.",
            ))
        except Exception as exc:
            if type(exc).__name__ == "ProcessNotFoundError":
                text = "WhatsApp açık değil veya işlem adı farklı: " + options["process"]
            else:
                text = f"{type(exc).__name__}: {exc}"
            self.messages.put(("error", text))
        else:
            self.messages.put(("done", (report, json_path, html_path, should_open)))

    def _on_agent_event(self, payload: dict) -> None:
        event = payload.get("event")
        hooks_installed = bool(payload.get("hooked")) if event == "hook_ready" else False
        if hooks_installed:
            self.hooks_ready.set()
        self.messages.put(("event", (event, hooks_installed)))

    def _stop(self) -> None:
        if not self.worker or not self.worker.is_alive():
            return
        self.stop_event.set()
        self.stop_button.configure(state="disabled")
        self.status_var.set("Yakalama durduruluyor; rapor hazırlanıyor…")
        self._append_log("Durdurma istendi. Rapor oluşturuluyor.")

    def _poll_messages(self) -> None:
        try:
            for _ in range(100):
                kind, payload = self.messages.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "event":
                    if not self.active:
                        continue
                    event, hooks_installed = payload
                    if event == "hook_ready":
                        self.status_var.set(
                            "Bağlandı; arama verileri bekleniyor…"
                            if hooks_installed else "Bağlandı; kanca kurulamadı."
                        )
                    elif event == "waiting":
                        self.status_var.set("WhatsApp aramasını başlatın veya kabul edin…")
                elif kind == "done":
                    self._capture_done(*payload)
                elif kind == "error":
                    self._capture_error(str(payload))
                elif kind == "report_done":
                    self._report_done(*payload)
                elif kind == "report_error":
                    self._report_error(str(payload))
                if self.destroyed:
                    return
        except queue.Empty:
            pass
        if not self.destroyed:
            self.root.after(100, self._poll_messages)

    def _capture_done(self, report: dict, json_path: str, html_path: str,
                      should_open: bool) -> None:
        self.active = False
        self.worker_kind = None
        self.progress.stop()
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.last_html = Path(html_path).resolve()
        self.last_folder = self.last_html.parent
        self.report_button.configure(state="normal")
        self.folder_button.configure(state="normal")
        self._append_log(f"JSON: {Path(json_path).resolve()}")
        self._append_log(f"HTML: {self.last_html}")
        if self.current_raw and self.current_raw.is_file():
            self._append_log(f"Ham olaylar: {self.current_raw}")
        events = report.get("capture", {}).get("events", 0)
        if not self.hooks_ready.is_set():
            self.status_var.set("Rapor oluşturuldu; kancalar etkinleşmedi.")
            self._append_log("Uyarı: WhatsApp sürümü için kancalar kurulamadı.")
        elif not has_peer_data(report):
            self.status_var.set("Rapor oluşturuldu; karşı taraf verisi yakalanmadı.")
            self._append_log("Uyarı: Arama verisi yok. Aramayı başlatıp biraz bekleyin.")
        else:
            self.status_var.set(f"Rapor hazır · {events} olay")
        if should_open and not self.closing:
            self._open_report()
        if self.closing:
            self._destroy()

    def _capture_error(self, text: str) -> None:
        self.active = False
        self.worker_kind = None
        self.progress.stop()
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_var.set("Yakalama tamamlanamadı.")
        self._append_log(text)
        if self.current_raw and self.current_raw.is_file():
            self._append_log(f"Kısmi ham olay dosyası: {self.current_raw}")
        if not self.closing:
            messagebox.showerror("Yakalama hatası", text, parent=self.root)
        else:
            self._destroy()

    def _open_report(self) -> None:
        if self.last_html and self.last_html.is_file():
            try:
                open_local_path(self.last_html)
            except OSError as exc:
                messagebox.showerror("Rapor açılamadı", str(exc), parent=self.root)

    def _open_folder(self) -> None:
        if self.last_folder and self.last_folder.is_dir():
            try:
                open_local_path(self.last_folder)
            except OSError as exc:
                messagebox.showerror("Klasör açılamadı", str(exc), parent=self.root)

    def _close(self) -> None:
        if self.worker and self.worker.is_alive():
            self.closing = True
            if self.worker_kind == "capture":
                self.stop_event.set()
                self.start_button.configure(state="disabled")
                self.stop_button.configure(state="disabled")
                self.status_var.set("Kapatılıyor; rapor hazırlanıyor…")
                self._append_log("Kapatma istendi; yakalama güvenli biçimde sonlandırılıyor.")
            else:
                self.import_button.configure(state="disabled")
                self.status_var.set("İşlem tamamlanınca kapatılacak…")
        else:
            self._destroy()

    def _destroy(self) -> None:
        if not self.destroyed:
            self.destroyed = True
            self.root.destroy()


def main(argv: list[str] | None = None) -> None:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) > 1:
        raise SystemExit("Kullanım: wa_peer_gui.py [rapor.json|olaylar.jsonl|rapor.html]")
    initial_source = Path(arguments[0]).expanduser() if arguments else None
    root = tk.Tk()
    WhatsAppCaptureApp(root, initial_source=initial_source)
    root.mainloop()


if __name__ == "__main__":
    main()
