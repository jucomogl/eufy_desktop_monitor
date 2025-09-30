import asyncio, threading, json, os, time, queue, sqlite3, datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from plyer import notification
import websockets

APP_TITLE = "Eufy Desktop Monitor"

# --------------------- Utils ---------------------
def now_ts():
    return datetime.datetime.now().isoformat(timespec="seconds")

def human_ts(dt=None):
    return (dt or datetime.datetime.now()).strftime("%Y-%m-%d %H:%M:%S")

# --------------------- Notifier ------------------
class Notifier:
    def __init__(self, cooldown=90):
        self.cooldown = cooldown
        self._last = {}
    def show(self, title, msg, key=None):
        t = time.time()
        if key and key in self._last and t - self._last[key] < self.cooldown: return
        if key: self._last[key] = t
        try:
            notification.notify(title=title, message=msg, timeout=5)
        except Exception:
            pass  # cicho – desktop powiadomienie opcjonalne

# --------------------- Incident Log --------------
class IncidentLog:
    def __init__(self, path="incidents.db"):
        self.path = path
        self._init()
    def _init(self):
        conn = sqlite3.connect(self.path)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS incidents(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            source TEXT NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            details TEXT
        )""")
        conn.commit(); conn.close()
    def add(self, source, type_, title, details=""):
        conn = sqlite3.connect(self.path)
        c = conn.cursor()
        c.execute("INSERT INTO incidents(ts,source,type,title,details) VALUES (?,?,?,?,?)",
                  (now_ts(), source, type_, title, details))
        conn.commit(); conn.close()

# --------------------- WS Client -----------------
class WSClient:
    """
    Łączy się z eufy-security-ws i wrzuca zdarzenia do kolejki GUI.
    """
    def __init__(self, ws_url, out_queue):
        self.ws_url = ws_url
        self.out_queue = out_queue
        self._stop = asyncio.Event()

    async def run(self):
        while not self._stop.is_set():
            try:
                async with websockets.connect(self.ws_url, ping_interval=20, ping_timeout=20) as ws:
                    await ws.send(json.dumps({"command":"initialize"}))
                    await ws.send(json.dumps({"command":"get_devices"}))
                    await ws.send(json.dumps({"command":"get_stations"}))
                    # sygnał do GUI
                    self.out_queue.put(("conn", {"status":"connected"}))
                    async for raw in ws:
                        try:
                            evt = json.loads(raw)
                        except Exception:
                            continue
                        self.out_queue.put(("event", evt))
            except Exception as e:
                self.out_queue.put(("conn", {"status":"disconnected", "error": str(e)}))
                await asyncio.sleep(5)

    def stop(self):
        self._stop.set()

# --------------------- Monitor Logic -------------
class MonitorLogic:
    """
    Przetwarza zdarzenia Eufy i generuje rekordy do GUI.
    """
    def __init__(self, cfg, gui_sink, notifier, log_db):
        self.cfg = cfg
        self.gui_sink = gui_sink        # callable: (type, payload) -> None (wątki-bezpieczne przez Queue)
        self.notifier = notifier
        self.log = log_db
        self.device_last_ok = {}        # sn -> datetime
        self.devices = {}               # sn -> {"name":..., "online":..., "last_event":...}

    def handle(self, kind, payload):
        if kind == "conn":
            self.gui_sink("conn", payload)
            return

        if kind != "event":
            return

        evt = payload
        t = evt.get("type","").lower()

        # --- urządzenia listy / właściwości ---
        if t in ("devices", "stations"):
            # pełne listy zwracane na start
            arr = evt.get("data") or []
            for d in arr:
                sn = d.get("serial_number") or d.get("device_sn") or d.get("station_sn")
                name = d.get("name") or d.get("device_name") or d.get("station_name") or sn
                online = d.get("state") in ("online","connected") or bool(d.get("online"))
                self.devices[sn] = {"name": name, "online": online, "last_event": None}
                if online:
                    self.device_last_ok[sn] = datetime.datetime.now()
                self.gui_sink("device_update", {"sn": sn, "name": name, "online": online, "last_event": None})
            return

        # --- zmiana właściwości pojedynczego urządzenia ---
        if t in ("device", "device update", "property changed"):
            sn = evt.get("device_sn") or evt.get("serial_number") or evt.get("device_id")
            name = evt.get("device_name") or evt.get("name") or sn
            props = evt.get("properties") or evt.get("data") or {}
            online = props.get("online") if isinstance(props.get("online"), bool) else (props.get("state") in ("online","connected"))
            if sn:
                dev = self.devices.setdefault(sn, {"name": name, "online": None, "last_event": None})
                dev["name"] = name
                if online is not None:
                    if online and not dev["online"]:
                        # recovery
                        self.notifier.show("Eufy: urządzenie wróciło", f"{name} online", key=f"rec_{sn}")
                        self.log.add(name, "recovery", "Device reachable", sn)
                    dev["online"] = online
                    if online:
                        self.device_last_ok[sn] = datetime.datetime.now()
                self.gui_sink("device_update", {"sn": sn, "name": name, "online": dev["online"], "last_event": dev["last_event"]})

            # detekcja długiej niedostępności
            self._maybe_flag_offline(sn, name)
            return

        # --- zdarzenia ruch/osoba/dzwonek ---
        if t in ("event", "station event", "device event"):
            name = evt.get("device_name") or evt.get("station_name") or "Eufy"
            action = evt.get("event_type") or evt.get("name") or evt.get("action") or "event"
            text = evt.get("message") or (evt.get("data") or {}).get("message") or ""
            sn = evt.get("device_sn") or evt.get("serial_number") or None

            if sn:
                dev = self.devices.setdefault(sn, {"name": name, "online": True, "last_event": None})
                dev["last_event"] = f"{action}: {text}"[:120]
                self.device_last_ok[sn] = datetime.datetime.now()
                self.gui_sink("device_update", {"sn": sn, "name": dev["name"], "online": dev["online"], "last_event": dev["last_event"]})

            self.gui_sink("log", f"{human_ts()}  [{name}] {action} — {text}")
            self.notifier.show(f"Eufy: {action}", f"{name}: {text}", key=f"evt_{name}_{action}")
            self.log.add(name, "alert", action, text)
            return

        # --- błędy globalne/urządzeń ---
        if t in ("error","station error","device error"):
            src = evt.get("device_name") or evt.get("station_name") or "Eufy"
            msg = evt.get("message") or str(evt)
            self.gui_sink("log", f"{human_ts()}  [ERROR] {src}: {msg}")
            self.notifier.show("Eufy: błąd", msg, key=f"err_{src}")
            self.log.add(src, "error", "Error", msg)
            return

    def _maybe_flag_offline(self, sn, name):
        if not sn: return
        last_ok = self.device_last_ok.get(sn)
        if not last_ok: return
        grace = self.cfg["health"]["offline_grace_seconds"]
        if (datetime.datetime.now() - last_ok).total_seconds() > grace:
            # oflaguj jako offline jeśli nie było już zgłoszone
            dev = self.devices.get(sn, {})
            if dev.get("online") is not False:
                dev["online"] = False
                self.gui_sink("device_update", {"sn": sn, "name": name, "online": False, "last_event": dev.get("last_event")})
                self.gui_sink("log", f"{human_ts()}  [INCIDENT] {name} offline")
                self.notifier.show("Eufy: urządzenie offline", f"{name} nie odpowiada.", key=f"off_{sn}")
                self.log.add(name, "incident", "Device offline", sn)

# --------------------- GUI -----------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("900x600")
        self.minsize(800, 500)

        self.queue = queue.Queue()
        self.ws_thread = None
        self.loop = None
        self.ws_client = None

        self.cfg = self._load_cfg()
        self.notifier = Notifier(self.cfg["notify"]["cooldown_seconds"])
        self.logdb = IncidentLog()
        self.logic = MonitorLogic(self.cfg, self._sink_from_logic, self.notifier, self.logdb)

        self._build_ui()
        self.after(150, self._poll_queue)

    # --- UI ---
    def _build_ui(self):
        # Toolbar
        tbar = ttk.Frame(self)
        tbar.pack(fill="x", padx=8, pady=6)

        self.btn_connect = ttk.Button(tbar, text="Połącz", command=self.start_ws)
        self.btn_connect.pack(side="left")
        self.btn_disconnect = ttk.Button(tbar, text="Rozłącz", command=self.stop_ws, state="disabled")
        self.btn_disconnect.pack(side="left", padx=(6,0))

        ttk.Button(tbar, text="Wyczyść log", command=self._clear_log).pack(side="right")
        ttk.Button(tbar, text="Eksportuj log…", command=self._export_log).pack(side="right", padx=(0,6))

        # Split: devices + log
        split = ttk.PanedWindow(self, orient="vertical")
        split.pack(fill="both", expand=True, padx=8, pady=6)

        # Devices table
        frame_top = ttk.Frame(split)
        cols = ("name","sn","online","last_event")
        self.tree = ttk.Treeview(frame_top, columns=cols, show="headings", height=10)
        self.tree.heading("name", text="Urządzenie")
        self.tree.heading("sn", text="Serial")
        self.tree.heading("online", text="Status")
        self.tree.heading("last_event", text="Ostatnie zdarzenie")
        self.tree.column("name", width=220)
        self.tree.column("sn", width=160)
        self.tree.column("online", width=100, anchor="center")
        self.tree.column("last_event", width=380)
        self.tree.pack(fill="both", expand=True)
        split.add(frame_top, weight=3)

        # Log box
        frame_bottom = ttk.Frame(split)
        self.logbox = tk.Text(frame_bottom, height=8, wrap="word", state="disabled")
        self.logbox.pack(fill="both", expand=True)
        split.add(frame_bottom, weight=2)

        # Status bar
        self.status = tk.StringVar(value="Niepołączony")
        sb = ttk.Label(self, textvariable=self.status, anchor="w")
        sb.pack(fill="x", padx=8, pady=(0,6))

        # styles
        style = ttk.Style(self)
        try:
            self.tk.call("source", "sun-valley.tcl")
            style.theme_use("sun-valley-dark")
        except Exception:
            pass

    # --- Queue sink from logic ---
    def _sink_from_logic(self, kind, payload):
        self.queue.put((kind, payload))

    # --- Queue polling ---
    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "conn":
                    if payload.get("status") == "connected":
                        self.status.set("Połączono z eufy-security-ws")
                        self.btn_connect.configure(state="disabled")
                        self.btn_disconnect.configure(state="normal")
                    else:
                        self.status.set(f"Rozłączono ({payload.get('error','')})")
                        self.btn_connect.configure(state="normal")
                        self.btn_disconnect.configure(state="disabled")
                elif kind == "device_update":
                    self._upsert_device(payload)
                elif kind == "log":
                    self._append_log(payload)
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    def _upsert_device(self, d):
        sn = d["sn"]
        name = d.get("name") or sn
        online = d.get("online")
        last_event = d.get("last_event") or ""
        # znajdź/utwórz wiersz
        iid = None
        for item in self.tree.get_children():
            if self.tree.set(item, "sn") == sn:
                iid = item; break
        row = (name, sn, "ONLINE" if online else "OFFLINE", last_event)
        if iid:
            for k, v in zip(("name","sn","online","last_event"), row):
                self.tree.set(iid, k, v)
        else:
            self.tree.insert("", "end", values=row)

    def _append_log(self, line):
        self.logbox.configure(state="normal")
        self.logbox.insert("end", line + "\n")
        self.logbox.see("end")
        self.logbox.configure(state="disabled")

    def _clear_log(self):
        self.logbox.configure(state="normal")
        self.logbox.delete("1.0", "end")
        self.logbox.configure(state="disabled")

    def _export_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Plik tekstowy","*.txt"), ("Wszystkie pliki","*.*")]
        )
        if not path: return
        data = self.logbox.get("1.0", "end")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
            messagebox.showinfo(APP_TITLE, "Zapisano log.")
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Błąd zapisu: {e}")

    # --- WS start/stop ---
    def start_ws(self):
        if self.ws_thread and self.ws_thread.is_alive():
            return
        self.status.set("Łączenie…")
        self.loop = asyncio.new_event_loop()
        self.ws_client = WSClient(self.cfg["ws_url"], self.queue)
        def runner():
            asyncio.set_event_loop(self.loop)
            try:
                self.loop.run_until_complete(self.ws_client.run())
            except Exception:
                pass
        self.ws_thread = threading.Thread(target=runner, daemon=True)
        self.ws_thread.start()

    def stop_ws(self):
        if self.ws_client:
            self.ws_client.stop()
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.status.set("Rozłączono")
        self.btn_connect.configure(state="normal")
        self.btn_disconnect.configure(state="disabled")

    # --- Config ---
    def _load_cfg(self):
        path = os.path.join(os.path.dirname(__file__), "config.json")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def on_close(self):
        self.stop_ws()
        self.destroy()

# --------------------- main ----------------------
if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
