import asyncio, json, os, sqlite3, datetime
from plyer import notification

# ---- proste powiadomienia desktop ----
class Notifier:
    def __init__(self, cooldown=90):
        self.cooldown = cooldown
        self.last = {}
    def show(self, title, msg, key=None):
        now = datetime.datetime.now().timestamp()
        if key and key in self.last and now - self.last[key] < self.cooldown:
            return
        if key: self.last[key] = now
        try:
            notification.notify(title=title, message=msg, timeout=5)
        except Exception:
            print(f"[NOTIFY] {title}: {msg}")

# ---- log incydentów (SQLite) ----
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
                  (datetime.datetime.now().isoformat(timespec="seconds"), source, type_, title, details))
        conn.commit(); conn.close()

# ---- klient Eufy WebSocket ----
# Używamy prostego websocketu; eufy-security-ws emituje zdarzenia jako JSON.
import websockets

class EufyClient:
    def __init__(self, ws_url, on_event):
        self.ws_url = ws_url
        self.on_event = on_event

    async def run(self):
        # Auto-reconnect pętla
        while True:
            try:
                async with websockets.connect(self.ws_url, ping_interval=20, ping_timeout=20) as ws:
                    # Subskrypcja wszystkich zdarzeń
                    await ws.send(json.dumps({"command":"initialize"}))
                    await ws.send(json.dumps({"command":"get_devices"}))
                    await ws.send(json.dumps({"command":"get_stations"}))
                    # nasłuch
                    async for raw in ws:
                        try:
                            evt = json.loads(raw)
                        except Exception:
                            continue
                        await self.on_event(evt)
            except Exception:
                await asyncio.sleep(5)  # ponów po krótkiej przerwie

# ---- logika zdarzeń/zdrowia ----
class EufyMonitor:
    def __init__(self, cfg):
        self.cfg = cfg
        self.notifier = Notifier(cfg["notify"]["cooldown_seconds"])
        self.log = IncidentLog()
        self.device_last_ok = {}  # device_sn -> datetime

    async def handle_event(self, evt):
        # Zdarzenia mają różne kształty; reagujemy na najczęstsze pola.
        # 1) Zdarzenia ruchu/osoby/dzwonka
        if evt.get("type") in ("event", "station event", "device event"):
            name = (evt.get("device_name") or evt.get("station_name") or "Eufy")
            action = (evt.get("event_type") or evt.get("name") or evt.get("action") or "event")
            text = evt.get("message") or evt.get("data", {}).get("message") or ""
            self.notifier.show(f"Eufy: {action}", f"{name}: {text}", key=f"evt_{name}_{action}")
            self.log.add(name, "alert", action, text)

        # 2) Aktualizacje statusu urządzeń (online/offline, ostatnia aktywność)
        if evt.get("type") in ("device", "device update", "property changed"):
            dev_sn = evt.get("device_sn") or evt.get("serial_number") or evt.get("device_id")
            name = evt.get("device_name") or evt.get("name") or dev_sn
            props = evt.get("properties") or evt.get("data") or {}
            # heurystyki "online"
            online = props.get("online") if isinstance(props.get("online"), bool) else props.get("state") in ("online","connected")
            now = datetime.datetime.now()
            if online:
                self.device_last_ok[dev_sn] = now
            else:
                # jeżeli od X sekund brak online -> incydent
                last_ok = self.device_last_ok.get(dev_sn, now - datetime.timedelta(hours=24))
                if (now - last_ok).total_seconds() > self.cfg["health"]["offline_grace_seconds"]:
                    self.notifier.show("Eufy: urządzenie offline", f"{name} nie odpowiada.", key=f"off_{dev_sn}")
                    self.log.add(name, "incident", "Device offline", json.dumps(props))

        # 3) Globalne błędy (np. P2P/Cloud)
        if evt.get("type") in ("error","station error","device error"):
            src = evt.get("device_name") or evt.get("station_name") or "Eufy"
            msg = evt.get("message") or str(evt)
            self.notifier.show("Eufy: błąd", msg, key=f"err_{src}")
            self.log.add(src, "error", "Error", msg)

    async def run(self):
        client = EufyClient(self.cfg["ws_url"], self.handle_event)
        self.notifier.show("Eufy Monitor", "Start nasłuchu (WebSocket).", key="start")
        await client.run()

def load_cfg():
    path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

if __name__ == "__main__":
    cfg = load_cfg()
    asyncio.run(EufyMonitor(cfg).run())

