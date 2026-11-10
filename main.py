"""
============================================================
 NetPulse - Tableau de bord de surveillance réseau local
============================================================
Description :
    Application de bureau permettant de :
      - découvrir les appareils connectés sur le réseau local (ARP / ping),
      - identifier leur fabricant (OUI de l'adresse MAC),
      - scanner leurs ports ouverts avec récupération de bannière,
      - calculer un score de sécurité basique et signaler les ports
        sensibles ouverts (Telnet, FTP, SMB, RDP, VNC...),
      - conserver un historique local des événements via SQLite.

⚠️  USAGE RESPONSABLE :
    N'utilisez cet outil que sur des réseaux que vous possédez ou que vous
    êtes explicitement autorisé(e) à tester. Le scan de réseaux tiers sans
    autorisation peut être illégal selon votre juridiction.

Dépendances :
    pip install customtkinter pillow scapy python-nmap psutil pyinstaller

Compilation en .exe autonome (Windows, à exécuter en tant qu'administrateur
pour bénéficier du scan ARP complet) :
    pyinstaller --noconsole --onefile --icon=NetPulse.ico --name=NetPulse main.py

Arborescence attendue du projet :
    NetPulse/
    ├── main.py
    ├── NetPulse.png      (icône source)
    ├── NetPulse.ico      (icône convertie, générée si absente)
    └── netpulse_history.db  (base SQLite, créée automatiquement)
============================================================
"""

from __future__ import annotations

import ipaddress
import os
import platform
import queue
import socket
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from tkinter import ttk

import customtkinter as ctk
from PIL import Image

# ------------------------------------------------------------------
# 1. CONFIGURATION GÉNÉRALE DU THÈME
# ------------------------------------------------------------------
ctk.set_appearance_mode("System")      # S'adapte au mode clair/sombre de l'OS
ctk.set_default_color_theme("blue")

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "netpulse_history.db")

# ------------------------------------------------------------------
# 2. CONSTANTES MÉTIER
# ------------------------------------------------------------------

# Ports couramment surveillés (numéro -> nom du service)
COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
}

# Ports considérés comme sensibles (services historiquement peu sécurisés)
SENSITIVE_PORTS: dict[int, str] = {
    21: "FTP — transfert de fichiers non chiffré",
    23: "Telnet — accès distant non chiffré",
    139: "NetBIOS — partage de fichiers Windows historique",
    445: "SMB — cible fréquente d'exploits (ex. EternalBlue)",
    1723: "PPTP — VPN obsolète et faible",
    3389: "RDP — bureau à distance, cible fréquente de brute-force",
    5900: "VNC — bureau à distance souvent mal sécurisé",
}

# Petite table de correspondance OUI -> fabricant (repli si scapy indisponible)
OUI_FALLBACK: dict[str, str] = {
    "3C5AB4": "Google, Inc.",
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Trading Ltd",
    "E45F01": "Raspberry Pi Trading Ltd",
    "F0F61C": "Apple, Inc.",
    "A45E60": "Apple, Inc.",
    "3C0754": "Apple, Inc.",
    "AC87A3": "Apple, Inc.",
    "001A11": "Google, Inc.",
    "F4F5D8": "Google, Inc.",
    "5C514F": "Samsung Electronics",
    "8C7967": "Samsung Electronics",
    "001CF0": "D-Link Corporation",
    "0014D1": "TP-Link Technologies",
    "50C7BF": "TP-Link Technologies",
    "B0487A": "TP-Link Technologies",
    "00E04C": "Realtek Semiconductor",
    "3C970E": "Intel Corporate",
    "A0369F": "Intel Corporate",
    "001B21": "Intel Corporate",
    "D4BED9": "Dell Inc.",
    "F8DB88": "Dell Inc.",
    "00505F": "VMware, Inc.",
    "005056": "VMware, Inc.",
    "080027": "Oracle VirtualBox",
    "525400": "QEMU / Machine virtuelle",
    "18FE34": "Espressif Inc. (ESP8266/ESP32)",
    "240AC4": "Espressif Inc. (ESP8266/ESP32)",
    "AC670B": "Espressif Inc. (ESP8266/ESP32)",
    "FCF5C4": "Espressif Inc. (ESP8266/ESP32)",
    "34E12D": "Amazon Technologies",
    "F0272D": "Amazon Technologies",
    "00259C": "Cisco Systems",
    "0022BD": "Cisco-Linksys",
    "001D0F": "Cisco Systems",
    "70B3D5": "Xiaomi Communications",
    "78118C": "Xiaomi Communications",
}


# ------------------------------------------------------------------
# 3. FONCTIONS UTILITAIRES (ressources / icône)
# ------------------------------------------------------------------
def resource_path(relative_path: str) -> str:
    """Chemin absolu compatible script Python ET exécutable PyInstaller."""
    base_path = getattr(sys, "_MEIPASS", APP_DIR)
    return os.path.join(base_path, relative_path)


def ensure_ico_from_png(png_name: str = "NetPulse.png", ico_name: str = "NetPulse.ico") -> str | None:
    """Convertit NetPulse.png en NetPulse.ico si ce dernier n'existe pas déjà."""
    png_path = os.path.join(APP_DIR, png_name)
    ico_path = os.path.join(APP_DIR, ico_name)

    if os.path.exists(ico_path):
        return ico_path
    if os.path.exists(png_path):
        try:
            img = Image.open(png_path)
            img.save(ico_path, format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
            return ico_path
        except Exception as exc:  # noqa: BLE001
            print(f"[NetPulse] Impossible de convertir l'icône : {exc}")
    return None


# ------------------------------------------------------------------
# 4. COUCHE BASE DE DONNÉES (SQLite) — historique local
# ------------------------------------------------------------------
class HistoryDatabase:
    """Encapsule toutes les opérations SQLite (appareils, événements, scans)."""

    def __init__(self, db_path: str = DB_PATH) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()  # SQLite + multi-threading -> on sérialise les accès
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    mac TEXT,
                    vendor TEXT,
                    last_seen TEXT,
                    status TEXT
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT,
                    event_type TEXT NOT NULL,
                    description TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS port_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    service TEXT,
                    state TEXT,
                    banner TEXT
                );

                CREATE TABLE IF NOT EXISTS security_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    label TEXT NOT NULL,
                    alerts TEXT
                );
                """
            )

    # ---- Écriture -----------------------------------------------------
    def upsert_device(self, ip: str, mac: str, vendor: str, status: str) -> None:
        now = datetime.now().isoformat(timespec="seconds")
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO devices (ip, mac, vendor, last_seen, status)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac=excluded.mac, vendor=excluded.vendor,
                    last_seen=excluded.last_seen, status=excluded.status
                """,
                (ip, mac, vendor, now, status),
            )

    def log_event(self, ip: str, event_type: str, description: str) -> None:
        now = datetime.now().isoformat(timespec="seconds")
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO events (timestamp, ip, event_type, description) VALUES (?, ?, ?, ?)",
                (now, ip, event_type, description),
            )

    def save_port_scan(self, ip: str, results: list["PortResult"]) -> None:
        now = datetime.now().isoformat(timespec="seconds")
        with self._lock, self._connect() as conn:
            conn.executemany(
                "INSERT INTO port_scans (timestamp, ip, port, service, state, banner) VALUES (?, ?, ?, ?, ?, ?)",
                [(now, ip, r.port, r.service, r.state, r.banner) for r in results],
            )

    def save_security_score(self, ip: str, score: int, label: str, alerts: list[str]) -> None:
        now = datetime.now().isoformat(timespec="seconds")
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO security_scores (timestamp, ip, score, label, alerts) VALUES (?, ?, ?, ?, ?)",
                (now, ip, score, label, " | ".join(alerts)),
            )

    # ---- Lecture --------------------------------------------------------
    def get_devices(self) -> list[sqlite3.Row]:
        with self._lock, self._connect() as conn:
            return conn.execute("SELECT * FROM devices ORDER BY ip").fetchall()

    def get_events(self, limit: int = 300) -> list[sqlite3.Row]:
        with self._lock, self._connect() as conn:
            return conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    def clear_history(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                "DELETE FROM events; DELETE FROM port_scans; DELETE FROM security_scores;"
            )


# ------------------------------------------------------------------
# 5. STRUCTURES DE DONNÉES
# ------------------------------------------------------------------
@dataclass
class Device:
    ip: str
    mac: str = "??:??:??:??:??:??"
    vendor: str = "Fabricant inconnu"
    status: str = "En ligne"


@dataclass
class PortResult:
    port: int
    service: str
    state: str            # "Ouvert" / "Fermé" / "Filtré"
    banner: str = ""


@dataclass
class SecurityReport:
    ip: str
    score: int
    label: str
    alerts: list[str] = field(default_factory=list)


# ------------------------------------------------------------------
# 6. MOTEUR DE DÉCOUVERTE RÉSEAU (ARP / ping)
# ------------------------------------------------------------------
class NetworkScanner:
    """Découvre les appareils actifs sur le sous-réseau local."""

    def __init__(self) -> None:
        self._scapy_available = self._try_import_scapy()

    @staticmethod
    def _try_import_scapy() -> bool:
        try:
            import scapy.all  # noqa: F401
            return True
        except Exception:  # noqa: BLE001
            return False

    # ---- Détection du sous-réseau local --------------------------------
    def get_local_subnet(self) -> str:
        """
        Détermine automatiquement le sous-réseau local (ex: "192.168.1.0/24")
        à partir des interfaces réseau actives (via psutil).
        """
        try:
            import psutil

            for iface_name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        network = ipaddress.IPv4Network(
                            f"{addr.address}/{addr.netmask}", strict=False
                        )
                        # On privilégie les plages privées classiques
                        if network.is_private and network.prefixlen >= 16:
                            return str(network)
        except Exception as exc:  # noqa: BLE001
            print(f"[NetPulse] Détection automatique du sous-réseau impossible : {exc}")

        # Repli : on tente de déduire l'IP locale via une socket UDP "factice"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            return str(network)
        except Exception:
            return "192.168.1.0/24"

    # ---- Scan ARP (méthode privilégiée, nécessite droits admin/root) -----
    def arp_scan(self, subnet: str, timeout: float = 2.0) -> list[Device]:
        if not self._scapy_available:
            return self.ping_sweep_scan(subnet)

        try:
            from scapy.all import ARP, Ether, srp

            arp_request = ARP(pdst=subnet)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            answered, _ = srp(packet, timeout=timeout, verbose=False, retry=1)

            devices: list[Device] = []
            for _, received in answered:
                mac = received.hwsrc.upper()
                vendor = self.get_vendor(mac)
                devices.append(Device(ip=received.psrc, mac=mac, vendor=vendor, status="En ligne"))
            return devices
        except PermissionError:
            print("[NetPulse] Droits administrateur/root requis pour le scan ARP (scapy). Repli sur ping.")
            return self.ping_sweep_scan(subnet)
        except Exception as exc:  # noqa: BLE001
            print(f"[NetPulse] Scan ARP indisponible ({exc}). Repli sur la méthode ping.")
            return self.ping_sweep_scan(subnet)

    # ---- Repli : ping sweep + lecture de la table ARP du système ----------
    def ping_sweep_scan(self, subnet: str, max_hosts: int = 254) -> list[Device]:
        """
        Méthode de secours ne nécessitant pas de privilèges élevés :
        1) on "pingue" chaque hôte du sous-réseau en parallèle,
        2) on relit la table ARP du système d'exploitation pour associer
           les adresses IP répondantes à leur adresse MAC.
        """
        try:
            network = ipaddress.IPv4Network(subnet, strict=False)
        except ValueError:
            return []

        hosts = list(network.hosts())[:max_hosts]

        def ping_once(ip: str) -> bool:
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", "500", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            try:
                import subprocess

                creation_flags = 0x08000000 if system == "windows" else 0  # CREATE_NO_WINDOW
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2,
                    creationflags=creation_flags,
                )
                return result.returncode == 0
            except Exception:
                return False

        with ThreadPoolExecutor(max_workers=64) as executor:
            futures = {executor.submit(ping_once, str(ip)): str(ip) for ip in hosts}
            responsive_ips = {futures[f] for f in as_completed(futures) if f.result()}

        arp_table = self._read_system_arp_table()

        devices: list[Device] = []
        for ip in responsive_ips:
            mac = arp_table.get(ip, "??:??:??:??:??:??")
            vendor = self.get_vendor(mac) if mac != "??:??:??:??:??:??" else "Fabricant inconnu"
            devices.append(Device(ip=ip, mac=mac, vendor=vendor, status="En ligne"))
        return devices

    @staticmethod
    def _read_system_arp_table() -> dict[str, str]:
        """Parse la table ARP du système (commande `arp -a`) : IP -> MAC."""
        import re
        import subprocess

        table: dict[str, str] = {}
        try:
            output = subprocess.run(
                ["arp", "-a"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5
            ).stdout.decode(errors="ignore")
        except Exception:
            return table

        # Fonctionne pour les formats Windows ("192.168.1.1   aa-bb-cc-dd-ee-ff")
        # et Linux/macOS ("? (192.168.1.1) at aa:bb:cc:dd:ee:ff")
        ip_mac_pattern = re.compile(
            r"(\d{1,3}(?:\.\d{1,3}){3}).{0,20}?"
            r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-]"
            r"[0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})"
        )
        for match in ip_mac_pattern.finditer(output):
            ip, mac = match.group(1), match.group(2).replace("-", ":").upper()
            table[ip] = mac
        return table

    # ---- Identification du fabricant via l'OUI de la MAC -------------------
    def get_vendor(self, mac: str) -> str:
        if not mac or mac == "??:??:??:??:??:??":
            return "Fabricant inconnu"

        oui = mac.replace(":", "").replace("-", "").upper()[:6]

        # 1) Tentative via la base OUI embarquée dans scapy (si disponible)
        if self._scapy_available:
            try:
                from scapy.all import conf

                manuf = conf.manufdb._get_manuf(mac.lower())  # type: ignore[attr-defined]
                if manuf and manuf.upper() != mac.upper() and manuf.lower() != "unknown":
                    return manuf
            except Exception:
                pass

        # 2) Repli sur notre petite table locale
        return OUI_FALLBACK.get(oui, "Fabricant inconnu")


# ------------------------------------------------------------------
# 7. SCANNER DE PORTS + RÉCUPÉRATION DE BANNIÈRE
# ------------------------------------------------------------------
class PortScanner:
    """Scanne un ensemble de ports TCP sur un hôte donné et tente de lire la bannière."""

    def __init__(self, timeout: float = 0.8) -> None:
        self.timeout = timeout
        self._nmap_available = self._try_nmap()

    @staticmethod
    def _try_nmap() -> bool:
        """Vérifie si python-nmap + le binaire nmap système sont disponibles."""
        try:
            import nmap  # noqa: F401

            scanner = nmap.PortScanner()
            scanner.nmap_version()  # lève une exception si le binaire est introuvable
            return True
        except Exception:
            return False

    def scan_host(self, ip: str, ports: list[int]) -> list[PortResult]:
        if self._nmap_available:
            try:
                return self._scan_with_nmap(ip, ports)
            except Exception as exc:  # noqa: BLE001
                print(f"[NetPulse] python-nmap a échoué ({exc}), repli sur le scanner interne.")

        return self._scan_with_sockets(ip, ports)

    # ---- Scan via python-nmap (plus précis : détection de service/version) --
    def _scan_with_nmap(self, ip: str, ports: list[int]) -> list[PortResult]:
        import nmap

        scanner = nmap.PortScanner()
        port_str = ",".join(str(p) for p in ports)
        scanner.scan(ip, port_str, arguments="-sV -T4 --host-timeout 10s")

        results: list[PortResult] = []
        if ip in scanner.all_hosts():
            tcp_data = scanner[ip].get("tcp", {})
            for port in ports:
                info = tcp_data.get(port)
                if not info:
                    results.append(PortResult(port, COMMON_PORTS.get(port, "?"), "Fermé"))
                    continue
                state = "Ouvert" if info.get("state") == "open" else info.get("state", "Fermé").capitalize()
                banner = " ".join(filter(None, [info.get("product", ""), info.get("version", "")])).strip()
                results.append(PortResult(port, COMMON_PORTS.get(port, info.get("name", "?")), state, banner))
        return results

    # ---- Scan interne via sockets bruts (portable, sans dépendance externe) --
    def _scan_with_sockets(self, ip: str, ports: list[int]) -> list[PortResult]:
        results: list[PortResult] = []

        def scan_one(port: int) -> PortResult:
            service = COMMON_PORTS.get(port, "?")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    outcome = sock.connect_ex((ip, port))
                    if outcome != 0:
                        return PortResult(port, service, "Fermé")

                    banner = ""
                    try:
                        sock.settimeout(0.6)
                        # Sonde minimale pour inciter certains services à répondre
                        if port in (80, 8080):
                            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        data = sock.recv(256)
                        banner = data.decode(errors="ignore").strip().splitlines()[0] if data else ""
                    except Exception:
                        banner = ""

                    return PortResult(port, service, "Ouvert", banner[:120])
            except Exception:
                return PortResult(port, service, "Filtré")

        with ThreadPoolExecutor(max_workers=min(32, len(ports) or 1)) as executor:
            futures = [executor.submit(scan_one, p) for p in ports]
            for future in as_completed(futures):
                results.append(future.result())

        # On conserve l'ordre logique des ports pour l'affichage
        results.sort(key=lambda r: r.port)
        return results


# ------------------------------------------------------------------
# 8. ANALYSE DE SÉCURITÉ BASIQUE
# ------------------------------------------------------------------
class SecurityAnalyzer:
    """Calcule un score de sécurité simplifié à partir des ports ouverts."""

    SENSITIVE_PENALTY = 15
    STANDARD_PENALTY = 3

    @classmethod
    def analyze(cls, ip: str, port_results: list[PortResult]) -> SecurityReport:
        score = 100
        alerts: list[str] = []

        open_ports = [r for r in port_results if r.state == "Ouvert"]

        for result in open_ports:
            if result.port in SENSITIVE_PORTS:
                score -= cls.SENSITIVE_PENALTY
                alerts.append(f"⚠️ Port {result.port} ({result.service}) ouvert — {SENSITIVE_PORTS[result.port]}")
            else:
                score -= cls.STANDARD_PENALTY

        score = max(0, min(100, score))

        if score >= 90:
            label = "Excellent"
        elif score >= 70:
            label = "Bon"
        elif score >= 50:
            label = "Moyen"
        elif score >= 30:
            label = "À risque"
        else:
            label = "Critique"

        if not alerts and open_ports:
            alerts.append("Aucun port sensible détecté parmi les ports ouverts.")
        elif not open_ports:
            alerts.append("Aucun port ouvert détecté sur la sélection scannée.")

        return SecurityReport(ip=ip, score=score, label=label, alerts=alerts)


# ------------------------------------------------------------------
# 9. INTERFACE GRAPHIQUE
# ------------------------------------------------------------------
class NetPulseApp(ctk.CTk):
    """Fenêtre principale : tableau de bord NetPulse."""

    SCORE_COLORS = {
        "Excellent": "#2E7D32",
        "Bon": "#66BB6A",
        "Moyen": "#F9A825",
        "À risque": "#EF6C00",
        "Critique": "#C62828",
    }

    def __init__(self) -> None:
        super().__init__()

        self.title("NetPulse - Surveillance & analyse du réseau local")
        self.geometry("1300x800")
        self.minsize(1050, 650)
        self._set_window_icon()

        # ---- Services métier ----
        self.db = HistoryDatabase()
        self.net_scanner = NetworkScanner()
        self.port_scanner = PortScanner()

        # ---- État applicatif ----
        self.devices: dict[str, Device] = {}
        self.event_queue: queue.Queue = queue.Queue()
        self.scan_in_progress = False

        # ---- Layout général ----
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=0, column=0, sticky="nsew", padx=15, pady=(15, 5))
        self.tab_devices = self.tabview.add("📡 Appareils")
        self.tab_ports = self.tabview.add("🔒 Ports & Sécurité")
        self.tab_history = self.tabview.add("🕘 Historique")

        self._build_status_bar()
        self._build_devices_tab()
        self._build_ports_tab()
        self._build_history_tab()

        self._style_treeviews()
        self._load_devices_from_db()
        self._refresh_history_table()

        # Boucle de traitement des messages provenant des threads de scan
        self.after(150, self._poll_event_queue)

    # ------------------------------------------------------------------
    # Icône & thème
    # ------------------------------------------------------------------
    def _set_window_icon(self) -> None:
        ico_path = resource_path("NetPulse.ico")
        png_path = resource_path("NetPulse.png")
        try:
            if os.path.exists(ico_path):
                self.iconbitmap(ico_path)
            elif os.path.exists(png_path):
                from PIL import ImageTk

                self.iconphoto(False, ImageTk.PhotoImage(Image.open(png_path)))
        except Exception as exc:  # noqa: BLE001
            print(f"[NetPulse] Icône non appliquée : {exc}")

    def change_theme(self, new_theme: str) -> None:
        ctk.set_appearance_mode(new_theme)
        self.after(50, self._style_treeviews)

    def _style_treeviews(self) -> None:
        """
        Les widgets ttk.Treeview ne suivent pas automatiquement le thème
        customtkinter : on les restyle manuellement selon le mode courant.
        """
        is_dark = ctk.get_appearance_mode() == "Dark"
        bg = "#2B2B2B" if is_dark else "#FFFFFF"
        fg = "#DCE4EE" if is_dark else "#1A1A1A"
        header_bg = "#212121" if is_dark else "#E7E7E7"
        selected_bg = "#1F6AA5"

        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Treeview",
            background=bg,
            foreground=fg,
            fieldbackground=bg,
            rowheight=26,
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background=header_bg,
            foreground=fg,
            relief="flat",
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "Treeview",
            background=[("selected", selected_bg)],
            foreground=[("selected", "#FFFFFF")],
        )

    # ------------------------------------------------------------------
    # Barre de statut (bas de fenêtre)
    # ------------------------------------------------------------------
    def _build_status_bar(self) -> None:
        self.status_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.status_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 10))
        self.status_frame.grid_columnconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(
            self.status_frame, text="Prêt.", anchor="w", text_color=("gray30", "gray70")
        )
        self.status_label.grid(row=0, column=0, sticky="ew")

        self.progress_bar = ctk.CTkProgressBar(self.status_frame, mode="indeterminate", width=200)
        # Masquée par défaut ; affichée pendant les scans (grid appliqué dynamiquement)

        self.theme_menu = ctk.CTkOptionMenu(
            self.status_frame, values=["System", "Light", "Dark"], command=self.change_theme, width=110
        )
        self.theme_menu.set("System")
        self.theme_menu.grid(row=0, column=2, sticky="e", padx=(10, 0))

    def _set_status(self, text: str, busy: bool = False) -> None:
        self.status_label.configure(text=text)
        if busy:
            self.progress_bar.grid(row=0, column=1, padx=10)
            self.progress_bar.start()
        else:
            self.progress_bar.stop()
            self.progress_bar.grid_forget()

    # ------------------------------------------------------------------
    # Onglet 1 : Appareils
    # ------------------------------------------------------------------
    def _build_devices_tab(self) -> None:
        tab = self.tab_devices
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        # --- Barre d'action ---
        top_bar = ctk.CTkFrame(tab, fg_color="transparent")
        top_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        top_bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(top_bar, text="Sous-réseau :", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, padx=(0, 5)
        )
        self.subnet_entry = ctk.CTkEntry(top_bar, placeholder_text="192.168.1.0/24")
        self.subnet_entry.insert(0, self.get_default_subnet())
        self.subnet_entry.grid(row=0, column=1, sticky="ew", padx=5)

        self.scan_button = ctk.CTkButton(
            top_bar, text="🔍  Scanner le réseau", command=self.start_network_scan, height=36
        )
        self.scan_button.grid(row=0, column=2, padx=5)

        self.clear_devices_button = ctk.CTkButton(
            top_bar,
            text="🗑️  Effacer la liste",
            command=self.clear_devices,
            fg_color="#B3261E",
            hover_color="#8C1D18",
            height=36,
        )
        self.clear_devices_button.grid(row=0, column=3, padx=5)

        # --- Tableau des appareils ---
        table_frame = ctk.CTkFrame(tab)
        table_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        columns = ("ip", "mac", "vendor", "status", "last_seen")
        self.devices_tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        headers = {
            "ip": "Adresse IP",
            "mac": "Adresse MAC",
            "vendor": "Fabricant",
            "status": "État",
            "last_seen": "Dernière détection",
        }
        widths = {"ip": 140, "mac": 160, "vendor": 260, "status": 110, "last_seen": 170}
        for col in columns:
            self.devices_tree.heading(col, text=headers[col])
            self.devices_tree.column(col, width=widths[col], anchor="w")
        self.devices_tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.devices_tree.yview)
        self.devices_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Double-clic -> bascule directement vers l'onglet Ports & Sécurité pour cet hôte
        self.devices_tree.bind("<Double-1>", self._on_device_double_click)

    def get_default_subnet(self) -> str:
        try:
            return self.net_scanner.get_local_subnet()
        except Exception:
            return "192.168.1.0/24"

    def start_network_scan(self) -> None:
        if self.scan_in_progress:
            return
        subnet = self.subnet_entry.get().strip() or "192.168.1.0/24"

        try:
            ipaddress.IPv4Network(subnet, strict=False)
        except ValueError:
            self._set_status(f"⚠️ Sous-réseau invalide : {subnet}")
            return

        self.scan_in_progress = True
        self.scan_button.configure(state="disabled")
        self._set_status(f"Scan du réseau {subnet} en cours…", busy=True)

        thread = threading.Thread(target=self._network_scan_worker, args=(subnet,), daemon=True)
        thread.start()

    def _network_scan_worker(self, subnet: str) -> None:
        """Exécuté dans un thread séparé : ne touche jamais directement au GUI."""
        try:
            devices = self.net_scanner.arp_scan(subnet)
        except Exception as exc:  # noqa: BLE001
            self.event_queue.put(("scan_error", str(exc)))
            self.event_queue.put(("scan_done", None))
            return

        self.event_queue.put(("scan_result", devices))
        self.event_queue.put(("scan_done", None))

    def clear_devices(self) -> None:
        self.devices.clear()
        for row in self.devices_tree.get_children():
            self.devices_tree.delete(row)
        self._refresh_port_device_menu()
        self._set_status("Liste des appareils effacée.")

    def _on_device_double_click(self, _event) -> None:
        selection = self.devices_tree.selection()
        if not selection:
            return
        ip = self.devices_tree.item(selection[0], "values")[0]
        self.device_selector.set(ip)
        self.tabview.set("🔒 Ports & Sécurité")

    def _load_devices_from_db(self) -> None:
        """Recharge les derniers appareils connus au démarrage (marqués 'hors ligne')."""
        for row in self.db.get_devices():
            device = Device(ip=row["ip"], mac=row["mac"] or "??:??:??:??:??:??",
                             vendor=row["vendor"] or "Fabricant inconnu", status="Hors ligne (historique)")
            self.devices[device.ip] = device
            self._insert_or_update_device_row(device, last_seen=row["last_seen"])
        self._refresh_port_device_menu()

    # ------------------------------------------------------------------
    # Onglet 2 : Ports & Sécurité
    # ------------------------------------------------------------------
    def _build_ports_tab(self) -> None:
        tab = self.tab_ports
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        # --- Sélection de l'hôte + ports à scanner ---
        top_bar = ctk.CTkFrame(tab, fg_color="transparent")
        top_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        top_bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(top_bar, text="Appareil :", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=(0, 5))
        self.device_selector = ctk.CTkComboBox(top_bar, values=["—"], width=220)
        self.device_selector.grid(row=0, column=1, sticky="w", padx=5)

        ctk.CTkLabel(top_bar, text="Ports (séparés par une virgule) :").grid(row=0, column=2, padx=(15, 5))
        self.ports_entry = ctk.CTkEntry(top_bar, width=320)
        self.ports_entry.insert(0, ",".join(str(p) for p in COMMON_PORTS))
        self.ports_entry.grid(row=0, column=3, sticky="ew", padx=5)
        top_bar.grid_columnconfigure(3, weight=1)

        self.port_scan_button = ctk.CTkButton(
            top_bar, text="🚦  Lancer le scan de ports", command=self.start_port_scan, height=36
        )
        self.port_scan_button.grid(row=0, column=4, padx=5)

        # --- Bandeau score de sécurité ---
        self.security_frame = ctk.CTkFrame(tab)
        self.security_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.security_frame.grid_columnconfigure(1, weight=1)

        self.score_label = ctk.CTkLabel(
            self.security_frame, text="—", font=ctk.CTkFont(size=26, weight="bold"), width=90
        )
        self.score_label.grid(row=0, column=0, rowspan=2, padx=15, pady=10)

        self.score_title_label = ctk.CTkLabel(
            self.security_frame, text="Aucune analyse effectuée", font=ctk.CTkFont(size=15, weight="bold"), anchor="w"
        )
        self.score_title_label.grid(row=0, column=1, sticky="w", pady=(10, 0))

        self.alerts_label = ctk.CTkLabel(
            self.security_frame, text="Lancez un scan de ports pour obtenir une analyse de sécurité.",
            anchor="w", justify="left", wraplength=850, text_color=("gray30", "gray70")
        )
        self.alerts_label.grid(row=1, column=1, sticky="w", pady=(0, 10))

        # --- Tableau des résultats de scan de ports ---
        table_frame = ctk.CTkFrame(tab)
        table_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        columns = ("port", "service", "state", "banner")
        self.ports_tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        headers = {"port": "Port", "service": "Service", "state": "État", "banner": "Bannière / info"}
        widths = {"port": 80, "service": 120, "state": 100, "banner": 500}
        for col in columns:
            self.ports_tree.heading(col, text=headers[col])
            self.ports_tree.column(col, width=widths[col], anchor="w")
        self.ports_tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.ports_tree.yview)
        self.ports_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")

        self.ports_tree.tag_configure("open", foreground="#2E7D32")
        self.ports_tree.tag_configure("closed", foreground="#9E9E9E")
        self.ports_tree.tag_configure("filtered", foreground="#F9A825")

    def _refresh_port_device_menu(self) -> None:
        ips = sorted(self.devices.keys()) or ["—"]
        self.device_selector.configure(values=ips)
        if self.device_selector.get() not in ips:
            self.device_selector.set(ips[0])

    def start_port_scan(self) -> None:
        ip = self.device_selector.get().strip()
        if not ip or ip == "—":
            self._set_status("⚠️ Sélectionnez d'abord un appareil (onglet Appareils).")
            return

        raw_ports = self.ports_entry.get().strip()
        try:
            ports = sorted({int(p.strip()) for p in raw_ports.split(",") if p.strip()})
        except ValueError:
            self._set_status("⚠️ Liste de ports invalide (utilisez des nombres séparés par des virgules).")
            return
        if not ports:
            self._set_status("⚠️ Aucun port à scanner.")
            return

        self.port_scan_button.configure(state="disabled")
        self._set_status(f"Scan de {len(ports)} port(s) sur {ip}…", busy=True)

        thread = threading.Thread(target=self._port_scan_worker, args=(ip, ports), daemon=True)
        thread.start()

    def _port_scan_worker(self, ip: str, ports: list[int]) -> None:
        try:
            results = self.port_scanner.scan_host(ip, ports)
            report = SecurityAnalyzer.analyze(ip, results)
        except Exception as exc:  # noqa: BLE001
            self.event_queue.put(("scan_error", str(exc)))
            self.event_queue.put(("port_scan_done", None))
            return

        self.event_queue.put(("port_scan_result", (ip, results, report)))
        self.event_queue.put(("port_scan_done", None))

    # ------------------------------------------------------------------
    # Onglet 3 : Historique
    # ------------------------------------------------------------------
    def _build_history_tab(self) -> None:
        tab = self.tab_history
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        top_bar = ctk.CTkFrame(tab, fg_color="transparent")
        top_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        top_bar.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            top_bar, text="Historique local des événements (SQLite)", font=ctk.CTkFont(size=14, weight="bold")
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkButton(top_bar, text="🔄  Actualiser", command=self._refresh_history_table, width=120).grid(
            row=0, column=1, padx=5
        )
        ctk.CTkButton(
            top_bar, text="🗑️  Vider l'historique", command=self._clear_history,
            fg_color="#B3261E", hover_color="#8C1D18", width=150,
        ).grid(row=0, column=2, padx=5)

        table_frame = ctk.CTkFrame(tab)
        table_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        columns = ("timestamp", "ip", "event_type", "description")
        self.history_tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        headers = {"timestamp": "Horodatage", "ip": "IP", "event_type": "Type", "description": "Description"}
        widths = {"timestamp": 170, "ip": 130, "event_type": 150, "description": 650}
        for col in columns:
            self.history_tree.heading(col, text=headers[col])
            self.history_tree.column(col, width=widths[col], anchor="w")
        self.history_tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")

    def _refresh_history_table(self) -> None:
        for row in self.history_tree.get_children():
            self.history_tree.delete(row)
        for event in self.db.get_events():
            self.history_tree.insert(
                "", "end", values=(event["timestamp"], event["ip"] or "-", event["event_type"], event["description"])
            )

    def _clear_history(self) -> None:
        self.db.clear_history()
        self._refresh_history_table()
        self._set_status("Historique des événements vidé.")

    # ------------------------------------------------------------------
    # Boucle d'intégration des résultats de scan (thread -> GUI)
    # ------------------------------------------------------------------
    def _poll_event_queue(self) -> None:
        try:
            while True:
                message_type, payload = self.event_queue.get_nowait()
                self._handle_event(message_type, payload)
        except queue.Empty:
            pass
        finally:
            self.after(150, self._poll_event_queue)

    def _handle_event(self, message_type: str, payload) -> None:
        if message_type == "scan_result":
            self._on_network_scan_result(payload)
        elif message_type == "scan_done":
            self.scan_in_progress = False
            self.scan_button.configure(state="normal")
            self._set_status("Scan réseau terminé.")
        elif message_type == "port_scan_result":
            ip, results, report = payload
            self._on_port_scan_result(ip, results, report)
        elif message_type == "port_scan_done":
            self.port_scan_button.configure(state="normal")
            self._set_status("Scan de ports terminé.")
        elif message_type == "scan_error":
            self._set_status(f"⚠️ Erreur : {payload}")

    def _on_network_scan_result(self, devices: list[Device]) -> None:
        seen_ips = set()
        for device in devices:
            seen_ips.add(device.ip)
            previously_known = device.ip in self.devices
            self.devices[device.ip] = device
            self._insert_or_update_device_row(device)
            self.db.upsert_device(device.ip, device.mac, device.vendor, device.status)
            if not previously_known:
                self.db.log_event(device.ip, "Nouvel appareil", f"Appareil détecté : {device.ip} ({device.vendor})")

        # Les appareils connus mais non revus lors de ce scan passent "Hors ligne"
        for ip, device in self.devices.items():
            if ip not in seen_ips and device.status == "En ligne":
                device.status = "Hors ligne"
                self._insert_or_update_device_row(device)
                self.db.upsert_device(device.ip, device.mac, device.vendor, device.status)
                self.db.log_event(ip, "Appareil hors ligne", f"{ip} ne répond plus.")

        self._refresh_port_device_menu()
        self._refresh_history_table()
        self._set_status(f"{len(devices)} appareil(s) détecté(s) sur le réseau.")

    def _insert_or_update_device_row(self, device: Device, last_seen: str | None = None) -> None:
        last_seen_display = last_seen or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.devices_tree.exists(device.ip):
            self.devices_tree.item(
                device.ip, values=(device.ip, device.mac, device.vendor, device.status, last_seen_display)
            )
        else:
            self.devices_tree.insert(
                "", "end", iid=device.ip,
                values=(device.ip, device.mac, device.vendor, device.status, last_seen_display),
            )

    def _on_port_scan_result(self, ip: str, results: list[PortResult], report: SecurityReport) -> None:
        # --- Tableau des ports ---
        for row in self.ports_tree.get_children():
            self.ports_tree.delete(row)
        for result in results:
            tag = {"Ouvert": "open", "Fermé": "closed"}.get(result.state, "filtered")
            self.ports_tree.insert(
                "", "end", values=(result.port, result.service, result.state, result.banner or "—"), tags=(tag,)
            )

        # --- Bandeau de score ---
        color = self.SCORE_COLORS.get(report.label, "#9E9E9E")
        self.score_label.configure(text=str(report.score), text_color=color)
        self.score_title_label.configure(text=f"Score de sécurité : {report.label} ({report.score}/100)")
        self.alerts_label.configure(text="\n".join(report.alerts))

        # --- Persistance en base ---
        self.db.save_port_scan(ip, results)
        self.db.save_security_score(ip, report.score, report.label, report.alerts)
        self.db.log_event(
            ip, "Scan de ports",
            f"{sum(1 for r in results if r.state == 'Ouvert')} port(s) ouvert(s) — score {report.score}/100 ({report.label})",
        )
        self._refresh_history_table()


# ------------------------------------------------------------------
# 10. POINT D'ENTRÉE
# ------------------------------------------------------------------
def main() -> None:
    ensure_ico_from_png()
    app = NetPulseApp()
    app.mainloop()


if __name__ == "__main__":
    main()
