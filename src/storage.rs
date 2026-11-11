//! Persistance : parametres (JSON) et historique (SQLite).

use crate::model::{now_string, Device, Event, PortScanOutcome};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

pub fn data_dir() -> PathBuf {
    let dir = dirs::data_local_dir()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
        .join("NetPulse");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

// ------------------------------------------------------------------
// Parametres
// ------------------------------------------------------------------
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub theme: String,
    pub zoom: f32,
    pub ping_timeout_ms: u32,
    pub discovery_threads: usize,
    pub tcp_probe: bool,
    pub resolve_names: bool,
    pub netbios: bool,
    pub port_timeout_ms: u64,
    pub port_threads: usize,
    pub grab_banners: bool,
    pub default_ports: String,
    pub auto_scan: bool,
    pub auto_scan_minutes: u32,
    pub notify_new_devices: bool,
    pub notify_offline: bool,
    pub last_target: String,
    pub monitor_targets: String,
    pub monitor_interval_s: u32,
    pub latency_alert_ms: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: "system".into(),
            zoom: 1.0,
            ping_timeout_ms: 700,
            discovery_threads: 128,
            tcp_probe: true,
            resolve_names: true,
            netbios: true,
            port_timeout_ms: 700,
            port_threads: 200,
            grab_banners: true,
            default_ports: crate::ports::PRESETS[0].1.to_string(),
            auto_scan: false,
            auto_scan_minutes: 15,
            notify_new_devices: true,
            notify_offline: false,
            last_target: String::new(),
            monitor_targets: "1.1.1.1, 8.8.8.8".into(),
            monitor_interval_s: 2,
            latency_alert_ms: 150,
        }
    }
}

impl Settings {
    fn path() -> PathBuf {
        data_dir().join("settings.json")
    }
    pub fn load() -> Self {
        std::fs::read_to_string(Self::path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }
    pub fn save(&self) {
        if let Ok(t) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(Self::path(), t);
        }
    }
}

// ------------------------------------------------------------------
// Base SQLite
// ------------------------------------------------------------------
pub struct Database {
    conn: Mutex<Connection>,
}

pub fn db_path() -> PathBuf {
    data_dir().join("netpulse.db")
}

impl Database {
    pub fn open() -> Result<Self, String> {
        let conn = Connection::open(db_path()).or_else(|_| Connection::open_in_memory()).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS devices (
                ip TEXT PRIMARY KEY, mac TEXT, vendor TEXT, hostname TEXT, name TEXT, notes TEXT,
                device_type TEXT, trusted INTEGER DEFAULT 0, favorite INTEGER DEFAULT 0,
                online INTEGER DEFAULT 0, latency_ms INTEGER, first_seen TEXT, last_seen TEXT,
                last_score INTEGER, open_ports TEXT
             );
             CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, ip TEXT,
                kind TEXT NOT NULL, description TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
             CREATE TABLE IF NOT EXISTS port_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, ip TEXT NOT NULL,
                port INTEGER NOT NULL, service TEXT, state TEXT, banner TEXT
             );
             CREATE TABLE IF NOT EXISTS security_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, ip TEXT NOT NULL,
                score INTEGER NOT NULL, grade TEXT, label TEXT NOT NULL, report TEXT
             );
             CREATE TABLE IF NOT EXISTS latency (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, target TEXT NOT NULL,
                rtt_ms INTEGER
             );",
        )
        .map_err(|e| e.to_string())?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Option<T> {
        let guard = self.conn.lock().ok()?;
        f(&guard).ok()
    }

    pub fn upsert_device(&self, d: &Device) {
        self.with(|c| {
            c.execute(
                "INSERT INTO devices (ip, mac, vendor, hostname, name, notes, device_type, trusted, favorite,
                    online, latency_ms, first_seen, last_seen, last_score, open_ports)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
                 ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac, vendor=excluded.vendor,
                    hostname=excluded.hostname, name=excluded.name, notes=excluded.notes,
                    device_type=excluded.device_type, trusted=excluded.trusted, favorite=excluded.favorite,
                    online=excluded.online, latency_ms=excluded.latency_ms, first_seen=excluded.first_seen,
                    last_seen=excluded.last_seen, last_score=excluded.last_score, open_ports=excluded.open_ports",
                params![
                    d.ip, d.mac, d.vendor, d.hostname, d.name, d.notes, d.device_type, d.trusted as i32,
                    d.favorite as i32, d.online as i32, d.latency_ms, d.first_seen, d.last_seen, d.last_score,
                    d.open_ports
                ],
            )
        });
    }

    pub fn delete_device(&self, ip: &str) {
        self.with(|c| c.execute("DELETE FROM devices WHERE ip=?1", params![ip]));
    }

    pub fn clear_devices(&self) {
        self.with(|c| c.execute("DELETE FROM devices", []));
    }

    pub fn devices(&self) -> Vec<Device> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT ip, mac, vendor, hostname, name, notes, device_type, trusted, favorite, online,
                        latency_ms, first_seen, last_seen, last_score, open_ports FROM devices",
            )?;
            let rows = st.query_map([], |r| {
                Ok(Device {
                    ip: r.get(0)?,
                    mac: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    vendor: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    hostname: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    name: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    notes: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                    device_type: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                    trusted: r.get::<_, Option<i32>>(7)?.unwrap_or(0) != 0,
                    favorite: r.get::<_, Option<i32>>(8)?.unwrap_or(0) != 0,
                    online: false,
                    latency_ms: r.get(10)?,
                    first_seen: r.get::<_, Option<String>>(11)?.unwrap_or_default(),
                    last_seen: r.get::<_, Option<String>>(12)?.unwrap_or_default(),
                    last_score: r.get(13)?,
                    open_ports: r.get::<_, Option<String>>(14)?.unwrap_or_default(),
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap_or_default()
    }

    pub fn log_event(&self, ip: &str, kind: &str, description: &str) {
        let now = now_string();
        self.with(|c| {
            c.execute(
                "INSERT INTO events (timestamp, ip, kind, description) VALUES (?1,?2,?3,?4)",
                params![now, ip, kind, description],
            )
        });
    }

    pub fn events(&self, limit: usize) -> Vec<Event> {
        self.with(|c| {
            let mut st = c.prepare("SELECT id, timestamp, ip, kind, description FROM events ORDER BY id DESC LIMIT ?1")?;
            let rows = st.query_map(params![limit as i64], |r| {
                Ok(Event {
                    id: r.get(0)?,
                    timestamp: r.get(1)?,
                    ip: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    kind: r.get(3)?,
                    description: r.get(4)?,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap_or_default()
    }

    pub fn clear_history(&self) {
        self.with(|c| {
            c.execute_batch("DELETE FROM events; DELETE FROM port_scans; DELETE FROM security_scores; DELETE FROM latency;")
        });
    }

    pub fn save_port_scan(&self, o: &PortScanOutcome) {
        let now = now_string();
        let report = serde_json::to_string(&o.report).unwrap_or_default();
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            for r in &o.open {
                tx.execute(
                    "INSERT INTO port_scans (timestamp, ip, port, service, state, banner) VALUES (?1,?2,?3,?4,?5,?6)",
                    params![now, o.ip, r.port, r.service, r.state.label(), r.banner],
                )?;
            }
            tx.execute(
                "INSERT INTO security_scores (timestamp, ip, score, grade, label, report) VALUES (?1,?2,?3,?4,?5,?6)",
                params![now, o.ip, o.report.score, o.report.grade, o.report.label, report],
            )?;
            tx.commit()
        });
    }

    /// Historique des scores (horodatage, score) pour une IP, du plus ancien au plus recent.
    pub fn score_history(&self, ip: &str) -> Vec<(String, i32)> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT timestamp, score FROM (SELECT id, timestamp, score FROM security_scores WHERE ip=?1
                 ORDER BY id DESC LIMIT 50) ORDER BY id ASC",
            )?;
            let rows = st.query_map(params![ip], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap_or_default()
    }

    pub fn stats(&self) -> (i64, i64, i64) {
        self.with(|c| {
            let e: i64 = c.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
            let p: i64 = c.query_row("SELECT COUNT(*) FROM security_scores", [], |r| r.get(0))?;
            let d: i64 = c.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))?;
            Ok((d, e, p))
        })
        .unwrap_or((0, 0, 0))
    }

    /// Sauvegarde coherente de la base vers un fichier.
    pub fn backup_to(&self, path: &std::path::Path) -> Result<(), String> {
        let p = path.to_string_lossy().replace('\'', "''");
        let _ = std::fs::remove_file(path);
        let guard = self.conn.lock().map_err(|e| e.to_string())?;
        guard.execute_batch(&format!("VACUUM INTO '{p}'")).map_err(|e| e.to_string())
    }
}
