//! Etat de l'application, messages des taches de fond et logique metier cote interface.

use crate::discovery::{self, LocalNet, ScanEvent};
use crate::model::{now_string, Device, Event, PortResult, PortScanOutcome};
use crate::platform::SocketEntry;
use crate::ports::{self, PortEvent};
use crate::storage::{Database, Settings};
use crate::tools::{self, Hop, HttpInfo, PingStats, PublicInfo, SpeedEvent};
use crossbeam_channel::{Receiver, Sender};
use eframe::egui;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(PartialEq, Clone, Copy)]
pub enum Tab {
    Dashboard,
    Devices,
    Ports,
    Tools,
    Connections,
    Interfaces,
    History,
    Settings,
}

#[derive(PartialEq, Clone, Copy)]
pub enum ToolTab {
    Ping,
    Trace,
    Dns,
    Wol,
    PublicIp,
    Speed,
    Http,
    Subnet,
    MacLookup,
}

pub enum Msg {
    ScanProgress(usize, usize),
    ScanFound(Device),
    ScanDone(bool),
    PortProgress(usize, usize),
    PortOpen(PortResult),
    PortDone(Result<PortScanOutcome, String>),
    PingReply(Option<u32>),
    PingError(String),
    TraceHop(Hop),
    TraceDone(Option<String>),
    Dns(Result<(Vec<String>, f64), String>),
    PublicIp(Result<PublicInfo, String>),
    Speed(SpeedEvent),
    SpeedDone,
    Http(Result<HttpInfo, String>),
    Monitor(String, Option<u32>),
    OuiUpdated(Result<usize, String>),
    Wol(Result<String, String>),
}

#[derive(Default)]
pub struct SpeedState {
    pub running: bool,
    pub latency: Option<f64>,
    pub down: Option<f64>,
    pub up: Option<f64>,
    pub live_down: f64,
    pub live_up: f64,
    pub progress: f32,
    pub phase: String,
    pub error: Option<String>,
    pub samples: Vec<[f64; 2]>,
}

pub struct NetPulseApp {
    pub ctx: egui::Context,
    pub settings: Settings,
    saved_settings: Settings,
    pub db: Arc<Database>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    pub tab: Tab,
    pub tool_tab: ToolTab,
    pub status: String,
    pub toasts: Vec<(String, Instant)>,

    // Reseau local
    pub locals: Vec<LocalNet>,
    pub gateway: Option<Ipv4Addr>,

    // Appareils
    pub devices: BTreeMap<Ipv4Addr, Device>,
    pub selected: Option<Ipv4Addr>,
    pub device_search: String,
    pub device_filter: usize,
    pub sort_col: usize,
    pub sort_asc: bool,
    pub scan_target: String,
    pub scanning: bool,
    scan_cancel: Arc<AtomicBool>,
    pub scan_progress: (usize, usize),
    scan_set: HashSet<Ipv4Addr>,
    scan_found: HashSet<Ipv4Addr>,
    session_seen: HashSet<Ipv4Addr>,
    pub scan_started: Option<Instant>,
    pub last_scan: Option<Instant>,
    pub last_scan_str: String,
    pub confirm_clear_devices: bool,

    // Ports
    pub port_target: String,
    pub port_spec: String,
    pub port_preset: usize,
    pub port_scanning: bool,
    port_cancel: Arc<AtomicBool>,
    pub port_progress: (usize, usize),
    pub port_live: Vec<PortResult>,
    pub port_outcome: Option<PortScanOutcome>,
    pub port_show_closed: bool,
    pub score_history: Vec<(String, i32)>,
    pub port_error: Option<String>,

    // Outils
    pub ping_target: String,
    pub ping_running: bool,
    ping_stop: Arc<AtomicBool>,
    pub ping_interval_ms: u32,
    pub ping_stats: PingStats,
    pub ping_points: Vec<[f64; 2]>,
    pub ping_log: VecDeque<String>,
    pub trace_target: String,
    pub trace_running: bool,
    trace_cancel: Arc<AtomicBool>,
    pub trace_hops: Vec<Hop>,
    pub trace_msg: String,
    pub dns_query: String,
    pub dns_busy: bool,
    pub dns_result: Option<Result<(Vec<String>, f64), String>>,
    pub wol_mac: String,
    pub wol_status: String,
    pub public_busy: bool,
    pub public_info: Option<Result<PublicInfo, String>>,
    pub speed: SpeedState,
    speed_cancel: Arc<AtomicBool>,
    pub http_url: String,
    pub http_busy: bool,
    pub http_result: Option<Result<HttpInfo, String>>,
    pub subnet_input: String,
    pub mac_input: String,
    pub oui_busy: bool,

    // Connexions
    pub connections: Vec<(SocketEntry, String)>,
    pub conn_filter: String,
    pub conn_state: usize,
    pub conn_auto: bool,
    conn_last: Option<Instant>,
    sys: Option<sysinfo::System>,

    // Interfaces / trafic
    networks: Option<sysinfo::Networks>,
    net_last: Instant,
    pub app_start: Instant,
    pub iface_rates: HashMap<String, (f64, f64)>,
    pub traffic: VecDeque<[f64; 3]>,

    // Surveillance latence
    monitor_targets: Arc<Mutex<Vec<String>>>,
    monitor_interval: Arc<AtomicU32>,
    pub monitor: BTreeMap<String, VecDeque<[f64; 2]>>,
    pub monitor_last: HashMap<String, Option<u32>>,
    monitor_fail: HashMap<String, u32>,
    monitor_down: HashSet<String>,

    // Historique
    pub events: Vec<Event>,
    pub hist_search: String,
    pub hist_kind: String,
    events_dirty: bool,
    pub confirm_clear_history: bool,
}

impl NetPulseApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let ctx = cc.egui_ctx.clone();
        let settings = Settings::load();
        let db = Arc::new(Database::open().unwrap_or_else(|e| {
            eprintln!("Base de données indisponible : {e}");
            std::process::exit(1)
        }));
        let (tx, rx) = crossbeam_channel::unbounded();
        let locals = discovery::local_networks();
        let gateway = crate::platform::default_gateway();
        let mut devices = BTreeMap::new();
        for d in db.devices() {
            devices.insert(d.ipv4(), d);
        }
        let scan_target = if settings.last_target.is_empty() { discovery::default_target() } else { settings.last_target.clone() };
        let port_spec = settings.default_ports.clone();
        let mut app = Self {
            ctx: ctx.clone(),
            saved_settings: settings.clone(),
            settings,
            db,
            tx,
            rx,
            tab: Tab::Dashboard,
            tool_tab: ToolTab::Ping,
            status: "Prêt.".into(),
            toasts: Vec::new(),
            locals,
            gateway,
            devices,
            selected: None,
            device_search: String::new(),
            device_filter: 0,
            sort_col: 2,
            sort_asc: true,
            scan_target,
            scanning: false,
            scan_cancel: Arc::new(AtomicBool::new(false)),
            scan_progress: (0, 0),
            scan_set: HashSet::new(),
            scan_found: HashSet::new(),
            session_seen: HashSet::new(),
            scan_started: None,
            last_scan: None,
            last_scan_str: "jamais".into(),
            confirm_clear_devices: false,
            port_target: gateway.map(|g| g.to_string()).unwrap_or_default(),
            port_spec,
            port_preset: 0,
            port_scanning: false,
            port_cancel: Arc::new(AtomicBool::new(false)),
            port_progress: (0, 0),
            port_live: Vec::new(),
            port_outcome: None,
            port_show_closed: false,
            score_history: Vec::new(),
            port_error: None,
            ping_target: gateway.map(|g| g.to_string()).unwrap_or_else(|| "1.1.1.1".into()),
            ping_running: false,
            ping_stop: Arc::new(AtomicBool::new(false)),
            ping_interval_ms: 1000,
            ping_stats: PingStats::default(),
            ping_points: Vec::new(),
            ping_log: VecDeque::new(),
            trace_target: "1.1.1.1".into(),
            trace_running: false,
            trace_cancel: Arc::new(AtomicBool::new(false)),
            trace_hops: Vec::new(),
            trace_msg: String::new(),
            dns_query: "github.com".into(),
            dns_busy: false,
            dns_result: None,
            wol_mac: String::new(),
            wol_status: String::new(),
            public_busy: false,
            public_info: None,
            speed: SpeedState::default(),
            speed_cancel: Arc::new(AtomicBool::new(false)),
            http_url: gateway.map(|g| format!("http://{g}")).unwrap_or_else(|| "https://github.com".into()),
            http_busy: false,
            http_result: None,
            subnet_input: discovery::default_target(),
            mac_input: String::new(),
            oui_busy: false,
            connections: Vec::new(),
            conn_filter: String::new(),
            conn_state: 0,
            conn_auto: false,
            conn_last: None,
            sys: sysinfo::System::new().ok(),
            networks: sysinfo::Networks::new_with_refreshed_list().ok(),
            net_last: Instant::now(),
            app_start: Instant::now(),
            iface_rates: HashMap::new(),
            traffic: VecDeque::new(),
            monitor_targets: Arc::new(Mutex::new(Vec::new())),
            monitor_interval: Arc::new(AtomicU32::new(2)),
            monitor: BTreeMap::new(),
            monitor_last: HashMap::new(),
            monitor_fail: HashMap::new(),
            monitor_down: HashSet::new(),
            events: Vec::new(),
            hist_search: String::new(),
            hist_kind: String::new(),
            events_dirty: true,
            confirm_clear_history: false,
        };
        app.apply_appearance();
        app.sync_monitor_targets();
        app.start_monitor_thread();
        app.db.log_event("", "Démarrage", &format!("NetPulse {} démarré", crate::VERSION));
        app
    }

    // ------------------------------------------------------------------
    // Utilitaires
    // ------------------------------------------------------------------
    pub fn toast(&mut self, text: impl Into<String>) {
        let t = text.into();
        self.status = t.clone();
        self.toasts.push((t, Instant::now()));
    }

    pub fn self_ips(&self) -> Vec<Ipv4Addr> {
        self.locals.iter().map(|l| l.ip).collect()
    }

    fn notify(&self, title: &str, body: &str) {
        let (title, body) = (title.to_string(), body.to_string());
        std::thread::spawn(move || {
            let _ = notify_rust::Notification::new().appname("NetPulse").summary(&title).body(&body).show();
        });
    }

    pub fn log_event(&mut self, ip: &str, kind: &str, desc: &str) {
        self.db.log_event(ip, kind, desc);
        self.events_dirty = true;
    }

    pub fn apply_appearance(&self) {
        let pref = match self.settings.theme.as_str() {
            "light" => egui::ThemePreference::Light,
            "dark" => egui::ThemePreference::Dark,
            _ => egui::ThemePreference::System,
        };
        self.ctx.set_theme(pref);
        self.ctx.set_zoom_factor(self.settings.zoom.clamp(0.6, 2.0));
    }

    fn sync_monitor_targets(&mut self) {
        let mut list = Vec::new();
        if let Some(g) = self.gateway {
            list.push(g.to_string());
        }
        for t in self.settings.monitor_targets.split([',', ';', ' ']).map(str::trim).filter(|t| !t.is_empty()) {
            if !list.iter().any(|x| x == t) {
                list.push(t.to_string());
            }
        }
        if let Ok(mut m) = self.monitor_targets.lock() {
            *m = list.clone();
        }
        self.monitor.retain(|k, _| list.contains(k));
        self.monitor_interval.store(self.settings.monitor_interval_s.clamp(1, 60), Ordering::Relaxed);
    }

    fn start_monitor_thread(&self) {
        let targets = self.monitor_targets.clone();
        let interval = self.monitor_interval.clone();
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        std::thread::spawn(move || {
            let mut resolved: HashMap<String, Ipv4Addr> = HashMap::new();
            loop {
                let list = targets.lock().map(|l| l.clone()).unwrap_or_default();
                for t in list {
                    let ip = match resolved.get(&t) {
                        Some(ip) => Some(*ip),
                        None => tools::resolve(&t).ok().inspect(|ip| {
                            resolved.insert(t.clone(), *ip);
                        }),
                    };
                    let rtt = ip.and_then(|ip| tools::ping(ip, 1500));
                    if tx.send(Msg::Monitor(t, rtt)).is_err() {
                        return;
                    }
                }
                ctx.request_repaint();
                std::thread::sleep(Duration::from_secs(interval.load(Ordering::Relaxed).max(1) as u64));
            }
        });
    }

    // ------------------------------------------------------------------
    // Decouverte
    // ------------------------------------------------------------------
    pub fn start_scan(&mut self) {
        if self.scanning {
            return;
        }
        let targets = match discovery::parse_targets(&self.scan_target) {
            Ok(t) => t,
            Err(e) => {
                self.toast(format!("Cible invalide : {e}"));
                return;
            }
        };
        self.locals = discovery::local_networks();
        self.gateway = crate::platform::default_gateway().or(self.gateway);
        self.settings.last_target = self.scan_target.clone();
        self.scan_set = targets.iter().copied().collect();
        self.scan_found.clear();
        self.scanning = true;
        self.scan_progress = (0, targets.len());
        self.scan_started = Some(Instant::now());
        let cancel = Arc::new(AtomicBool::new(false));
        self.scan_cancel = cancel.clone();
        self.status = format!("Analyse de {} ({} adresses)...", self.scan_target, targets.len());
        let cfg = discovery::ScanConfig {
            targets,
            timeout_ms: self.settings.ping_timeout_ms,
            threads: self.settings.discovery_threads,
            tcp_probe: self.settings.tcp_probe,
            resolve_names: self.settings.resolve_names,
            netbios: self.settings.netbios,
        };
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        std::thread::spawn(move || {
            discovery::scan(&cfg, &cancel, &|ev| {
                let _ = tx.send(match ev {
                    ScanEvent::Progress { done, total } => Msg::ScanProgress(done, total),
                    ScanEvent::Found(d) => Msg::ScanFound(d),
                });
                ctx.request_repaint();
            });
            let _ = tx.send(Msg::ScanDone(cancel.load(Ordering::Relaxed)));
            ctx.request_repaint();
        });
    }

    pub fn cancel_scan(&self) {
        self.scan_cancel.store(true, Ordering::Relaxed);
    }

    fn on_found(&mut self, mut d: Device) {
        let key = d.ipv4();
        self.scan_found.insert(key);
        let gw = self.gateway;
        let self_ips = self.self_ips();
        let mut events: Vec<(String, String, String)> = Vec::new();
        let mut notify_new = None;
        let was_seen_in_session = self.session_seen.contains(&key);
        match self.devices.get_mut(&key) {
            Some(e) => {
                if !d.mac.is_empty() && !e.mac.is_empty() && e.mac != d.mac {
                    events.push((
                        d.ip.clone(),
                        "Changement MAC".into(),
                        format!("{} : MAC {} -> {} (réattribution d'adresse ou usurpation ARP possible)", d.ip, e.mac, d.mac),
                    ));
                }
                if !e.online && was_seen_in_session {
                    events.push((d.ip.clone(), "De retour".into(), format!("{} ({}) est de nouveau en ligne", d.ip, e.display_name())));
                }
                if !d.mac.is_empty() {
                    e.mac = d.mac.clone();
                    e.vendor = d.vendor.clone();
                }
                if !d.hostname.is_empty() {
                    e.hostname = d.hostname.clone();
                }
                e.online = true;
                e.latency_ms = d.latency_ms;
                e.last_seen = d.last_seen.clone();
                if e.first_seen.is_empty() {
                    e.first_seen = d.first_seen.clone();
                }
                e.device_type = discovery::guess_type(e, gw, &self_ips);
                self.db.upsert_device(e);
            }
            None => {
                d.device_type = discovery::guess_type(&d, gw, &self_ips);
                d.trusted = self_ips.contains(&key) || gw == Some(key);
                let label = if d.hostname.is_empty() { d.vendor.clone() } else { format!("{} - {}", d.hostname, d.vendor) };
                events.push((d.ip.clone(), "Nouvel appareil".into(), format!("Nouvel appareil : {} ({label}) [{}]", d.ip, d.mac)));
                notify_new = Some(format!("{} - {label}", d.ip));
                self.db.upsert_device(&d);
                self.devices.insert(key, d);
            }
        }
        self.session_seen.insert(key);
        for (ip, k, desc) in events {
            self.log_event(&ip, &k, &desc);
        }
        if let Some(body) = notify_new {
            if self.settings.notify_new_devices && self.last_scan.is_some() {
                self.notify("Nouvel appareil sur le réseau", &body);
            }
        }
    }

    fn on_scan_done(&mut self, cancelled: bool) {
        self.scanning = false;
        let elapsed = self.scan_started.map(|s| s.elapsed().as_secs_f64()).unwrap_or(0.0);
        let mut offline = Vec::new();
        if !cancelled {
            for (ip, d) in self.devices.iter_mut() {
                if self.scan_set.contains(ip) && !self.scan_found.contains(ip) && d.online {
                    d.online = false;
                    d.latency_ms = None;
                    self.db.upsert_device(d);
                    offline.push((ip.to_string(), d.display_name().to_string()));
                }
            }
        }
        for (ip, name) in &offline {
            self.log_event(ip, "Hors ligne", &format!("{ip} {name} ne répond plus"));
            if self.settings.notify_offline {
                self.notify("Appareil hors ligne", &format!("{ip} {name}"));
            }
        }
        let n = self.scan_found.len();
        self.log_event(
            "",
            "Scan réseau",
            &format!(
                "{} : {n} appareil(s) actif(s) en {elapsed:.1} s{}",
                self.scan_target,
                if cancelled { " (interrompu)" } else { "" }
            ),
        );
        self.last_scan = Some(Instant::now());
        self.last_scan_str = now_string();
        self.toast(format!("Analyse terminée : {n} appareil(s) actif(s) en {elapsed:.1} s"));
    }

    pub fn delete_device(&mut self, ip: Ipv4Addr) {
        self.devices.remove(&ip);
        self.db.delete_device(&ip.to_string());
        if self.selected == Some(ip) {
            self.selected = None;
        }
    }

    pub fn clear_devices(&mut self) {
        self.devices.clear();
        self.db.clear_devices();
        self.selected = None;
        self.toast("Liste des appareils effacée.");
    }

    pub fn save_device(&self, ip: Ipv4Addr) {
        if let Some(d) = self.devices.get(&ip) {
            self.db.upsert_device(d);
        }
    }

    // ------------------------------------------------------------------
    // Ports
    // ------------------------------------------------------------------
    pub fn start_port_scan(&mut self) {
        if self.port_scanning {
            return;
        }
        let target = self.port_target.trim().to_string();
        if target.is_empty() {
            self.toast("Indiquez un hôte à analyser.");
            return;
        }
        let ports = match ports::parse_ports(&self.port_spec) {
            Ok(p) => p,
            Err(e) => {
                self.toast(e);
                return;
            }
        };
        self.port_scanning = true;
        self.port_error = None;
        self.port_live.clear();
        self.port_outcome = None;
        self.port_progress = (0, ports.len());
        let cancel = Arc::new(AtomicBool::new(false));
        self.port_cancel = cancel.clone();
        self.status = format!("Scan de {} port(s) sur {target}...", ports.len());
        let cfg = ports::PortScanConfig {
            target,
            ports,
            timeout: Duration::from_millis(self.settings.port_timeout_ms),
            threads: self.settings.port_threads,
            banners: self.settings.grab_banners,
        };
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        std::thread::spawn(move || {
            let res = ports::scan(&cfg, &cancel, &|ev| {
                let _ = tx.send(match ev {
                    PortEvent::Progress { done, total } => Msg::PortProgress(done, total),
                    PortEvent::Open(r) => Msg::PortOpen(r),
                });
                ctx.request_repaint();
            });
            let _ = tx.send(Msg::PortDone(res));
            ctx.request_repaint();
        });
    }

    pub fn cancel_port_scan(&self) {
        self.port_cancel.store(true, Ordering::Relaxed);
    }

    fn on_port_done(&mut self, res: Result<PortScanOutcome, String>) {
        self.port_scanning = false;
        match res {
            Ok(o) => {
                self.db.save_port_scan(&o);
                let open_list = o.open.iter().map(|r| r.port.to_string()).collect::<Vec<_>>().join(",");
                if let Ok(ip) = o.ip.parse::<Ipv4Addr>() {
                    let gw = self.gateway;
                    let self_ips = self.self_ips();
                    if let Some(d) = self.devices.get_mut(&ip) {
                        d.last_score = Some(o.report.score);
                        d.open_ports = open_list.clone();
                        d.device_type = discovery::guess_type(d, gw, &self_ips);
                        self.db.upsert_device(d);
                    }
                }
                self.score_history = self.db.score_history(&o.ip);
                self.log_event(
                    &o.ip,
                    "Scan de ports",
                    &format!(
                        "{} : {} port(s) ouvert(s) [{}] - score {}/100 ({}){}",
                        o.target,
                        o.open.len(),
                        open_list,
                        o.report.score,
                        o.report.label,
                        if o.cancelled { " (interrompu)" } else { "" }
                    ),
                );
                self.toast(format!(
                    "Scan terminé : {} ouvert(s) sur {} port(s) en {:.1} s - score {}/100",
                    o.open.len(),
                    o.scanned,
                    o.duration_s,
                    o.report.score
                ));
                self.port_outcome = Some(o);
            }
            Err(e) => {
                self.toast(format!("Erreur de scan : {e}"));
                self.port_error = Some(e);
            }
        }
    }

    pub fn scan_ports_of(&mut self, ip: Ipv4Addr) {
        self.port_target = ip.to_string();
        self.score_history = self.db.score_history(&self.port_target);
        self.tab = Tab::Ports;
    }

    // ------------------------------------------------------------------
    // Outils
    // ------------------------------------------------------------------
    pub fn start_ping(&mut self) {
        if self.ping_running {
            self.ping_stop.store(true, Ordering::Relaxed);
            self.ping_running = false;
            return;
        }
        self.ping_stats = PingStats::default();
        self.ping_points.clear();
        self.ping_log.clear();
        self.ping_running = true;
        let stop = Arc::new(AtomicBool::new(false));
        self.ping_stop = stop.clone();
        let target = self.ping_target.trim().to_string();
        let interval = self.ping_interval_ms.max(200);
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        std::thread::spawn(move || {
            let ip = match tools::resolve(&target) {
                Ok(ip) => ip,
                Err(e) => {
                    let _ = tx.send(Msg::PingError(e));
                    ctx.request_repaint();
                    return;
                }
            };
            while !stop.load(Ordering::Relaxed) {
                let t = Instant::now();
                let r = tools::ping(ip, 2000);
                if stop.load(Ordering::Relaxed) || tx.send(Msg::PingReply(r)).is_err() {
                    break;
                }
                ctx.request_repaint();
                let spent = t.elapsed().as_millis() as u32;
                if spent < interval {
                    std::thread::sleep(Duration::from_millis((interval - spent) as u64));
                }
            }
        });
    }

    pub fn start_trace(&mut self) {
        if self.trace_running {
            self.trace_cancel.store(true, Ordering::Relaxed);
            return;
        }
        self.trace_hops.clear();
        self.trace_msg = "Traceroute en cours...".into();
        self.trace_running = true;
        let cancel = Arc::new(AtomicBool::new(false));
        self.trace_cancel = cancel.clone();
        let target = self.trace_target.trim().to_string();
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        std::thread::spawn(move || match tools::resolve(&target) {
            Ok(ip) => {
                tools::traceroute(ip, 30, 1500, &cancel, &|h| {
                    let _ = tx.send(Msg::TraceHop(h));
                    ctx.request_repaint();
                });
                let _ = tx.send(Msg::TraceDone(None));
                ctx.request_repaint();
            }
            Err(e) => {
                let _ = tx.send(Msg::TraceDone(Some(e)));
                ctx.request_repaint();
            }
        });
    }

    fn spawn<F: FnOnce() -> Msg + Send + 'static>(&self, f: F) {
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(f());
            ctx.request_repaint();
        });
    }

    pub fn start_dns(&mut self) {
        self.dns_busy = true;
        let q = self.dns_query.clone();
        self.spawn(move || Msg::Dns(tools::dns_lookup(&q)));
    }

    pub fn send_wol(&mut self, mac: String) {
        self.spawn(move || Msg::Wol(tools::wake_on_lan(&mac, None).map(|_| mac)));
    }

    pub fn fetch_public_ip(&mut self) {
        if self.public_busy {
            return;
        }
        self.public_busy = true;
        self.spawn(|| Msg::PublicIp(tools::public_info()));
    }

    pub fn start_speed(&mut self) {
        if self.speed.running {
            self.speed_cancel.store(true, Ordering::Relaxed);
            return;
        }
        self.speed = SpeedState { running: true, phase: "Mesure de la latence...".into(), ..Default::default() };
        let cancel = Arc::new(AtomicBool::new(false));
        self.speed_cancel = cancel.clone();
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        std::thread::spawn(move || {
            tools::speed_test(&cancel, &|ev| {
                let _ = tx.send(Msg::Speed(ev));
                ctx.request_repaint();
            });
            let _ = tx.send(Msg::SpeedDone);
            ctx.request_repaint();
        });
    }

    pub fn start_http(&mut self) {
        self.http_busy = true;
        let url = self.http_url.clone();
        self.spawn(move || Msg::Http(tools::http_check(&url)));
    }

    pub fn update_oui(&mut self) {
        self.oui_busy = true;
        self.toast("Téléchargement de la base IEEE des fabricants...");
        self.spawn(|| Msg::OuiUpdated(crate::oui::update_from_ieee()));
    }

    // ------------------------------------------------------------------
    // Connexions / interfaces
    // ------------------------------------------------------------------
    pub fn refresh_connections(&mut self) {
        if let Some(sys) = self.sys.as_mut() {
            sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        }
        let entries = crate::platform::socket_table();
        self.connections = entries
            .into_iter()
            .map(|e| {
                let name = if e.pid == 0 {
                    "Système (inactif)".to_string()
                } else if e.pid == 4 {
                    "System".to_string()
                } else {
                    self.sys
                        .as_ref()
                        .and_then(|s| s.process(sysinfo::Pid::from_u32(e.pid)))
                        .map(|p| p.name().to_string_lossy().to_string())
                        .unwrap_or_else(|| "?".into())
                };
                (e, name)
            })
            .collect();
        self.conn_last = Some(Instant::now());
    }

    pub fn refresh_interfaces(&mut self) {
        self.locals = discovery::local_networks();
        self.gateway = crate::platform::default_gateway().or(self.gateway);
        self.networks = sysinfo::Networks::new_with_refreshed_list().ok();
        self.sync_monitor_targets();
    }

    pub fn network_list(&self) -> Vec<(String, String, Vec<String>, u64, u64, u64, (f64, f64))> {
        let mut out = Vec::new();
        if let Some(nets) = &self.networks {
            for (name, data) in nets {
                let ips: Vec<String> = data.ip_networks().iter().map(|n| format!("{}/{}", n.addr, n.prefix)).collect();
                out.push((
                    name.to_string_lossy().to_string(),
                    data.mac_address().to_string().to_uppercase(),
                    ips,
                    data.total_received(),
                    data.total_transmitted(),
                    data.mtu(),
                    self.iface_rates.get(&name.to_string_lossy().to_string()).copied().unwrap_or((0.0, 0.0)),
                ));
            }
        }
        out.sort_by(|a, b| b.3.cmp(&a.3));
        out
    }

    fn tick_traffic(&mut self) {
        let dt = self.net_last.elapsed().as_secs_f64();
        if dt < 1.0 {
            return;
        }
        self.net_last = Instant::now();
        let Some(nets) = self.networks.as_mut() else { return };
        nets.refresh(true);
        let (mut rx_total, mut tx_total) = (0.0, 0.0);
        self.iface_rates.clear();
        for (name, data) in nets.iter() {
            let rx = data.received() as f64 * 8.0 / dt / 1e6;
            let txr = data.transmitted() as f64 * 8.0 / dt / 1e6;
            rx_total += rx;
            tx_total += txr;
            self.iface_rates.insert(name.to_string_lossy().to_string(), (rx, txr));
        }
        let t = self.app_start.elapsed().as_secs_f64();
        self.traffic.push_back([t, rx_total, tx_total]);
        while self.traffic.len() > 300 {
            self.traffic.pop_front();
        }
    }

    // ------------------------------------------------------------------
    // Historique
    // ------------------------------------------------------------------
    pub fn reload_events(&mut self) {
        self.events = self.db.events(2000);
        self.events_dirty = false;
    }

    pub fn clear_history(&mut self) {
        self.db.clear_history();
        self.events.clear();
        self.score_history.clear();
        self.toast("Historique vidé.");
    }

    // ------------------------------------------------------------------
    // Boucle de messages
    // ------------------------------------------------------------------
    fn handle(&mut self, m: Msg) {
        match m {
            Msg::ScanProgress(d, t) => self.scan_progress = (d, t),
            Msg::ScanFound(d) => self.on_found(d),
            Msg::ScanDone(c) => self.on_scan_done(c),
            Msg::PortProgress(d, t) => self.port_progress = (d, t),
            Msg::PortOpen(r) => {
                self.port_live.push(r);
                self.port_live.sort_by_key(|r| r.port);
            }
            Msg::PortDone(r) => self.on_port_done(r),
            Msg::PingReply(r) => {
                if !self.ping_running {
                    return;
                }
                self.ping_stats.add(r);
                let seq = self.ping_stats.sent;
                self.ping_points.push([seq as f64, r.map(|v| v as f64).unwrap_or(f64::NAN)]);
                if self.ping_points.len() > 600 {
                    self.ping_points.remove(0);
                }
                self.ping_log.push_front(match r {
                    Some(ms) => format!("#{seq}  réponse en {ms} ms"),
                    None => format!("#{seq}  délai dépassé"),
                });
                self.ping_log.truncate(200);
            }
            Msg::PingError(e) => {
                self.ping_running = false;
                self.toast(e);
            }
            Msg::TraceHop(h) => self.trace_hops.push(h),
            Msg::TraceDone(err) => {
                self.trace_running = false;
                self.trace_msg = match err {
                    Some(e) => e,
                    None => match self.trace_hops.last() {
                        Some(h) if h.reached => format!("Destination atteinte en {} saut(s).", h.ttl),
                        Some(_) => "Destination non atteinte.".into(),
                        None => "Interrompu.".into(),
                    },
                };
            }
            Msg::Dns(r) => {
                self.dns_busy = false;
                self.dns_result = Some(r);
            }
            Msg::PublicIp(r) => {
                self.public_busy = false;
                if let Ok(i) = &r {
                    self.status = format!("IP publique : {}", i.ip);
                }
                self.public_info = Some(r);
            }
            Msg::Speed(ev) => match ev {
                SpeedEvent::Latency(l) => {
                    self.speed.latency = Some(l);
                    self.speed.phase = "Téléchargement...".into();
                }
                SpeedEvent::Download { mbps, progress } => {
                    self.speed.live_down = mbps;
                    self.speed.progress = progress;
                    let x = self.speed.samples.len() as f64;
                    self.speed.samples.push([x, mbps]);
                }
                SpeedEvent::DownloadDone(v) => {
                    self.speed.down = Some(v);
                    self.speed.phase = "Envoi...".into();
                    self.speed.progress = 0.0;
                }
                SpeedEvent::Upload { mbps, progress } => {
                    self.speed.live_up = mbps;
                    self.speed.progress = progress;
                }
                SpeedEvent::UploadDone(v) => self.speed.up = Some(v),
                SpeedEvent::Error(e) => self.speed.error = Some(e),
            },
            Msg::SpeedDone => {
                self.speed.running = false;
                self.speed.phase = "Terminé.".into();
                let desc = format!(
                    "Débit : {:.1} Mbit/s descendant, {:.1} Mbit/s montant, latence {:.0} ms",
                    self.speed.down.unwrap_or(0.0),
                    self.speed.up.unwrap_or(0.0),
                    self.speed.latency.unwrap_or(0.0)
                );
                if self.speed.down.is_some() {
                    self.log_event("", "Test de débit", &desc);
                }
            }
            Msg::Http(r) => {
                self.http_busy = false;
                self.http_result = Some(r);
            }
            Msg::Monitor(target, rtt) => {
                let t = self.app_start.elapsed().as_secs_f64();
                let hist = self.monitor.entry(target.clone()).or_default();
                hist.push_back([t, rtt.map(|v| v as f64).unwrap_or(f64::NAN)]);
                while hist.len() > 600 {
                    hist.pop_front();
                }
                self.monitor_last.insert(target.clone(), rtt);
                let fails = self.monitor_fail.entry(target.clone()).or_insert(0);
                if rtt.is_none() {
                    *fails += 1;
                } else {
                    *fails = 0;
                }
                let fails = *fails;
                if fails >= 3 && !self.monitor_down.contains(&target) {
                    self.monitor_down.insert(target.clone());
                    self.log_event(&target, "Coupure", &format!("{target} ne répond plus (3 échecs consécutifs)"));
                    if self.settings.notify_offline {
                        self.notify("Coupure détectée", &format!("{target} ne répond plus"));
                    }
                } else if rtt.is_some() && self.monitor_down.remove(&target) {
                    self.log_event(&target, "Rétablissement", &format!("{target} répond de nouveau"));
                }
                if let Some(v) = rtt {
                    if v > self.settings.latency_alert_ms && self.settings.latency_alert_ms > 0 {
                        self.status = format!("Latence élevée vers {target} : {v} ms");
                    }
                }
            }
            Msg::OuiUpdated(r) => {
                self.oui_busy = false;
                match r {
                    Ok(n) => {
                        for d in self.devices.values_mut() {
                            if !d.mac.is_empty() {
                                d.vendor = crate::oui::vendor_or_unknown(&d.mac);
                            }
                        }
                        self.toast(format!("Base des fabricants mise à jour : {n} entrées."));
                    }
                    Err(e) => self.toast(format!("Mise à jour impossible : {e}")),
                }
            }
            Msg::Wol(r) => match r {
                Ok(mac) => {
                    self.wol_status = format!("Paquet magique envoyé a {mac}.");
                    self.log_event("", "Wake-on-LAN", &format!("Paquet magique envoyé a {mac}"));
                    self.toast(self.wol_status.clone());
                }
                Err(e) => {
                    self.wol_status = format!("Erreur : {e}");
                    self.toast(self.wol_status.clone());
                }
            },
        }
    }
}

impl eframe::App for NetPulseApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        while let Ok(m) = self.rx.try_recv() {
            self.handle(m);
        }
        self.tick_traffic();
        if self.events_dirty {
            self.reload_events();
        }
        if self.conn_auto
            && self.tab == Tab::Connections
            && self.conn_last.is_none_or(|t| t.elapsed() > Duration::from_secs(2))
        {
            self.refresh_connections();
        }
        if self.settings.auto_scan
            && !self.scanning
            && self.last_scan.is_none_or(|t| t.elapsed() > Duration::from_secs(self.settings.auto_scan_minutes.max(1) as u64 * 60))
        {
            self.start_scan();
        }

        crate::views::draw(self, ui);

        if self.settings != self.saved_settings {
            let appearance = self.settings.theme != self.saved_settings.theme || self.settings.zoom != self.saved_settings.zoom;
            let monitor = self.settings.monitor_targets != self.saved_settings.monitor_targets
                || self.settings.monitor_interval_s != self.saved_settings.monitor_interval_s;
            self.settings.save();
            self.saved_settings = self.settings.clone();
            if appearance {
                self.apply_appearance();
            }
            if monitor {
                self.sync_monitor_targets();
            }
        }
        self.toasts.retain(|(_, t)| t.elapsed() < Duration::from_secs(5));
        ui.ctx().request_repaint_after(Duration::from_millis(1000));
    }
}
