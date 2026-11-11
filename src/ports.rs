//! Scanner de ports TCP (connexion complete) avec recuperation de banniere.

use crate::model::{now_string, PortResult, PortScanOutcome, PortState};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const PRESETS: &[(&str, &str)] = &[
    (
        "Courants",
        "21,22,23,25,53,80,110,111,135,139,143,443,445,465,548,554,587,631,993,995,1433,1723,1883,2049,3306,3389,5000,5432,5900,6379,8000,8080,8443,9100",
    ),
    ("Web", "80,81,443,591,3000,5000,7080,8000,8008,8080,8081,8088,8443,8888,9000,9443"),
    ("Bases de données", "1433,1521,3306,5432,5984,6379,7474,8086,9042,9200,11211,27017,28017"),
    ("Accès distant", "22,23,512,513,514,3389,5800,5900,5901,5938,5985,5986,6568,7070"),
    ("Partage de fichiers", "20,21,69,111,137,139,445,548,873,2049,3260"),
    (
        "IoT / multimédia",
        "80,443,554,1883,1900,5000,5353,7000,7547,8008,8009,8060,8080,8123,8554,8883,9000,32400,49152,62078",
    ),
    ("Bien connus (1-1024)", "1-1024"),
    ("Étendu (1-10000)", "1-10000"),
    ("Tous (1-65535)", "1-65535"),
];

pub fn service_name(port: u16) -> &'static str {
    match port {
        20 => "FTP-data",
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        69 => "TFTP",
        80 => "HTTP",
        81 => "HTTP-alt",
        88 => "Kerberos",
        110 => "POP3",
        111 => "RPCbind",
        119 => "NNTP",
        123 => "NTP",
        135 => "MS-RPC",
        137 => "NetBIOS-NS",
        138 => "NetBIOS-DGM",
        139 => "NetBIOS-SSN",
        143 => "IMAP",
        161 | 162 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        500 => "IKE",
        512 => "rexec",
        513 => "rlogin",
        514 => "rsh",
        515 => "LPD",
        548 => "AFP",
        554 => "RTSP",
        587 => "SMTP-submission",
        591 => "HTTP-alt",
        631 => "IPP (CUPS)",
        636 => "LDAPS",
        873 => "rsync",
        902 => "VMware",
        993 => "IMAPS",
        995 => "POP3S",
        1080 => "SOCKS",
        1194 => "OpenVPN",
        1433 => "MS-SQL",
        1521 => "Oracle",
        1723 => "PPTP",
        1883 => "MQTT",
        1900 => "UPnP/SSDP",
        2049 => "NFS",
        2375 => "Docker API",
        2376 => "Docker API (TLS)",
        3000 => "HTTP-dev",
        3260 => "iSCSI",
        3306 => "MySQL",
        3389 => "RDP",
        4444 => "Metasploit?",
        5000 => "UPnP / HTTP-alt",
        5353 => "mDNS",
        5432 => "PostgreSQL",
        5555 => "ADB (Android)",
        5800 => "VNC-HTTP",
        5900..=5903 => "VNC",
        5938 => "TeamViewer",
        5984 => "CouchDB",
        5985 => "WinRM",
        5986 => "WinRM (TLS)",
        6379 => "Redis",
        6568 => "AnyDesk",
        7000 => "AirPlay",
        7070 => "AnyDesk/RTSP",
        7474 => "Neo4j",
        7547 => "TR-069",
        8000 => "HTTP-alt",
        8008 | 8009 => "Chromecast",
        8060 => "Roku",
        8080 | 8081 | 8088 => "HTTP-proxy",
        8086 => "InfluxDB",
        8123 => "Home Assistant",
        8443 => "HTTPS-alt",
        8554 => "RTSP-alt",
        8883 => "MQTT (TLS)",
        8888 => "HTTP-alt",
        9000 => "HTTP-alt",
        9042 => "Cassandra",
        9100 => "Impression RAW",
        9200 => "Elasticsearch",
        9443 => "HTTPS-alt",
        11211 => "Memcached",
        27017 | 28017 => "MongoDB",
        32400 => "Plex",
        49152 => "UPnP",
        62078 => "iPhone sync",
        _ => "?",
    }
}

fn is_tls_port(port: u16) -> bool {
    matches!(port, 443 | 465 | 636 | 853 | 993 | 995 | 2376 | 5986 | 8443 | 8883 | 9443)
}

fn is_http_port(port: u16) -> bool {
    matches!(port, 80 | 81 | 591 | 3000 | 5000 | 7080 | 8000 | 8008 | 8060 | 8080 | 8081 | 8088 | 8123 | 8888 | 9000 | 32400)
}

/// "22,80,1000-1010" -> liste triee et dedupliquee.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut set = std::collections::BTreeSet::new();
    for part in spec.split([',', ';', ' ']).map(str::trim).filter(|p| !p.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            let a: u16 = a.trim().parse().map_err(|_| format!("Port invalide : {part}"))?;
            let b: u16 = b.trim().parse().map_err(|_| format!("Port invalide : {part}"))?;
            if a == 0 || a > b {
                return Err(format!("Plage invalide : {part}"));
            }
            set.extend(a..=b);
        } else {
            let p: u16 = part.parse().map_err(|_| format!("Port invalide : {part}"))?;
            if p == 0 {
                return Err("Le port 0 n'est pas valide".into());
            }
            set.insert(p);
        }
    }
    if set.is_empty() {
        return Err("Aucun port à scanner".into());
    }
    Ok(set.into_iter().collect())
}

pub fn resolve_ipv4(host: &str) -> Result<Ipv4Addr, String> {
    let host = host.trim();
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    let addrs = (host, 0).to_socket_addrs().map_err(|e| format!("Résolution de {host} impossible : {e}"))?;
    for a in addrs {
        if let IpAddr::V4(v4) = a.ip() {
            return Ok(v4);
        }
    }
    Err(format!("Aucune adresse IPv4 pour {host}"))
}

fn clean_banner(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut out: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if out.len() > 180 {
        let mut cut = 180;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push_str("...");
    }
    out
}

fn grab_banner(stream: &mut TcpStream, host: &str, port: u16) -> String {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(900)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    if is_tls_port(port) {
        return "Service chiffré (TLS)".into();
    }
    if is_http_port(port) {
        let req = format!("HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: NetPulse\r\n\r\n");
        let _ = stream.write_all(req.as_bytes());
        let mut buf = vec![0u8; 2048];
        let mut total = 0;
        while total < buf.len() {
            match stream.read(&mut buf[total..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
        let text = String::from_utf8_lossy(&buf[..total]).to_string();
        let status = text.lines().next().unwrap_or("").trim().to_string();
        let server = text
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("server:"))
            .map(|l| l[7..].trim().to_string());
        return match server {
            Some(s) if !status.is_empty() => clean_banner(format!("{status} | {s}").as_bytes()),
            _ => clean_banner(status.as_bytes()),
        };
    }
    let mut buf = [0u8; 512];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => clean_banner(&buf[..n]),
        _ => String::new(),
    }
}

pub struct PortScanConfig {
    pub target: String,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub threads: usize,
    pub banners: bool,
}

pub enum PortEvent {
    Progress { done: usize, total: usize },
    Open(PortResult),
}

pub fn scan(cfg: &PortScanConfig, cancel: &AtomicBool, on_event: &(dyn Fn(PortEvent) + Sync)) -> Result<PortScanOutcome, String> {
    let ip = resolve_ipv4(&cfg.target)?;
    let started = now_string();
    let t0 = Instant::now();
    let total = cfg.ports.len();
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let keep_all = total <= 1024;
    let results: Mutex<Vec<PortResult>> = Mutex::new(Vec::new());
    let closed = AtomicUsize::new(0);
    let filtered = AtomicUsize::new(0);
    let host = cfg.target.trim().to_string();

    std::thread::scope(|s| {
        for _ in 0..cfg.threads.clamp(1, 1000).min(total) {
            s.spawn(|| loop {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= total {
                    break;
                }
                let port = cfg.ports[i];
                let addr = SocketAddr::new(IpAddr::V4(ip), port);
                let start = Instant::now();
                let res = match TcpStream::connect_timeout(&addr, cfg.timeout) {
                    Ok(mut stream) => {
                        let latency = start.elapsed().as_millis() as u32;
                        let banner = if cfg.banners { grab_banner(&mut stream, &host, port) } else { String::new() };
                        let r = PortResult {
                            port,
                            service: service_name(port).into(),
                            state: PortState::Open,
                            banner,
                            latency_ms: latency,
                        };
                        on_event(PortEvent::Open(r.clone()));
                        Some(r)
                    }
                    Err(e) => {
                        let state = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                            closed.fetch_add(1, Ordering::Relaxed);
                            PortState::Closed
                        } else {
                            filtered.fetch_add(1, Ordering::Relaxed);
                            PortState::Filtered
                        };
                        keep_all.then(|| PortResult {
                            port,
                            service: service_name(port).into(),
                            state,
                            banner: String::new(),
                            latency_ms: 0,
                        })
                    }
                };
                if let Some(r) = res {
                    if let Ok(mut v) = results.lock() {
                        v.push(r);
                    }
                }
                let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                if d % 25 == 0 || d == total {
                    on_event(PortEvent::Progress { done: d, total });
                }
            });
        }
    });

    let mut all = results.into_inner().unwrap_or_default();
    all.sort_by_key(|r| r.port);
    let open: Vec<PortResult> = all.iter().filter(|r| r.state == PortState::Open).cloned().collect();
    let report = crate::security::analyze(&cfg.target, &open);
    Ok(PortScanOutcome {
        target: cfg.target.clone(),
        ip: ip.to_string(),
        started,
        duration_s: t0.elapsed().as_secs_f64(),
        scanned: done.load(Ordering::Relaxed),
        open,
        closed: closed.load(Ordering::Relaxed),
        filtered: filtered.load(Ordering::Relaxed),
        all: if keep_all { all } else { Vec::new() },
        report,
        cancelled: cancel.load(Ordering::Relaxed),
    })
}

/// Rapport HTML autonome d'un scan de ports.
pub fn html_report(o: &PortScanOutcome) -> String {
    fn esc(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    }
    let mut rows = String::new();
    for r in &o.open {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{} ms</td><td>{}</td></tr>",
            r.port,
            esc(&r.service),
            r.latency_ms,
            esc(&r.banner)
        ));
    }
    let mut findings = String::new();
    for f in &o.report.findings {
        findings.push_str(&format!(
            "<tr><td class=\"sev {}\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            f.severity.label().to_lowercase(),
            f.severity.label(),
            esc(&f.title),
            esc(&f.detail),
            esc(&f.recommendation)
        ));
    }
    format!(
        r#"<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>Rapport NetPulse - {target}</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#1d2330;background:#f6f7fb}}h1{{margin-bottom:4px}}
.card{{background:#fff;border-radius:10px;padding:18px 22px;margin:16px 0;box-shadow:0 1px 3px #0002}}
table{{border-collapse:collapse;width:100%}}td,th{{text-align:left;padding:6px 10px;border-bottom:1px solid #e3e6ee}}
.score{{font-size:42px;font-weight:700}}.sev{{font-weight:600}}.critique{{color:#b71c1c}}.élevé{{color:#e65100}}.moyen{{color:#f9a825}}.faible{{color:#1565c0}}.info{{color:#607d8b}}</style></head>
<body><h1>Rapport de sécurité NetPulse</h1><div>Cible : <b>{target}</b> ({ip}) - généré le {date}</div>
<div class="card"><div class="score">{score}/100 - {grade}</div><div>{label}</div>
<div>{scanned} ports testés en {dur:.1} s : {nopen} ouverts, {closed} fermés, {filtered} filtrés.</div></div>
<div class="card"><h2>Constats</h2><table><tr><th>Gravité</th><th>Constat</th><th>Détail</th><th>Recommandation</th></tr>{findings}</table></div>
<div class="card"><h2>Ports ouverts</h2><table><tr><th>Port</th><th>Service</th><th>Latence</th><th>Bannière</th></tr>{rows}</table></div>
<p style="color:#888">NetPulse effectue uniquement des connexions TCP simples. À utiliser seulement sur des réseaux que vous êtes autorisé à analyser.</p>
</body></html>"#,
        target = esc(&o.target),
        ip = o.ip,
        date = now_string(),
        score = o.report.score,
        grade = o.report.grade,
        label = esc(&o.report.label),
        scanned = o.scanned,
        dur = o.duration_s,
        nopen = o.open.len(),
        closed = o.closed,
        filtered = o.filtered,
    )
}
