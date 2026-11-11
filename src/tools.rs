//! Outils reseau : ping, traceroute, DNS, Wake-on-LAN, IP publique, debit, HTTP, calculateur IP.

use crate::platform::{self, IcmpStatus};
use crate::ports::resolve_ipv4;
use serde::Deserialize;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub fn http_agent(timeout_s: u64) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_s)))
        .http_status_as_error(false)
        .user_agent(concat!("NetPulse/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

// ------------------------------------------------------------------
// Ping
// ------------------------------------------------------------------
pub fn ping(ip: Ipv4Addr, timeout_ms: u32) -> Option<u32> {
    let r = platform::icmp_echo(ip, timeout_ms, None);
    (r.status == IcmpStatus::Reply).then_some(r.rtt_ms)
}

#[derive(Default, Clone)]
pub struct PingStats {
    pub sent: u32,
    pub received: u32,
    pub min: u32,
    pub max: u32,
    pub sum: u64,
    pub jitter_sum: u64,
    pub last: Option<u32>,
}

impl PingStats {
    pub fn add(&mut self, rtt: Option<u32>) {
        self.sent += 1;
        if let Some(r) = rtt {
            if self.received == 0 {
                self.min = r;
                self.max = r;
            } else {
                self.min = self.min.min(r);
                self.max = self.max.max(r);
            }
            if let Some(prev) = self.last {
                self.jitter_sum += (r as i64 - prev as i64).unsigned_abs();
            }
            self.received += 1;
            self.sum += r as u64;
            self.last = Some(r);
        }
    }
    pub fn avg(&self) -> f64 {
        if self.received == 0 { 0.0 } else { self.sum as f64 / self.received as f64 }
    }
    pub fn loss(&self) -> f64 {
        if self.sent == 0 { 0.0 } else { 100.0 * (self.sent - self.received) as f64 / self.sent as f64 }
    }
    pub fn jitter(&self) -> f64 {
        if self.received < 2 { 0.0 } else { self.jitter_sum as f64 / (self.received - 1) as f64 }
    }
}

// ------------------------------------------------------------------
// Traceroute
// ------------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct Hop {
    pub ttl: u8,
    pub ip: Option<Ipv4Addr>,
    pub host: String,
    pub rtts: Vec<Option<u32>>,
    pub reached: bool,
}

pub fn traceroute(target: Ipv4Addr, max_hops: u8, timeout_ms: u32, cancel: &AtomicBool, on_hop: &dyn Fn(Hop)) {
    for ttl in 1..=max_hops {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let mut rtts = Vec::new();
        let mut ip = None;
        let mut reached = false;
        for _ in 0..3 {
            let r = platform::icmp_echo(target, timeout_ms, Some(ttl));
            match r.status {
                IcmpStatus::Reply => {
                    reached = true;
                    ip = r.from.or(Some(target));
                    rtts.push(Some(r.rtt_ms));
                }
                IcmpStatus::TtlExpired => {
                    ip = r.from.or(ip);
                    rtts.push(Some(r.rtt_ms));
                }
                _ => rtts.push(None),
            }
        }
        let host = ip.and_then(crate::discovery::reverse_dns).unwrap_or_default();
        on_hop(Hop { ttl, ip, host, rtts, reached });
        if reached {
            return;
        }
    }
}

// ------------------------------------------------------------------
// DNS
// ------------------------------------------------------------------
pub fn dns_lookup(query: &str) -> Result<(Vec<String>, f64), String> {
    let q = query.trim();
    let t0 = Instant::now();
    if let Ok(ip) = q.parse::<IpAddr>() {
        let name = dns_lookup::lookup_addr(&ip).map_err(|e| format!("{e:?}"))?;
        return Ok((vec![format!("PTR  {name}")], t0.elapsed().as_secs_f64() * 1000.0));
    }
    let ips: Vec<String> = dns_lookup::lookup_host(q)
        .map_err(|e| format!("Résolution impossible : {e:?}"))?
        .map(|ip| match ip {
            IpAddr::V4(v) => format!("A     {v}"),
            IpAddr::V6(v) => format!("AAAA  {v}"),
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok((ips, t0.elapsed().as_secs_f64() * 1000.0))
}

// ------------------------------------------------------------------
// Wake-on-LAN
// ------------------------------------------------------------------
pub fn wake_on_lan(mac: &str, broadcast: Option<Ipv4Addr>) -> Result<(), String> {
    let mac = platform::parse_mac(mac).ok_or("Adresse MAC invalide")?;
    let mut pkt = vec![0xFFu8; 6];
    for _ in 0..16 {
        pkt.extend_from_slice(&mac);
    }
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_broadcast(true).map_err(|e| e.to_string())?;
    let mut dests = vec![Ipv4Addr::BROADCAST];
    if let Some(b) = broadcast {
        dests.push(b);
    }
    for net in crate::discovery::local_networks() {
        let host_bits = if net.prefix >= 32 { 0 } else { u32::MAX >> net.prefix as u32 };
        dests.push(Ipv4Addr::from(u32::from(net.ip) | host_bits));
    }
    dests.dedup();
    let mut ok = false;
    for d in dests {
        for port in [9u16, 7] {
            if sock.send_to(&pkt, (d, port)).is_ok() {
                ok = true;
            }
        }
    }
    if ok { Ok(()) } else { Err("Envoi du paquet magique impossible".into()) }
}

// ------------------------------------------------------------------
// IP publique
// ------------------------------------------------------------------
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct PublicInfo {
    pub ip: String,
    pub hostname: String,
    pub city: String,
    pub region: String,
    pub country: String,
    pub loc: String,
    pub org: String,
    pub postal: String,
    pub timezone: String,
}

pub fn public_info() -> Result<PublicInfo, String> {
    let mut resp = http_agent(10).get("https://ipinfo.io/json").call().map_err(|e| e.to_string())?;
    let text = resp.body_mut().read_to_string().map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

// ------------------------------------------------------------------
// Test de debit (Cloudflare)
// ------------------------------------------------------------------
pub enum SpeedEvent {
    Latency(f64),
    Download { mbps: f64, progress: f32 },
    DownloadDone(f64),
    Upload { mbps: f64, progress: f32 },
    UploadDone(f64),
    Error(String),
}

pub fn speed_test(cancel: &AtomicBool, on: &dyn Fn(SpeedEvent)) {
    let agent = http_agent(60);
    // Latence HTTP (moyenne de 5 petites requetes).
    let mut lat = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        if agent.get("https://speed.cloudflare.com/__down?bytes=0").call().is_ok() {
            lat.push(t.elapsed().as_secs_f64() * 1000.0);
        }
    }
    if lat.is_empty() {
        on(SpeedEvent::Error("Serveur de test injoignable".into()));
        return;
    }
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    on(SpeedEvent::Latency(lat[lat.len() / 2]));

    // Telechargement
    let total: u64 = 50_000_000;
    let t0 = Instant::now();
    let mut got: u64 = 0;
    match agent.get(format!("https://speed.cloudflare.com/__down?bytes={total}")).call() {
        Ok(mut resp) => {
            let mut reader = resp.body_mut().with_config().limit(total + 1024).reader();
            let mut buf = vec![0u8; 64 * 1024];
            let mut last = Instant::now();
            loop {
                if cancel.load(Ordering::Relaxed) || t0.elapsed() > Duration::from_secs(20) {
                    break;
                }
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => got += n as u64,
                    Err(e) => {
                        on(SpeedEvent::Error(e.to_string()));
                        break;
                    }
                }
                if last.elapsed() > Duration::from_millis(200) {
                    last = Instant::now();
                    let mbps = got as f64 * 8.0 / t0.elapsed().as_secs_f64() / 1e6;
                    on(SpeedEvent::Download { mbps, progress: got as f32 / total as f32 });
                }
            }
        }
        Err(e) => {
            on(SpeedEvent::Error(e.to_string()));
            return;
        }
    }
    let down = got as f64 * 8.0 / t0.elapsed().as_secs_f64().max(0.001) / 1e6;
    on(SpeedEvent::DownloadDone(down));
    if cancel.load(Ordering::Relaxed) {
        return;
    }

    // Envoi : plusieurs blocs de 5 Mo.
    let chunk = vec![0x5Au8; 5_000_000];
    let rounds = 4;
    let t1 = Instant::now();
    let mut sent: u64 = 0;
    for i in 0..rounds {
        if cancel.load(Ordering::Relaxed) || t1.elapsed() > Duration::from_secs(20) {
            break;
        }
        match agent.post("https://speed.cloudflare.com/__up").send(&chunk[..]) {
            Ok(_) => {
                sent += chunk.len() as u64;
                let mbps = sent as f64 * 8.0 / t1.elapsed().as_secs_f64() / 1e6;
                on(SpeedEvent::Upload { mbps, progress: (i + 1) as f32 / rounds as f32 });
            }
            Err(e) => {
                on(SpeedEvent::Error(e.to_string()));
                break;
            }
        }
    }
    let up = sent as f64 * 8.0 / t1.elapsed().as_secs_f64().max(0.001) / 1e6;
    on(SpeedEvent::UploadDone(up));
}

// ------------------------------------------------------------------
// Verification HTTP
// ------------------------------------------------------------------
#[derive(Clone, Debug, Default)]
pub struct HttpInfo {
    pub url: String,
    pub status: u16,
    pub reason: String,
    pub time_ms: f64,
    pub headers: Vec<(String, String)>,
    pub size: usize,
    pub https: bool,
    pub missing_security_headers: Vec<&'static str>,
}

pub fn http_check(url: &str) -> Result<HttpInfo, String> {
    let mut url = url.trim().to_string();
    if !url.starts_with("http://") && !url.starts_with("https://") {
        url = format!("http://{url}");
    }
    let t0 = Instant::now();
    let mut resp = http_agent(15).get(&url).call().map_err(|e| e.to_string())?;
    let time_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let status = resp.status();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binaire>").to_string()))
        .collect();
    let size = resp.body_mut().with_config().limit(10 * 1024 * 1024).read_to_vec().map(|b| b.len()).unwrap_or(0);
    let has = |h: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(h));
    let mut missing = Vec::new();
    for h in ["strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy"] {
        if !has(h) {
            missing.push(h);
        }
    }
    Ok(HttpInfo {
        https: url.starts_with("https://"),
        url,
        status: status.as_u16(),
        reason: status.canonical_reason().unwrap_or("").to_string(),
        time_ms,
        headers,
        size,
        missing_security_headers: missing,
    })
}

// ------------------------------------------------------------------
// Calculateur de sous-reseau
// ------------------------------------------------------------------
pub struct SubnetInfo {
    pub rows: Vec<(&'static str, String)>,
}

pub fn subnet_calc(input: &str) -> Result<SubnetInfo, String> {
    let (ip_s, prefix_s) = input.trim().split_once('/').unwrap_or((input.trim(), "24"));
    let ip: Ipv4Addr = ip_s.trim().parse().map_err(|_| "Adresse IPv4 invalide".to_string())?;
    let prefix: u32 = if prefix_s.contains('.') {
        let m: Ipv4Addr = prefix_s.parse().map_err(|_| "Masque invalide".to_string())?;
        let v = u32::from(m);
        if v.leading_ones() + v.trailing_zeros() != 32 {
            return Err("Masque non contigu".into());
        }
        v.leading_ones()
    } else {
        prefix_s.trim().parse().map_err(|_| "Préfixe invalide".to_string())?
    };
    if prefix > 32 {
        return Err("Préfixe invalide (0-32)".into());
    }
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let net = u32::from(ip) & mask;
    let bcast = net | !mask;
    let total: u64 = 1u64 << (32 - prefix);
    let (first, last, hosts) = match prefix {
        32 => (net, net, 1u64),
        31 => (net, bcast, 2),
        _ => (net + 1, bcast - 1, total - 2),
    };
    let class = match ip.octets()[0] {
        0..=127 => "A",
        128..=191 => "B",
        192..=223 => "C",
        224..=239 => "D (multicast)",
        _ => "E (réservé)",
    };
    let kind = if ip.is_private() {
        "Privée (RFC 1918)"
    } else if ip.is_loopback() {
        "Boucle locale"
    } else if ip.is_link_local() {
        "Lien local (APIPA)"
    } else if ip.is_multicast() {
        "Multicast"
    } else if ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]) {
        "CGNAT (RFC 6598)"
    } else {
        "Publique"
    };
    let bin = |v: u32| {
        v.to_be_bytes().iter().map(|b| format!("{b:08b}")).collect::<Vec<_>>().join(".")
    };
    Ok(SubnetInfo {
        rows: vec![
            ("Adresse", ip.to_string()),
            ("Notation CIDR", format!("{}/{prefix}", Ipv4Addr::from(net))),
            ("Masque", Ipv4Addr::from(mask).to_string()),
            ("Masque générique (wildcard)", Ipv4Addr::from(!mask).to_string()),
            ("Réseau", Ipv4Addr::from(net).to_string()),
            ("Diffusion (broadcast)", Ipv4Addr::from(bcast).to_string()),
            ("Premier hôte", Ipv4Addr::from(first).to_string()),
            ("Dernier hôte", Ipv4Addr::from(last).to_string()),
            ("Hôtes utilisables", hosts.to_string()),
            ("Adresses totales", total.to_string()),
            ("Classe", class.into()),
            ("Type", kind.into()),
            ("Adresse (binaire)", bin(u32::from(ip))),
            ("Masque (binaire)", bin(mask)),
        ],
    })
}

/// Resout un nom d'hote ou une IP (utilise par plusieurs outils).
pub fn resolve(host: &str) -> Result<Ipv4Addr, String> {
    resolve_ipv4(host)
}
