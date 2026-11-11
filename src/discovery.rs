//! Decouverte des appareils : ICMP + ARP + sonde TCP, resolution de noms, NetBIOS.

use crate::model::{now_string, Device};
use crate::platform::{self, IcmpStatus};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub const MAX_HOSTS: usize = 65_536;

#[derive(Clone, Debug)]
pub struct LocalNet {
    pub iface: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub cidr: String,
    pub mac: String,
}

pub fn network_of(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
    Ipv4Addr::from(u32::from(ip) & mask)
}

pub fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    network_of(a, prefix) == network_of(b, prefix)
}

/// Reseaux IPv4 prives des interfaces actives (hors boucle locale).
pub fn local_networks() -> Vec<LocalNet> {
    let mut macs = std::collections::HashMap::new();
    if let Ok(nets) = sysinfo::Networks::new_with_refreshed_list() {
        for (_, data) in &nets {
            for n in data.ip_networks() {
                if let IpAddr::V4(v4) = n.addr {
                    macs.insert(v4, data.mac_address().to_string().to_uppercase());
                }
            }
        }
    }
    let mut out = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for i in ifaces {
            if let if_addrs::IfAddr::V4(v4) = &i.addr {
                if v4.ip.is_loopback() || v4.ip.is_link_local() {
                    continue;
                }
                let prefix = v4.prefixlen.max(8);
                let net = network_of(v4.ip, prefix);
                out.push(LocalNet {
                    iface: i.name.clone(),
                    ip: v4.ip,
                    prefix,
                    cidr: format!("{net}/{prefix}"),
                    mac: macs.get(&v4.ip).cloned().unwrap_or_default(),
                });
            }
        }
    }
    // Les interfaces portant la passerelle par defaut passent en premier.
    if let Some(gw) = platform::default_gateway() {
        out.sort_by_key(|n| !same_subnet(n.ip, gw, n.prefix));
    }
    out
}

pub fn default_target() -> String {
    local_networks()
        .into_iter()
        .find(|n| n.ip.is_private())
        .map(|n| {
            // On limite la proposition par defaut a un /24 autour de l'adresse locale.
            if n.prefix < 24 {
                format!("{}/24", network_of(n.ip, 24))
            } else {
                n.cidr
            }
        })
        .unwrap_or_else(|| "192.168.1.0/24".into())
}

/// Analyse une cible : "192.168.1.0/24", "192.168.1.10-50", "10.0.0.1-10.0.0.40", "192.168.1.5", listes separees par des virgules.
pub fn parse_targets(spec: &str) -> Result<Vec<Ipv4Addr>, String> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for part in spec.split([',', ';', ' ']).map(str::trim).filter(|p| !p.is_empty()) {
        if let Some((ip, prefix)) = part.split_once('/') {
            let ip: Ipv4Addr = ip.trim().parse().map_err(|_| format!("Adresse invalide : {part}"))?;
            let prefix: u8 = prefix.trim().parse().map_err(|_| format!("Masque invalide : {part}"))?;
            if !(8..=32).contains(&prefix) {
                return Err(format!("Masque /{prefix} non pris en charge (entre /8 et /32)"));
            }
            let base = u32::from(network_of(ip, prefix));
            let size: u64 = 1u64 << (32 - prefix as u32);
            if size as usize > MAX_HOSTS + 2 {
                return Err(format!("Plage trop grande ({size} adresses, maximum {MAX_HOSTS})"));
            }
            if prefix >= 31 {
                for k in 0..size as u32 {
                    out.push(Ipv4Addr::from(base + k));
                }
            } else {
                for k in 1..(size as u32 - 1) {
                    out.push(Ipv4Addr::from(base + k));
                }
            }
        } else if let Some((a, b)) = part.split_once('-') {
            let start: Ipv4Addr = a.trim().parse().map_err(|_| format!("Adresse invalide : {part}"))?;
            let end: Ipv4Addr = if b.contains('.') {
                b.trim().parse().map_err(|_| format!("Adresse invalide : {part}"))?
            } else {
                let last: u8 = b.trim().parse().map_err(|_| format!("Plage invalide : {part}"))?;
                let o = start.octets();
                Ipv4Addr::new(o[0], o[1], o[2], last)
            };
            let (s, e) = (u32::from(start), u32::from(end));
            if s > e {
                return Err(format!("Plage inversée : {part}"));
            }
            if (e - s) as usize > MAX_HOSTS {
                return Err(format!("Plage trop grande : {part}"));
            }
            for v in s..=e {
                out.push(Ipv4Addr::from(v));
            }
        } else {
            out.push(part.parse().map_err(|_| format!("Adresse invalide : {part}"))?);
        }
    }
    out.sort();
    out.dedup();
    if out.is_empty() {
        return Err("Aucune adresse à analyser".into());
    }
    if out.len() > MAX_HOSTS {
        return Err(format!("Trop d'adresses ({}), maximum {MAX_HOSTS}", out.len()));
    }
    Ok(out)
}

/// Nom NetBIOS via une requete NBSTAT (UDP 137), utile pour les machines Windows.
pub fn netbios_name(ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    let mut pkt: Vec<u8> = vec![0x4E, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20];
    // Nom "*" encode (premier niveau) : '*' puis 15 octets nuls.
    let mut raw = [0u8; 16];
    raw[0] = b'*';
    for b in raw {
        pkt.push(b'A' + (b >> 4));
        pkt.push(b'A' + (b & 0x0F));
    }
    pkt.extend_from_slice(&[0x00, 0x00, 0x21, 0x00, 0x01]);
    sock.send_to(&pkt, SocketAddr::new(IpAddr::V4(ip), 137)).ok()?;
    let mut buf = [0u8; 1024];
    let (n, _) = sock.recv_from(&mut buf).ok()?;
    if n < 57 {
        return None;
    }
    let count = buf[56] as usize;
    let mut off = 57;
    for _ in 0..count {
        if off + 18 > n {
            break;
        }
        let name = String::from_utf8_lossy(&buf[off..off + 15]).trim().to_string();
        let suffix = buf[off + 15];
        let group = buf[off + 16] & 0x80 != 0;
        if suffix == 0x00 && !group && !name.is_empty() {
            return Some(name);
        }
        off += 18;
    }
    None
}

pub fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    let name = dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok()?;
    if name.is_empty() || name == ip.to_string() {
        None
    } else {
        Some(name)
    }
}

/// Sonde TCP : une connexion acceptee OU refusee prouve que l'hote est actif.
fn tcp_alive(ip: Ipv4Addr, timeout: Duration) -> bool {
    for port in [445u16, 80, 443, 22, 62078, 8080] {
        match TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), port), timeout) {
            Ok(_) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return true,
            Err(_) => {}
        }
    }
    false
}

pub fn guess_type(d: &Device, gateway: Option<Ipv4Addr>, self_ips: &[Ipv4Addr]) -> String {
    let ip = d.ipv4();
    if self_ips.contains(&ip) {
        return "Cet ordinateur".into();
    }
    if Some(ip) == gateway {
        return "Passerelle / box".into();
    }
    let v = d.vendor.to_lowercase();
    let h = d.hostname.to_lowercase();
    let ports = &d.open_ports;
    let any = |s: &str, keys: &[&str]| keys.iter().any(|k| s.contains(k));
    let has_port = |p: &str| ports.split(',').any(|x| x.trim() == p);

    if any(&h, &["iphone", "android", "galaxy", "pixel", "redmi", "oneplus", "huawei-p", "xiaomi"]) {
        return "Smartphone".into();
    }
    if any(&h, &["ipad", "tab-", "tablet"]) {
        return "Tablette".into();
    }
    if any(&h, &["tv", "bravia", "roku", "chromecast", "firetv", "shield"]) || has_port("8008") || has_port("8060") {
        return "TV / multimédia".into();
    }
    if any(&v, &["hewlett", "hp inc", "epson", "canon", "brother", "xerox", "lexmark", "kyocera", "ricoh"])
        || has_port("9100")
        || has_port("631")
    {
        return "Imprimante".into();
    }
    if any(&v, &["synology", "qnap", "western digital", "buffalo", "asustor"]) {
        return "NAS / stockage".into();
    }
    if any(&v, &["raspberry"]) {
        return "Raspberry Pi".into();
    }
    if any(&v, &["espressif", "tuya", "shelly", "sonoff", "itead", "philips lighting", "signify", "nest", "ring", "wyze", "xiaomi"]) {
        return "Objet connecté (IoT)".into();
    }
    if any(&v, &["sonos", "bose", "harman", "denon", "yamaha"]) {
        return "Audio / enceinte".into();
    }
    if any(&v, &["nintendo", "sony interactive", "valve"]) {
        return "Console de jeu".into();
    }
    if any(&v, &["hikvision", "dahua", "axis comm", "reolink", "foscam"]) || has_port("554") {
        return "Caméra IP".into();
    }
    if any(&v, &["vmware", "virtualbox", "pcs systemtechnik", "qemu", "parallels"]) {
        return "Machine virtuelle".into();
    }
    if any(&v, &["tp-link", "netgear", "ubiquiti", "cisco", "juniper", "mikrotik", "aruba", "d-link", "zyxel", "freebox", "sagemcom", "technicolor", "arcadyan", "huawei technologies", "avm", "linksys", "eero"]) {
        return "Équipement réseau".into();
    }
    if any(&v, &["apple"]) {
        return "Appareil Apple".into();
    }
    if any(&v, &["samsung", "oneplus", "oppo", "vivo", "motorola", "google"]) {
        return "Mobile / Android".into();
    }
    if any(&v, &["intel", "realtek", "dell", "lenovo", "asustek", "micro-star", "gigabyte", "liteon", "azurewave", "hon hai", "quanta", "wistron", "compal"])
        || has_port("3389")
        || has_port("445")
    {
        return "Ordinateur".into();
    }
    if crate::oui::is_randomized(&d.mac) {
        return "Appareil mobile (MAC privée)".into();
    }
    "Inconnu".into()
}

pub struct ScanConfig {
    pub targets: Vec<Ipv4Addr>,
    pub timeout_ms: u32,
    pub threads: usize,
    pub tcp_probe: bool,
    pub resolve_names: bool,
    pub netbios: bool,
}

pub enum ScanEvent {
    Progress { done: usize, total: usize },
    Found(Device),
}

pub fn probe(ip: Ipv4Addr, cfg: &ScanConfig, locals: &[LocalNet]) -> Option<Device> {
    let on_link = locals.iter().any(|n| same_subnet(n.ip, ip, n.prefix));
    let local = locals.iter().find(|n| n.ip == ip);
    let start = Instant::now();
    let reply = platform::icmp_echo(ip, cfg.timeout_ms, None);
    let mut latency = (reply.status == IcmpStatus::Reply && reply.from == Some(ip)).then_some(reply.rtt_ms);
    let mut mac = if local.is_some() { None } else if on_link { platform::arp_resolve(ip).map(|m| platform::format_mac(&m)) } else { None };
    let mut alive = latency.is_some() || mac.is_some() || local.is_some();
    if !alive && cfg.tcp_probe {
        alive = tcp_alive(ip, Duration::from_millis(cfg.timeout_ms.min(400) as u64));
        if alive {
            latency = Some(start.elapsed().as_millis() as u32);
            if on_link && mac.is_none() {
                mac = platform::arp_resolve(ip).map(|m| platform::format_mac(&m));
            }
        }
    }
    if !alive {
        return None;
    }
    let mac = match local {
        Some(l) if !l.mac.is_empty() => l.mac.clone(),
        _ => mac.unwrap_or_default(),
    };
    let mut hostname = String::new();
    if local.is_some() {
        hostname = dns_lookup::get_hostname().unwrap_or_default();
    } else if cfg.resolve_names {
        hostname = reverse_dns(ip).unwrap_or_default();
        if hostname.is_empty() && cfg.netbios {
            hostname = netbios_name(ip, Duration::from_millis(400)).unwrap_or_default();
        }
    }
    let now = now_string();
    Some(Device {
        ip: ip.to_string(),
        vendor: if mac.is_empty() { "Fabricant inconnu".into() } else { crate::oui::vendor_or_unknown(&mac) },
        mac,
        hostname,
        online: true,
        latency_ms: latency,
        first_seen: now.clone(),
        last_seen: now,
        ..Default::default()
    })
}

pub fn scan(cfg: &ScanConfig, cancel: &AtomicBool, on_event: &(dyn Fn(ScanEvent) + Sync)) {
    let locals = local_networks();
    let total = cfg.targets.len();
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..cfg.threads.clamp(1, 512).min(total.max(1)) {
            s.spawn(|| loop {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= total {
                    break;
                }
                if let Some(d) = probe(cfg.targets[i], cfg, &locals) {
                    on_event(ScanEvent::Found(d));
                }
                let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                if d % 4 == 0 || d == total {
                    on_event(ScanEvent::Progress { done: d, total });
                }
            });
        }
    });
}
