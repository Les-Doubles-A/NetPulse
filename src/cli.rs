//! Mode ligne de commande : `NetPulse.exe <commande> [arguments]`.

use crate::{discovery, ports, tools};
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;
use std::time::Duration;

const HELP: &str = "\
NetPulse - surveillance et analyse du réseau local

Usage : NetPulse.exe [commande] [arguments]
Sans argument, l'interface graphique est lancée.

Commandes :
  scan [cible]              Découvre les appareils (ex. 192.168.1.0/24, 10.0.0.1-50)
  ports <hôte> [ports]      Scanne des ports TCP (ex. 22,80,443 ou 1-1024)
  ping <hôte> [nombre]      Ping ICMP avec statistiques
  trace <hôte>              Traceroute ICMP
  dns <nom|ip>              Résolution DNS directe ou inverse
  wol <mac>                 Envoie un paquet Wake-on-LAN
  ip                        Affiche l'adresse IP publique
  interfaces                Liste les réseaux locaux détectés
  subnet <cidr>             Calculateur de sous-réseau
  json                      (option) sortie JSON pour scan et ports
  -h, --help                Affiche cette aide
  -V, --version             Affiche la version
";

pub fn run(args: &[String]) -> i32 {
    println!();
    let json = args.iter().any(|a| a == "--json" || a == "json");
    let args: Vec<&str> = args.iter().map(String::as_str).filter(|a| *a != "--json" && *a != "json").collect();
    let code = match args.first().copied() {
        None | Some("-h") | Some("--help") | Some("help") => {
            print!("{HELP}");
            0
        }
        Some("-V") | Some("--version") | Some("version") => {
            println!("NetPulse {}", crate::VERSION);
            0
        }
        Some("scan") => scan(args.get(1).copied(), json),
        Some("ports") => match args.get(1) {
            Some(h) => port_scan(h, args.get(2).copied(), json),
            None => usage("ports <hôte> [ports]"),
        },
        Some("ping") => match args.get(1) {
            Some(h) => ping(h, args.get(2).and_then(|n| n.parse().ok()).unwrap_or(4)),
            None => usage("ping <hôte> [nombre]"),
        },
        Some("trace") | Some("traceroute") => match args.get(1) {
            Some(h) => trace(h),
            None => usage("trace <hôte>"),
        },
        Some("dns") => match args.get(1) {
            Some(q) => match tools::dns_lookup(q) {
                Ok((rows, ms)) => {
                    for r in rows {
                        println!("  {r}");
                    }
                    println!("  ({ms:.1} ms)");
                    0
                }
                Err(e) => fail(&e),
            },
            None => usage("dns <nom|ip>"),
        },
        Some("wol") => match args.get(1) {
            Some(m) => match tools::wake_on_lan(m, None) {
                Ok(()) => {
                    println!("Paquet magique envoyé a {m}");
                    0
                }
                Err(e) => fail(&e),
            },
            None => usage("wol <mac>"),
        },
        Some("ip") => match tools::public_info() {
            Ok(i) => {
                println!("IP publique : {}\nFournisseur : {}\nLocalisation : {} {} {}", i.ip, i.org, i.city, i.region, i.country);
                0
            }
            Err(e) => fail(&e),
        },
        Some("interfaces") => {
            println!("Passerelle : {}", crate::platform::default_gateway().map(|g| g.to_string()).unwrap_or("-".into()));
            for n in discovery::local_networks() {
                println!("  {:<28} {:<16} {:<20} {}", n.iface, n.ip, n.cidr, n.mac);
            }
            0
        }
        Some("subnet") => match args.get(1) {
            Some(c) => match tools::subnet_calc(c) {
                Ok(info) => {
                    for (k, v) in info.rows {
                        println!("  {k:<28} {v}");
                    }
                    0
                }
                Err(e) => fail(&e),
            },
            None => usage("subnet <cidr>"),
        },
        Some(other) => {
            eprintln!("Commande inconnue : {other}\n");
            print!("{HELP}");
            2
        }
    };
    code
}

fn usage(u: &str) -> i32 {
    eprintln!("Usage : NetPulse.exe {u}");
    2
}

fn fail(e: &str) -> i32 {
    eprintln!("Erreur : {e}");
    1
}

fn scan(target: Option<&str>, json: bool) -> i32 {
    let s = crate::storage::Settings::load();
    let target = target.map(str::to_string).unwrap_or_else(discovery::default_target);
    let targets = match discovery::parse_targets(&target) {
        Ok(t) => t,
        Err(e) => return fail(&e),
    };
    if !json {
        println!("Analyse de {target} ({} adresses)...", targets.len());
    }
    let cfg = discovery::ScanConfig {
        targets,
        timeout_ms: s.ping_timeout_ms,
        threads: s.discovery_threads,
        tcp_probe: s.tcp_probe,
        resolve_names: s.resolve_names,
        netbios: s.netbios,
    };
    let found = Mutex::new(Vec::new());
    let cancel = AtomicBool::new(false);
    discovery::scan(&cfg, &cancel, &|ev| {
        if let discovery::ScanEvent::Found(d) = ev {
            if let Ok(mut f) = found.lock() {
                f.push(d);
            }
        }
    });
    let mut found = found.into_inner().unwrap_or_default();
    found.sort_by_key(|d| d.ipv4());
    if json {
        println!("{}", serde_json::to_string_pretty(&found).unwrap_or_default());
        return 0;
    }
    println!("{:<16} {:<18} {:<8} {:<30} {}", "IP", "MAC", "Latence", "Nom", "Fabricant");
    for d in &found {
        println!(
            "{:<16} {:<18} {:<8} {:<30} {}",
            d.ip,
            d.mac,
            d.latency_ms.map(|l| format!("{l} ms")).unwrap_or_default(),
            d.hostname,
            d.vendor
        );
    }
    println!("\n{} appareil(s) actif(s).", found.len());
    0
}

fn port_scan(host: &str, spec: Option<&str>, json: bool) -> i32 {
    let s = crate::storage::Settings::load();
    let ports = match ports::parse_ports(spec.unwrap_or(&s.default_ports)) {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let cfg = ports::PortScanConfig {
        target: host.to_string(),
        ports,
        timeout: Duration::from_millis(s.port_timeout_ms),
        threads: s.port_threads,
        banners: s.grab_banners,
    };
    if !json {
        println!("Scan de {} port(s) sur {host}...", cfg.ports.len());
    }
    let cancel = AtomicBool::new(false);
    match ports::scan(&cfg, &cancel, &|_| {}) {
        Ok(o) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&o).unwrap_or_default());
                return 0;
            }
            for r in &o.open {
                println!("  {:>5}/tcp  {:<18} {}", r.port, r.service, r.banner);
            }
            println!(
                "\n{} ouvert(s), {} fermé(s), {} filtré(s) en {:.1} s",
                o.open.len(),
                o.closed,
                o.filtered,
                o.duration_s
            );
            println!("Score de sécurité : {}/100 ({} - {})", o.report.score, o.report.grade, o.report.label);
            for f in &o.report.findings {
                println!("  [{}] {} -> {}", f.severity.label(), f.title, f.recommendation);
            }
            0
        }
        Err(e) => fail(&e),
    }
}

fn ping(host: &str, count: u32) -> i32 {
    let ip = match tools::resolve(host) {
        Ok(ip) => ip,
        Err(e) => return fail(&e),
    };
    println!("Ping de {host} [{ip}]");
    let mut st = tools::PingStats::default();
    for i in 0..count {
        let r = tools::ping(ip, 1000);
        st.add(r);
        match r {
            Some(ms) => println!("  Réponse de {ip} : temps={ms} ms"),
            None => println!("  Délai d'attente dépassé."),
        }
        if i + 1 < count {
            std::thread::sleep(Duration::from_millis(1000));
        }
    }
    println!(
        "\nEnvoyes {}, reçus {}, perte {:.0}%  min/moy/max/gigue = {}/{:.1}/{}/{:.1} ms",
        st.sent,
        st.received,
        st.loss(),
        st.min,
        st.avg(),
        st.max,
        st.jitter()
    );
    if st.received > 0 { 0 } else { 1 }
}

fn trace(host: &str) -> i32 {
    let ip = match tools::resolve(host) {
        Ok(ip) => ip,
        Err(e) => return fail(&e),
    };
    println!("Traceroute vers {host} [{ip}], 30 sauts maximum");
    let cancel = AtomicBool::new(false);
    tools::traceroute(ip, 30, 1500, &cancel, &|h| {
        let rtts: Vec<String> = h.rtts.iter().map(|r| r.map(|v| format!("{v} ms")).unwrap_or("*".into())).collect();
        println!(
            "  {:>2}  {:<24} {:<16} {}",
            h.ttl,
            rtts.join("  "),
            h.ip.map(|i| i.to_string()).unwrap_or("*".into()),
            h.host
        );
    });
    0
}
