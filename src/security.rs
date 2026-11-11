//! Analyse de securite heuristique a partir des ports ouverts et des bannieres.

use crate::model::{Finding, PortResult, SecurityReport, Severity};

struct Rule {
    port: u16,
    severity: Severity,
    title: &'static str,
    detail: &'static str,
    advice: &'static str,
}

const RULES: &[Rule] = &[
    Rule { port: 23, severity: Severity::Critical, title: "Telnet exposé", detail: "Accès distant en clair : identifiants et commandes lisibles sur le réseau.", advice: "Désactiver Telnet et utiliser SSH." },
    Rule { port: 512, severity: Severity::Critical, title: "rexec exposé", detail: "Service Unix historique sans chiffrement.", advice: "Désactiver rexec." },
    Rule { port: 513, severity: Severity::Critical, title: "rlogin exposé", detail: "Authentification faible, trafic en clair.", advice: "Désactiver rlogin et utiliser SSH." },
    Rule { port: 514, severity: Severity::Critical, title: "rsh exposé", detail: "Exécution distante sans chiffrement.", advice: "Désactiver rsh et utiliser SSH." },
    Rule { port: 2375, severity: Severity::Critical, title: "API Docker non chiffrée", detail: "Permet souvent de prendre le contrôle complet de l'hôte.", advice: "Fermer le port 2375 ou exiger TLS mutuel (2376)." },
    Rule { port: 5555, severity: Severity::Critical, title: "Débogage Android (ADB) ouvert", detail: "Accès shell à l'appareil Android sans authentification forte.", advice: "Désactiver le débogage ADB sur le réseau." },
    Rule { port: 6379, severity: Severity::Critical, title: "Redis accessible", detail: "Redis est souvent déployé sans mot de passe.", advice: "Lier Redis à 127.0.0.1 et activer l'authentification." },
    Rule { port: 11211, severity: Severity::High, title: "Memcached accessible", detail: "Pas d'authentification par défaut, fuite de données possible.", advice: "Restreindre Memcached à l'hôte local." },
    Rule { port: 27017, severity: Severity::Critical, title: "MongoDB accessible", detail: "Nombreuses fuites de données dues à des instances ouvertes.", advice: "Activer l'authentification et filtrer l'accès." },
    Rule { port: 9200, severity: Severity::High, title: "Elasticsearch accessible", detail: "API REST pouvant exposer toutes les données indexées.", advice: "Activer la sécurité X-Pack et filtrer l'accès." },
    Rule { port: 21, severity: Severity::High, title: "FTP en clair", detail: "Identifiants et fichiers transmis sans chiffrement.", advice: "Utiliser SFTP ou FTPS." },
    Rule { port: 69, severity: Severity::High, title: "TFTP", detail: "Transfert de fichiers sans authentification.", advice: "Désactiver TFTP s'il n'est pas indispensable." },
    Rule { port: 139, severity: Severity::High, title: "NetBIOS", detail: "Partage Windows historique, fuite d'informations.", advice: "Désactiver NetBIOS sur TCP/IP si inutile." },
    Rule { port: 445, severity: Severity::High, title: "SMB exposé", detail: "Cible fréquente de vers et rançongiciels (ex. EternalBlue).", advice: "Limiter SMB au réseau de confiance, désactiver SMBv1, appliquer les mises à jour." },
    Rule { port: 3389, severity: Severity::High, title: "Bureau à distance (RDP)", detail: "Cible fréquente d'attaques par force brute.", advice: "Activer NLA, utiliser un VPN et des mots de passe forts." },
    Rule { port: 5900, severity: Severity::High, title: "VNC", detail: "Souvent protégé par un mot de passe faible ou absent.", advice: "Exiger un mot de passe fort et passer par un tunnel chiffré." },
    Rule { port: 5901, severity: Severity::High, title: "VNC", detail: "Souvent protégé par un mot de passe faible ou absent.", advice: "Exiger un mot de passe fort et passer par un tunnel chiffré." },
    Rule { port: 7547, severity: Severity::High, title: "TR-069 (gestion opérateur)", detail: "Interface de gestion de box historiquement vulnérable.", advice: "Vérifier que ce port n'est pas exposé côté Internet." },
    Rule { port: 1433, severity: Severity::Medium, title: "Microsoft SQL Server exposé", detail: "Base de données accessible depuis le réseau.", advice: "Restreindre l'accès par pare-feu." },
    Rule { port: 1521, severity: Severity::Medium, title: "Oracle DB exposé", detail: "Base de données accessible depuis le réseau.", advice: "Restreindre l'accès par pare-feu." },
    Rule { port: 3306, severity: Severity::Medium, title: "MySQL/MariaDB exposé", detail: "Base de données accessible depuis le réseau.", advice: "Lier à 127.0.0.1 ou filtrer par pare-feu." },
    Rule { port: 5432, severity: Severity::Medium, title: "PostgreSQL exposé", detail: "Base de données accessible depuis le réseau.", advice: "Restreindre pg_hba.conf et le pare-feu." },
    Rule { port: 5984, severity: Severity::Medium, title: "CouchDB exposé", detail: "API base de données accessible.", advice: "Activer l'authentification." },
    Rule { port: 1723, severity: Severity::Medium, title: "VPN PPTP", detail: "Protocole VPN obsolète au chiffrement cassé.", advice: "Migrer vers WireGuard ou OpenVPN." },
    Rule { port: 135, severity: Severity::Medium, title: "MS-RPC", detail: "Service Windows exposant de nombreuses interfaces.", advice: "Filtrer hors du réseau de confiance." },
    Rule { port: 111, severity: Severity::Medium, title: "RPCbind", detail: "Révèle les services RPC disponibles.", advice: "Filtrer si NFS n'est pas utilise." },
    Rule { port: 2049, severity: Severity::Medium, title: "NFS", detail: "Partages de fichiers parfois exportés sans restriction.", advice: "Vérifier /etc/exports." },
    Rule { port: 1883, severity: Severity::Medium, title: "MQTT non chiffré", detail: "Broker IoT pouvant accepter des connexions anonymes.", advice: "Activer l'authentification et TLS (8883)." },
    Rule { port: 554, severity: Severity::Medium, title: "Flux RTSP (caméra)", detail: "Flux vidéo parfois accessible sans authentification.", advice: "Changer les identifiants par défaut et mettre à jour le firmware." },
    Rule { port: 5985, severity: Severity::Medium, title: "WinRM (HTTP)", detail: "Administration à distance Windows.", advice: "Utiliser WinRM sur HTTPS (5986) et filtrer." },
    Rule { port: 873, severity: Severity::Medium, title: "rsync", detail: "Modules parfois accessibles sans mot de passe.", advice: "Exiger une authentification." },
    Rule { port: 5938, severity: Severity::Low, title: "TeamViewer", detail: "Logiciel de prise en main à distance actif.", advice: "Vérifier que son usage est légitime." },
    Rule { port: 6568, severity: Severity::Low, title: "AnyDesk", detail: "Logiciel de prise en main à distance actif.", advice: "Vérifier que son usage est légitime." },
    Rule { port: 25, severity: Severity::Low, title: "Serveur SMTP", detail: "Relais de messagerie ouvert possible.", advice: "Vérifier que le relais n'est pas ouvert." },
    Rule { port: 110, severity: Severity::Low, title: "POP3 en clair", detail: "Messagerie sans chiffrement.", advice: "Utiliser POP3S (995)." },
    Rule { port: 143, severity: Severity::Low, title: "IMAP en clair", detail: "Messagerie sans chiffrement.", advice: "Utiliser IMAPS (993)." },
    Rule { port: 9100, severity: Severity::Low, title: "Impression RAW", detail: "Permet d'envoyer des travaux sans authentification.", advice: "Restreindre l'accès à l'imprimante." },
    Rule { port: 1900, severity: Severity::Low, title: "UPnP", detail: "Peut ouvrir automatiquement des ports sur la box.", advice: "Désactiver UPnP si inutile." },
];

const BANNER_RULES: &[(&str, Severity, &str, &str)] = &[
    ("vsftpd 2.3.4", Severity::Critical, "vsFTPd 2.3.4 (version piégée connue)", "Mettre à jour immédiatement."),
    ("openssh_4", Severity::High, "OpenSSH très ancien", "Mettre à jour OpenSSH."),
    ("openssh_5", Severity::High, "OpenSSH obsolète", "Mettre à jour OpenSSH."),
    ("openssh_6", Severity::Medium, "OpenSSH ancien", "Mettre à jour OpenSSH."),
    ("openssh_7", Severity::Low, "OpenSSH ancien", "Envisager une mise à jour d'OpenSSH."),
    ("apache/2.2", Severity::High, "Apache 2.2 (fin de vie)", "Migrer vers Apache 2.4 à jour."),
    ("apache/2.0", Severity::High, "Apache 2.0 (fin de vie)", "Migrer vers Apache 2.4 à jour."),
    ("microsoft-iis/6", Severity::High, "IIS 6 (fin de vie)", "Mettre à jour le serveur."),
    ("microsoft-iis/7", Severity::Medium, "IIS 7 (ancien)", "Mettre à jour le serveur."),
    ("nginx/1.0", Severity::Medium, "nginx très ancien", "Mettre à jour nginx."),
    ("php/5", Severity::High, "PHP 5 (fin de vie)", "Migrer vers une version de PHP supportée."),
    ("proftpd 1.3.3", Severity::High, "ProFTPD 1.3.3 vulnérable", "Mettre à jour ProFTPD."),
    ("dropbear_2012", Severity::Medium, "Dropbear SSH ancien", "Mettre à jour le firmware."),
];

pub fn analyze(target: &str, open: &[PortResult]) -> SecurityReport {
    let mut findings = Vec::new();
    let mut penalty = 0i32;

    for r in open {
        if let Some(rule) = RULES.iter().find(|x| x.port == r.port) {
            penalty += match rule.severity {
                Severity::Critical => 30,
                Severity::High => 15,
                Severity::Medium => 8,
                Severity::Low => 3,
                Severity::Info => 0,
            };
            findings.push(Finding {
                severity: rule.severity.clone(),
                port: Some(r.port),
                title: format!("{} (port {})", rule.title, r.port),
                detail: rule.detail.into(),
                recommendation: rule.advice.into(),
            });
        } else {
            penalty += 2;
        }
        let lb = r.banner.to_ascii_lowercase();
        for (needle, sev, title, advice) in BANNER_RULES {
            if lb.contains(needle) {
                penalty += 10;
                findings.push(Finding {
                    severity: sev.clone(),
                    port: Some(r.port),
                    title: format!("{title} (port {})", r.port),
                    detail: format!("Bannière : {}", r.banner),
                    recommendation: (*advice).into(),
                });
            }
        }
    }

    let has = |p: u16| open.iter().any(|r| r.port == p);
    let http_only = [80, 8080, 8000, 8888, 81].iter().any(|p| has(*p)) && ![443, 8443, 9443].iter().any(|p| has(*p));
    if http_only {
        penalty += 3;
        findings.push(Finding {
            severity: Severity::Low,
            port: None,
            title: "Interface web sans HTTPS".into(),
            detail: "Un service HTTP est ouvert sans équivalent HTTPS : les mots de passe saisis transitent en clair.".into(),
            recommendation: "Activer HTTPS sur l'interface d'administration.".into(),
        });
    }
    if open.len() > 15 {
        penalty += 10;
        findings.push(Finding {
            severity: Severity::Medium,
            port: None,
            title: format!("Surface d'attaque importante ({} ports ouverts)", open.len()),
            detail: "Chaque service exposé est un point d'entrée potentiel.".into(),
            recommendation: "Fermer les services inutiles.".into(),
        });
    }
    if open.is_empty() {
        findings.push(Finding {
            severity: Severity::Info,
            port: None,
            title: "Aucun port ouvert détecté".into(),
            detail: "Aucun des ports testés n'accepte de connexion (ou un pare-feu les filtré).".into(),
            recommendation: "Rien à signaler.".into(),
        });
    } else if findings.is_empty() {
        findings.push(Finding {
            severity: Severity::Info,
            port: None,
            title: "Aucun service sensible détecté".into(),
            detail: format!("{} port(s) ouvert(s), aucun considéré à risque.", open.len()),
            recommendation: "Vérifier que chaque service ouvert est nécessaire.".into(),
        });
    }

    findings.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap_or(std::cmp::Ordering::Equal));
    let score = (100 - penalty).clamp(0, 100);
    let (grade, label) = match score {
        90..=100 => ("A", "Excellent"),
        75..=89 => ("B", "Bon"),
        60..=74 => ("C", "Moyen"),
        40..=59 => ("D", "À risque"),
        20..=39 => ("E", "Mauvais"),
        _ => ("F", "Critique"),
    };
    SecurityReport { target: target.into(), score, grade: grade.into(), label: label.into(), findings }
}
