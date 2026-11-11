use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

pub fn now_string() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Device {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub hostname: String,
    /// Nom personnalise donne par l'utilisateur.
    pub name: String,
    pub notes: String,
    pub device_type: String,
    /// Appareil reconnu / approuve par l'utilisateur.
    pub trusted: bool,
    pub favorite: bool,
    pub online: bool,
    pub latency_ms: Option<u32>,
    pub first_seen: String,
    pub last_seen: String,
    pub last_score: Option<i32>,
    pub open_ports: String,
}

impl Device {
    pub fn ipv4(&self) -> Ipv4Addr {
        self.ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED)
    }
    pub fn display_name(&self) -> &str {
        if !self.name.is_empty() {
            &self.name
        } else if !self.hostname.is_empty() {
            &self.hostname
        } else {
            ""
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

impl PortState {
    pub fn label(&self) -> &'static str {
        match self {
            PortState::Open => "Ouvert",
            PortState::Closed => "Fermé",
            PortState::Filtered => "Filtré",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub service: String,
    pub state: PortState,
    pub banner: String,
    pub latency_ms: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Faible",
            Severity::Medium => "Moyen",
            Severity::High => "Élevé",
            Severity::Critical => "Critique",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub port: Option<u16>,
    pub title: String,
    pub detail: String,
    pub recommendation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityReport {
    pub target: String,
    pub score: i32,
    pub grade: String,
    pub label: String,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortScanOutcome {
    pub target: String,
    pub ip: String,
    pub started: String,
    pub duration_s: f64,
    pub scanned: usize,
    pub open: Vec<PortResult>,
    pub closed: usize,
    pub filtered: usize,
    /// Tous les résultats (seulement pour les petites listes de ports).
    pub all: Vec<PortResult>,
    pub report: SecurityReport,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub id: i64,
    pub timestamp: String,
    pub ip: String,
    pub kind: String,
    pub description: String,
}
