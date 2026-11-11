//! Base OUI (IEEE) : prefixe MAC -> fabricant.
//! Une copie est embarquee dans l'executable ; une version plus recente peut
//! etre telechargee depuis l'IEEE et est alors stockee dans le dossier de donnees.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

static EMBEDDED: &str = include_str!("../assets/oui.txt");
static DB: OnceLock<RwLock<HashMap<u32, String>>> = OnceLock::new();

pub const IEEE_URL: &str = "https://standards-oui.ieee.org/oui/oui.csv";

fn local_file() -> PathBuf {
    crate::storage::data_dir().join("oui.txt")
}

fn parse(text: &str) -> HashMap<u32, String> {
    let mut map = HashMap::with_capacity(48_000);
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('\t') {
            if let Ok(key) = u32::from_str_radix(k.trim(), 16) {
                map.insert(key, v.trim().to_string());
            }
        }
    }
    map
}

fn db() -> &'static RwLock<HashMap<u32, String>> {
    DB.get_or_init(|| {
        let text = std::fs::read_to_string(local_file()).ok();
        let map = match text {
            Some(t) if t.len() > 100_000 => parse(&t),
            _ => parse(EMBEDDED),
        };
        RwLock::new(map)
    })
}

pub fn entries() -> usize {
    db().read().map(|m| m.len()).unwrap_or(0)
}

/// Le bit "administre localement" signale une adresse MAC aleatoire (privee).
pub fn is_randomized(mac: &str) -> bool {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() < 2 {
        return false;
    }
    u8::from_str_radix(&hex[0..2], 16).map(|b| b & 0x02 != 0).unwrap_or(false)
}

pub fn lookup(mac: &str) -> Option<String> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() < 6 {
        return None;
    }
    let key = u32::from_str_radix(&hex[0..6], 16).ok()?;
    if let Some(v) = db().read().ok()?.get(&key) {
        return Some(v.clone());
    }
    if is_randomized(mac) {
        return Some("Adresse MAC privée (aléatoire)".into());
    }
    None
}

pub fn vendor_or_unknown(mac: &str) -> String {
    lookup(mac).unwrap_or_else(|| "Fabricant inconnu".into())
}

/// Telecharge la base IEEE, la convertit et la recharge. Retourne le nombre d'entrees.
pub fn update_from_ieee() -> Result<usize, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(60)))
        .build()
        .into();
    let mut resp = agent.get(IEEE_URL).call().map_err(|e| e.to_string())?;
    let body = resp
        .body_mut()
        .with_config()
        .limit(64 * 1024 * 1024)
        .read_to_string()
        .map_err(|e| e.to_string())?;
    let mut out = String::with_capacity(body.len() / 2);
    let mut count = 0usize;
    for line in body.lines().skip(1) {
        let cols = split_csv(line);
        if cols.len() >= 3 && cols[1].len() == 6 {
            let name = cols[2].split_whitespace().collect::<Vec<_>>().join(" ");
            out.push_str(&cols[1].to_uppercase());
            out.push('\t');
            out.push_str(&name);
            out.push('\n');
            count += 1;
        }
    }
    if count < 10_000 {
        return Err(format!("Réponse inattendue ({count} entrées)"));
    }
    std::fs::write(local_file(), &out).map_err(|e| e.to_string())?;
    if let Ok(mut w) = db().write() {
        *w = parse(&out);
    }
    Ok(count)
}

fn split_csv(line: &str) -> Vec<String> {
    let mut cols = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => cols.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    cols.push(cur);
    cols
}
