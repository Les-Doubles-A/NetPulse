//! Couche systeme : ICMP, ARP, routes et tables de connexions.
//! Implementation native Windows (iphlpapi), repli generique ailleurs.

use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IcmpStatus {
    /// Reponse d'echo recue.
    Reply,
    /// TTL expire en transit (utilise par traceroute) : `from` est le routeur intermediaire.
    TtlExpired,
    /// Pas de reponse dans le delai.
    Timeout,
    /// Destination injoignable ou autre erreur.
    Unreachable,
}

#[derive(Debug, Clone, Copy)]
pub struct IcmpReply {
    pub status: IcmpStatus,
    pub from: Option<Ipv4Addr>,
    pub rtt_ms: u32,
}

#[derive(Debug, Clone)]
pub struct SocketEntry {
    pub proto: &'static str,
    pub local: Ipv4Addr,
    pub local_port: u16,
    pub remote: Option<Ipv4Addr>,
    pub remote_port: u16,
    pub state: &'static str,
    pub pid: u32,
}

pub fn tcp_state_name(s: u32) -> &'static str {
    match s {
        1 => "FERMEE",
        2 => "ECOUTE",
        3 => "SYN_ENVOYE",
        4 => "SYN_RECU",
        5 => "ETABLIE",
        6 => "FIN_WAIT_1",
        7 => "FIN_WAIT_2",
        8 => "CLOSE_WAIT",
        9 => "FERMETURE",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "SUPPRESSION",
        _ => "?",
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::NetworkManagement::IpHelper::*;

    fn to_ipaddr(ip: Ipv4Addr) -> u32 {
        u32::from_ne_bytes(ip.octets())
    }
    fn from_ipaddr(v: u32) -> Ipv4Addr {
        Ipv4Addr::from(v.to_ne_bytes())
    }
    fn port_from_dword(p: u32) -> u16 {
        u16::from_be((p & 0xFFFF) as u16)
    }

    pub fn icmp_echo(ip: Ipv4Addr, timeout_ms: u32, ttl: Option<u8>) -> IcmpReply {
        unsafe {
            let handle = IcmpCreateFile();
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return IcmpReply { status: IcmpStatus::Unreachable, from: None, rtt_ms: 0 };
            }
            let payload = [0x4Eu8; 32];
            // Tampon aligne sur 8 octets (la structure contient un pointeur).
            let reply_len = std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8 + 64;
            let mut buf = vec![0u64; reply_len.div_ceil(8)];
            let opts = IP_OPTION_INFORMATION {
                Ttl: ttl.unwrap_or(128),
                Tos: 0,
                Flags: 0,
                OptionsSize: 0,
                OptionsData: std::ptr::null_mut(),
            };
            let n = IcmpSendEcho(
                handle,
                to_ipaddr(ip),
                payload.as_ptr() as *const c_void,
                payload.len() as u16,
                &opts,
                buf.as_mut_ptr() as *mut c_void,
                (buf.len() * 8) as u32,
                timeout_ms.max(1),
            );
            IcmpCloseHandle(handle);
            let reply: ICMP_ECHO_REPLY = std::ptr::read(buf.as_ptr() as *const ICMP_ECHO_REPLY);
            let from = if reply.Address != 0 { Some(from_ipaddr(reply.Address)) } else { None };
            if n == 0 && from.is_none() {
                return IcmpReply { status: IcmpStatus::Timeout, from: None, rtt_ms: 0 };
            }
            let status = match reply.Status {
                IP_SUCCESS => IcmpStatus::Reply,
                IP_TTL_EXPIRED_TRANSIT => IcmpStatus::TtlExpired,
                IP_REQ_TIMED_OUT => IcmpStatus::Timeout,
                _ => IcmpStatus::Unreachable,
            };
            IcmpReply { status, from, rtt_ms: reply.RoundTripTime }
        }
    }

    pub fn arp_resolve(ip: Ipv4Addr) -> Option<[u8; 6]> {
        unsafe {
            let mut mac = [0u32; 2];
            let mut len: u32 = 6;
            let r = SendARP(to_ipaddr(ip), 0, mac.as_mut_ptr() as *mut c_void, &mut len);
            if r == 0 && len >= 6 {
                let bytes: [u8; 8] = std::mem::transmute(mac);
                let out = [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]];
                if out != [0; 6] {
                    return Some(out);
                }
            }
            None
        }
    }

    pub fn default_gateway() -> Option<Ipv4Addr> {
        unsafe {
            let mut row: MIB_IPFORWARDROW = std::mem::zeroed();
            let r = GetBestRoute(to_ipaddr(Ipv4Addr::new(1, 1, 1, 1)), 0, &mut row);
            if r == 0 && row.dwForwardNextHop != 0 {
                Some(from_ipaddr(row.dwForwardNextHop))
            } else {
                None
            }
        }
    }

    unsafe fn fetch_table(f: impl Fn(*mut c_void, *mut u32) -> u32) -> Option<Vec<u64>> {
        let mut size: u32 = 0;
        f(std::ptr::null_mut(), &mut size);
        for _ in 0..4 {
            let mut buf = vec![0u64; (size as usize).div_ceil(8) + 64];
            let mut sz = (buf.len() * 8) as u32;
            let r = f(buf.as_mut_ptr() as *mut c_void, &mut sz);
            if r == 0 {
                return Some(buf);
            }
            size = sz;
        }
        None
    }

    pub fn socket_table() -> Vec<SocketEntry> {
        let mut out = Vec::new();
        unsafe {
            let af = windows_sys::Win32::Networking::WinSock::AF_INET as u32;
            if let Some(buf) = fetch_table(|p, s| GetExtendedTcpTable(p, s, 1, af, TCP_TABLE_OWNER_PID_ALL, 0)) {
                let base = buf.as_ptr() as *const u8;
                let n = std::ptr::read_unaligned(base as *const u32) as usize;
                let rows = base.add(4) as *const MIB_TCPROW_OWNER_PID;
                for i in 0..n {
                    let r = std::ptr::read_unaligned(rows.add(i));
                    let remote = from_ipaddr(r.dwRemoteAddr);
                    out.push(SocketEntry {
                        proto: "TCP",
                        local: from_ipaddr(r.dwLocalAddr),
                        local_port: port_from_dword(r.dwLocalPort),
                        remote: if r.dwState == 2 { None } else { Some(remote) },
                        remote_port: if r.dwState == 2 { 0 } else { port_from_dword(r.dwRemotePort) },
                        state: tcp_state_name(r.dwState),
                        pid: r.dwOwningPid,
                    });
                }
            }
            if let Some(buf) = fetch_table(|p, s| GetExtendedUdpTable(p, s, 1, af, UDP_TABLE_OWNER_PID, 0)) {
                let base = buf.as_ptr() as *const u8;
                let n = std::ptr::read_unaligned(base as *const u32) as usize;
                let rows = base.add(4) as *const MIB_UDPROW_OWNER_PID;
                for i in 0..n {
                    let r = std::ptr::read_unaligned(rows.add(i));
                    out.push(SocketEntry {
                        proto: "UDP",
                        local: from_ipaddr(r.dwLocalAddr),
                        local_port: port_from_dword(r.dwLocalPort),
                        remote: None,
                        remote_port: 0,
                        state: "-",
                        pid: r.dwOwningPid,
                    });
                }
            }
        }
        out
    }

    pub fn attach_parent_console() -> bool {
        unsafe {
            windows_sys::Win32::System::Console::AttachConsole(
                windows_sys::Win32::System::Console::ATTACH_PARENT_PROCESS,
            ) != 0
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use std::process::Command;
    use std::time::Instant;

    pub fn icmp_echo(ip: Ipv4Addr, timeout_ms: u32, ttl: Option<u8>) -> IcmpReply {
        let secs = (timeout_ms.max(1000) / 1000).to_string();
        let mut cmd = Command::new("ping");
        cmd.args(["-c", "1", "-W", &secs]);
        if let Some(t) = ttl {
            cmd.args(["-t", &t.to_string()]);
        }
        cmd.arg(ip.to_string());
        let start = Instant::now();
        match cmd.output() {
            Ok(o) if o.status.success() => IcmpReply {
                status: IcmpStatus::Reply,
                from: Some(ip),
                rtt_ms: start.elapsed().as_millis() as u32,
            },
            _ => IcmpReply { status: IcmpStatus::Timeout, from: None, rtt_ms: 0 },
        }
    }

    pub fn arp_resolve(ip: Ipv4Addr) -> Option<[u8; 6]> {
        let text = std::fs::read_to_string("/proc/net/arp").ok()?;
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 4 && cols[0] == ip.to_string() {
                let parts: Vec<u8> = cols[3].split(':').filter_map(|h| u8::from_str_radix(h, 16).ok()).collect();
                if parts.len() == 6 && parts.iter().any(|b| *b != 0) {
                    return Some([parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]]);
                }
            }
        }
        None
    }

    pub fn default_gateway() -> Option<Ipv4Addr> {
        let text = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() > 2 && cols[1] == "00000000" {
                let v = u32::from_str_radix(cols[2], 16).ok()?;
                return Some(Ipv4Addr::from(v.to_le_bytes()));
            }
        }
        None
    }

    pub fn socket_table() -> Vec<SocketEntry> {
        Vec::new()
    }

    pub fn attach_parent_console() -> bool {
        true
    }
}

pub use imp::*;

pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
