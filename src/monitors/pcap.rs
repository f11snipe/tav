use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use pcap::Capture;
use pktparse::{ethernet, ipv4, ipv6, tcp, udp};
use pktparse::ethernet::EtherType;
use pktparse::ip::IPProtocol;
use crate::config::PcapDetectors;
use crate::engine::event::{EventSender, Severity, Subject, ThreatEvent};
use super::{Monitor, MonitorContext};

// ── Thresholds ────────────────────────────────────────────────────────────────

/// Minimum connection samples before beaconing is evaluated.
const BEACON_MIN_SAMPLES: usize = 5;
/// If stddev/mean inter-arrival ratio is below this, flag as beaconing.
const BEACON_STDDEV_RATIO: f64 = 0.10;
/// Unique destination ports from one source within the window to flag as scan.
const PORTSCAN_UNIQUE_PORTS: usize = 20;
/// Sliding window for port-scan tracking.
const FLOW_WINDOW: Duration = Duration::from_secs(60);

// ── Monitor ───────────────────────────────────────────────────────────────────

pub struct PcapMonitor {
    pub blocked_domains: Arc<HashSet<String>>,
    pub blocked_ips:     Arc<Vec<String>>,
}

impl PcapMonitor {
    pub fn new(blocked_domains: Arc<HashSet<String>>, blocked_ips: Arc<Vec<String>>) -> Self {
        Self { blocked_domains, blocked_ips }
    }
}

#[async_trait]
impl Monitor for PcapMonitor {
    fn name(&self) -> &str { "network/pcap" }

    async fn run(&self, ctx: MonitorContext) -> Result<()> {
        let (enabled, interface, bpf_filter, detectors) = {
            let cfg = ctx.config.read().await;
            let pc  = &cfg.pcap;
            (pc.enabled, pc.interface.clone(), pc.bpf_filter.clone(), pc.detectors.clone())
        };

        if !enabled {
            tracing::info!("pcap monitor: disabled in config, sleeping");
            ctx.cancel.cancelled().await;
            return Ok(());
        }

        let blocked_domains = self.blocked_domains.clone();
        let blocked_ips     = self.blocked_ips.clone();
        let tx              = ctx.tx.clone();

        // Bridge the blocking pcap loop into the async engine via an mpsc channel.
        let (pkt_tx, mut pkt_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);

        let iface = interface.clone();
        let bpf   = bpf_filter.clone();

        tokio::task::spawn_blocking(move || {
            let device = if iface == "any" {
                match pcap::Device::lookup() {
                    Ok(Some(d)) => d,
                    Ok(None)    => { tracing::error!("pcap: no default network device found"); return; }
                    Err(e)      => { tracing::error!("pcap: device lookup failed: {:?}", e); return; }
                }
            } else {
                match pcap::Device::list() {
                    Ok(devs) => match devs.into_iter().find(|d| d.name == iface) {
                        Some(d) => d,
                        None    => { tracing::error!("pcap: interface '{}' not found", iface); return; }
                    }
                    Err(e) => { tracing::error!("pcap: device list failed: {:?}", e); return; }
                }
            };

            tracing::info!("pcap: opening capture on '{}'", device.name);

            let mut cap = match Capture::from_device(device)
                .and_then(|c| c.promisc(true).snaplen(65_535).timeout(200).open())
            {
                Ok(c)  => c,
                Err(e) => {
                    tracing::error!("pcap: failed to open capture (need root?): {:?}", e);
                    return;
                }
            };

            if !bpf.is_empty() {
                if let Err(e) = cap.filter(&bpf, true) {
                    tracing::warn!("pcap: BPF filter '{}' rejected: {:?}", bpf, e);
                }
            }

            loop {
                match cap.next_packet() {
                    Ok(pkt) => {
                        if pkt_tx.blocking_send(pkt.data.to_vec()).is_err() {
                            break; // async receiver dropped → clean shutdown
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        if pkt_tx.is_closed() { break; }
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!("pcap: capture error: {:?}", e);
                        break;
                    }
                }
            }
        });

        let mut port_scan_state: HashMap<String, PortScanState> = HashMap::new();
        let mut beacon_state:    HashMap<String, BeaconState>   = HashMap::new();

        loop {
            tokio::select! {
                _ = ctx.cancel.cancelled() => {
                    tracing::info!("pcap monitor: shutting down");
                    break;
                }
                Some(data) = pkt_rx.recv() => {
                    process_packet(
                        &data,
                        &blocked_domains,
                        &blocked_ips,
                        &detectors,
                        &tx,
                        &mut port_scan_state,
                        &mut beacon_state,
                    );
                }
            }
        }
        Ok(())
    }
}

// ── Packet pipeline ───────────────────────────────────────────────────────────

fn process_packet(
    data:            &[u8],
    blocked_domains: &HashSet<String>,
    blocked_ips:     &[String],
    det:             &PcapDetectors,
    tx:              &EventSender,
    port_scan_state: &mut HashMap<String, PortScanState>,
    beacon_state:    &mut HashMap<String, BeaconState>,
) {
    // ── Ethernet ──────────────────────────────────────────────────────────────
    let Ok((eth_payload, eth)) = ethernet::parse_ethernet_frame(data) else { return };

    // ── IP dispatch ───────────────────────────────────────────────────────────
    let (src_ip, dst_ip, protocol, transport): (String, String, IPProtocol, &[u8]) =
        match eth.ethertype {
            EtherType::IPv4 => {
                let Ok((t, hdr)) = ipv4::parse_ipv4_header(eth_payload) else { return };
                (hdr.source_addr.to_string(), hdr.dest_addr.to_string(), hdr.protocol, t)
            }
            EtherType::IPv6 => {
                let Ok((t, hdr)) = ipv6::parse_ipv6_header(eth_payload) else { return };
                (hdr.source_addr.to_string(), hdr.dest_addr.to_string(), hdr.next_header, t)
            }
            _ => return,
        };

    // Check destination against IP blocklist
    if !blocked_ips.is_empty() {
        for cidr in blocked_ips {
            if ip_in_cidr(&dst_ip, cidr) {
                emit_conn(tx, "network/pcap/intel", Severity::High,
                    &src_ip, &dst_ip, "tcp", "ip_blocklist");
                break;
            }
        }
    }

    match protocol {
        IPProtocol::UDP => handle_udp(transport, &src_ip, &dst_ip, blocked_domains, det, tx),
        IPProtocol::TCP => handle_tcp(
            transport, &src_ip, &dst_ip,
            blocked_domains, det, tx,
            port_scan_state, beacon_state,
        ),
        _ => {}
    }
}

// ── UDP / DNS ─────────────────────────────────────────────────────────────────

fn handle_udp(
    payload:         &[u8],
    _src_ip:         &str,
    _dst_ip:         &str,
    blocked_domains: &HashSet<String>,
    det:             &PcapDetectors,
    tx:              &EventSender,
) {
    if !det.dns_queries { return; }

    let Ok((dns_payload, udp_hdr)) = udp::parse_udp_header(payload) else { return };
    if udp_hdr.dest_port != 53 && udp_hdr.source_port != 53 { return; }

    for domain in extract_dns_names(dns_payload) {
        if blocked_domains.contains(&domain) {
            let ev = ThreatEvent::new(
                "network/pcap/dns",
                Severity::High,
                Subject::DnsQuery { domain: domain.clone(), source: "pcap".into() },
                "blocked_domain",
            );
            let _ = tx.send(ev);
        }
    }
}

// ── TCP / TLS / HTTP / behavioral ─────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn handle_tcp(
    payload:         &[u8],
    src_ip:          &str,
    dst_ip:          &str,
    blocked_domains: &HashSet<String>,
    det:             &PcapDetectors,
    tx:              &EventSender,
    port_scan_state: &mut HashMap<String, PortScanState>,
    beacon_state:    &mut HashMap<String, BeaconState>,
) {
    let Ok((app_payload, tcp_hdr)) = tcp::parse_tcp_header(payload) else { return };

    let src_port = tcp_hdr.source_port;
    let dst_port = tcp_hdr.dest_port;

    // Port-scan detection: SYN without ACK
    if det.port_scans && tcp_hdr.flag_syn && !tcp_hdr.flag_ack {
        check_port_scan(port_scan_state, src_ip, dst_port, tx);
    }

    // Beaconing detection: established connections (ACK, no SYN)
    if det.beaconing && tcp_hdr.flag_ack && !tcp_hdr.flag_syn {
        check_beaconing(beacon_state, src_ip, dst_ip, tx);
    }

    if app_payload.is_empty() { return; }

    // TLS SNI (TCP/443)
    if det.tls_sni && (dst_port == 443 || src_port == 443) {
        if let Some(sni) = extract_tls_sni(app_payload) {
            let domain = sni.to_lowercase();
            if blocked_domains.contains(&domain) {
                let _ = tx.send(ThreatEvent::new(
                    "network/pcap/tls",
                    Severity::High,
                    Subject::DnsQuery { domain, source: "tls_sni".into() },
                    "blocked_domain_tls",
                ));
            }
        }
    }

    // HTTP Host header (TCP/80)
    if det.http_hosts && (dst_port == 80 || src_port == 80) {
        if let Some(host) = extract_http_host(app_payload) {
            let domain = host.to_lowercase();
            let domain = domain.split(':').next().unwrap_or(&domain).to_string();
            if blocked_domains.contains(&domain) {
                let _ = tx.send(ThreatEvent::new(
                    "network/pcap/http",
                    Severity::High,
                    Subject::DnsQuery { domain, source: "http_host".into() },
                    "blocked_domain_http",
                ));
            }
        }
    }
}

// ── Behavioral detection ──────────────────────────────────────────────────────

struct PortScanState {
    ports:      HashSet<u16>,
    first_seen: Instant,
    alerted:    bool,
}

struct BeaconState {
    timestamps: Vec<Instant>,
    alerted:    bool,
}

fn check_port_scan(
    state:    &mut HashMap<String, PortScanState>,
    src_ip:   &str,
    dst_port: u16,
    tx:       &EventSender,
) {
    let now = Instant::now();
    let entry = state.entry(src_ip.to_string()).or_insert_with(|| PortScanState {
        ports:      HashSet::new(),
        first_seen: now,
        alerted:    false,
    });

    if entry.alerted { return; }

    if now.duration_since(entry.first_seen) > FLOW_WINDOW {
        entry.ports.clear();
        entry.first_seen = now;
    }

    entry.ports.insert(dst_port);

    if entry.ports.len() >= PORTSCAN_UNIQUE_PORTS {
        entry.alerted = true;
        let _ = tx.send(ThreatEvent::new(
            "network/pcap/portscan",
            Severity::High,
            Subject::Connection {
                local_addr:   String::new(),
                remote_addr:  Some(src_ip.to_string()),
                proto:        "tcp".into(),
                state:        "syn".into(),
                pid:          None,
                process_name: None,
            },
            "port_scan_detected",
        ));
    }
}

fn check_beaconing(
    state:  &mut HashMap<String, BeaconState>,
    src_ip: &str,
    dst_ip: &str,
    tx:     &EventSender,
) {
    let key   = format!("{src_ip}\u{2192}{dst_ip}"); // "src→dst"
    let entry = state.entry(key).or_insert_with(|| BeaconState {
        timestamps: Vec::new(),
        alerted:    false,
    });

    if entry.alerted { return; }

    entry.timestamps.push(Instant::now());
    if entry.timestamps.len() < BEACON_MIN_SAMPLES { return; }

    let intervals: Vec<f64> = entry.timestamps
        .windows(2)
        .map(|w| w[1].duration_since(w[0]).as_secs_f64())
        .collect();

    let n    = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n;
    if mean <= 0.0 { return; }

    let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
    let stddev   = variance.sqrt();

    if stddev / mean < BEACON_STDDEV_RATIO {
        entry.alerted = true;
        let _ = tx.send(ThreatEvent::new(
            "network/pcap/beacon",
            Severity::High,
            Subject::Connection {
                local_addr:   src_ip.to_string(),
                remote_addr:  Some(dst_ip.to_string()),
                proto:        "tcp".into(),
                state:        "established".into(),
                pid:          None,
                process_name: None,
            },
            "beaconing_detected",
        ));
    }
}

// ── Protocol helpers ──────────────────────────────────────────────────────────

/// Extract DNS question names from a raw DNS UDP payload.
/// Handles label encoding; follows a simplified pointer-compression path.
fn extract_dns_names(payload: &[u8]) -> Vec<String> {
    if payload.len() < 12 { return vec![]; }

    let qcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if qcount == 0 { return vec![]; }

    let mut pos  = 12usize;
    let mut names = Vec::new();

    for _ in 0..qcount.min(16) {
        match parse_dns_name(payload, &mut pos) {
            Some(name) => {
                pos  += 4; // QTYPE(2) + QCLASS(2)
                names.push(name);
            }
            None => break,
        }
    }
    names
}

fn parse_dns_name(data: &[u8], pos: &mut usize) -> Option<String> {
    let mut name  = String::new();
    let mut hops  = 0usize;

    loop {
        if *pos >= data.len() { return None; }
        let byte = data[*pos] as usize;

        if byte == 0 {
            *pos += 1;
            break;
        }

        // Pointer compression: top two bits set (0xC0)
        if byte & 0xC0 == 0xC0 {
            *pos += 2;
            break;
        }

        *pos += 1;
        if *pos + byte > data.len() { return None; }

        if !name.is_empty() { name.push('.'); }
        name.push_str(std::str::from_utf8(&data[*pos..*pos + byte]).ok()?);
        *pos += byte;

        hops += 1;
        if hops > 128 { return None; }
    }

    if name.is_empty() { None } else { Some(name.to_lowercase()) }
}

/// Parse TLS SNI from a ClientHello application-layer payload.
fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    // TLS record header: ContentType(1) + Version(2) + Length(2)
    if payload.len() < 5 { return None; }
    if payload[0] != 0x16 { return None; } // Handshake

    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len { return None; }
    let hs = &payload[5..5 + record_len];

    // Handshake header: Type(1) + Length(3)
    if hs.len() < 4 || hs[0] != 0x01 { return None; } // ClientHello

    let hs_body_len = (hs[1] as usize) << 16 | (hs[2] as usize) << 8 | hs[3] as usize;
    if hs.len() < 4 + hs_body_len { return None; }
    let hello = &hs[4..4 + hs_body_len];

    // ClientHello: ProtocolVersion(2) + Random(32)
    if hello.len() < 34 { return None; }
    let mut pos = 34usize;

    // Session ID: Length(1) + Data
    if hello.len() <= pos { return None; }
    pos += 1 + hello[pos] as usize;

    // Cipher suites: Length(2) + Data
    if hello.len() < pos + 2 { return None; }
    let cs_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // Compression methods: Length(1) + Data
    if hello.len() <= pos { return None; }
    pos += 1 + hello[pos] as usize;

    // Extensions: TotalLength(2) + ...
    if hello.len() < pos + 2 { return None; }
    let ext_total = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if hello.len() < ext_end { return None; }

    // Walk extensions looking for SNI (type 0x0000)
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let ext_len  = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension: ListLen(2) + NameType(1) + NameLen(2) + Name
            if ext_len < 5 || pos + ext_len > hello.len() { return None; }
            let name_len = u16::from_be_bytes([hello[pos + 3], hello[pos + 4]]) as usize;
            if ext_len < 5 + name_len { return None; }
            let name_bytes = &hello[pos + 5..pos + 5 + name_len];
            return String::from_utf8(name_bytes.to_vec()).ok();
        }

        pos += ext_len;
    }
    None
}

/// Extract the `Host:` header value from an HTTP/1.x request payload.
fn extract_http_host(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;
    let verb = text.split_whitespace().next()?;
    if !matches!(verb, "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH") {
        return None;
    }
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(val) = lower.strip_prefix("host:") {
            return Some(val.trim().to_string());
        }
    }
    None
}

/// Check whether an IP address string falls within a CIDR range string.
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    use std::net::IpAddr;

    let Ok(addr) = ip.parse::<IpAddr>() else { return false };

    if let Ok(network) = cidr.parse::<IpNetwork>() {
        return network.contains(addr);
    }

    // Bare IP (no slash) — exact match
    if let Ok(other) = cidr.parse::<IpAddr>() {
        return addr == other;
    }

    false
}

fn emit_conn(
    tx:          &EventSender,
    monitor:     &str,
    severity:    Severity,
    local_addr:  &str,
    remote_addr: &str,
    proto:       &str,
    rule:        &str,
) {
    let _ = tx.send(ThreatEvent::new(
        monitor,
        severity,
        Subject::Connection {
            local_addr:   local_addr.to_string(),
            remote_addr:  Some(remote_addr.to_string()),
            proto:        proto.to_string(),
            state:        "active".to_string(),
            pid:          None,
            process_name: None,
        },
        rule,
    ));
}

// ── Unit tests (no raw sockets needed) ───────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_sni_returns_none_on_garbage() {
        assert!(extract_tls_sni(&[]).is_none());
        assert!(extract_tls_sni(&[0x16, 0x03, 0x01, 0x00, 0x05]).is_none());
        // Non-handshake record type
        assert!(extract_tls_sni(&[0x17, 0x03, 0x03, 0x00, 0x05, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn http_host_extracted_from_get() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        assert_eq!(extract_http_host(req).as_deref(), Some("example.com"));
    }

    #[test]
    fn http_host_case_insensitive_header() {
        let req = b"POST /api HTTP/1.1\r\nhost: api.example.com\r\n\r\n";
        assert_eq!(extract_http_host(req).as_deref(), Some("api.example.com"));
    }

    #[test]
    fn http_host_ignores_responses() {
        let resp = b"HTTP/1.1 200 OK\r\nHost: example.com\r\n\r\n";
        assert!(extract_http_host(resp).is_none());
    }

    #[test]
    fn ip_in_cidr_matches() {
        assert!( ip_in_cidr("192.168.1.5",  "192.168.1.0/24"));
        assert!(!ip_in_cidr("10.0.0.1",     "192.168.1.0/24"));
        assert!( ip_in_cidr("10.0.0.1",     "10.0.0.0/8"));
        assert!( ip_in_cidr("10.255.255.1", "10.0.0.0/8"));
        assert!(!ip_in_cidr("11.0.0.1",     "10.0.0.0/8"));
    }

    #[test]
    fn port_scan_triggers_at_threshold() {
        use tokio::sync::broadcast;
        let (tx, mut rx) = broadcast::channel(64);
        let mut state    = HashMap::new();

        for port in 0..PORTSCAN_UNIQUE_PORTS as u16 {
            check_port_scan(&mut state, "1.2.3.4", port, &tx);
        }

        assert!(rx.try_recv().is_ok(), "expected port-scan alert at threshold");
    }

    #[test]
    fn port_scan_alerts_only_once() {
        use tokio::sync::broadcast;
        let (tx, mut rx) = broadcast::channel(64);
        let mut state    = HashMap::new();

        for port in 0..(PORTSCAN_UNIQUE_PORTS as u16 * 2) {
            check_port_scan(&mut state, "1.2.3.4", port, &tx);
        }

        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err(), "expected exactly one port-scan alert");
    }

    #[test]
    fn beaconing_stddev_ratio_math() {
        // Uniform 30s intervals → stddev = 0 → ratio = 0.0 < 0.10
        let intervals: Vec<f64> = vec![30.0; BEACON_MIN_SAMPLES - 1];
        let mean      = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance  = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>()
                        / intervals.len() as f64;
        let stddev    = variance.sqrt();
        assert_eq!(stddev, 0.0);
        assert!(stddev / mean < BEACON_STDDEV_RATIO);
    }

    #[test]
    fn dns_name_parser_handles_simple_label() {
        // DNS query for "example.com" encoded as labels
        let pkt = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // QNAME: 7 "example" 3 "com" 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            // QTYPE=A(1) QCLASS=IN(1)
            0x00, 0x01,
            0x00, 0x01,
        ];
        let names = extract_dns_names(&pkt);
        assert_eq!(names, vec!["example.com".to_string()]);
    }
}
