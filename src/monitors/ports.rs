use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;
use anyhow::Result;
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use crate::config::ProcessPortRule;
use crate::engine::event::{Severity, Subject, ThreatEvent};
use super::{Monitor, MonitorContext};

pub struct PortMonitor;

#[async_trait]
impl Monitor for PortMonitor {
    fn name(&self) -> &str { "network/ports" }

    async fn run(&self, ctx: MonitorContext) -> Result<()> {
        let mut config_changed = ctx.config_changed.clone();
        let (mut enabled, mut expected, mut blocked_cidrs, mut proc_rules, mut poll_ms) =
            read_config(&ctx).await;

        if !enabled {
            tracing::info!("port monitor: disabled in config, sleeping");
            ctx.cancel.cancelled().await;
            return Ok(());
        }

        let mut prev_listeners: HashSet<u16>         = HashSet::new();
        let mut known_blocked:  HashSet<String>       = HashSet::new();
        let mut known_proc:     HashSet<(u32, u16)>   = HashSet::new();

        loop {
            tokio::select! {
                _ = ctx.cancel.cancelled() => {
                    tracing::info!("port monitor: shutting down");
                    break;
                }
                Ok(()) = config_changed.changed() => {
                    (enabled, expected, blocked_cidrs, proc_rules, poll_ms) =
                        read_config(&ctx).await;
                    if !enabled {
                        tracing::info!("port monitor: disabled via config reload");
                        ctx.cancel.cancelled().await;
                        break;
                    }
                    tracing::info!("port monitor: config reloaded");
                }
                _ = tokio::time::sleep(Duration::from_millis(poll_ms)) => {
                    let monitor_name   = self.name().to_string();
                    let expected_c     = expected.clone();
                    let blocked_c      = blocked_cidrs.clone();
                    let proc_rules_c   = proc_rules.clone();

                    let sockets = tokio::task::spawn_blocking(query_sockets).await?;
                    let sockets = match sockets {
                        Ok(s)  => s,
                        Err(e) => {
                            tracing::warn!("port monitor: lsof query failed: {:#}", e);
                            continue;
                        }
                    };

                    let mut curr_listeners: HashSet<u16> = HashSet::new();
                    let mut events = Vec::new();

                    for sock in &sockets {
                        let port = extract_port(&sock.local);

                        // ── Unexpected listener check ────────────────────────
                        if sock.state == "LISTEN" {
                            if let Some(p) = port {
                                curr_listeners.insert(p);
                                if !expected_c.is_empty()
                                    && !expected_c.contains(&p)
                                    && !prev_listeners.contains(&p)
                                {
                                    events.push(ThreatEvent::new(
                                        &monitor_name,
                                        Severity::Medium,
                                        conn_subject(sock),
                                        &format!("unexpected_listener:{}", p),
                                    ));
                                }
                            }
                        }

                        // ── Blocked destination check ────────────────────────
                        if sock.state == "ESTABLISHED" {
                            if let Some(remote) = &sock.remote {
                                if is_blocked_dest(remote, &blocked_c) {
                                    let key = format!("{}:{}->{}", sock.pid, sock.local, remote);
                                    if !known_blocked.contains(&key) {
                                        known_blocked.insert(key);
                                        events.push(ThreatEvent::new(
                                            &monitor_name,
                                            Severity::High,
                                            conn_subject(sock),
                                            &format!("blocked_destination:{}", remote),
                                        ));
                                    }
                                }
                            }
                        }

                        // ── Process-specific port rules ──────────────────────
                        for rule in &proc_rules_c {
                            if !sock.command.to_lowercase().contains(&rule.name.to_lowercase()) {
                                continue;
                            }
                            let fires = match rule.alert_on.as_str() {
                                "any_listen"  => sock.state == "LISTEN",
                                "any_connect" => sock.state == "ESTABLISHED",
                                _             => false,
                            };
                            if fires {
                                let p = port.unwrap_or(0);
                                let key = (sock.pid, p);
                                if !known_proc.contains(&key) {
                                    known_proc.insert(key);
                                    events.push(ThreatEvent::new(
                                        &monitor_name,
                                        Severity::High,
                                        conn_subject(sock),
                                        &format!("process_port_rule:{}:{}", rule.name, rule.alert_on),
                                    ));
                                }
                            }
                        }
                    }

                    prev_listeners = curr_listeners;

                    for ev in events {
                        let _ = ctx.tx.send(ev);
                    }
                }
            }
        }

        Ok(())
    }
}

// ─── Socket info ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct SocketInfo {
    command: String,
    pid:     u32,
    proto:   String,
    local:   String,
    remote:  Option<String>,
    state:   String,
}

fn conn_subject(s: &SocketInfo) -> Subject {
    Subject::Connection {
        local_addr:   s.local.clone(),
        remote_addr:  s.remote.clone(),
        proto:        s.proto.clone(),
        state:        s.state.clone(),
        pid:          Some(s.pid),
        process_name: Some(s.command.clone()),
    }
}

// ─── lsof-based socket query (cross-platform: macOS + Linux) ─────────────────

fn query_sockets() -> Result<Vec<SocketInfo>> {
    let out = std::process::Command::new("lsof")
        .args(["-i", "TCP", "-i", "UDP", "-n", "-P"])
        .output()
        .map_err(|e| anyhow::anyhow!("lsof not found or failed to launch: {}", e))?;

    Ok(parse_lsof(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_lsof(output: &str) -> Vec<SocketInfo> {
    let mut result = Vec::new();

    for line in output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Minimum columns: COMMAND PID USER FD TYPE DEVICE SIZE NODE NAME
        if parts.len() < 9 { continue; }

        let command = parts[0].to_string();
        let Ok(pid) = parts[1].parse::<u32>() else { continue };

        // parts[4] = TYPE (IPv4/IPv6/...)
        if !matches!(parts[4], "IPv4" | "IPv6") { continue; }

        // parts[7] = NODE (TCP/UDP/...)
        let proto = parts[7].to_string();
        if !matches!(proto.as_str(), "TCP" | "UDP") { continue; }

        // parts[8..] = NAME field
        let name = parts[8..].join(" ");

        // Split state: "local (STATE)" or "local->remote (STATE)" or "local->remote"
        let (addrs, state) = if let Some(p) = name.rfind('(') {
            let state = name[p + 1..].trim_end_matches(')').trim().to_string();
            let addrs = name[..p].trim().to_string();
            (addrs, state)
        } else {
            (name.trim().to_string(), String::new())
        };

        let (local, remote) = if let Some(arrow) = addrs.find("->") {
            (addrs[..arrow].to_string(), Some(addrs[arrow + 2..].to_string()))
        } else {
            (addrs, None)
        };

        result.push(SocketInfo { command, pid, proto, local, remote, state });
    }

    result
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn extract_port(addr: &str) -> Option<u16> {
    addr.rsplit(':').next()?.parse().ok()
}

fn extract_host(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        // IPv6 bracket: [::1]:80
        return rest.split(']').next().unwrap_or(addr);
    }
    // IPv4 / hostname: host:port
    if let Some(colon) = addr.rfind(':') {
        return &addr[..colon];
    }
    addr
}

fn is_blocked_dest(remote: &str, blocklist: &[IpNetwork]) -> bool {
    if blocklist.is_empty() { return false; }
    let host = extract_host(remote);
    if host == "*" { return false; }
    if let Ok(ip) = host.parse::<IpAddr>() {
        blocklist.iter().any(|net| net.contains(ip))
    } else {
        false
    }
}

// ─── Config reader ────────────────────────────────────────────────────────────

async fn read_config(ctx: &MonitorContext) -> (bool, HashSet<u16>, Vec<IpNetwork>, Vec<ProcessPortRule>, u64) {
    let cfg      = ctx.config.read().await;
    let pc       = &cfg.network.ports;
    let enabled  = pc.enabled;
    let expected = pc.expected_listeners.iter().cloned().collect();
    let cidrs    = pc.blocked_destinations.iter()
        .filter_map(|s| s.parse::<IpNetwork>().ok())
        .collect();
    let rules    = pc.monitor_processes.clone();
    let poll_ms  = pc.poll_interval_ms
        .or_else(|| cfg.global.as_ref().map(|g| g.poll_interval_ms))
        .unwrap_or(1000);
    (enabled, expected, cidrs, rules, poll_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listen_line() {
        let output = "\
COMMAND   PID      USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n\
nginx     123      root    6u  IPv4 0xdeadbeef      0t0  TCP *:80 (LISTEN)\n\
";
        let socks = parse_lsof(output);
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].command, "nginx");
        assert_eq!(socks[0].pid, 123);
        assert_eq!(socks[0].proto, "TCP");
        assert_eq!(socks[0].local, "*:80");
        assert!(socks[0].remote.is_none());
        assert_eq!(socks[0].state, "LISTEN");
    }

    #[test]
    fn parse_established_line() {
        let output = "\
COMMAND   PID      USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n\
curl      456   charlie    5u  IPv4 0xdeadbeef      0t0  TCP 192.168.1.2:54321->8.8.8.8:443 (ESTABLISHED)\n\
";
        let socks = parse_lsof(output);
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].local, "192.168.1.2:54321");
        assert_eq!(socks[0].remote, Some("8.8.8.8:443".into()));
        assert_eq!(socks[0].state, "ESTABLISHED");
    }

    #[test]
    fn extract_port_wildcard() {
        assert_eq!(extract_port("*:80"), Some(80));
        assert_eq!(extract_port("0.0.0.0:443"), Some(443));
        assert_eq!(extract_port("[::]:8080"), Some(8080));
    }

    #[test]
    fn blocked_dest_cidr() {
        let net: IpNetwork = "10.0.0.0/8".parse().unwrap();
        assert!(is_blocked_dest("10.1.2.3:4444", &[net]));
        let net2: IpNetwork = "10.0.0.0/8".parse().unwrap();
        assert!(!is_blocked_dest("8.8.8.8:443", &[net2]));
    }
}
