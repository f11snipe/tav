# tav

A minimal, portable terminal antivirus for Unix systems. Monitors the filesystem, processes, network connections, and DNS in real time — acting on threats via configurable policies (quarantine, kill, alert, webhook, syslog).

---

## Features

| Monitor | What it watches |
|---------|----------------|
| **filesystem** | File creates/writes in watched dirs; regex path matching, hash checking, script content analysis |
| **processes** | Running processes by name/cmdline; per-user binary prohibitions |
| **ports** | Listening sockets and outbound connections; CIDR blocklist |
| **dns** | Passive `/etc/hosts` watcher; regex pattern matching on domains |
| **pcap** *(opt)* | Live packet capture — DNS queries, TLS SNI, HTTP Host, beaconing, port scans |

| Action | Effect |
|--------|--------|
| `quarantine` | Move matched file to `~/.tav/quarantine/` |
| `kill` | SIGKILL matched process |
| `alert` | Append JSON event to `~/.tav/audit.jsonl` |
| `watch_only` | Log without taking action |

Optional output modes (in addition to the audit log): JSON to stdout, syslog, HTTP webhook.

---

## Build

```bash
# Standard build
cargo build --release

# With live packet capture (requires libpcap + root to run)
cargo build --release --features pcap

# With YARA rule scanning (requires libyara)
cargo build --release --features yara

# With TUI dashboard
cargo build --release --features tui

# All optional features
cargo build --release --features pcap,yara,tui
```

```bash
# Install from source
cargo install --path .
```

---

## Quick start

```bash
# 1. Copy the example config and edit for your environment
cp conf/config.yaml ~/.tav/config.yaml

# 2. Run (foreground, verbose)
tav -v run -c ~/.tav/config.yaml

# 3. Or run as a background daemon
tav daemon start -c ~/.tav/config.yaml
tav daemon status
tav daemon stop
```

---

## Commands

```
tav [OPTIONS] <COMMAND>

Options:
  -v, --verbose    Enable info-level log output
  -B, --no-banner  Suppress the startup banner

Commands:
  run         Run the engine in the foreground
  config      Parse and dump the config file (for testing)
  audit       Query the audit log
  quarantine  List or restore quarantined files
  intel       Manage the threat intelligence database
  daemon      Start / stop / reload the background daemon
  watch       Live TUI dashboard (requires --features tui)
```

### `tav run`

```bash
tav run -c conf/config.yaml
```

Runs all enabled monitors in the foreground. Press Ctrl-C to stop cleanly.

### `tav audit`

```bash
# Show the last 50 events
tav audit

# Filter by monitor and minimum severity
tav audit --monitor filesystem --severity high

# Events since a date, limit to 10
tav audit --since 2026-05-01 -n 10
```

### `tav quarantine`

```bash
tav quarantine list
tav quarantine restore <ID>
```

### `tav intel`

```bash
# Add indicators manually
tav intel add hash   d41d8cd98f00b204e9800998ecf8427e
tav intel add domain evil.example.com
tav intel add ip     10.0.0.5

# Bulk import from a flat file (one value per line, # comments ignored)
tav intel import --type domain blocklist.txt

# Pull all enabled feeds from config
tav intel update -c conf/config.yaml

# Show database counts and feed status
tav intel status
```

### `tav daemon`

```bash
tav daemon start  -c conf/config.yaml   # fork to background, write ~/.tav/tav.pid
tav daemon status                        # check PID + socket response
tav daemon reload                        # hot-reload config without restart
tav daemon stop                          # send SIGTERM
```

The daemon exposes a Unix socket at `~/.tav/tav.sock`. Config hot-reload also triggers on SIGHUP.

### `tav watch` *(requires `--features tui`)*

```bash
tav watch
```

Opens a live three-panel dashboard showing recent events and per-monitor stats, reading from `~/.tav/audit.jsonl`. Press `q` or `Esc` to exit.

---

## Configuration

Full annotated example at [`conf/config.yaml`](conf/config.yaml). The key sections:

### Global

```yaml
global:
  quarantine_dir: ~/.tav/quarantine
  audit_log:      ~/.tav/audit.jsonl
  dedup_secs:     30          # suppress duplicate events for the same subject
```

### Policies

Named policies can be referenced by any monitor's `policy:` field.

```yaml
policies:
  strict:      [quarantine, alert]
  notify_only: [alert]
  kill_alert:  [kill, alert]
```

### Filesystem monitor

```yaml
filesystem:
  enabled: true
  policy: strict              # quarantine + alert on matches

  watch:
    - /tmp
    - /var/tmp

  block:                      # regex matched case-insensitively against file path
    - badfile.*
    - \.exe$

  hashes:
    enabled: false
    block_list: ~/.tav/hashes/blocklist.txt    # SHA-256 hex, one per line
    allow_list: ~/.tav/hashes/allowlist.txt

  scripts:
    enabled: true
    policy: strict
    extensions: [sh, py, ps1, js, rb, php, pl]
    patterns:
      - name:     curl_pipe_shell
        regex:    'curl\s+.*\|\s*(bash|sh)'
        severity: high
      - name:     base64_exec
        regex:    'base64\s+-d.*\|\s*(bash|sh|python)'
        severity: critical

  yara:                       # requires --features yara
    enabled: false
    rules_dir: ~/.tav/rules/yara
```

### Process monitor

```yaml
processes:
  enabled: true
  policy: kill_alert
  poll_ms: 500

  watch:                      # log matching processes, no action
    - sketchy_tool

  block:                      # regex matched against name/cmdline → triggers policy
    - cryptominer
    - malwareps

  prohibit:                   # kill when a specific user runs these binaries
    www-data:
      - /bin/sh
      - /bin/bash
```

### Port/socket monitor

```yaml
ports:
  enabled: true
  policy: notify_only
  poll_ms: 5000

  expected_listeners: [22, 80, 443]    # alert on anything else

  block_destinations:                  # flag outbound connections to these CIDRs
    - 10.0.0.0/8

  process_rules:
    - name:     nc
      alert_on: any_listen             # alert if netcat opens any listening port
```

### DNS monitor

```yaml
dns:
  enabled: true
  mode: passive               # watches /etc/hosts for suspicious entries
  policy: notify_only
  block_patterns:
    - pattern: '.*\.onion$'
      severity: high
    - pattern: '[a-z0-9]{20,}\.(com|net|org)$'
      severity: medium        # DGA-like hostnames
```

### Threat intelligence

```yaml
intel:
  auto_update: false
  update_interval_hours: 24

  feeds:
    - name:      feodo_tracker
      url:       https://feodotracker.abuse.ch/downloads/ipblocklist.txt
      feed_type: ip
      enabled:   true

    - name:      stevenblack_hosts
      url:       https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
      feed_type: domain
      enabled:   true
```

Run `tav intel update -c conf/config.yaml` to fetch enabled feeds. The IP and domain blocklists are automatically loaded into the port and DNS monitors at startup.

### Live PCAP monitor *(requires `--features pcap` and root)*

```yaml
pcap:
  enabled: false
  interface: any              # or "en0", "eth0"
  bpf_filter: ""              # BPF expression; empty = all packets
  # policy: notify_only

  detectors:
    dns_queries: true         # alert on DNS queries for blocked domains
    http_hosts:  true         # extract HTTP Host header, check against intel
    tls_sni:     true         # extract TLS SNI from ClientHello
    beaconing:   false        # detect regular-interval C2 connections
    port_scans:  false        # detect SYN-only port sweeps
```

```bash
sudo tav --features pcap run -c conf/config.yaml
```

### Output modes

```yaml
output:
  json_stdout: false    # print each ThreatEvent as NDJSON to stdout
  syslog:      false    # forward to syslog (daemon.warning priority)
  webhook:     null     # HTTP POST JSON events to a URL

# Example: pipe JSON events to another tool
# output:
#   json_stdout: true
#
# tav run | jq 'select(.severity == "high")'
```

Webhook POST body is the full `ThreatEvent` JSON:

```bash
# Example: send alerts to Slack-compatible webhook
output:
  webhook: https://hooks.slack.com/services/...
```

---

## Event format

Every detection produces a `ThreatEvent` written to the audit log (and optionally to stdout/syslog/webhook):

```json
{
  "id": "3fa4e1b2-...",
  "timestamp": "2026-05-06T14:23:01Z",
  "monitor": "filesystem/script",
  "severity": "high",
  "subject": {
    "type": "file",
    "path": "/tmp/deploy.sh",
    "hash": null
  },
  "matched_rule": "curl_pipe_shell",
  "action_taken": "quarantine"
}
```

Monitor names used in events and policy routing:

| Monitor name | Source |
|---|---|
| `filesystem` | path regex match |
| `filesystem/hash` | SHA-256 blocklist hit |
| `filesystem/script` | script content pattern |
| `filesystem/yara` | YARA rule match |
| `processes` | process name/cmdline match |
| `network/ports` | unexpected listener or blocked destination |
| `network/dns` | suspicious hosts file entry |
| `network/pcap/dns` | DNS query for blocked domain |
| `network/pcap/tls` | TLS SNI for blocked domain |
| `network/pcap/http` | HTTP Host for blocked domain |
| `network/pcap/beacon` | beaconing pattern detected |
| `network/pcap/portscan` | port scan detected |

---

## File layout

```
~/.tav/
  audit.jsonl          # append-only event log
  quarantine/          # quarantined files (original path stored in metadata)
  intel/
    hashes.db          # SQLite: hashes, domains, IPs, feed metadata
  tav.pid              # daemon PID (when running as daemon)
  tav.sock             # daemon IPC socket (when running as daemon)
  tav-daemon.log       # daemon stdout/stderr
  hashes/
    blocklist.txt      # optional: SHA-256 hex, one per line
    allowlist.txt
  rules/
    yara/              # place .yar / .yara files here
```
