# SSH Honeypot

An aggressive SSH honeypot that captures every credential brute-forcers throw at it, wastes their time with a convincing fake environment, and logs every keystroke they type.

## Features

- **Credential capture** — every username/password/pubkey attempt saved to JSONL
- **Auth tarpit** — 2–5 second artificial delay per attempt, throttling brute-forcers to a crawl
- **Convincing fake shell** — Ubuntu 22.04, randomized hostname/IP/kernel/PIDs per session
- **Rotating identity** — server fingerprint rotates hourly; each connection gets a consistent snapshot
- **Enticing fake files** — AWS keys, DB passwords, Stripe secrets, SSH private keys, shadow file
- **Honeytokens** — accessing sensitive files triggers an alert and poisons the attacker's clipboard
- **Command logging** — full per-session logs of every command typed
- **Progressive degradation** — shell gets slower, corrupted, then simulates disk failure as attacker lingers
- **SSH pivot simulation** — fake internal network (db, app, dev hosts) attackers can laterally move through
- **Rival attacker broadcasts** — fake `wall` messages suggesting other sessions and monitoring activity
- **SCP upload capture** — saves files attackers try to upload

## How It Works

### 1. Tarpit on every auth attempt
Every password or public-key attempt sleeps 2–5 seconds before responding. A tool running 10 parallel threads gets throttled from thousands of attempts per minute down to a trickle.

### 2. Randomized server identity
Each connection sees a consistent but randomized server fingerprint — different hostname, internal IP, kernel version, PIDs, memory, and disk size. Rotates hourly so long-running scanners can't fingerprint the honeypot.

### 3. Fake shell
Attackers land as `root` on a fake Ubuntu server with a realistic filesystem:

```
/root/credentials.txt          ← DB, AWS, Stripe keys
/root/important/
    aws_credentials.json
    stripe_keys.txt
    database.conf
    deploy_key.pem
/root/.ssh/id_rsa              ← fake private key
/root/.bash_history            ← incriminating history
/etc/shadow                    ← fake password hashes
/etc/hostname, /etc/hosts      ← consistent with session identity
/proc/meminfo, /proc/cpuinfo   ← realistic /proc entries
/var/www/html/config.php       ← fake DB config
```

### 4. Command responses that waste time

| Command | Behavior |
|---|---|
| `cat credentials.txt` | 0.3–1.2s pause, then fake secrets + clipboard poison |
| `python3 / perl / ruby` | hangs 3–7s → Segmentation fault |
| `find` | hangs 4–9s, returns nothing |
| `wget / curl` | slow DNS, progress bar stalls at 73%, then timeout |
| `ssh 10.0.1.x` | pivots into fake internal hosts with their own secrets |
| `sudo` | asks for password, waits 1.5s, rejects |
| `vim / nano / emacs` | Error opening terminal |
| `apt-get / yum` | lock file permission denied |
| `nmap` | hangs 5–12s, returns fake port scan |
| `john / hashcat` | runs for 30s then "cracks" a honeytoken password |
| `rm -rf /` | simulates filesystem destruction then kernel panic, then reboots |
| `mysql` | interactive fake MySQL shell with real-looking tables |
| `docker exec` | drops into fake container shell |

### 5. Progressive degradation

| Commands run | Effect |
|---|---|
| 15+ | Responses get progressively slower |
| 25+ | Random character corruption in output |
| 40+ | Kernel OOM messages appear |
| 60+ | EXT4 I/O errors appended to output |
| 80+ | Read-only filesystem errors |

### 6. Logging

```
honeypot_logs/
├── honeypot.log           # real-time server events
├── credentials.jsonl      # every auth attempt (JSON lines)
├── honeytokens.jsonl      # honeytoken access events
├── sessions/
│   └── <ip>_<port>_<ts>.log   # per-session command history
└── uploads/               # files uploaded via SCP
```

## Setup

### Requirements

Go 1.22+. No external dependencies beyond `golang.org/x/crypto`.

```bash
go build -o ultor .
```

### Run on port 2222

```bash
./ultor
```

### Run on port 22 (production)

**Move your real SSH daemon to a different port first**, or you will lock yourself out.

```bash
# 1. Move real sshd to port 2222 (edit /etc/ssh/sshd_config, change Port to 2222)
sudo systemctl restart sshd

# 2. Verify you can still SSH in on port 2222
ssh -p 2222 user@yourserver

# 3. Option A: iptables redirect
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# 3. Option B: bind directly with cap_net_bind_service
sudo setcap cap_net_bind_service=+ep ./ultor
./ultor -port 22
```

### Run as a systemd service

```ini
# /etc/systemd/system/ssh-honeypot.service
[Unit]
Description=SSH Honeypot
After=network.target

[Service]
ExecStart=/opt/ultor/ultor -port 2222
WorkingDirectory=/opt/ultor
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now ssh-honeypot
```

## Configuration

Flags:

| Flag | Default | Description |
|---|---|---|
| `-port` | `2222` | Listening port |
| `-host` | `0.0.0.0` | Bind address |
| `-max-conns` | `512` | Max concurrent connections |

Constants in `config.go`:

| Constant | Default | Description |
|---|---|---|
| `tarpitMin` | `2s` | Min auth delay |
| `tarpitMax` | `5s` | Max auth delay |
| `caughtRevealDelay` | `20m` | When to show the "you've been caught" message |
| `scpMaxSize` | `100MB` | Max SCP upload size |

## Analyzing Captures

```bash
go run ./cmd/analyze/                        # top 20 of everything
go run ./cmd/analyze/ --top 50               # top 50
go run ./cmd/analyze/ --sessions             # include per-session command detail
go run ./cmd/analyze/ --log-dir /path/to/logs

# or build once:
go build -o analyze ./cmd/analyze/
./analyze --top 20
```

Sample output:

```
══════════════════════════════════════════════════════════════
  SSH HONEYPOT REPORT  —  2024-11-07 09:30 UTC
══════════════════════════════════════════════════════════════

Auth Attempts
─────────────
Total attempts    : 14823
First             : 2024-11-01T00:04:12Z
Last              : 2024-11-07T09:28:55Z
Unique IPs        : 342
Unique usernames  : 89
Unique passwords  : 4201

Top 5 Source IPs
────────────────
IP               Attempts
───────────────  ────────
185.234.219.42   2341
45.142.212.100   1876
194.165.16.11    1203
91.92.243.88      987
185.220.101.45    743

Top 5 Usernames
───────────────
Username  Count
────────  ─────
root      9823
admin     2341
ubuntu     876
pi         412
user       201

Top 5 Passwords
───────────────
Password    Count
──────────  ─────
123456       412
admin        389
root         301
password     287
1234         201

Top 5 Credential Pairs
──────────────────────
Username  Password    Count
────────  ──────────  ─────
root      123456       201
admin     admin        189
root      password     143
root                   98
admin     1234         87

Honeytoken Access
─────────────────
Total accesses : 7

Timestamp            IP              User  File
───────────────────  ──────────────  ────  ─────────────────────────────────────
2024-11-03T14:22:11  185.234.219.42  root  /root/credentials.txt
2024-11-04T02:11:08  45.142.212.100  root  /root/important/aws_credentials.json
2024-11-04T02:11:19  45.142.212.100  root  /root/.ssh/id_rsa
2024-11-05T18:44:33  194.165.16.11   root  /etc/shadow
2024-11-06T07:12:01  91.92.243.88    root  /root/credentials.txt
2024-11-06T07:12:44  91.92.243.88    root  /root/wallet.dat
2024-11-07T03:55:22  185.220.101.45  root  /root/important/aws_credentials.json

Session Logs
────────────
Total sessions : 1482
Active sessions: 203 (ran at least one command)

Top 10 Interactive Commands
───────────────────────────
Command   Count
────────  ─────
ls        412
cat       389
cd        301
id        287
whoami    201
ps        189
uname     143
history    98
wget       87
ssh        76

Top 10 Exec Commands (non-interactive)
───────────────────────────────────────
Command   Count
────────  ─────
id         312
uname      289
whoami     201
cat        187
ls         143

Notable Sessions
────────────────
  185_234_219_42_54821_20241103_142133.log  [downloader, anti-forensic]
  45_142_212_100_39812_20241104_021044.log  [downloader, pivot, payload]
  91_92_243_88_51200_20241106_071148.log    [rm-nuke]
  185_220_101_45_44821_20241107_035501.log  [cracker, scanner]

══════════════════════════════════════════════════════════════
```

## Legal Notice

Deploy this only on systems you own or have explicit authorization to monitor. Captured data may include sensitive attacker information — store and handle it accordingly. Check local laws regarding honeypot operation in your jurisdiction.

## License

MIT
