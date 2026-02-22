package main

import (
	"path/filepath"
	"time"
)

// Runtime-overridable via flags
var (
	listenHost    = "0.0.0.0"
	listenPort    = 2222
	maxConns      = 512 // concurrent connection limit
)

const (
	hostKeyFile = "./honeypot_host_key"
	logDir      = "./honeypot_logs"

	tarpitMin = 2.0 * float64(time.Second)
	tarpitMax = 5.0 * float64(time.Second)

	// Progressive degradation — command count thresholds
	degradeJitter   = 15
	degradeCorrupt  = 25
	degradeOOM      = 40
	degradeDisk     = 60
	degradeReadOnly = 80

	// "You've been caught" reveal timer
	caughtRevealDelay = 20 * time.Minute

	// Rival attacker broadcast window
	rivalMinDelay = 60 * time.Second
	rivalMaxDelay = 120 * time.Second

	// Max SCP upload size (bytes)
	scpMaxSize = 100 * 1024 * 1024 // 100 MB
)

var (
	credLogFile      = filepath.Join(logDir, "credentials.jsonl")
	honeytokenLogFile = filepath.Join(logDir, "honeytokens.jsonl")
	sessionDir       = filepath.Join(logDir, "sessions")
	uploadDir        = filepath.Join(logDir, "uploads")
)

var oomMessages = []string{
	"\r\n[%9.6f] Out of memory: Kill process 14823 (php-fpm) score 312 or sacrifice child\r\n" +
		"[%9.6f] Killed process 14823 (php-fpm) total-vm:1048576kB, anon-rss:204800kB\r\n",
	"\r\n[%9.6f] EXT4-fs error (device nvme0n1p1): ext4_journal_check_start:61: Detected aborted journal\r\n" +
		"[%9.6f] EXT4-fs (nvme0n1p1): Remounting filesystem read-only\r\n",
	"\r\n[%9.6f] SCSI error: return code = 0x08000002\r\n" +
		"[%9.6f] end_request: I/O error, dev nvme0n1, sector 1234567890\r\n",
	"\r\n[%9.6f] page allocation failure: order:4, mode:0x14200c0\r\n",
	"\r\n[%9.6f] BUG: unable to handle kernel NULL pointer dereference at 0000000000000018\r\n" +
		"[%9.6f] IP: tcp_v4_rcv+0x3a8/0xa00\r\n",
}

var rmrfPaths = []string{
	"/root/credentials.txt", "/root/important/aws_credentials.json",
	"/root/.ssh/id_rsa", "/root/.ssh/authorized_keys",
	"/root/backup/db_backup_2024-11-03.sql.gz",
	"/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config",
	"/var/www/html/config.php", "/usr/bin/python3", "/usr/bin/ssh",
	"/lib/x86_64-linux-gnu/libc.so.6",
	"/bin/bash", "/bin/sh", "/bin/ls", "/bin/cat",
	"/sbin/init", "/usr/sbin/sshd",
}
