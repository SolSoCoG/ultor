package main

import (
	"encoding/base64"
	"fmt"
	mrand "math/rand"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type fakeShell struct {
	ch      ssh.Channel
	ip      string
	user    string
	slog    *sessionLogger
	profile serverProfile // snapshotted at connection time, never changes

	rawIn    chan byte
	done     chan struct{}
	doneOnce sync.Once
	mu       sync.Mutex

	cwd                 string
	cmdCount            int
	cmdHistory          []string
	histIdx             int // -1 = not browsing history
	honeytokensAccessed []string
	startTime           time.Time
	dispatchDepth       int // guards against sudo/eval recursion
}

func newFakeShell(ch ssh.Channel, ip, user string, sess *sessionLogger, p serverProfile) *fakeShell {
	s := &fakeShell{
		ch:        ch,
		ip:        ip,
		user:      user,
		slog:      sess,
		profile:   p,
		rawIn:     make(chan byte, 256),
		done:      make(chan struct{}),
		cwd:       "/root",
		startTime: time.Now(),
		histIdx:   -1,
	}
	go s.inputReader()
	return s
}

func (s *fakeShell) inputReader() {
	buf := make([]byte, 1)
	for {
		n, err := s.ch.Read(buf)
		if n > 0 {
			select {
			case s.rawIn <- buf[0]:
			case <-s.done:
				return
			}
		}
		if err != nil {
			s.closeDone()
			return
		}
	}
}

func (s *fakeShell) readRaw() (byte, bool) {
	select {
	case b := <-s.rawIn:
		return b, true
	case <-s.done:
		return 0, false
	}
}

// readLine reads until Enter or Ctrl+C/D, echoing nothing (for passwords).
func (s *fakeShell) readLine() string {
	var buf []byte
	for {
		b, ok := s.readRaw()
		if !ok || b == '\r' || b == '\n' {
			return string(buf)
		}
		if b == 0x03 || b == 0x04 {
			return ""
		}
		if (b == 0x7f || b == 0x08) && len(buf) > 0 {
			buf = buf[:len(buf)-1]
		} else if b >= 0x20 {
			buf = append(buf, b)
		}
	}
}

func (s *fakeShell) write(data string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ch.Write([]byte(data)) //nolint:errcheck
}

func (s *fakeShell) writef(format string, args ...interface{}) {
	s.write(fmt.Sprintf(format, args...))
}

func (s *fakeShell) closeDone() {
	s.doneOnce.Do(func() { close(s.done) })
}

// profileResponse returns a per-session response for commands whose output
// contains identity values (hostname, IP, PIDs, memory, disk).
// Returns ("", false) for commands not in this set.
func (s *fakeShell) profileResponse(cmd string) (string, bool) {
	p := s.profile
	h := p.hostname
	ip := p.ip
	k := p.kernelShort()
	kb := p.kernelBuild()
	upStr := " " + currentTimeStr() + " up " + p.uptimeStr + ",  1 user,  load average: " + p.loadStr
	dg := p.diskSize
	du := p.diskUsed
	avail := 100 - du
	diskUsedG := dg * du / 100
	diskAvailG := dg * avail / 100

	switch cmd {
	case "hostname":
		return h, true
	case "uname -a":
		return fmt.Sprintf("Linux %s %s %s x86_64 x86_64 x86_64 GNU/Linux", h, k, kb), true
	case "uptime":
		return upStr, true
	case "cat /proc/version":
		return fmt.Sprintf(
			"Linux version %s (buildd@lcy02-amd64-001) (gcc (Ubuntu 11.4.0) 11.4.0) %s", k, kb), true
	case "dmesg":
		return fmt.Sprintf(
			"[    0.000000] Linux version %s\n"+
				"[    1.234567] EXT4-fs (nvme0n1p1): mounted filesystem with ordered data mode\n"+
				"[ 3842.112233] possible SYN flooding on port 22. Sending cookies.\n"+
				"[ 9431.887654] device nvme0n1: entered write error state\n"+
				"[12891.334455] Out of memory: Kill process 8821 (php-fpm) score 289\n"+
				"[18234.556677] audit: apparmor=\"DENIED\" operation=\"open\" name=\"/root/credentials.txt\"",
			k), true
	case "ps aux":
		return fmt.Sprintf(
			"USER         PID %%CPU %%MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"+
				"root           1  0.0  0.0  22548  1592 ?        Ss   Jan01   1:04 /sbin/init\n"+
				"root        %4d  0.0  0.1  15424  4096 ?        Ss   Jan01   0:00 /usr/sbin/sshd -D\n"+
				"root        %4d  0.0  0.2 143456 10240 ?        S    Jan01   0:12 nginx: master\n"+
				"www-data    %4d  0.0  0.2 143456  8192 ?        S    Jan01   5:33 nginx: worker\n"+
				"mysql       %4d  0.8  8.1 2345678 320M ?        Sl   Jan01 124:12 /usr/sbin/mysqld\n"+
				"root        9901  0.0  0.0  10752  1536 pts/0    R+   09:14   0:00 ps aux",
			p.sshdPID, p.nginxPID, p.nginxPID+1, p.mysqlPID), true
	case "netstat -tulnp":
		return fmt.Sprintf(
			"Proto Recv-Q Send-Q Local Address   Foreign Address   State    PID/Program name\n"+
				"tcp        0      0 0.0.0.0:22      0.0.0.0:*         LISTEN   %d/sshd\n"+
				"tcp        0      0 0.0.0.0:80      0.0.0.0:*         LISTEN   %d/nginx\n"+
				"tcp        0      0 0.0.0.0:3306    0.0.0.0:*         LISTEN   %d/mysqld",
			p.sshdPID, p.nginxPID, p.mysqlPID), true
	case "ifconfig":
		return fmt.Sprintf(
			"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\n"+
				"        inet %s  netmask 255.255.255.0  broadcast 10.0.1.255\n"+
				"        inet6 fe80::dead:beef:cafe:1234  prefixlen 64\n"+
				"        RX packets 12345678  bytes 9876543210 (9.8 GB)\n"+
				"\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"+
				"        inet 127.0.0.1  netmask 255.0.0.0",
			ip), true
	case "ip a":
		return fmt.Sprintf(
			"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"+
				"    inet 127.0.0.1/8 scope host lo\n"+
				"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001\n"+
				"    inet %s/24 brd 10.0.1.255 scope global eth0",
			ip), true
	case "ip route":
		return fmt.Sprintf(
			"default via 10.0.1.1 dev eth0 proto dhcp src %s metric 100\n"+
				"10.0.1.0/24 dev eth0 proto kernel scope link src %s\n"+
				"172.16.0.0/16 via 10.0.1.1 dev eth0",
			ip, ip), true
	case "ip r":
		return fmt.Sprintf(
			"default via 10.0.1.1 dev eth0\n10.0.1.0/24 dev eth0 proto kernel scope link src %s",
			ip), true
	case "df -h":
		return fmt.Sprintf(
			"Filesystem      Size  Used Avail Use%% Mounted on\n"+
				"/dev/nvme0n1p1  %dG   %dG  %dG  %d%% /\n"+
				"tmpfs           7.8G   12M  7.8G   1%% /dev/shm\n"+
				"/dev/nvme1n1    500G  210G  290G  42%% /var/data",
			dg, diskUsedG, diskAvailG, du), true
	case "df":
		// POSIX 1K-block output
		diskTotalK := dg * 1024 * 1024
		diskUsedK := diskTotalK * du / 100
		diskAvailK := diskTotalK - diskUsedK
		return fmt.Sprintf(
			"Filesystem     1K-blocks     Used Available Use%% Mounted on\n"+
				"/dev/nvme0n1p1 %9d %8d %9d  %d%% /\n"+
				"tmpfs           8192000    12288   8179712   1%% /dev/shm\n"+
				"/dev/nvme1n1  524288000 220200960 304087040  42%% /var/data",
			diskTotalK, diskUsedK, diskAvailK, du), true
	case "df -a":
		// 1K-blocks including virtual filesystems
		diskTotalK := dg * 1024 * 1024
		diskUsedK := diskTotalK * du / 100
		diskAvailK := diskTotalK - diskUsedK
		return fmt.Sprintf(
			"Filesystem     1K-blocks     Used Available Use%% Mounted on\n"+
				"sysfs                  0        0         0    - /sys\n"+
				"proc                   0        0         0    - /proc\n"+
				"devtmpfs         8192000        0   8192000   0%% /dev\n"+
				"tmpfs            8192000    12288   8179712   1%% /dev/shm\n"+
				"/dev/nvme0n1p1 %9d %8d %9d  %d%% /\n"+
				"/dev/nvme1n1  524288000 220200960 304087040  42%% /var/data",
			diskTotalK, diskUsedK, diskAvailK, du), true
	case "df -ha":
		// Human-readable including virtual filesystems
		return fmt.Sprintf(
			"Filesystem      Size  Used Avail Use%% Mounted on\n"+
				"sysfs              0     0     0    - /sys\n"+
				"proc               0     0     0    - /proc\n"+
				"devtmpfs        7.8G     0  7.8G   0%% /dev\n"+
				"tmpfs           7.8G     0  7.8G   0%% /dev/shm\n"+
				"/dev/nvme0n1p1  %dG   %dG  %dG  %d%% /\n"+
				"tmpfs           7.8G   12M  7.8G   1%% /run\n"+
				"/dev/nvme1n1    500G  210G  290G  42%% /var/data",
			dg, diskUsedG, diskAvailG, du), true
	case "ps":
		// Only the current session (no other users)
		return "  PID TTY          TIME CMD\n" +
			" 9901 pts/0    00:00:00 bash", true
	case "ps a":
		// All processes attached to a terminal
		return fmt.Sprintf(
			"  PID TTY      STAT   TIME COMMAND\n"+
				" %4d ?        Ss     0:00 /usr/sbin/sshd -D\n"+
				" 9901 pts/0    Ss     0:00 -bash\n"+
				" 9902 pts/0    R+     0:00 ps a",
			p.sshdPID), true
	case "ps u":
		// User-oriented format, current terminal only
		return fmt.Sprintf(
			"USER         PID %%CPU %%MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"+
				"root        9901  0.0  0.0  10752  2048 pts/0    Ss   %s   0:00 -bash\n"+
				"root        9902  0.0  0.0   8192  1536 pts/0    R+   %s   0:00 ps u",
			time.Now().Add(-13*time.Minute).Format("15:04"),
			time.Now().Format("15:04")), true
	case "ps au":
		// All tty processes with user column
		return fmt.Sprintf(
			"USER         PID %%CPU %%MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"+
				"root        %4d  0.0  0.1  15424  4096 ?        Ss   Jan01   0:00 /usr/sbin/sshd -D\n"+
				"root        9901  0.0  0.0  10752  2048 pts/0    Ss   %s   0:00 -bash\n"+
				"root        9902  0.0  0.0   8192  1536 pts/0    R+   %s   0:00 ps au",
			p.sshdPID,
			time.Now().Add(-13*time.Minute).Format("15:04"),
			time.Now().Format("15:04")), true
	case "ps -e", "ps -A":
		// All processes — same content as ps aux
		return fmt.Sprintf(
			"  PID TTY          TIME CMD\n"+
				"    1 ?        00:01:04 init\n"+
				" %4d ?        00:00:00 sshd\n"+
				" %4d ?        00:00:12 nginx\n"+
				" %4d ?        00:00:12 nginx\n"+
				" %4d ?        02:04:12 mysqld\n"+
				" 9901 pts/0    00:00:00 bash\n"+
				" 9902 pts/0    00:00:00 ps",
			p.sshdPID, p.nginxPID, p.nginxPID+1, p.mysqlPID), true
	case "ps -ef":
		return fmt.Sprintf(
			"UID          PID    PPID  C STIME TTY          TIME CMD\n"+
				"root           1       0  0 Jan01 ?        00:01:04 /sbin/init\n"+
				"root        %4d       1  0 Jan01 ?        00:00:00 /usr/sbin/sshd -D\n"+
				"root        %4d       1  0 Jan01 ?        00:00:12 nginx: master process /usr/sbin/nginx\n"+
				"www-data    %4d    %4d  0 Jan01 ?        00:05:33 nginx: worker process\n"+
				"mysql       %4d       1  1 Jan01 ?        02:04:12 /usr/sbin/mysqld\n"+
				"root        9901    %4d  0 %s pts/0    00:00:00 -bash\n"+
				"root        9902    9901  0 %s pts/0    00:00:00 ps -ef",
			p.sshdPID,
			p.nginxPID, p.nginxPID+1, p.nginxPID,
			p.mysqlPID,
			p.sshdPID,
			time.Now().Add(-13*time.Minute).Format("15:04"),
			time.Now().Format("15:04")), true
	case "ps -aux":
		// -aux is treated same as aux by procps
		return s.profileResponse("ps aux")
	case "free -h":
		return fmt.Sprintf(
			"               total        used        free      shared  buff/cache   available\n"+
				"Mem:           %s       %s       2.0Gi        45Mi       2.0Gi       4.0Gi\n"+
				"Swap:          2.0Gi          0B       2.0Gi",
			p.memTotal, p.memUsed), true
	case "free -m":
		totalMB := 0
		fmt.Sscanf(p.memTotal, "%dGi", &totalMB)
		totalMB *= 1024
		usedMB := 0
		fmt.Sscanf(p.memUsed, "%dGi", &usedMB)
		usedMB *= 1024
		freeMB := totalMB - usedMB - 2048
		return fmt.Sprintf(
			"               total        used        free      shared  buff/cache   available\n"+
				"Mem:           %5d       %5d       %5d          45        2048        %5d\n"+
				"Swap:           2048           0        2048",
			totalMB, usedMB, freeMB, freeMB+2048), true
	case "free -g":
		totalG := 0
		fmt.Sscanf(p.memTotal, "%dGi", &totalG)
		usedG := 0
		fmt.Sscanf(p.memUsed, "%dGi", &usedG)
		freeG := totalG - usedG - 2
		return fmt.Sprintf(
			"               total        used        free      shared  buff/cache   available\n"+
				"Mem:             %3d          %3d          %3d           0           2          %3d\n"+
				"Swap:              2            0            2",
			totalG, usedG, freeG, freeG+2), true
	case "free -k":
		totalKB := 0
		fmt.Sscanf(p.memTotal, "%dGi", &totalKB)
		totalKB *= 1024 * 1024
		usedKB := 0
		fmt.Sscanf(p.memUsed, "%dGi", &usedKB)
		usedKB *= 1024 * 1024
		freeKB := totalKB - usedKB - 2*1024*1024
		return fmt.Sprintf(
			"               total        used        free      shared  buff/cache   available\n"+
				"Mem:        %9d   %9d   %9d       46080     2097152     %9d\n"+
				"Swap:         2097152           0     2097152",
			totalKB, usedKB, freeKB, freeKB+2*1024*1024), true
	case "uname -r":
		return k, true
	case "uname -s":
		return "Linux", true
	case "uname -n":
		return h, true
	case "uname -v":
		return kb, true
	case "uname -m":
		return "x86_64", true
	case "uname -p":
		return "x86_64", true
	case "uname -i":
		return "x86_64", true
	case "uname -o":
		return "GNU/Linux", true
	case "hostname -f":
		return h + ".internal.company.com", true
	case "hostname -s":
		return h, true
	case "hostname -i":
		return ip, true
	case "hostname -I":
		return ip + " 127.0.0.1", true
	case "uptime -p":
		return fmt.Sprintf("up %d weeks, %d days", p.uptimeDays/7, p.uptimeDays%7), true
	case "uptime -s":
		t := time.Now().Add(-time.Duration(p.uptimeDays) * 24 * time.Hour)
		return t.Format("2006-01-02 15:04:05"), true
	case "netstat -an":
		return fmt.Sprintf(
			"Active Internet connections (servers and established)\n"+
				"Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"+
				"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"+
				"tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"+
				"tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN\n"+
				"tcp        0    256 %s:22              %s:41892        ESTABLISHED",
			ip, p.lastIP), true
	case "netstat -rn", "netstat -r":
		return fmt.Sprintf(
			"Kernel IP routing table\n"+
				"Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface\n"+
				"0.0.0.0         10.0.1.1        0.0.0.0         UG        0 0          0 eth0\n"+
				"10.0.1.0        0.0.0.0         255.255.255.0   U         0 0          0 eth0"), true
	case "netstat -s":
		return "Ip:\n    10234 total packets received\n    0 forwarded\n    0 incoming packets discarded\nTcp:\n    8432 active connection openings\n    423 passive connection openings\n    0 failed connection attempts", true
	case "netstat -a", "netstat":
		return fmt.Sprintf(
			"Active Internet connections (servers and established)\n"+
				"Proto Recv-Q Send-Q Local Address     Foreign Address   State\n"+
				"tcp        0      0 0.0.0.0:ssh       0.0.0.0:*         LISTEN\n"+
				"tcp        0      0 0.0.0.0:http      0.0.0.0:*         LISTEN\n"+
				"tcp        0      0 0.0.0.0:mysql     0.0.0.0:*         LISTEN\n"+
				"tcp        0    256 %s:ssh     %s:41892  ESTABLISHED",
			ip, p.lastIP), true
	case "ss -an", "ss -tln", "ss -tlnp", "ss -tulnp", "ss":
		return fmt.Sprintf(
			"Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port\n"+
				"tcp    LISTEN  0       128     0.0.0.0:22          0.0.0.0:*\n"+
				"tcp    LISTEN  0       511     0.0.0.0:80          0.0.0.0:*\n"+
				"tcp    LISTEN  0       70      0.0.0.0:3306        0.0.0.0:*\n"+
				"tcp    ESTAB   0       256     %s:22          %s:41892",
			ip, p.lastIP), true
	case "ss -tan":
		return fmt.Sprintf(
			"State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port\n"+
				"LISTEN  0       128     0.0.0.0:22          0.0.0.0:*\n"+
				"LISTEN  0       511     0.0.0.0:80          0.0.0.0:*\n"+
				"LISTEN  0       70      0.0.0.0:3306        0.0.0.0:*\n"+
				"ESTAB   0       256     %s:22          %s:41892",
			ip, p.lastIP), true
	case "route":
		return fmt.Sprintf(
			"Kernel IP routing table\n"+
				"Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"+
				"default         10.0.1.1        0.0.0.0         UG    100    0        0 eth0\n"+
				"10.0.1.0        *               255.255.255.0   U     100    0        0 eth0\n"+
				"172.16.0.0      10.0.1.1        255.255.0.0     UG    100    0        0 eth0"), true
	case "arp":
		return fmt.Sprintf(
			"Address                  HWtype  HWaddress           Flags Mask   Iface\n"+
				"10.0.1.1                 ether   02:42:ac:11:00:01   C             eth0\n"+
				"10.0.1.10                ether   02:42:ac:11:00:0a   C             eth0\n"+
				"%s                 ether   02:42:ac:11:00:2d   C             eth0",
			ip), true
	case "ifconfig eth0":
		return fmt.Sprintf(
			"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\n"+
				"        inet %s  netmask 255.255.255.0  broadcast 10.0.1.255\n"+
				"        inet6 fe80::dead:beef:cafe:1234  prefixlen 64\n"+
				"        RX packets 12345678  bytes 9876543210 (9.8 GB)\n"+
				"        TX packets 9876543  bytes 4567890123 (4.5 GB)",
			ip), true
	case "ifconfig lo":
		return "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n" +
			"        inet 127.0.0.1  netmask 255.0.0.0\n" +
			"        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n" +
			"        RX packets 45678  bytes 3456789 (3.4 MB)", true
	case "ifconfig -a":
		r, _ := s.profileResponse("ifconfig")
		return r, true
	case "last":
		return fmt.Sprintf(
			"root     pts/0        %s     Thu Nov  7 08:55   still logged in\n"+
				"root     pts/0        198.51.100.10    Wed Nov  6 23:12 - 23:45  (00:33)\n\n"+
				"wtmp begins Mon Sep 02 00:00:01 2024",
			p.lastIP), true
	case "w":
		return fmt.Sprintf(
			"%s\n"+
				"USER     TTY      FROM              LOGIN@   IDLE JCPU   PCPU WHAT\n"+
				"root     pts/0    %s      09:01    0.00s  0.02s  0.00s w",
			upStr, p.lastIP), true
	}
	return "", false
}

func (s *fakeShell) isRunning() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

func (s *fakeShell) logHoneytoken(file string) {
	s.honeytokensAccessed = append(s.honeytokensAccessed, file)
	logHoneytoken(s.ip, s.user, file)
}

func (s *fakeShell) prompt() string {
	return fmt.Sprintf("root@%s:%s# ", s.profile.hostname, s.cwd)
}

func (s *fakeShell) run() {
	motd := fmt.Sprintf("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux %s x86_64)\r\n\r\n", s.profile.kernelShort()) +
		" * Documentation:  https://help.ubuntu.com\r\n" +
		" * Management:     https://landscape.canonical.com\r\n\r\n" +
		"  System information as of " + time.Now().Format("Mon Jan _2 15:04:05 MST 2006") + "\r\n\r\n" +
		fmt.Sprintf("  System load:  %.2f              Users logged in: 1\r\n", mrand.Float64()*0.5) +
		fmt.Sprintf("  Usage of /:   %d%% of %dGB   IPv4 address for eth0: %s\r\n\r\n",
			s.profile.diskUsed, s.profile.diskSize, s.profile.ip) +
		"Last login: " + time.Now().Add(-2*time.Hour).Format("Mon Jan _2 15:04:05 2006") + " from " + s.profile.lastIP + "\r\n"
	s.write(motd)
	s.write(s.prompt())

	go s.rivalAttacker()
	go s.caughtReveal()

	var buf []byte
	var escBuf []byte

	// replaceInputLine clears the current input on screen and writes newLine.
	replaceInputLine := func(newLine string) {
		// Move to start of line, erase to end, rewrite content.
		s.write("\r\x1b[K" + s.prompt() + newLine)
		buf = []byte(newLine)
	}

	for {
		b, ok := s.readRaw()
		if !ok {
			return
		}

		// Collect escape sequences (arrow keys, etc.)
		if len(escBuf) > 0 {
			escBuf = append(escBuf, b)
			// Full CSI sequence: ESC [ <final>  where final is 0x40–0x7E
			if len(escBuf) == 3 && escBuf[1] == '[' {
				switch escBuf[2] {
				case 'A': // Up arrow — older history
					if len(s.cmdHistory) > 0 {
						if s.histIdx == -1 {
							s.histIdx = len(s.cmdHistory) - 1
						} else if s.histIdx > 0 {
							s.histIdx--
						}
						replaceInputLine(s.cmdHistory[s.histIdx])
					}
				case 'B': // Down arrow — newer history
					if s.histIdx != -1 {
						if s.histIdx < len(s.cmdHistory)-1 {
							s.histIdx++
							replaceInputLine(s.cmdHistory[s.histIdx])
						} else {
							s.histIdx = -1
							replaceInputLine("")
						}
					}
				// Left/right arrows: ignore (no cursor movement support)
				}
				escBuf = escBuf[:0]
			} else if len(escBuf) >= 3 || (len(escBuf) == 2 && b != '[') {
				// Absorb other sequences (F-keys, etc.)
				escBuf = escBuf[:0]
			}
			continue
		}
		if b == 0x1b {
			escBuf = append(escBuf[:0], b)
			continue
		}

		switch {
		case b == '\r' || b == '\n':
			s.write("\r\n")
			line := strings.TrimSpace(string(buf))
			buf = buf[:0]
			s.histIdx = -1
			if line != "" {
				s.cmdCount++
				s.cmdHistory = append(s.cmdHistory, line)
				s.slog.log("CMD: %s", line)
				out := s.dispatch(line)
				if out != "" {
					out = s.degradeOutput(out)
					s.write(strings.ReplaceAll(out, "\n", "\r\n") + "\r\n")
				}
				if !s.isRunning() {
					return
				}
				s.maybeOOM()
			}
			s.write(s.prompt())

		case b == 0x7f || b == 0x08:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				s.write("\b \b")
			}

		case b == 0x03:
			buf = buf[:0]
			s.write("^C\r\n" + s.prompt())

		case b == 0x04:
			if len(buf) == 0 {
				s.write("logout\r\n")
				s.closeDone()
				return
			}

		case b == 0x09: // TAB
			s.tabComplete(&buf)

		case b == 0x0c: // Ctrl+L
			s.write("\x1b[2J\x1b[H" + s.prompt() + string(buf))

		case b >= 0x20:
			buf = append(buf, b)
			s.write(string([]byte{b}))
		}
	}
}

// shellCommands is the full set of recognized commands, used for tab completion.
var shellCommands = []string{
	"alias", "awk", "base64", "bg", "cat", "cd", "chmod", "chown", "chgrp",
	"clear", "cp", "crontab", "curl", "date", "dd", "df", "docker", "du",
	"echo", "env", "export", "fg", "file", "find", "free", "gcc", "g++",
	"git", "go", "grep", "egrep", "groups", "gunzip", "gzip", "hashcat",
	"head", "history", "hostname", "id", "ifconfig", "ip", "iptables",
	"jobs", "john", "kill", "killall", "kubectl", "last", "less", "ln",
	"ls", "ll", "lsblk", "lscpu", "lsof", "ltrace", "mkdir", "more",
	"mount", "mv", "nano", "nc", "netstat", "nmap", "nohup", "openssl",
	"passwd", "perl", "php", "ping", "pip", "pip3", "pkill", "printenv",
	"ps", "pwd", "python", "python3", "rm", "rmdir", "rsync", "ruby",
	"screen", "sed", "sleep", "sort", "ss", "ssh", "stat", "strace",
	"strings", "su", "sudo", "systemctl", "tail", "tar", "tee", "tmux",
	"touch", "tr", "type", "ufw", "uname", "unset", "unzip", "uptime",
	"useradd", "vi", "vim", "w", "wc", "wget", "which", "who", "whoami",
	"xargs", "zip",
}

func (s *fakeShell) tabComplete(buf *[]byte) {
	line := string(*buf)
	fields := strings.Fields(line)
	trailingSpace := strings.HasSuffix(line, " ")

	var completions []string
	var prefix string

	if len(fields) == 0 || (len(fields) == 1 && !trailingSpace) {
		// Complete command name
		if len(fields) == 1 {
			prefix = fields[0]
		}
		for _, cmd := range shellCommands {
			if strings.HasPrefix(cmd, prefix) {
				completions = append(completions, cmd)
			}
		}
	} else {
		// Complete file/path; cd only shows directories
		if !trailingSpace && len(fields) > 0 {
			prefix = fields[len(fields)-1]
		}
		dirsOnly := len(fields) >= 1 && fields[0] == "cd"
		completions = s.completePath(prefix, dirsOnly)
	}

	if len(completions) == 0 {
		s.write("\x07") // bell — no match
		return
	}

	if len(completions) == 1 {
		suffix := completions[0][len(prefix):]
		*buf = append(*buf, []byte(suffix)...)
		s.write(suffix)
		// Append space after a completed command word (not after a path)
		if len(fields) == 0 || (len(fields) == 1 && !trailingSpace) {
			*buf = append(*buf, ' ')
			s.write(" ")
		}
		return
	}

	// Multiple matches: display all, then redisplay the prompt + current line
	s.write("\r\n")
	for i, c := range completions {
		s.writef("%-20s", c)
		if (i+1)%4 == 0 {
			s.write("\r\n")
		}
	}
	if len(completions)%4 != 0 {
		s.write("\r\n")
	}
	s.write(s.prompt() + line)
}

func (s *fakeShell) completePath(prefix string, dirsOnly bool) []string {
	dir := s.cwd
	filePrefix := prefix
	hasSlash := strings.Contains(prefix, "/")

	if idx := strings.LastIndex(prefix, "/"); idx >= 0 {
		dir = prefix[:idx]
		if dir == "" {
			dir = "/"
		}
		filePrefix = prefix[idx+1:]
	}

	entries, ok := fakeFS[dir]
	if !ok {
		return nil
	}
	var completions []string
	for _, e := range entries {
		if !strings.HasPrefix(e, filePrefix) {
			continue
		}
		// Build the full completion string (no double-slash at root)
		var full string
		if hasSlash {
			if dir == "/" {
				full = "/" + e
			} else {
				full = dir + "/" + e
			}
		} else {
			full = e
		}
		// Determine absolute path to check if entry is a directory
		var absPath string
		if hasSlash {
			absPath = full
		} else {
			absPath = dir + "/" + e
		}
		_, isDir := fakeFS[absPath]
		if isDir {
			full += "/" // real bash appends / for directories
		}
		if dirsOnly && !isDir {
			continue
		}
		completions = append(completions, full)
	}
	return completions
}

// dispatchCompound splits compound shell expressions (;  &&  ||  |) and runs
// each part in sequence, mimicking real bash behaviour. Returns (output, true)
// when the line contains a metacharacter, ("", false) otherwise so that
// dispatch() can handle the simple case directly.
func (s *fakeShell) dispatchCompound(line string) (string, bool) {
	// Tokenise, respecting single/double quotes (no nesting needed).
	type token struct {
		text string
		op   string // "", ";", "&&", "||", "|"
	}
	var tokens []token
	var cur strings.Builder
	i := 0
	hasOp := false
	for i < len(line) {
		c := line[i]
		switch {
		case c == '\'' || c == '"':
			// Copy quoted section verbatim.
			q := c
			cur.WriteByte(c)
			i++
			for i < len(line) && line[i] != q {
				cur.WriteByte(line[i])
				i++
			}
			if i < len(line) {
				cur.WriteByte(line[i])
				i++
			}
		case i+1 < len(line) && c == '&' && line[i+1] == '&':
			tokens = append(tokens, token{text: strings.TrimSpace(cur.String()), op: "&&"})
			cur.Reset()
			i += 2
			hasOp = true
		case i+1 < len(line) && c == '|' && line[i+1] == '|':
			tokens = append(tokens, token{text: strings.TrimSpace(cur.String()), op: "||"})
			cur.Reset()
			i += 2
			hasOp = true
		case c == '|':
			tokens = append(tokens, token{text: strings.TrimSpace(cur.String()), op: "|"})
			cur.Reset()
			i++
			hasOp = true
		case c == ';':
			tokens = append(tokens, token{text: strings.TrimSpace(cur.String()), op: ";"})
			cur.Reset()
			i++
			hasOp = true
		default:
			cur.WriteByte(c)
			i++
		}
	}
	if tail := strings.TrimSpace(cur.String()); tail != "" {
		tokens = append(tokens, token{text: tail, op: ""})
	}
	if !hasOp || len(tokens) == 0 {
		return "", false
	}

	// Linear walk: tokens[i].op is the connector *after* tokens[i].
	var out []string
	prevOp := ";"   // first token always runs (like a fresh statement)
	prevFailed := false
	for _, tok := range tokens {
		if tok.text == "" {
			prevOp = tok.op
			continue
		}
		run := false
		switch prevOp {
		case ";", "":
			run = true
		case "&&":
			run = !prevFailed
		case "||":
			run = prevFailed
		case "|":
			run = true // simplified: always run piped commands
		}
		if run {
			res := s.dispatch(tok.text)
			if res != "" {
				out = append(out, res)
			}
			prevFailed = (res == fmt.Sprintf("bash: %s: command not found", strings.SplitN(tok.text, " ", 2)[0]))
		}
		prevOp = tok.op
	}
	return strings.Join(out, "\n"), true
}

// dispatch routes a command line to the appropriate handler and returns output.
// Blocking commands (wget, dd, john, etc.) write directly to the channel and return "".
func (s *fakeShell) dispatch(line string) string {
	// Hard cap on recursion depth (sudo eval sudo eval …).
	// Real execution is impossible regardless, but deep stacks waste memory.
	s.dispatchDepth++
	defer func() { s.dispatchDepth-- }()
	if s.dispatchDepth > 8 {
		return "bash: maximum nesting level exceeded (8)"
	}

	// Handle compound commands: split on ; && || and run each part.
	// This makes `id; uname -a` and `id && whoami` behave like real bash.
	if out, ok := s.dispatchCompound(line); ok {
		return out
	}

	// Strip leading VAR=val assignments
	for {
		first := strings.SplitN(line, " ", 2)[0]
		if strings.Contains(first, "=") && len(strings.SplitN(line, " ", 2)) == 2 {
			line = strings.SplitN(line, " ", 2)[1]
		} else {
			break
		}
	}

	// Profile-specific responses (per-session, consistent with snapshotted identity)
	if resp, ok := s.profileResponse(line); ok {
		time.Sleep(s.jitter(20, 80))
		return resp
	}

	// Exact-match static responses
	if resp, ok := cmdResponses[line]; ok {
		time.Sleep(s.jitter(20, 80))
		return resp
	}

	parts := strings.SplitN(line, " ", 2)
	cmd := parts[0]
	args := ""
	if len(parts) > 1 {
		args = strings.TrimSpace(parts[1])
	}

	time.Sleep(s.jitter(10, 60))

	switch cmd {
	case "exit", "logout", "quit":
		s.write("logout\r\n")
		s.closeDone()
		return ""

	case "ls":
		return s.cmdLS("ls", args)
	case "ll":
		return s.cmdLS("ll", args)
	case "dir":
		return s.cmdLS("ls", args)

	case "cat":
		return s.cmdCat(args)
	case "less", "more", "head", "tail":
		return s.cmdCat(args)

	case "cd":
		return s.cmdCD(args)

	case "pwd":
		return s.cwd

	case "echo":
		// Strip quotes
		r := strings.NewReplacer(`"`, "", `'`, "")
		return r.Replace(args)

	case "printf":
		r := strings.NewReplacer(`"`, "", `'`, "")
		return r.Replace(args)

	case "clear", "reset":
		s.write("\x1b[2J\x1b[H")
		return ""

	case "history":
		if strings.Contains(args, "-c") {
			s.slog.log("ATTEMPTED HISTORY CLEAR")
			return "" // pretend it worked; we still have everything
		}
		// Show the fake .bash_history — more interesting than real cmd history
		if hist, ok := fakeFiles["/root/.bash_history"]; ok {
			return hist
		}
		var lines []string
		for i, c := range s.cmdHistory {
			lines = append(lines, fmt.Sprintf(" %4d  %s", i+1, c))
		}
		return strings.Join(lines, "\n")

	case "sudo":
		if s.dispatchDepth > 4 {
			return "sudo: pam_authenticate: Conversation error"
		}
		s.writef("[sudo] password for %s: ", s.user)
		s.readLine()
		s.write("\r\n")
		time.Sleep(time.Duration(1500+mrand.Intn(1500)) * time.Millisecond)
		if args != "" {
			// Strip -E, -u flags silently
			stripped := args
			for strings.HasPrefix(stripped, "-") {
				parts2 := strings.SplitN(stripped, " ", 2)
				if len(parts2) < 2 {
					stripped = ""
					break
				}
				stripped = strings.TrimSpace(parts2[1])
			}
			if stripped != "" {
				return s.dispatch(stripped)
			}
		}
		return "sudo: 1 incorrect password attempt"

	case "su":
		s.write("Password: ")
		s.readLine()
		s.write("\r\n")
		time.Sleep(1500 * time.Millisecond)
		return "su: Authentication failure"

	case "passwd":
		return "passwd: Authentication token manipulation error"

	case "useradd", "groupadd", "usermod", "userdel", "groupdel":
		time.Sleep(s.jitter(200, 600))
		return cmd + ": Permission denied."

	case "wget":
		s.cmdWget(args)
		return ""

	case "curl":
		return s.cmdCurl(args)

	case "dd":
		s.cmdDD(args)
		return ""

	case "find":
		return s.cmdFind(args)

	case "grep", "egrep", "fgrep":
		return s.cmdGrep(args)

	case "ssh":
		s.cmdSSH(args)
		return ""

	case "mysql":
		s.cmdMySQL(args)
		return ""

	case "docker":
		return s.cmdDocker(args)

	case "john":
		s.cmdJohn(args)
		return ""

	case "hashcat":
		s.cmdHashcat(args)
		return ""

	case "strace", "ltrace":
		s.cmdStrace(line, args)
		return ""

	case "aws":
		return s.cmdAWS(args)

	case "base64":
		return s.cmdBase64(args)

	case "python", "python3":
		s.cmdPython(args)
		return ""

	case "php", "lua", "node", "nodejs":
		time.Sleep(s.jitter(3000, 7000))
		return "Segmentation fault (core dumped)"

	case "perl", "ruby":
		time.Sleep(s.jitter(3000, 7000))
		return "Segmentation fault (core dumped)"

	case "gcc", "g++", "cc", "make":
		return s.cmdGCC(cmd, args)

	case "go":
		return s.cmdGo(args)

	case "rm":
		return s.cmdRM(args)

	case "tar":
		return s.cmdTar(args)

	case "git":
		return s.cmdGit(args)

	case "screen", "tmux":
		s.cmdScreen()
		return ""

	case "ping":
		return s.cmdPing(args)

	case "nmap":
		return s.cmdNmap(args)

	case "nc", "netcat", "ncat", "socat":
		time.Sleep(s.jitter(500, 2000))
		return ""

	case "scp":
		time.Sleep(s.jitter(2000, 5000))
		return "scp: connection unexpectedly closed"

	case "sftp":
		time.Sleep(s.jitter(2000, 5000))
		return "sftp: connection unexpectedly closed"

	case "rsync":
		time.Sleep(s.jitter(2000, 5000))
		return "rsync: connection unexpectedly closed (0 bytes received so far) [sender]\r\nrsync error: unexplained error (code 255) at io.c(226) [sender=3.2.7]"

	case "ip":
		return s.cmdIP(args)

	case "df":
		return s.cmdDF(args)

	case "ps":
		return s.cmdPS(args)

	case "uname":
		return s.cmdUname(args)

	case "hostname":
		return s.cmdHostname(args)

	case "ifconfig":
		return s.cmdIfconfig(args)

	case "netstat":
		return s.cmdNetstat(args)

	case "ss":
		return s.cmdSS(args)

	case "route":
		return s.cmdRoute(args)

	case "arp":
		return s.cmdArp(args)

	case "uptime":
		return s.cmdUptime(args)

	case "dmesg":
		return s.cmdDmesg(args)

	case "who":
		return s.cmdWho(args)

	case "free":
		return s.cmdFree(args)

	case "traceroute", "tracepath", "mtr":
		return s.cmdTraceroute(args)

	case "dig":
		return s.cmdDig(args)

	case "nslookup":
		return s.cmdNslookup(args)

	case "host":
		return s.cmdHost(args)

	case "dpkg":
		return s.cmdDpkg(args)

	case "journalctl":
		return s.cmdJournalctl(args)

	case "lspci":
		return "00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma]\n" +
			"00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]\n" +
			"00:01.1 IDE interface: Intel Corporation 82371SB PIIX3 IDE [Natoma/Triton II]\n" +
			"00:02.0 VGA compatible controller: Cirrus Logic GD 5446\n" +
			"00:03.0 Ethernet controller: Intel Corporation 82540EM Gigabit Ethernet Controller"

	case "lsusb":
		return "Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub\n" +
			"Bus 002 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub"

	case "vmstat":
		return s.cmdVmstat(args)

	case "iostat":
		return s.cmdIostat(args)

	case "mpstat":
		return "Linux " + s.profile.kernelShort() + "\n\n" +
			"10:14:33     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle\n" +
			"10:14:33     all    0.12    0.00    0.08    0.03    0.00    0.00    0.01    0.00    0.00   99.76"

	case "sysctl":
		return s.cmdSysctl(args)

	case "lsmod":
		return "Module                  Size  Used by\n" +
			"ip_tables              32768  4 iptable_filter,iptable_nat,iptable_mangle,iptable_raw\n" +
			"x_tables               45056  3 ip_tables,xt_conntrack,xt_tcpudp\n" +
			"nf_conntrack          143360  3 xt_conntrack,nf_nat,nf_conntrack_netlink\n" +
			"ext4                  724992  1\n" +
			"mbcache                16384  1 ext4\n" +
			"jbd2                  131072  1 ext4\n" +
			"virtio_net             57344  0\n" +
			"virtio_blk             20480  3\n" +
			"dm_mod                143360  0"

	case "modinfo":
		return "filename:       /lib/modules/" + s.profile.kernelShort() + "/kernel/drivers/net/virtio_net.ko\n" +
			"license:        GPL\nauthor:         Rusty Russell <rusty@rustcorp.com.au>"

	case "last":
		return s.cmdLast(args)
	case "w":
		return s.cmdW(args)

	case "md5sum":
		if args != "" {
			h := fmt.Sprintf("%x", mrand.Int63())
			h += fmt.Sprintf("%x", mrand.Int63())
			return h[:32] + "  " + args
		}
		return ""

	case "sha256sum":
		if args != "" {
			h := fmt.Sprintf("%x%x%x%x", mrand.Int63(), mrand.Int63(), mrand.Int63(), mrand.Int63())
			return h[:64] + "  " + args
		}
		return ""

	case "sha1sum":
		if args != "" {
			h := fmt.Sprintf("%x%x%x", mrand.Int63(), mrand.Int63(), mrand.Int63())
			return h[:40] + "  " + args
		}
		return ""

	case "basename":
		if args != "" {
			parts2 := strings.Fields(args)
			p2 := parts2[0]
			if idx2 := strings.LastIndex(p2, "/"); idx2 >= 0 {
				p2 = p2[idx2+1:]
			}
			if len(parts2) > 1 {
				p2 = strings.TrimSuffix(p2, parts2[1])
			}
			return p2
		}
		return ""

	case "dirname":
		if args != "" {
			p2 := strings.Fields(args)[0]
			if idx2 := strings.LastIndex(p2, "/"); idx2 > 0 {
				return p2[:idx2]
			}
			return "."
		}
		return "."

	case "seq":
		return s.cmdSeq(args)

	case "env", "printenv":
		if args == "" {
			if r, ok := cmdResponses[cmd]; ok {
				return r
			}
			return cmdResponses["env"]
		}
		switch args {
		case "HOME":
			return "/root"
		case "USER", "LOGNAME":
			return "root"
		case "SHELL":
			return "/bin/bash"
		case "PATH":
			return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
		default:
			return ""
		}

	case "service", "systemctl":
		return s.cmdSystemctl(args)

	case "apt", "apt-get":
		return s.cmdApt(args)
	case "yum", "dnf", "apk":
		return s.cmdApt(args)

	case "pip", "pip3":
		return s.cmdPip(args)

	case "kubectl":
		return s.cmdKubectl(args)

	case "openssl":
		return s.cmdOpenssl(args)

	case "redis-cli":
		return "PONG"

	case "psql":
		time.Sleep(s.jitter(300, 800))
		return "psql: error: connection to server on socket \"/var/run/postgresql/.s.PGSQL.5432\" failed: No such file or directory"

	// File ops — pretend to succeed
	case "chmod", "chown", "chgrp":
		time.Sleep(s.jitter(30, 150))
		return ""
	case "cp", "mv":
		time.Sleep(s.jitter(50, 300))
		return ""
	case "touch", "mkdir", "rmdir", "ln":
		return ""

	case "nano", "vim", "vi", "emacs", "pico", "micro", "joe":
		time.Sleep(s.jitter(300, 800))
		return "Error opening terminal: unknown terminal type."

	case "top", "htop", "iotop", "atop", "glances":
		return "Error opening terminal: unknown terminal type."

	case "kill", "killall", "pkill":
		time.Sleep(s.jitter(50, 200))
		return ""

	case "export", "set", "source", ".":
		return ""

	case "eval":
		if args != "" {
			return s.dispatch(args)
		}
		return ""

	case "unset":
		s.slog.log("UNSET: %s", args)
		return ""

	case "which":
		if args != "" {
			return "/usr/bin/" + strings.Fields(args)[0]
		}
		return ""
	case "whereis":
		return args + ": /usr/bin/" + args + " /usr/share/man/man1/" + args + ".1.gz"
	case "type":
		return args + " is /usr/bin/" + args

	case "help":
		if args != "" {
			return fmt.Sprintf("%s: help text not available.\nType 'man %s' for information about the command.", args, args)
		}
		return "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\n" +
			"These shell commands are defined internally.  Type `help' to see this list.\n" +
			"Type `help name' to find out more about the function `name'.\n" +
			"Use `info bash' to find out more about the shell in general.\n\n" +
			"  job_spec [&]                             history [-c] [-d offset] [n]\n" +
			"  (( expression ))                         if COMMANDS; then COMMANDS; fi\n" +
			"  . filename [arguments]                   jobs [-lnprs] [jobspec ...]\n" +
			"  :                                        kill [-s sigspec] pid\n" +
			"  [ arg... ]                               let arg [arg ...]\n" +
			"  [[ expression ]]                         local [option] name[=value]\n" +
			"  alias [-p] [name[=value] ...]            logout [n]\n" +
			"  bg [job_spec ...]                        mapfile [-d delim] [-n count]\n" +
			"  bind [-lpsvPSVX] [-m keymap]             popd [-n] [+N | -N]\n" +
			"  break [n]                                printf [-v var] format\n" +
			"  builtin [shell-builtin [arg ...]]        pushd [-n] [+N | -N | dir]\n" +
			"  caller [expr]                            pwd [-LP]\n" +
			"  case WORD in [PATTERN [| PATTERN]...)    read [-ers] [-a array]\n" +
			"  cd [-L|[-P [-e]] [-@]] [dir]             readarray [-d delim] [-n count]\n" +
			"  command [-pVv] command [arg ...]          readonly [-aAf] [name[=value]]\n" +
			"  compgen [-abcdefgjksuv] [-o option]      return [n]\n" +
			"  complete [-abcdefgjksuv] [-pr] [-DEI]    select NAME [in WORDS ...]\n" +
			"  continue [n]                             set [-abefhkmnptuvxBCHP]\n" +
			"  declare [-aAfFgilnrtux] [-p] [name]      shift [n]\n" +
			"  dirs [-clpv] [+N] [-N]                   shopt [-pqsu] [-o] [optname]\n" +
			"  disown [-h] [-ar] [jobspec ...]          source filename [arguments]\n" +
			"  echo [-neE] [arg ...]                    suspend [-f]\n" +
			"  enable [-a] [-dnps] [-f filename]        test [expr]\n" +
			"  eval [arg ...]                           time [-p] pipeline\n" +
			"  exec [-cl] [-a name] [command [args]]    times\n" +
			"  exit [n]                                 trap [-lp] [[arg] signal_spec]\n" +
			"  export [-fn] [name[=value] ...] or       true\n" +
			"  false                                    type [-afptP] name [name ...]\n" +
			"  fc [-e ename] [-lnr] [first] [last]      typeset [-aAfFgilnrtux] [-p]\n" +
			"  fg [job_spec]                            ulimit [-SHabcdefiklmnpqrstuvxPT]\n" +
			"  for NAME [in WORDS ... ] ; do COMMANDS   umask [-p] [-S] [mode]\n" +
			"  for (( exp1; exp2; exp3 )); do CMDS      unalias [-a] name [name ...]\n" +
			"  function name { COMMANDS ; } or name     unset [-f] [-v] [-n] [name ...]\n" +
			"  getopts optstring name [arg]             until COMMANDS; do COMMANDS;\n" +
			"  hash [-lr] [-p pathname] [-dt] [name]    variables - Names and meanings\n" +
			"  if COMMANDS; then COMMANDS; [elif ...]   wait [-fn] [-p var] [id ...]"

	case "man":
		return "No manual entry for " + args

	case "stat":
		return "  File: " + args + "\n  Size: 4096\t\tBlocks: 8\t IO Block: 4096   regular file\nAccess: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"

	case "file":
		return args + ": ELF 64-bit LSB executable, x86-64, dynamically linked"

	case "wc":
		return "      42     256    1984 " + args

	case "date":
		return time.Now().Format("Mon Jan _2 15:04:05 UTC 2006")

	case "sleep":
		d := 1
		fmt.Sscanf(args, "%d", &d)
		if d > 10 {
			d = 10
		}
		time.Sleep(time.Duration(d) * time.Second)
		return ""

	case "nohup":
		if args != "" {
			go func() { time.Sleep(2 * time.Second) }()
			return "nohup: ignoring input and appending output to 'nohup.out'"
		}
		return ""

	case "crontab":
		if strings.Contains(args, "-l") {
			return cmdResponses["crontab -l"]
		}
		return ""

	case "tee":
		return ""
	case "awk", "sed":
		return ""
	case "sort", "uniq", "cut", "tr":
		return ""
	case "xargs":
		return ""
	case "xxd", "od", "hexdump":
		return "00000000: 4865 6c6c 6f20 576f 726c 640a            Hello World."
	case "strings":
		return "/lib/x86_64-linux-gnu/libc.so.6\n/lib64/ld-linux-x86-64.so.2\nGCC: (Ubuntu) 11.4.0"
	case "ldd":
		return "\tlinux-vdso.so.1 (0x00007fff5e3a1000)\n\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f8b4c200000)"
	case "stty":
		return ""
	case "tty":
		return "/dev/pts/0"
	case "du":
		return "4.0K\t" + s.cwd
	case "sync":
		time.Sleep(100 * time.Millisecond)
		return ""
	case "lsof":
		return fmt.Sprintf("COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\nsshd  %6d root    3u  IPv4  18492      0t0  TCP *:ssh (LISTEN)", s.profile.sshdPID)
	case "lsblk":
		return fmt.Sprintf("NAME        MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT\nnvme0n1     259:0    0  %dG  0 disk\n└─nvme0n1p1 259:1    0  %dG  0 part /", s.profile.diskSize, s.profile.diskSize)
	case "mount":
		return "/dev/nvme0n1p1 on / type ext4 (rw,relatime)\ntmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)"
	case "lscpu":
		return "Architecture:          x86_64\nCPU(s):                4\nModel name:            Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz"
	case "iptables":
		return "Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\nACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh"
	case "ufw":
		return "Status: active\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n80/tcp                     ALLOW       Anywhere"
	case "gpg":
		return "gpg: no valid OpenPGP data found."
	case "ssh-keygen":
		return "Generating public/private rsa key pair.\nEnter file in which to save the key (/root/.ssh/id_rsa): \n/root/.ssh/id_rsa already exists.\nOverwrite (y/n)? "
	case "zip", "unzip", "gzip", "gunzip":
		time.Sleep(s.jitter(200, 800))
		return ""
	case "jobs", "bg", "fg":
		return ""
	case "alias", "unalias":
		return ""
	case "true", ":":
		return ""
	case "false":
		return ""
	case "":
		return ""

	default:
		return fmt.Sprintf("bash: %s: command not found", cmd)
	}
}

// ── Filesystem commands ────────────────────────────────────────────────────────

func (s *fakeShell) cmdLS(variant, args string) string {
	target := s.cwd
	for _, a := range strings.Fields(args) {
		if !strings.HasPrefix(a, "-") {
			if strings.HasPrefix(a, "/") {
				target = a
			} else {
				target = s.cwd + "/" + a
			}
		}
	}
	entries, ok := fakeFS[target]
	if !ok {
		return fmt.Sprintf("ls: cannot access '%s': No such file or directory", target)
	}
	if variant == "ll" || strings.Contains(args, "-l") {
		var lines []string
		lines = append(lines, fmt.Sprintf("total %d", len(entries)*4))
		for _, e := range entries {
			lines = append(lines, fmt.Sprintf("-rw-r--r-- 1 root root %6d Nov  5 12:00 %s", mrand.Intn(65000)+512, e))
		}
		return strings.Join(lines, "\n")
	}
	return strings.Join(entries, "  ")
}

func (s *fakeShell) cmdCD(args string) string {
	target := strings.TrimSpace(args)
	if target == "" || target == "~" || target == "/root" {
		s.cwd = "/root"
		return ""
	}
	if target == ".." {
		idx := strings.LastIndex(s.cwd, "/")
		if idx > 0 {
			s.cwd = s.cwd[:idx]
		} else {
			s.cwd = "/"
		}
		return ""
	}
	if !strings.HasPrefix(target, "/") {
		target = s.cwd + "/" + target
	}
	// Normalize double slashes
	for strings.Contains(target, "//") {
		target = strings.ReplaceAll(target, "//", "/")
	}
	if _, ok := fakeFS[target]; ok {
		s.cwd = target
		return ""
	}
	return fmt.Sprintf("bash: cd: %s: No such file or directory", args)
}

func (s *fakeShell) cmdCat(args string) string {
	targets := strings.Fields(args)
	if len(targets) == 0 {
		return ""
	}
	var results []string
	for _, t := range targets {
		target := t
		if !strings.HasPrefix(target, "/") {
			target = s.cwd + "/" + target
		}
		if honeytokenFiles[target] {
			s.logHoneytoken(target)
			s.poisonClipboard(fakeFiles[target])
			time.Sleep(time.Duration(200+mrand.Intn(400)) * time.Millisecond)
		}
		if content, ok := fakeFiles[target]; ok {
			// Substitute per-session identity so logs look consistent
			content = strings.ReplaceAll(content, "prod-web-01", s.profile.hostname)
			content = strings.ReplaceAll(content, "10.0.1.5", s.profile.ip)
			results = append(results, content)
		} else {
			results = append(results, fmt.Sprintf("cat: %s: No such file or directory", t))
		}
	}
	return strings.Join(results, "\n")
}

func (s *fakeShell) cmdFind(args string) string {
	// Long delay, return empty (like a real find on a big fs)
	time.Sleep(time.Duration(4000+mrand.Intn(5000)) * time.Millisecond)
	return ""
}

func (s *fakeShell) cmdGrep(args string) string {
	time.Sleep(s.jitter(50, 300))
	if strings.Contains(args, "password") || strings.Contains(args, "pass") || strings.Contains(args, "secret") {
		return "/root/credentials.txt:DB_PASS=Sup3rS3cur3P@ss2024!\n/var/www/html/config.php:define('DB_PASS', 'W3bUs3r!Pass2024');"
	}
	return ""
}

// ── Network/download commands ──────────────────────────────────────────────────

func (s *fakeShell) progressBar(filename string, sizeKB int) bool {
	total := sizeKB * 1024
	s.writef("--2024-11-07 09:14:33--  http://target/%s\r\nResolving target... 93.184.216.34\r\n"+
		"Connecting to target|93.184.216.34|:80... connected.\r\nHTTP request sent, awaiting response... 200 OK\r\n"+
		"Length: %d [application/octet-stream]\r\nSaving to: '%s'\r\n\r\n", filename, total, filename)
	steps := 20
	for i := 0; i <= steps; i++ {
		select {
		case b := <-s.rawIn:
			if b == 0x03 {
				s.write("^C\r\n")
				return false
			}
		case <-s.done:
			return false
		default:
		}
		pct := i * 100 / steps
		bar := strings.Repeat("=", i) + ">" + strings.Repeat(" ", steps-i)
		s.writef("\r%s %3d%% [%-22s] %d K/s eta %ds",
			filename, pct, bar, 512+mrand.Intn(2048), (steps-i)*2)
		time.Sleep(time.Duration(150+mrand.Intn(300)) * time.Millisecond)
	}
	s.writef("\r\n\r\n%s              saved [%d/%d]\r\n", filename, total, total)
	return true
}

// progressBarStall shows a progress bar that stalls at stallPct% until Ctrl+C, then returns an error.
func (s *fakeShell) progressBarStall(filename string, totalBytes int, stallPct int) {
	bar20 := func(pct int) string {
		filled := pct / 5
		if filled > 20 {
			filled = 20
		}
		return strings.Repeat("=", filled) + ">" + strings.Repeat(" ", 20-filled)
	}
	for pct := 0; pct <= stallPct; pct += 3 + mrand.Intn(8) {
		if pct > stallPct {
			pct = stallPct
		}
		done := totalBytes * pct / 100
		speed := fmt.Sprintf("%.1fMB/s", 0.8+mrand.Float64()*2.7)
		s.writef("\r%-20s [%s] %3d%%  %dK  %s  ", filename, bar20(pct), pct, done/1024, speed)
		time.Sleep(time.Duration(300+mrand.Intn(600)) * time.Millisecond)
		select {
		case b := <-s.rawIn:
			if b == 0x03 {
				s.write("\r\nERROR: Network timeout after 30s. Partial download saved.\r\n")
				return
			}
		case <-s.done:
			return
		default:
		}
	}
	// Stall forever at stallPct%
	for {
		select {
		case b := <-s.rawIn:
			if b == 0x03 {
				s.write("\r\nERROR: Network timeout after 30s. Partial download saved.\r\n")
				return
			}
		case <-s.done:
			return
		case <-time.After(5 * time.Second):
			// keep stalling
		}
	}
}

func (s *fakeShell) cmdWget(args string) {
	fields := strings.Fields(args)
	url := ""
	for _, f := range fields {
		if strings.HasPrefix(f, "http") || strings.HasPrefix(f, "ftp") {
			url = f
			break
		}
		if !strings.HasPrefix(f, "-") {
			url = f
		}
	}
	filename := url
	if idx := strings.LastIndex(url, "/"); idx >= 0 {
		filename = url[idx+1:]
	}
	if filename == "" {
		filename = "index.html"
	}
	s.slog.log("WGET: %s", url)

	host := "example.com"
	if parts := strings.SplitN(url, "/", 4); len(parts) >= 3 {
		host = parts[2]
	}
	total := 500000 + mrand.Intn(4500000)
	s.writef("--%s--  %s\r\n", time.Now().Format("2006-01-02 15:04:05"), url)
	time.Sleep(500 * time.Millisecond)
	s.writef("Resolving %s (%s)... ", host, host)
	time.Sleep(1200 * time.Millisecond)
	s.writef("1.2.3.4\r\nConnecting to %s|1.2.3.4|:80... ", host)
	time.Sleep(1500 * time.Millisecond)
	s.writef("connected.\r\nHTTP request sent, awaiting response... 200 OK\r\n")
	time.Sleep(400 * time.Millisecond)
	s.writef("Length: %d (%dM) [application/octet-stream]\r\nSaving to: '%s'\r\n\r\n", total, total/1024/1024, filename)
	// Stall at 73%
	s.progressBarStall(filename, total, 73)
}

func (s *fakeShell) cmdCurl(args string) string {
	s.slog.log("CURL: %s", args)
	if strings.Contains(args, "-s") || strings.Contains(args, "--silent") {
		time.Sleep(s.jitter(300, 1500))
		return ""
	}
	url := ""
	for _, f := range strings.Fields(args) {
		if strings.HasPrefix(f, "http") {
			url = f
			break
		}
	}
	host := "example.com"
	if parts := strings.SplitN(url, "/", 4); len(parts) >= 3 {
		host = parts[2]
	}
	_ = host
	total := 200000 + mrand.Intn(1800000)
	s.write("  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\r\n")
	s.write("                                 Dload  Upload   Total   Spent    Left  Speed\r\n")
	time.Sleep(800 * time.Millisecond)
	for pct := 0; pct < 74; pct += 5 + mrand.Intn(12) {
		done := total * pct / 100
		speed := 50 + mrand.Intn(250)
		left := (total - done) / (speed * 1000)
		s.writef("\r%3d  %5d  %3d  %5d    0     0   %dk      0  0:00:%02d --:--:--  %dk",
			pct, total/1024, pct, done/1024, speed, left, speed)
		time.Sleep(time.Duration(400+mrand.Intn(600)) * time.Millisecond)
		select {
		case b := <-s.rawIn:
			if b == 0x03 {
				s.write("\r\n^C\r\n")
				return ""
			}
		case <-s.done:
			return ""
		default:
		}
	}
	time.Sleep(4 * time.Second)
	return "\r\ncurl: (28) Operation timed out after 30001 milliseconds with 0 bytes received"
}

func (s *fakeShell) cmdDD(args string) {
	s.slog.log("DD: %s", args)
	bs := 1024 * 1024
	blocks := 0
	for {
		select {
		case b := <-s.rawIn:
			if b == 0x03 {
				s.write("\r\n^C\r\n")
				total := int64(blocks) * int64(bs)
				s.writef("%d+0 records in\r\n%d+0 records out\r\n%d bytes (%.1f GB) copied\r\n",
					blocks, blocks, total, float64(total)/1e9)
				return
			}
		case <-s.done:
			return
		default:
		}
		blocks += 5 + mrand.Intn(25)
		total := int64(blocks) * int64(bs)
		speed := 80.0 + mrand.Float64()*170.0
		s.writef("\r%d+0 records in\r\n%d+0 records out\r\n%d bytes (%.1f GB, %.1f GiB) copied, %.1f s, %.1f MB/s",
			blocks, blocks, total, float64(total)/1e9, float64(total)/1073741824, float64(blocks)*0.9, speed)
		time.Sleep(time.Duration(800+mrand.Intn(700)) * time.Millisecond)
	}
}

// cmdRsync is now handled inline in dispatch with "connection unexpectedly closed"

// ── SSH pivot ─────────────────────────────────────────────────────────────────

type pivotShell struct {
	s    *fakeShell
	host internalHost
	cwd  string
}

func (s *fakeShell) cmdSSH(args string) {
	fields := strings.Fields(args)
	target := ""
	for _, f := range fields {
		if !strings.HasPrefix(f, "-") && !strings.Contains(f, "@") {
			target = f
			break
		}
		if strings.Contains(f, "@") {
			parts := strings.SplitN(f, "@", 2)
			target = parts[1]
			break
		}
	}
	// Also check for user@host format
	for _, f := range fields {
		if strings.Contains(f, "@") {
			target = strings.SplitN(f, "@", 2)[1]
			break
		}
	}

	host, ok := internalHosts[target]
	if !ok {
		time.Sleep(s.jitter(2000, 5000))
		s.writef("ssh: connect to host %s port 22: Connection timed out\r\n", target)
		return
	}

	s.slog.log("SSH_PIVOT: %s → %s (%s)", s.ip, target, host.hostname)
	logEvent("SSH_PIVOT", s.ip, fmt.Sprintf("→ %s (%s)", target, host.hostname))

	s.writef("Warning: Permanently added '%s' (RSA) to the list of known hosts.\r\n", target)
	time.Sleep(time.Duration(800+mrand.Intn(1200)) * time.Millisecond)
	if host.banner != "" {
		s.writef("Linux %s %s\r\n\r\n", host.hostname, host.banner)
	}
	if host.motd != "" {
		s.writef("  ** %s **\r\n\r\n", host.motd)
	}

	p := &pivotShell{s: s, host: host, cwd: host.cwd}
	p.run()
}

func (p *pivotShell) prompt() string {
	return fmt.Sprintf("root@%s:%s# ", p.host.hostname, p.cwd)
}

func (p *pivotShell) run() {
	p.s.write(p.prompt())
	var buf []byte
	var escBuf []byte
	for {
		b, ok := p.s.readRaw()
		if !ok {
			return
		}
		if len(escBuf) > 0 {
			escBuf = append(escBuf, b)
			if len(escBuf) >= 3 || (len(escBuf) == 2 && b >= 'A' && b <= 'Z') {
				escBuf = escBuf[:0]
			}
			continue
		}
		if b == 0x1b {
			escBuf = append(escBuf[:0], b)
			continue
		}
		switch {
		case b == '\r' || b == '\n':
			p.s.write("\r\n")
			line := strings.TrimSpace(string(buf))
			buf = buf[:0]
			if line != "" {
				p.s.slog.log("PIVOT(%s) CMD: %s", p.host.hostname, line)
				out, quit := p.handle(line)
				if out != "" {
					p.s.write(strings.ReplaceAll(out, "\n", "\r\n") + "\r\n")
				}
				if quit {
					p.s.writef("Connection to %s closed.\r\n", p.host.hostname)
					return
				}
			}
			p.s.write(p.prompt())
		case b == 0x7f || b == 0x08:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				p.s.write("\b \b")
			}
		case b == 0x03:
			buf = buf[:0]
			p.s.write("^C\r\n" + p.prompt())
		case b == 0x04:
			p.s.writef("\r\nConnection to %s closed.\r\n", p.host.hostname)
			return
		case b >= 0x20:
			buf = append(buf, b)
			p.s.write(string([]byte{b}))
		}
	}
}

func (p *pivotShell) handle(line string) (string, bool) {
	parts := strings.SplitN(line, " ", 2)
	cmd := parts[0]
	args := ""
	if len(parts) > 1 {
		args = strings.TrimSpace(parts[1])
	}
	time.Sleep(time.Duration(30+mrand.Intn(150)) * time.Millisecond)
	switch cmd {
	case "exit", "logout", "quit":
		return "", true
	case "pwd":
		return p.cwd, false
	case "ls":
		if entries, ok := p.host.files[p.cwd]; ok {
			return strings.Join(entries, "  "), false
		}
		return "", false
	case "cd":
		t := strings.TrimSpace(args)
		if t == "" || t == "~" {
			p.cwd = p.host.cwd
		} else {
			if !strings.HasPrefix(t, "/") {
				t = p.cwd + "/" + t
			}
			if _, ok := p.host.files[t]; ok {
				p.cwd = t
			}
		}
		return "", false
	case "cat":
		target := strings.TrimSpace(args)
		if !strings.HasPrefix(target, "/") {
			target = p.cwd + "/" + target
		}
		if content, ok := p.host.sensitive[target]; ok {
			p.s.logHoneytoken(fmt.Sprintf("pivot:%s:%s", p.host.hostname, target))
			time.Sleep(time.Duration(200+mrand.Intn(400)) * time.Millisecond)
			return content, false
		}
		return fmt.Sprintf("cat: %s: No such file or directory", args), false
	case "id":
		return "uid=0(root) gid=0(root) groups=0(root)", false
	case "whoami":
		return "root", false
	case "hostname":
		return p.host.hostname, false
	default:
		return fmt.Sprintf("bash: %s: command not found", cmd), false
	}
}

// ── Database / Container commands ─────────────────────────────────────────────

func (s *fakeShell) cmdMySQL(args string) {
	s.slog.log("MYSQL_LAUNCH: %s", args)
	db := ""
	fields := strings.Fields(args)
	for i, f := range fields {
		if f == "-D" && i+1 < len(fields) {
			db = fields[i+1]
		}
		if strings.HasPrefix(f, "--database=") {
			db = strings.TrimPrefix(f, "--database=")
		}
	}
	// Last non-flag arg is the db name
	for _, f := range fields {
		if !strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "-p") &&
			f != "root" && !strings.Contains(f, "=") {
			db = f
		}
	}
	newMySQLShell(s, db).run()
}

func (s *fakeShell) cmdDocker(args string) string {
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return "Usage:  docker [OPTIONS] COMMAND"
	}
	sub := parts[0]
	rest := ""
	if len(parts) > 1 {
		rest = strings.Join(parts[1:], " ")
	}

	switch sub {
	case "ps":
		return cmdResponses["docker ps"]
	case "images":
		return cmdResponses["docker images"]
	case "exec":
		// parse: docker exec [-it] <name> <cmd>
		name := ""
		for _, f := range strings.Fields(rest) {
			if !strings.HasPrefix(f, "-") {
				name = f
				break
			}
		}
		if name != "" {
			s.slog.log("DOCKER_EXEC: %s", rest)
			ds := newDockerShell(s, name)
			ds.run()
		}
		return ""
	case "inspect":
		return `[{"Id":"a3f8c2d1e4b5","State":{"Status":"running"},"NetworkSettings":{"IPAddress":"172.17.0.2"}}]`
	case "logs":
		time.Sleep(s.jitter(200, 600))
		return "[2024-11-07 09:14:01] INFO: Starting application\n[2024-11-07 09:14:02] INFO: Connected to database"
	case "run", "start", "stop", "restart", "rm", "rmi":
		time.Sleep(s.jitter(500, 2000))
		return ""
	case "pull":
		s.progressBar("image", 64*1024)
		return ""
	case "build":
		time.Sleep(s.jitter(3000, 8000))
		return "Successfully built a1b2c3d4e5f6"
	case "network":
		return "NETWORK ID     NAME      DRIVER    SCOPE\na1b2c3d4e5f6   bridge    bridge    local\nb7c8d9e0f1a2   host      host      local"
	case "volume":
		return "DRIVER    VOLUME NAME\nlocal     webapp_data\nlocal     mysql_data"
	default:
		return fmt.Sprintf("docker: '%s' is not a docker command.", sub)
	}
}

// ── Offensive tool simulations ─────────────────────────────────────────────────

func (s *fakeShell) cmdJohn(args string) {
	s.slog.log("JOHN: %s", args)
	s.writef("Using default input encoding: UTF-8\r\n")
	s.writef("Loaded 3 password hashes with 3 different salts (sha512crypt [SHA512 256/256 AVX2 4x])\r\n")
	s.writef("Cost 1 (iteration count) is 656000 for all loaded hashes\r\n")
	s.writef("Will run 4 OpenMP threads\r\n")
	s.writef("Press 'q' or Ctrl-C to abort, almost any other key for status\r\n\r\n")

	wordlists := []string{"password", "123456", "admin", "root", "qwerty", "letmein", "monkey"}
	crackDur := time.Duration(30+mrand.Intn(30)) * time.Second
	start := time.Now()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	tried := 0
	for {
		select {
		case b := <-s.rawIn:
			if b == 0x03 || b == 'q' {
				s.writef("\r\nSession aborted\r\n%d password hashes cracked, 0 left\r\n", 0)
				return
			}
		case <-s.done:
			return
		case <-ticker.C:
			tried += 50000 + mrand.Intn(30000)
			word := wordlists[mrand.Intn(len(wordlists))]
			s.writef("%d p/s trying: %s%d\r\n", tried/int(time.Since(start).Seconds()+1), word, mrand.Intn(9999))
		default:
		}
		if time.Since(start) >= crackDur {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	s.writef("\r\nh0n3yp0t_g0tcha  (root)\r\n")
	s.writef("Session completed. Use --show to show cracked passwords.\r\n")
	s.writef("3 password hashes cracked, 0 left\r\n")
}

func (s *fakeShell) cmdHashcat(args string) {
	s.slog.log("HASHCAT: %s", args)
	s.writef("hashcat (v6.2.6) starting...\r\n\r\n")
	s.writef("OpenCL API (OpenCL 3.0 PoCL): ...\r\n")
	s.writef("* Device #1: pthread-Intel Xeon Platinum 8259CL, 3982/8028 MB (1024 MB allocatable), 4MCU\r\n\r\n")
	s.writef("Dictionary cache built:\r\n* Filename..: /usr/share/wordlists/rockyou.txt\r\n* Passwords.: 14344384\r\n\r\n")

	crackDur := time.Duration(20+mrand.Intn(20)) * time.Second
	start := time.Now()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case b := <-s.rawIn:
			if b == 0x03 || b == 'q' {
				s.write("\r\nAborted\r\n")
				return
			}
		case <-s.done:
			return
		case <-ticker.C:
			speed := 8000 + mrand.Intn(4000)
			elapsed := time.Since(start)
			eta := crackDur - elapsed
			s.writef("\rSpeed.#1.: %d H/s (%.2fms) / ETA: %02d:%02d:%02d",
				speed, float64(mrand.Intn(100))/10.0,
				int(eta.Hours()), int(eta.Minutes())%60, int(eta.Seconds())%60)
		default:
		}
		if time.Since(start) >= crackDur {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	s.writef("\r\n\r\n$6$rounds=656000$rEfXkHmT$FAKEHASH:h0n3yp0t_g0tcha\r\n\r\n")
	s.writef("Session..........: hashcat\r\nStatus...........: Cracked\r\n")
	s.writef("Recovered........: 1/3 (33.33%%) Digests\r\n")
}

func (s *fakeShell) cmdStrace(variant, args string) {
	s.slog.log("STRACE: %s %s", variant, args)
	pid := 1000 + mrand.Intn(8999)
	target := "process"
	if fields := strings.Fields(args); len(fields) > 0 {
		target = fields[len(fields)-1]
	}
	s.writef("strace: Process %d attached\r\n", pid)
	syscalls := []string{
		"read(%d, \"\", 4096) = 0",
		"write(1, \"...\", %d) = %d",
		"epoll_wait(%d, [], 1, %d) = 0",
		"futex(0x%08x, FUTEX_WAIT_PRIVATE, 0, NULL) = -1 EINTR (Interrupted system call)",
		"nanosleep({tv_sec=0, tv_nsec=%d000000}, NULL) = 0",
		"recvfrom(%d, NULL, 0, 0, NULL, NULL) = 0",
		"sendto(%d, \"\\x00\\x01\", 2, 0, NULL, 0) = 2",
		"mmap(NULL, %d, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x%08x",
		"openat(AT_FDCWD, \"/proc/self/maps\", O_RDONLY) = %d",
		"close(%d) = 0",
	}
	_ = target
	n := 20 + mrand.Intn(20)
	for i := 0; i < n; i++ {
		select {
		case b := <-s.rawIn:
			if b == 0x03 {
				s.writef("\r\nstrace: Process %d detached\r\n", pid)
				return
			}
		case <-s.done:
			return
		default:
		}
		tmpl := syscalls[mrand.Intn(len(syscalls))]
		line := fmt.Sprintf(tmpl,
			3+mrand.Intn(17), 10+mrand.Intn(190), 10+mrand.Intn(190),
			5+mrand.Intn(10), 100+mrand.Intn(4900), mrand.Intn(1<<31),
			mrand.Intn(999), 3+mrand.Intn(17), 3+mrand.Intn(17),
			4096+mrand.Intn(61440), mrand.Intn(1<<31), 3+mrand.Intn(17), 3+mrand.Intn(17))
		s.writef("%s\r\n", line)
		time.Sleep(time.Duration(50+mrand.Intn(250)) * time.Millisecond)
	}
	s.writef("strace: Process %d detached\r\n", pid)
}

// ── Cloud / Crypto ─────────────────────────────────────────────────────────────

func (s *fakeShell) cmdAWS(args string) string {
	s.slog.log("AWS: %s", args)
	time.Sleep(s.jitter(500, 2000))
	switch {
	case strings.HasPrefix(args, "s3 ls"):
		return "2024-01-15 09:23:11 company-prod-backups\n2024-03-22 14:05:44 company-assets-cdn\n2024-06-01 11:30:00 company-logs-archive"
	case strings.HasPrefix(args, "s3 cp") || strings.HasPrefix(args, "s3 sync"):
		return "upload: ./file to s3://company-prod-backups/file\nCompleted 1.0 MiB/~1.0 MiB"
	case strings.HasPrefix(args, "ec2 describe"):
		return fmt.Sprintf(`{"Reservations": [{"Instances": [{"InstanceId": "i-0a1b2c3d4e5f67890","InstanceType":"t3.medium","State":{"Name":"running"},"PrivateIpAddress":"%s"}]}]}`, s.profile.ip)
	case strings.HasPrefix(args, "iam"):
		return `{"User": {"UserName": "root-admin","Arn": "arn:aws:iam::123456789012:user/root-admin"}}`
	case strings.HasPrefix(args, "sts get-caller"):
		return `{"UserId": "AIDAI...","Account": "123456789012","Arn": "arn:aws:iam::123456789012:user/root-admin"}`
	case strings.HasPrefix(args, "secretsmanager") || strings.HasPrefix(args, "ssm"):
		s.logHoneytoken("aws:secrets")
		return `{"Name": "prod/db/password","SecretString": "{\"password\":\"Sup3rS3cur3P@ss2024!\"}"}`
	case strings.HasPrefix(args, "lambda"):
		return `{"Functions": [{"FunctionName": "api-handler","Runtime": "python3.9"}]}`
	default:
		return "An error occurred (AuthFailure): AWS was not able to validate the provided access credentials"
	}
}

func (s *fakeShell) cmdBase64(args string) string {
	if strings.Contains(args, "-d") || strings.Contains(args, "--decode") {
		// Log the payload for threat intel, but return an error
		payload := ""
		for _, f := range strings.Fields(args) {
			if !strings.HasPrefix(f, "-") {
				payload = f
				break
			}
		}
		if payload != "" {
			decoded, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				decoded, _ = base64.RawStdEncoding.DecodeString(payload)
			}
			if len(decoded) > 0 {
				s.slog.log("BASE64_PAYLOAD: %s → %s", payload, string(decoded))
				logEvent("PAYLOAD", s.ip, fmt.Sprintf("base64: %s", string(decoded)))
			}
		}
		s.jitter(100, 300)
		return "base64: invalid input"
	}
	return base64.StdEncoding.EncodeToString([]byte(args))
}

func (s *fakeShell) cmdOpenssl(args string) string {
	time.Sleep(s.jitter(200, 800))
	if strings.Contains(args, "passwd") {
		return "$6$salt$FakeHashedPasswordOutput"
	}
	if strings.Contains(args, "rand") {
		return fmt.Sprintf("%x", mrand.Int63())
	}
	if strings.Contains(args, "s_client") || strings.Contains(args, "connect") {
		return "CONNECTED(00000003)\ndepth=2 C = US, O = Internet Security Research Group, CN = ISRG Root X1\n---\nSSL handshake has read 5243 bytes"
	}
	return "openssl: Error: '" + args + "' is an invalid command."
}

// ── Code execution / compile ───────────────────────────────────────────────────

func (s *fakeShell) cmdPython(args string) {
	if strings.Contains(args, "-c") || strings.Contains(args, "-m") {
		s.slog.log("PYTHON_EXEC: %s", args)
		time.Sleep(s.jitter(200, 600))
		return
	}
	// Interactive REPL
	s.writef("Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\r\n")
	s.writef("Type \"help\", \"copyright\", \"credits\" or \"license\" for more information.\r\n")
	s.write(">>> ")
	var buf []byte
	for {
		b, ok := s.readRaw()
		if !ok {
			return
		}
		switch {
		case b == '\r' || b == '\n':
			s.write("\r\n")
			line := strings.TrimSpace(string(buf))
			buf = buf[:0]
			if line == "exit()" || line == "quit()" || line == "" && false {
				return
			}
			if line == "" {
				s.write(">>> ")
				continue
			}
			s.slog.log("PYTHON_REPL: %s", line)
			// Swallow any os.system / subprocess
			if strings.Contains(line, "os.system") || strings.Contains(line, "subprocess") ||
				strings.Contains(line, "__import__") || strings.Contains(line, "exec(") {
				s.write("0\r\n>>> ")
				continue
			}
			if strings.HasPrefix(line, "print(") {
				inner := strings.TrimPrefix(line, "print(")
				inner = strings.TrimSuffix(inner, ")")
				inner = strings.Trim(inner, `"'`)
				s.writef("%s\r\n>>> ", inner)
				continue
			}
			s.write(">>> ")
		case b == 0x7f || b == 0x08:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				s.write("\b \b")
			}
		case b == 0x03:
			buf = buf[:0]
			s.write("\r\nKeyboardInterrupt\r\n>>> ")
		case b == 0x04:
			s.write("\r\n")
			return
		case b >= 0x20:
			buf = append(buf, b)
			s.write(string([]byte{b}))
		}
	}
}

func (s *fakeShell) cmdGCC(cmd, args string) string {
	src := args
	if fields := strings.Fields(args); len(fields) > 0 {
		src = fields[len(fields)-1]
	}
	s.writef("gcc: %s\r\n", src)
	time.Sleep(s.jitter(2000, 5000))
	errors := []string{
		"undefined reference to 'main'",
		"implicit declaration of function 'execve'",
		"segmentation fault during compilation",
		"undefined reference to '__stack_chk_fail'",
		"relocation truncated to fit: R_X86_64_PC32",
	}
	for i := 0; i < 3+mrand.Intn(6); i++ {
		line := 10 + mrand.Intn(290)
		s.writef("%s:%d: error: %s\r\n", src, line, errors[mrand.Intn(len(errors))])
		time.Sleep(200 * time.Millisecond)
	}
	return "collect2: error: ld returned 1 exit status"
}

func (s *fakeShell) cmdGo(args string) string {
	time.Sleep(s.jitter(500, 2000))
	switch strings.SplitN(args, " ", 2)[0] {
	case "build":
		return ""
	case "run":
		return ""
	case "get":
		return "go: downloading module..."
	case "version":
		return "go version go1.22.1 linux/amd64"
	default:
		return "Go is a tool for managing Go source code."
	}
}

// ── Filesystem destruction ─────────────────────────────────────────────────────

func (s *fakeShell) cmdRM(args string) string {
	isRecursive := strings.Contains(args, "-r") || strings.Contains(args, "-R")
	isForce := strings.Contains(args, "-f")
	isNuke := false
	if isRecursive {
		for _, f := range strings.Fields(args) {
			if f == "/" || f == "/*" || strings.HasPrefix(f, "/../") {
				isNuke = true
				break
			}
		}
		if strings.Contains(args, "/ ") || strings.HasSuffix(args, "/") {
			isNuke = true
		}
	}
	_ = isForce

	if !isNuke {
		time.Sleep(s.jitter(50, 200))
		return ""
	}

	s.slog.log("RM_NUKE: %s", args)
	logEvent("RM_NUKE", s.ip, args)

	for _, path := range rmrfPaths {
		select {
		case b := <-s.rawIn:
			if b == 0x03 {
				s.write("^C\r\n")
				return "rm: cannot remove '/': Device or resource busy"
			}
		case <-s.done:
			return ""
		default:
		}
		s.writef("removed '%s'\r\n", path)
		time.Sleep(time.Duration(80+mrand.Intn(250)) * time.Millisecond)
	}

	// Kernel panic sequence
	time.Sleep(600 * time.Millisecond)
	s.write("\r\n\r\n[  695.431827] EXT4-fs error (device nvme0n1p1): ext4_validate_block_bitmap:376: comm kworker: bg allocated block not in buddy cache\r\n")
	s.write("[  695.803244] EXT4-fs (nvme0n1p1): Delayed block allocation failed for inode 13 at logical offset 0 with max blocks 8 with error -5\r\n")
	s.write("[  695.803247] EXT4-fs (nvme0n1p1): This should not happen!! Data will be lost\r\n\r\n")
	time.Sleep(400 * time.Millisecond)
	s.write("[  696.012345] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)\r\n")
	s.write(fmt.Sprintf("[  696.012399] CPU: 0 PID: 1 Comm: swapper/0 Not tainted %s\r\n", s.profile.kernelShort()))
	s.write("[  696.012401] Hardware name: Amazon EC2 t3.medium\r\n")
	s.write("[  696.012402] Call Trace:\r\n[  696.012410]  panic+0x10d/0x2d4\r\n")
	s.write("[  696.012417]  mount_root+0x1a3/0x1b8\r\n[  696.012425]  kernel_init_freeable+0x22f/0x23e\r\n")
	s.write(fmt.Sprintf("[  696.012436]  ret_from_fork+0x22/0x30\r\n\r\nConnection to %s closed.\r\n", s.profile.hostname))
	time.Sleep(1500 * time.Millisecond)

	// "Reboot" — shell resets to pristine state, maximum confusion
	s.write(fmt.Sprintf("\r\nBroadcast message from root@%s:\r\nThe system will reboot NOW!\r\n\r\n", s.profile.hostname))
	time.Sleep(4 * time.Second)
	motd := fmt.Sprintf("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux %s x86_64)\r\n\r\n", s.profile.kernelShort()) +
		" * Documentation:  https://help.ubuntu.com\r\n\r\n" +
		"Last login: " + time.Now().Add(-2*time.Hour).Format("Mon Jan _2 15:04:05 2006") + " from " + s.profile.lastIP + "\r\n"
	s.write(motd)
	// Reset state
	s.cwd = "/root"
	s.cmdCount = 0
	return ""
}

func (s *fakeShell) cmdTar(args string) string {
	isExtract := strings.Contains(args, "-x") || strings.Contains(args, "xz") ||
		strings.Contains(args, "xf") || strings.Contains(args, " x ")
	archive := "archive.tar.gz"
	for _, f := range strings.Fields(args) {
		if !strings.HasPrefix(f, "-") && (strings.HasSuffix(f, ".gz") || strings.HasSuffix(f, ".tar") || strings.HasSuffix(f, ".tgz")) {
			archive = f
			break
		}
	}

	if !isExtract {
		time.Sleep(s.jitter(500, 2000))
		return ""
	}

	if strings.Contains(archive, "server_keys") {
		s.logHoneytoken("/root/backup/server_keys.tar.gz")
	}

	fakeContents := []string{
		"./ssh_host_rsa_key", "./ssh_host_ed25519_key",
		"./id_rsa", "./id_rsa.pub", "./authorized_keys",
		"./config", "./known_hosts", "./deploy.key",
	}
	s.writef("%s:\r\n", archive)
	for _, f := range fakeContents {
		time.Sleep(time.Duration(100+mrand.Intn(400)) * time.Millisecond)
		s.writef("  %s\r\n", f)
	}
	time.Sleep(800 * time.Millisecond)
	return "gzip: stdin: invalid compressed data--crc error\r\ntar: Child returned status 1\r\ntar: Error is not recoverable: exiting now"
}

// ── Git ────────────────────────────────────────────────────────────────────────

func (s *fakeShell) cmdGit(args string) string {
	sub := strings.SplitN(args, " ", 2)[0]
	switch sub {
	case "log":
		return cmdResponses["git log"]
	case "status":
		return cmdResponses["git status"]
	case "branch":
		if strings.Contains(args, "-v") {
			return "* main                   a3f8c2d fix: rotate encryption key\n  staging                 b7e9d3a feat: add new endpoint\n  backup/pre-migration    c4a1b2e chore: backup before migration"
		}
		return cmdResponses["git branch"]
	case "remote":
		return cmdResponses["git remote -v"]
	case "show":
		return "commit a3f8c2d1e4b5f6a7b8c9d0e1f2a3b4c5d6e7f8a9\n" +
			"Author: deploy <deploy@company.com>\nDate:   Wed Nov  6 23:44:01 2024\n\n" +
			"    fix: rotate encryption key for payment processor\n\n" +
			"+STRIPE_SECRET_KEY=sk_live_xF3kH0n3yp0tN0tR3al9z\n-STRIPE_SECRET_KEY=sk_live_xOldH0n3yK3yN0tR3al7y"
	case "diff":
		return ""
	case "stash":
		return "Saved working directory and index state WIP on main: a3f8c2d fix: rotate encryption key"
	case "clone":
		s.progressBar("repo", 2048)
		return ""
	case "pull":
		time.Sleep(s.jitter(500, 2000))
		return "Already up to date."
	case "push":
		time.Sleep(s.jitter(1000, 3000))
		return "Everything up-to-date"
	case "fetch":
		time.Sleep(s.jitter(300, 1000))
		return ""
	case "checkout", "switch":
		return ""
	case "add", "commit":
		return ""
	case "config":
		return ""
	default:
		return fmt.Sprintf("git: '%s' is not a git command.", sub)
	}
}

// ── System management ──────────────────────────────────────────────────────────

func (s *fakeShell) cmdSystemctl(args string) string {
	time.Sleep(s.jitter(500, 1500))
	return "System has not been booted with systemd as init system (PID 1). Can't operate.\nFailed to connect to bus: Host is down"
}

func (s *fakeShell) cmdApt(args string) string {
	time.Sleep(s.jitter(1000, 3000))
	return "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\nE: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?"
}

func (s *fakeShell) cmdPip(args string) string {
	time.Sleep(s.jitter(1000, 3000))
	return "ERROR: Could not install packages due to an OSError: [Errno 13] Permission denied: '/usr/local/lib/python3.10'\nConsider using the `--user` option or check the permissions."
}

func (s *fakeShell) cmdKubectl(args string) string {
	time.Sleep(s.jitter(200, 800))
	if strings.HasPrefix(args, "get") {
		return "NAME                    READY   STATUS    RESTARTS   AGE\nwebapp-6d4f9b7c4-x8k2p  1/1     Running   0          45d"
	}
	if strings.HasPrefix(args, "describe") {
		return "Name:         webapp-6d4f9b7c4-x8k2p\nNamespace:    default\nStatus:       Running\nIP:           10.244.0.5"
	}
	return fmt.Sprintf("Error from server (NotFound): %s not found", args)
}

func (s *fakeShell) cmdPing(args string) string {
	fields := strings.Fields(args)
	host := "localhost"
	for _, f := range fields {
		if !strings.HasPrefix(f, "-") {
			host = f
			break
		}
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("PING %s (10.0.1.1) 56(84) bytes of data.", host))
	for i := 0; i < 4; i++ {
		select {
		case b := <-s.rawIn:
			if b == 0x03 {
				s.write("^C\r\n")
				s.writef("--- %s ping statistics ---\r\n%d packets transmitted, %d received, 0%% packet loss\r\n", host, i, i)
				return ""
			}
		case <-s.done:
			return ""
		default:
		}
		rtt := 0.5 + mrand.Float64()*2.0
		lines = append(lines, fmt.Sprintf("64 bytes from %s: icmp_seq=%d ttl=64 time=%.3f ms", host, i+1, rtt))
		time.Sleep(time.Second)
	}
	lines = append(lines, fmt.Sprintf("--- %s ping statistics ---", host))
	lines = append(lines, "4 packets transmitted, 4 received, 0% packet loss, time 3003ms")
	return strings.Join(lines, "\n")
}

func (s *fakeShell) cmdNmap(args string) string {
	s.slog.log("NMAP: %s", args)
	time.Sleep(s.jitter(3000, 8000))
	return "Starting Nmap 7.94 ( https://nmap.org )\n" +
		"Nmap scan report for 10.0.1.0/24\n" +
		"Host is up (0.00031s latency).\n\n" +
		"PORT     STATE SERVICE\n" +
		"22/tcp   open  ssh\n" +
		"80/tcp   open  http\n" +
		"3306/tcp open  mysql\n\n" +
		"Nmap done: 1 IP address (1 host up) scanned in 5.32 seconds"
}

func (s *fakeShell) cmdDF(args string) string {
	// Strip path argument — we always show the same filesystem.
	// Normalise flags: pick the most specific recognised key.
	flags := ""
	for _, f := range strings.Fields(args) {
		if strings.HasPrefix(f, "-") {
			flags += strings.TrimPrefix(f, "-")
		}
	}
	var key string
	switch {
	case strings.ContainsAny(flags, "h") && strings.ContainsAny(flags, "a"):
		key = "df -ha"
	case strings.ContainsAny(flags, "h"):
		key = "df -h"
	case strings.ContainsAny(flags, "a"):
		key = "df -a"
	default:
		key = "df"
	}
	r, _ := s.profileResponse(key)
	return r
}

func (s *fakeShell) cmdPS(args string) string {
	// Normalise: strip dashes, sort chars so "aux" == "uax", etc.
	stripped := strings.ReplaceAll(args, "-", "")
	has := func(ch byte) bool { return strings.IndexByte(stripped, ch) >= 0 }

	var key string
	switch {
	case has('f') && has('e'):
		key = "ps -ef"
	case has('f') && has('u'):
		key = "ps -ef"
	case has('a') && has('u') && has('x'):
		key = "ps aux"
	case has('e') || has('A'):
		key = "ps -e"
	case has('a') && has('u'):
		key = "ps au"
	case has('a'):
		key = "ps a"
	case has('u'):
		key = "ps u"
	case stripped == "":
		key = "ps"
	default:
		key = "ps aux" // safe fallback for unknown flag combos
	}
	r, _ := s.profileResponse(key)
	return r
}

func (s *fakeShell) cmdIP(args string) string {
	ipA, _ := s.profileResponse("ip a")
	ipR, _ := s.profileResponse("ip route")
	switch strings.TrimSpace(args) {
	case "a", "addr", "address":
		return ipA
	case "r", "route":
		return ipR
	case "link":
		return "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 state UP"
	case "neigh":
		return cmdResponses["arp -n"]
	default:
		return ipA
	}
}

func (s *fakeShell) cmdScreen() {
	time.Sleep(time.Duration(500+mrand.Intn(1000)) * time.Millisecond)
	s.write("\r\n\x1b[?1049h") // enter alternate screen buffer
	time.Sleep(300 * time.Millisecond)
	s.writef("\r\n[screen 0: bash]\r\n%s", s.prompt())
	// Wait 8-20s (or until Ctrl+C)
	timeout := time.Duration(8000+mrand.Intn(12000)) * time.Millisecond
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case b := <-s.rawIn:
			if b == 0x03 || b == 0x04 {
				goto crash
			}
		case <-timer.C:
			goto crash
		case <-s.done:
			return
		}
	}
crash:
	s.write("\r\n\x1b[?1049l") // restore normal screen
	s.write("\r\n[screen is terminating]\r\nSegmentation fault (core dumped)\r\n")
}

// ── Background goroutines ──────────────────────────────────────────────────────

func (s *fakeShell) rivalAttacker() {
	// These look like real Linux wall(1) broadcasts and system messages.
	// They create urgency by suggesting other sessions, monitoring, or competing attackers.
	type broadcast struct {
		from string
		body string
	}
	h := s.profile.hostname
	ip := s.profile.ip
	msgs := []broadcast{
		// Monitoring / cron jobs — look totally legitimate
		{"cron@" + h, fmt.Sprintf("/opt/monitoring/check.py: anomalous outbound connection from pts/0 (%s → unknown)", ip)},
		{"backup@" + h, "Nightly backup started: /root/important → s3://company-prod-backups/" + time.Now().Format("2006-01-02") + "/"},
		{"ossec@" + h, fmt.Sprintf("OSSEC HIDS: Active response executed: host-deny on %s", ip)},
		{"logwatch@" + h, "Unusual activity in /var/log/auth.log: 1 new root session since last report"},
		// Suggest another privileged session
		{"root@" + h, "pts/1: session opened for user root by (uid=0)"},
		{"sshd@" + h, "Accepted publickey for root from 203.0.113.42 port 51234 ssh2: RSA SHA256:..."},
		// Actual competing attacker — but plausible, not cartoonish
		{"root@" + h, "pts/2: rsync -avz /root/backup/ user@185.220.101.45:/tmp/dump/ (pid 14823)"},
		{"root@" + h, "pts/1: aws s3 cp /root/important/aws_credentials.json s3://185.220.101.45-drop/"},
	}
	idx := mrand.Intn(len(msgs)) // start at random position so it's not deterministic
	for {
		delay := time.Duration(rivalMinDelay) + time.Duration(mrand.Float64()*float64(rivalMaxDelay-rivalMinDelay))
		select {
		case <-time.After(delay):
		case <-s.done:
			return
		}
		m := msgs[idx%len(msgs)]
		ts := time.Now().Format("Mon Jan _2 15:04:05 2006")
		// Standard wall(1) format
		msg := fmt.Sprintf("\r\n\r\nBroadcast message from %s (%s):\r\n\r\n%s\r\n\r\n", m.from, ts, m.body)
		s.write(msg + s.prompt())
		idx++
	}
}

func (s *fakeShell) caughtReveal() {
	select {
	case <-time.After(caughtRevealDelay):
	case <-s.done:
		return
	}
	elapsed := time.Since(s.startTime).Round(time.Second)
	honeytoks := strings.Join(s.honeytokensAccessed, ", ")
	if honeytoks == "" {
		honeytoks = "none"
	}
	cmds := strings.Join(s.cmdHistory, " | ")
	if len(cmds) > 200 {
		cmds = cmds[:200] + "..."
	}

	reveal := fmt.Sprintf("\r\n\r\n"+
		"╔══════════════════════════════════════════════════════════╗\r\n"+
		"║          *** YOU HAVE BEEN CAUGHT ***                    ║\r\n"+
		"╠══════════════════════════════════════════════════════════╣\r\n"+
		"║ This server is a honeypot. Your session has been         ║\r\n"+
		"║ fully logged and reported to abuse@yourisp.com           ║\r\n"+
		"╠══════════════════════════════════════════════════════════╣\r\n"+
		"║ Attacker IP   : %-40s║\r\n"+
		"║ Session time  : %-40s║\r\n"+
		"║ Commands run  : %-40d║\r\n"+
		"║ Honeytokens   : %-40s║\r\n"+
		"╠══════════════════════════════════════════════════════════╣\r\n"+
		"║ Commands: %-47s║\r\n"+
		"╚══════════════════════════════════════════════════════════╝\r\n\r\n",
		s.ip, elapsed.String(), len(s.cmdHistory),
		honeytoks[:min(40, len(honeytoks))],
		cmds[:min(47, len(cmds))],
	)
	s.write(reveal)
	time.Sleep(3 * time.Second)
	s.write(fmt.Sprintf("Connection to %s closed by remote host.\r\n", s.profile.hostname))
	s.closeDone()
}

// ── Degradation & utilities ────────────────────────────────────────────────────

func (s *fakeShell) degradeOutput(out string) string {
	if s.cmdCount < degradeCorrupt {
		return out
	}
	chance := (s.cmdCount - degradeCorrupt) * 2
	runes := []rune(out)
	for i, r := range runes {
		if r >= 0x20 && r < 0x7f && mrand.Intn(1000) < chance {
			runes[i] = rune(0x20 + mrand.Intn(0x5f))
		}
	}
	// Add disk error suffix at high degradation
	result := string(runes)
	if s.cmdCount >= degradeDisk && mrand.Intn(100) < 15 {
		result += "\nEXT4-fs error: I/O error reading journal superblock"
	}
	if s.cmdCount >= degradeReadOnly && mrand.Intn(100) < 20 {
		result += "\nbash: write error: Read-only file system"
	}
	return result
}

func (s *fakeShell) maybeOOM() {
	if s.cmdCount < degradeOOM || mrand.Intn(100) >= 20 {
		return
	}
	msg := oomMessages[mrand.Intn(len(oomMessages))]
	uptime := time.Since(s.startTime).Seconds() + 9431.0
	s.write(fmt.Sprintf(msg, uptime, uptime+0.001))
}

func (s *fakeShell) jitter(minMs, maxMs int) time.Duration {
	base := time.Duration(minMs+mrand.Intn(maxMs-minMs+1)) * time.Millisecond
	if s.cmdCount >= degradeJitter {
		mult := 1.0 + float64(s.cmdCount-degradeJitter)*0.05
		if mult > 5.0 {
			mult = 5.0
		}
		base = time.Duration(float64(base) * mult)
	}
	return base
}

// poisonClipboard injects content into the attacker's clipboard via OSC 52.
// The content is subtly corrupted: last characters of passwords are changed.
func (s *fakeShell) poisonClipboard(content string) {
	// Subtly corrupt the content before poisoning
	poisoned := corruptCredentials(content)
	encoded := base64.StdEncoding.EncodeToString([]byte(poisoned))
	// OSC 52 escape sequence: ESC ] 52 ; c ; <base64> BEL
	s.write("\x1b]52;c;" + encoded + "\x07")
}

func corruptCredentials(content string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.Contains(line, "=") || strings.Contains(line, ":") {
			// Flip a few chars near the end
			runes := []rune(line)
			if len(runes) > 5 {
				runes[len(runes)-2] = rune('0' + mrand.Intn(10))
				runes[len(runes)-1] = rune('a' + mrand.Intn(26))
			}
			lines[i] = string(runes)
		}
	}
	return strings.Join(lines, "\n")
}

// ── New command handlers ───────────────────────────────────────────────────────

func (s *fakeShell) cmdUname(args string) string {
	p := s.profile
	k := p.kernelShort()
	kb := p.kernelBuild()
	h := p.hostname
	// parse flags
	flags := strings.ReplaceAll(args, "-", "")
	// -a: all
	if strings.Contains(flags, "a") {
		return fmt.Sprintf("Linux %s %s %s x86_64 x86_64 x86_64 GNU/Linux", h, k, kb)
	}
	var parts []string
	for _, c := range flags {
		switch c {
		case 's':
			parts = append(parts, "Linux")
		case 'n':
			parts = append(parts, h)
		case 'r':
			parts = append(parts, k)
		case 'v':
			parts = append(parts, kb)
		case 'm':
			parts = append(parts, "x86_64")
		case 'p':
			parts = append(parts, "x86_64")
		case 'i':
			parts = append(parts, "x86_64")
		case 'o':
			parts = append(parts, "GNU/Linux")
		}
	}
	if len(parts) == 0 {
		return "Linux"
	}
	return strings.Join(parts, " ")
}

func (s *fakeShell) cmdHostname(args string) string {
	flags := strings.TrimSpace(args)
	switch flags {
	case "-f", "--fqdn", "--long":
		return s.profile.hostname + ".internal.company.com"
	case "-s", "--short":
		return s.profile.hostname
	case "-i":
		return s.profile.ip
	case "-I":
		return s.profile.ip + " 127.0.0.1"
	case "-d", "--domain":
		return "internal.company.com"
	case "":
		return s.profile.hostname
	default:
		return s.profile.hostname
	}
}

func (s *fakeShell) cmdIfconfig(args string) string {
	fields := strings.Fields(args)
	iface := ""
	for _, f := range fields {
		if !strings.HasPrefix(f, "-") {
			iface = f
			break
		}
	}
	hasA := strings.Contains(args, "-a")
	switch iface {
	case "eth0":
		r, _ := s.profileResponse("ifconfig eth0")
		return r
	case "lo":
		r, _ := s.profileResponse("ifconfig lo")
		return r
	default:
		if hasA {
			r, _ := s.profileResponse("ifconfig")
			lo, _ := s.profileResponse("ifconfig lo")
			return r + "\n" + lo
		}
		r, _ := s.profileResponse("ifconfig")
		return r
	}
}

func (s *fakeShell) cmdNetstat(args string) string {
	// Normalise flags
	flags := strings.ReplaceAll(args, "-", "")
	switch {
	case strings.ContainsAny(flags, "t") && strings.ContainsAny(flags, "u") &&
		strings.ContainsAny(flags, "l") && strings.ContainsAny(flags, "n") &&
		strings.ContainsAny(flags, "p"):
		r, _ := s.profileResponse("netstat -tulnp")
		return r
	case strings.ContainsAny(flags, "r"):
		r, _ := s.profileResponse("netstat -rn")
		return r
	case strings.ContainsAny(flags, "s"):
		r, _ := s.profileResponse("netstat -s")
		return r
	case strings.ContainsAny(flags, "n"):
		r, _ := s.profileResponse("netstat -an")
		return r
	default:
		r, _ := s.profileResponse("netstat")
		return r
	}
}

func (s *fakeShell) cmdSS(args string) string {
	flags := strings.ReplaceAll(args, "-", "")
	switch {
	case strings.ContainsAny(flags, "t") && strings.ContainsAny(flags, "n"):
		r, _ := s.profileResponse("ss -tan")
		return r
	default:
		r, _ := s.profileResponse("ss -an")
		return r
	}
}

func (s *fakeShell) cmdRoute(args string) string {
	r, _ := s.profileResponse("route")
	return r
}

func (s *fakeShell) cmdArp(args string) string {
	if strings.Contains(args, "-a") {
		return cmdResponses["arp -a"]
	}
	r, _ := s.profileResponse("arp")
	return r
}

func (s *fakeShell) cmdUptime(args string) string {
	switch strings.TrimSpace(args) {
	case "-p", "--pretty":
		r, _ := s.profileResponse("uptime -p")
		return r
	case "-s", "--since":
		r, _ := s.profileResponse("uptime -s")
		return r
	default:
		r, _ := s.profileResponse("uptime")
		return r
	}
}

func (s *fakeShell) cmdDmesg(args string) string {
	p := s.profile
	k := p.kernelShort()
	if strings.Contains(args, "-T") || strings.Contains(args, "--ctime") {
		// Timestamped format
		now := time.Now()
		return fmt.Sprintf(
			"[%s] Linux version %s\n"+
				"[%s] EXT4-fs (nvme0n1p1): mounted filesystem with ordered data mode\n"+
				"[%s] possible SYN flooding on port 22. Sending cookies.\n"+
				"[%s] device nvme0n1: entered write error state\n"+
				"[%s] Out of memory: Kill process 8821 (php-fpm) score 289",
			now.Add(-time.Duration(p.uptimeDays)*24*time.Hour).Format("Mon Jan _2 15:04:05 2006"),
			k,
			now.Add(-2*time.Hour).Format("Mon Jan _2 15:04:05 2006"),
			now.Add(-30*time.Minute).Format("Mon Jan _2 15:04:05 2006"),
			now.Add(-10*time.Minute).Format("Mon Jan _2 15:04:05 2006"),
			now.Add(-5*time.Minute).Format("Mon Jan _2 15:04:05 2006"),
		)
	}
	r, _ := s.profileResponse("dmesg")
	return r
}

func (s *fakeShell) cmdWho(args string) string {
	// who / who -a / who -b / who -q
	upStr := s.profile.uptimeStr
	_ = upStr
	if strings.Contains(args, "-b") {
		t := time.Now().Add(-time.Duration(s.profile.uptimeDays) * 24 * time.Hour)
		return "         system boot  " + t.Format("2006-01-02 15:04")
	}
	if strings.Contains(args, "-q") {
		return "root\n# users=1"
	}
	return fmt.Sprintf("root     pts/0        %s %s (%s)",
		time.Now().Add(-13*time.Minute).Format("2006-01-02 15:04"),
		"",
		s.profile.lastIP)
}

func (s *fakeShell) cmdFree(args string) string {
	flags := strings.TrimSpace(args)
	switch {
	case strings.Contains(flags, "-m"):
		r, _ := s.profileResponse("free -m")
		return r
	case strings.Contains(flags, "-g"):
		r, _ := s.profileResponse("free -g")
		return r
	case strings.Contains(flags, "-k"):
		r, _ := s.profileResponse("free -k")
		return r
	default:
		r, _ := s.profileResponse("free -h")
		return r
	}
}

func (s *fakeShell) cmdLast(args string) string {
	p := s.profile
	base, _ := s.profileResponse("last")
	if strings.Contains(args, "-n") || strings.Contains(args, "-") {
		// Just return the base
		_ = p
		return base
	}
	return base
}

func (s *fakeShell) cmdW(args string) string {
	if strings.Contains(args, "-h") {
		// No header
		p := s.profile
		return fmt.Sprintf("root     pts/0    %s      09:01    0.00s  0.02s  0.00s w", p.lastIP)
	}
	r, _ := s.profileResponse("w")
	return r
}

func (s *fakeShell) cmdTraceroute(args string) string {
	s.slog.log("TRACEROUTE: %s", args)
	fields := strings.Fields(args)
	host := "8.8.8.8"
	for _, f := range fields {
		if !strings.HasPrefix(f, "-") {
			host = f
			break
		}
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("traceroute to %s (%s), 30 hops max, 60 byte packets", host, host))
	hops := []string{
		fmt.Sprintf(" 1  10.0.1.1 (10.0.1.1)  %.3f ms  %.3f ms  %.3f ms", mrand.Float64()*2, mrand.Float64()*2, mrand.Float64()*2),
		fmt.Sprintf(" 2  172.31.0.1 (172.31.0.1)  %.3f ms  %.3f ms  %.3f ms", 1+mrand.Float64()*3, 1+mrand.Float64()*3, 1+mrand.Float64()*3),
		fmt.Sprintf(" 3  100.64.0.1 (100.64.0.1)  %.3f ms  %.3f ms  %.3f ms", 3+mrand.Float64()*5, 3+mrand.Float64()*5, 3+mrand.Float64()*5),
		fmt.Sprintf(" 4  * * *"),
		fmt.Sprintf(" 5  72.14.203.1 (72.14.203.1)  %.3f ms  %.3f ms  %.3f ms", 8+mrand.Float64()*5, 8+mrand.Float64()*5, 8+mrand.Float64()*5),
		fmt.Sprintf(" 6  108.170.246.65 (108.170.246.65)  %.3f ms  %.3f ms  %.3f ms", 12+mrand.Float64()*5, 12+mrand.Float64()*5, 12+mrand.Float64()*5),
		fmt.Sprintf(" 7  %s (%s)  %.3f ms  %.3f ms  %.3f ms", host, host, 15+mrand.Float64()*5, 15+mrand.Float64()*5, 15+mrand.Float64()*5),
	}
	lines = append(lines, hops...)
	time.Sleep(s.jitter(2000, 5000))
	return strings.Join(lines, "\n")
}

func (s *fakeShell) cmdDig(args string) string {
	s.slog.log("DIG: %s", args)
	fields := strings.Fields(args)
	domain := "company.com"
	for _, f := range fields {
		if !strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "@") && !strings.Contains(f, "=") {
			domain = f
			break
		}
	}
	time.Sleep(s.jitter(200, 600))
	return fmt.Sprintf(
		"; <<>> DiG 9.18.12-0ubuntu0.22.04.1-Ubuntu <<>> %s\n"+
			";; global options: +cmd\n"+
			";; Got answer:\n"+
			";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: %d\n"+
			";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n"+
			";; QUESTION SECTION:\n"+
			";%s.\t\t\tIN\tA\n\n"+
			";; ANSWER SECTION:\n"+
			"%s.\t\t300\tIN\tA\t93.184.216.34\n\n"+
			";; Query time: %d msec\n"+
			";; SERVER: 10.0.1.1#53(10.0.1.1) (UDP)\n"+
			";; WHEN: %s\n"+
			";; MSG SIZE  rcvd: 65",
		domain, mrand.Intn(65535), domain, domain,
		10+mrand.Intn(40),
		time.Now().Format("Mon Jan _2 15:04:05 MST 2006"))
}

func (s *fakeShell) cmdNslookup(args string) string {
	s.slog.log("NSLOOKUP: %s", args)
	fields := strings.Fields(args)
	domain := "company.com"
	for _, f := range fields {
		if !strings.HasPrefix(f, "-") {
			domain = f
			break
		}
	}
	time.Sleep(s.jitter(200, 600))
	return fmt.Sprintf(
		"Server:\t\t10.0.1.1\nAddress:\t10.0.1.1#53\n\nNon-authoritative answer:\nName:\t%s\nAddress: 93.184.216.34",
		domain)
}

func (s *fakeShell) cmdHost(args string) string {
	fields := strings.Fields(args)
	domain := "company.com"
	for _, f := range fields {
		if !strings.HasPrefix(f, "-") {
			domain = f
			break
		}
	}
	time.Sleep(s.jitter(200, 600))
	return fmt.Sprintf("%s has address 93.184.216.34\n%s mail is handled by 10 mail.company.com.", domain, domain)
}

func (s *fakeShell) cmdDpkg(args string) string {
	if strings.Contains(args, "-l") || strings.Contains(args, "--list") {
		return "Desired=Unknown/Install/Remove/Purge/Hold\n" +
			"| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n" +
			"|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n" +
			"||/ Name                Version              Architecture Description\n" +
			"+++-===================-====================-============-================================================\n" +
			"ii  adduser             3.118ubuntu5         all          add and remove users and groups\n" +
			"ii  apt                 2.4.10               amd64        commandline package manager\n" +
			"ii  base-files          12ubuntu4.4          amd64        Debian base system miscellaneous files\n" +
			"ii  bash                5.1-6ubuntu1         amd64        GNU Bourne Again SHell\n" +
			"ii  curl                7.81.0-1ubuntu1.14   amd64        command line tool for transferring data\n" +
			"ii  libc6               2.35-0ubuntu3.6      amd64        GNU C Library: Shared libraries\n" +
			"ii  mysql-server        8.0.35-0ubuntu0.22.04.1 amd64    MySQL database server\n" +
			"ii  nginx               1.18.0-6ubuntu14.4   amd64        small, powerful, scalable web/proxy server\n" +
			"ii  openssh-server      1:8.9p1-3ubuntu0.6   amd64        secure shell (SSH) server\n" +
			"ii  openssl             3.0.2-0ubuntu1.14    amd64        Secure Sockets Layer toolkit\n" +
			"ii  python3             3.10.6-1~22.04       amd64        interactive high-level object-oriented language\n" +
			"ii  sudo                1.9.9-1ubuntu2.4     amd64        Provide limited super user privileges"
	}
	if strings.Contains(args, "-s") || strings.Contains(args, "--status") {
		pkg := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(args, "-s", ""), "--status", ""))
		return fmt.Sprintf("Package: %s\nStatus: install ok installed\nPriority: optional\nSection: misc\nInstalled-Size: 1024\nMaintainer: Ubuntu Developers\nVersion: 1.0.0\nDescription: Package description not available.", pkg)
	}
	return "dpkg: error: need an action option"
}

func (s *fakeShell) cmdJournalctl(args string) string {
	h := s.profile.hostname
	now := time.Now()
	lines := []string{
		fmt.Sprintf("%s systemd[1]: Started OpenSSH Server Daemon.", now.Add(-5*time.Hour).Format("Jan _2 15:04:05")+" "+h),
		fmt.Sprintf("%s sshd[%d]: Server listening on 0.0.0.0 port 22.", now.Add(-5*time.Hour).Format("Jan _2 15:04:05")+" "+h, s.profile.sshdPID),
		fmt.Sprintf("%s sshd[%d]: Accepted password for root from %s port 41234 ssh2", now.Add(-1*time.Hour).Format("Jan _2 15:04:05")+" "+h, s.profile.sshdPID, s.profile.lastIP),
		fmt.Sprintf("%s sudo[9844]: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/cat credentials.txt", now.Add(-45*time.Minute).Format("Jan _2 15:04:05")+" "+h),
		fmt.Sprintf("%s nginx[%d]: Starting nginx: nginx.", now.Add(-5*time.Hour).Format("Jan _2 15:04:05")+" "+h, s.profile.nginxPID),
		fmt.Sprintf("%s kernel: EXT4-fs (nvme0n1p1): mounted filesystem with ordered data mode", now.Add(-5*time.Hour).Format("Jan _2 15:04:05")+" "+h),
	}
	if strings.Contains(args, "-f") || strings.Contains(args, "--follow") {
		// Write lines and then stall
		for _, l := range lines {
			s.writef("%s\r\n", l)
		}
		s.write("-- Logs begin at ... --\r\n")
		for {
			select {
			case b := <-s.rawIn:
				if b == 0x03 {
					s.write("^C\r\n")
					return ""
				}
			case <-s.done:
				return ""
			case <-time.After(30 * time.Second):
			}
		}
	}
	return strings.Join(lines, "\n")
}

func (s *fakeShell) cmdVmstat(args string) string {
	p := s.profile
	totalKB := 0
	fmt.Sscanf(p.memTotal, "%dGi", &totalKB)
	totalKB *= 1024 * 1024
	usedKB := 0
	fmt.Sscanf(p.memUsed, "%dGi", &usedKB)
	usedKB *= 1024 * 1024
	freeKB := totalKB - usedKB - 2*1024*1024
	return fmt.Sprintf(
		"procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----\n"+
			" r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st\n"+
			" %d  0      0 %d %d %d    0    0     1    12  %d  %d  0  0 100  0  0",
		mrand.Intn(3), freeKB, 512*1024, 2*1024*1024,
		100+mrand.Intn(200), 200+mrand.Intn(400))
}

func (s *fakeShell) cmdIostat(args string) string {
	return fmt.Sprintf(
		"Linux %s  %s  _x86_64_  (2 CPU)\n\n"+
			"avg-cpu:  %%user   %%nice %%system %%iowait  %%steal   %%idle\n"+
			"           0.12    0.00    0.08    0.03    0.00   99.77\n\n"+
			"Device             tps    kB_read/s    kB_wrtn/s    kB_dscd/s    kB_read    kB_wrtn    kB_dscd\n"+
			"nvme0n1           1.23         4.56        12.34         0.00     123456     234567          0",
		s.profile.kernelShort(), time.Now().Format("01/02/2006"))
}

func (s *fakeShell) cmdSysctl(args string) string {
	if strings.Contains(args, "-a") || strings.Contains(args, "--all") {
		return "kernel.hostname = " + s.profile.hostname + "\n" +
			"kernel.ostype = Linux\n" +
			"kernel.osrelease = " + s.profile.kernelShort() + "\n" +
			"kernel.pid_max = 4194304\n" +
			"net.ipv4.ip_forward = 0\n" +
			"net.ipv4.conf.all.accept_redirects = 0\n" +
			"vm.swappiness = 10\n" +
			"vm.overcommit_memory = 0\n" +
			"fs.file-max = 1000000"
	}
	// sysctl <key>
	key := strings.TrimSpace(strings.TrimPrefix(args, "-n"))
	key = strings.TrimSpace(key)
	switch key {
	case "kernel.hostname":
		return "kernel.hostname = " + s.profile.hostname
	case "kernel.osrelease":
		return "kernel.osrelease = " + s.profile.kernelShort()
	case "net.ipv4.ip_forward":
		return "net.ipv4.ip_forward = 0"
	case "vm.swappiness":
		return "vm.swappiness = 10"
	default:
		if key != "" {
			return key + " = 1"
		}
		return "kernel.hostname = " + s.profile.hostname
	}
}

func (s *fakeShell) cmdSeq(args string) string {
	fields := strings.Fields(args)
	if len(fields) == 0 {
		return ""
	}
	var start, end, step int
	switch len(fields) {
	case 1:
		start = 1
		step = 1
		fmt.Sscanf(fields[0], "%d", &end)
	case 2:
		step = 1
		fmt.Sscanf(fields[0], "%d", &start)
		fmt.Sscanf(fields[1], "%d", &end)
	default:
		fmt.Sscanf(fields[0], "%d", &start)
		fmt.Sscanf(fields[1], "%d", &step)
		fmt.Sscanf(fields[2], "%d", &end)
	}
	if step <= 0 {
		step = 1
	}
	if end-start > 1000 {
		end = start + 1000 // cap to avoid huge output
	}
	var lines []string
	for i := start; i <= end; i += step {
		lines = append(lines, fmt.Sprintf("%d", i))
	}
	return strings.Join(lines, "\n")
}
