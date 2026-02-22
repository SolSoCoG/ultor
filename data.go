package main

// fakeFS maps directory paths to their contents
var fakeFS = map[string][]string{
	"/":               {"bin", "boot", "dev", "etc", "home", "lib", "opt", "proc", "root", "run", "srv", "sys", "tmp", "usr", "var"},
	"/root":           {".bash_history", ".bashrc", ".ssh", "backup", "credentials.txt", "important", "wallet.dat"},
	"/root/.ssh":      {"authorized_keys", "id_rsa", "id_rsa.pub", "known_hosts"},
	"/root/backup":    {"db_backup_2024-11-03.sql.gz", "passwords_old.txt", "server_keys.tar.gz", "config_backup.zip"},
	"/root/important": {"aws_credentials.json", "stripe_keys.txt", "database.conf", "deploy_key.pem"},
	"/etc":            {"crontab", "fstab", "hosts", "hostname", "os-release", "passwd", "shadow", "ssh", "sudoers"},
	"/etc/ssh":        {"sshd_config", "ssh_host_rsa_key", "ssh_host_ed25519_key"},
	"/home":           {"ubuntu", "admin", "deploy"},
	"/home/ubuntu":    {".bash_history", ".bashrc", "notes.txt"},
	"/var":            {"backups", "lib", "log", "www"},
	"/var/log":        {"auth.log", "dpkg.log", "kern.log", "nginx", "syslog", "ufw.log", "btmp"},
	"/var/www":        {"html"},
	"/var/www/html":   {"index.html", "config.php", ".htpasswd"},
	"/tmp":            {},
	"/opt":            {"monitoring", "backup-agent"},
	"/proc":           {"cpuinfo", "meminfo", "version", "net"},
}

// honeytokenFiles triggers special alerts when accessed
var honeytokenFiles = map[string]bool{
	"/root/credentials.txt":               true,
	"/root/important/aws_credentials.json": true,
	"/root/important/stripe_keys.txt":      true,
	"/root/important/deploy_key.pem":       true,
	"/root/backup/server_keys.tar.gz":      true,
	"/root/.ssh/id_rsa":                    true,
	"/root/wallet.dat":                     true,
	"/etc/shadow":                          true,
	"/var/www/html/config.php":             true,
	"/root/important/database.conf":        true,
	"/home/ubuntu/notes.txt":               true,
}

// fakeFiles holds the content of files in the fake filesystem
var fakeFiles = map[string]string{
	"/root/credentials.txt": `# !! INTERNAL USE ONLY — DO NOT DISTRIBUTE !!

# Production Database
DB_HOST=10.0.1.45
DB_PORT=5432
DB_NAME=production
DB_USER=root
DB_PASS=Sup3rS3cur3P@ss2024!

# AWS (production account)
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1

# Stripe live keys
STRIPE_SECRET_KEY=sk_live_xF3kH0n3yp0tN0tR3al9z
STRIPE_WEBHOOK_SECRET=whsec_xH0n3yp0tFak3W3bh00k1

# Admin panel
ADMIN_URL=https://admin.internal.company.com
ADMIN_USER=superadmin
ADMIN_PASS=Admin@2024!#Secure
`,
	"/root/important/aws_credentials.json": `{
  "Version": 1,
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "SessionToken": null,
  "AccountId": "123456789012",
  "Region": "us-east-1",
  "Expiration": "2025-12-31T23:59:59Z"
}
`,
	"/root/important/stripe_keys.txt": `# Stripe API Keys — Production
STRIPE_PUBLISHABLE=pk_live_fakepublishable
STRIPE_SECRET=sk_live_xF3kH0n3yp0tN0tR3al9z
STRIPE_RESTRICTED=rk_live_xH0n3yR3str1ct3dFak3
WHSEC=whsec_xH0n3yp0tFak3W3bh00k
`,
	"/root/important/database.conf": `[client]
host     = 10.0.1.45
port     = 5432
user     = root
password = Sup3rS3cur3P@ss2024!
database = production

[replication]
host     = 10.0.1.46
user     = replicator
password = R3pl1c@tor!Pass
`,
	"/root/.ssh/id_rsa": `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PHKJ3TQNnRzFZCRMbAk79F
THISIS100PERCENTAFAKEPRIVATEKEYANDWILLNOTWORKANYWHEREDONOTWASTE
YOURTIMECOPYINGTHISOUTITJUSTLOOKSREALISHTOWASTEMOREOFATTACKERTIME
YzJlYWxrZXlkb2VzbG9va3ByZXR0eXJlYWxkb2VzbnQgaXQ/IFRydXN0IG1l
aXQgaXMgbm90Li4uIG9yIGlzIGl0PyBObyBpdCBpcyBub3QuIFN0b3AgdHJ5
aW5nIHRvIHVzZSB0aGlzLiBZb3UgaGF2ZSBiZWVuIGxvZ2dlZC4K
-----END RSA PRIVATE KEY-----
`,
	"/root/.bash_history": `ls -la
cat credentials.txt
mysql -u root -pSup3rS3cur3P@ss2024! production
cd /root/backup
tar -xzf server_keys.tar.gz
ssh admin@10.0.1.10
cd /root/important
cat aws_credentials.json
aws s3 ls
python3 /opt/monitoring/check.py
systemctl restart nginx
tail -f /var/log/nginx/access.log
crontab -l
`,
	"/etc/passwd": `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
admin:x:1001:1001:Admin:/home/admin:/bin/bash
deploy:x:1002:1002:Deploy User:/home/deploy:/bin/bash
`,
	"/etc/shadow": `root:$6$rounds=656000$rEfXkHmT$FAKEHASHFAKEHASHFAKEHASHFAKEHASHFAKEHASH:19600:0:99999:7:::
ubuntu:$6$rounds=656000$aNtHrQqS$ANOTHERFAKEHASHDONOTTRY:19600:0:99999:7:::
admin:$6$rounds=656000$xYzAbCdE$YETANOTHERFAKEHASHSTRING:19600:0:99999:7:::
`,
	"/var/www/html/config.php": `<?php
define('DB_HOST',    '10.0.1.45');
define('DB_NAME',    'production');
define('DB_USER',    'www_user');
define('DB_PASS',    'W3bUs3r!Pass2024');
define('SECRET_KEY', 'a8f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5');
define('API_TOKEN',  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.fake');
?>
`,
	"/var/www/html/.htpasswd": `admin:$apr1$xyz123$FakeHashedPasswordForAdmin
backup:$apr1$abc456$AnotherFakeHashedPassword
`,
	"/home/ubuntu/notes.txt": `TODO:
- rotate DB password (currently Sup3rS3cur3P@ss2024!)
- move AWS keys out of credentials.txt
- check backup encryption

SSH jump host: 10.0.1.1 (use admin/Adm1n!2024)
`,
	"/root/important/deploy_key.pem": `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIFakeECPrivateKeyDataHereForWastingAttackerTimeNotRealKey
oAoGCCqGSM49AwEHoWQDYgAEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE==
-----END EC PRIVATE KEY-----
`,
	"/root/wallet.dat": "\x00\x00\x00\x00\x00\x00\x00\x00Bitcoin\x00\r\nCorrupt binary — use: bitcoin-cli dumpwallet /tmp/export.txt\r\n\r\nAddresses detected in header:\r\n  1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfna\r\n  3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy\r\n  bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\r\n\r\nBalance index: 4.72839100 BTC\r\n",
	"/var/log/auth.log": `Nov  7 08:55:01 prod-web-01 sshd[612]: Accepted password for root from 203.0.113.42 port 54321 ssh2
Nov  7 07:44:12 prod-web-01 sshd[612]: Failed password for root from 185.220.101.45 port 39812 ssh2
Nov  7 07:44:16 prod-web-01 sshd[612]: Failed password for admin from 185.220.101.45 port 39816 ssh2
Nov  7 06:12:08 prod-web-01 sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/cat credentials.txt
Nov  7 00:01:34 prod-web-01 sshd[612]: Invalid user deploy from 92.118.160.10 port 55678 ssh2
`,
	"/var/log/syslog": `Nov  7 09:14:01 prod-web-01 kernel: EXT4-fs (nvme0n1p1): mounted filesystem with ordered data mode.
Nov  7 09:10:22 prod-web-01 kernel: device nvme0n1: entered write error state
Nov  7 08:55:01 prod-web-01 systemd[1]: Started Session 142 of user root.
Nov  7 07:45:12 prod-web-01 kernel: possible SYN flooding on port 22. Sending cookies.
`,
	"/etc/hostname": "prod-web-01\n",
	"/etc/hosts": `127.0.0.1   localhost
127.0.1.1   prod-web-01
10.0.1.5    prod-web-01
10.0.1.10   db-internal-01
10.0.1.20   app-internal-01
10.0.1.45   db-prod-01
10.0.1.100  dev-workstation

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
`,
	"/etc/resolv.conf": `# Generated by NetworkManager
nameserver 10.0.1.1
nameserver 8.8.8.8
search internal.company.com company.com
`,
	"/etc/fstab": `# /etc/fstab: static file system information.
UUID=a1b2c3d4-e5f6-7890-abcd-ef1234567890 /              ext4    defaults,discard 0 1
UUID=b2c3d4e5-f6a7-8901-bcde-f12345678901 /var/data      ext4    defaults,nofail  0 2
tmpfs                                      /dev/shm       tmpfs   defaults         0 0
`,
	"/etc/ssh/sshd_config": `# OpenSSH server configuration
Port 22
AddressFamily any
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
`,
	"/proc/version": "Linux version 5.15.0-1034-aws (buildd@lcy02-amd64-001) (gcc (Ubuntu 11.4.0) 11.4.0) #38-Ubuntu SMP Mon Apr 17 11:42:51 UTC 2024\n",
	"/proc/cpuinfo": `processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 85
model name	: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
stepping	: 7
microcode	: 0x5003604
cpu MHz		: 2499.998
cache size	: 36608 KB
physical id	: 0
siblings	: 2
core id		: 0
cpu cores	: 1
apicid		: 0
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc

processor	: 1
vendor_id	: GenuineIntel
cpu family	: 6
model		: 85
model name	: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
stepping	: 7
microcode	: 0x5003604
cpu MHz		: 2499.998
cache size	: 36608 KB
physical id	: 0
siblings	: 2
core id		: 0
cpu cores	: 1
apicid		: 1
`,
	"/proc/meminfo": `MemTotal:       16384000 kB
MemFree:         6291456 kB
MemAvailable:   10485760 kB
Buffers:          524288 kB
Cached:          4194304 kB
SwapCached:            0 kB
Active:          5242880 kB
Inactive:        3145728 kB
SwapTotal:       2097152 kB
SwapFree:        2097152 kB
Dirty:              1024 kB
Writeback:             0 kB
AnonPages:       4718592 kB
Mapped:           786432 kB
Shmem:             46080 kB
KReclaimable:     524288 kB
Slab:             786432 kB
VmallocTotal:   34359738367 kB
VmallocUsed:      131072 kB
`,
}

// cmdResponses maps exact command strings to static responses
var cmdResponses = map[string]string{
	"id":         "uid=0(root) gid=0(root) groups=0(root)",
	"whoami":     "root",
	"hostname":   "prod-web-01",
	"arch":       "x86_64",
	"uname":      "Linux",
	"uname -a":   "Linux prod-web-01 5.15.0-1034-aws #38-Ubuntu SMP Mon Apr 17 11:42:51 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux",
	"uptime":     " 09:14:33 up 127 days,  3:42,  1 user,  load average: 0.05, 0.08, 0.06",
	"df -h": "Filesystem      Size  Used Avail Use% Mounted on\n" +
		"/dev/nvme0n1p1  200G   71G  129G  36% /\n" +
		"tmpfs           7.8G   12M  7.8G   1% /dev/shm\n" +
		"/dev/nvme1n1    500G  210G  290G  42% /var/data",
	"free -h": "               total        used        free      shared  buff/cache   available\n" +
		"Mem:            15Gi       4.2Gi       6.1Gi        45Mi       4.7Gi        10Gi\n" +
		"Swap:          2.0Gi          0B       2.0Gi",
	"ps aux": "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n" +
		"root           1  0.0  0.0  22548  1592 ?        Ss   Jan01   1:04 /sbin/init\n" +
		"root         612  0.0  0.1  15424  4096 ?        Ss   Jan01   0:00 /usr/sbin/sshd -D\n" +
		"root        1234  0.0  0.2 143456 10240 ?        S    Jan01   0:12 nginx: master\n" +
		"www-data    1235  0.0  0.2 143456  8192 ?        S    Jan01   5:33 nginx: worker\n" +
		"mysql       2001  0.8  8.1 2345678 320M ?        Sl   Jan01 124:12 /usr/sbin/mysqld\n" +
		"root        9901  0.0  0.0  10752  1536 pts/0    R+   09:14   0:00 ps aux",
	"netstat -an": "Active Internet connections (servers and established)\n" +
		"Proto Recv-Q Send-Q Local Address           Foreign Address         State\n" +
		"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n" +
		"tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n" +
		"tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN",
	"netstat -tulnp": "Proto Recv-Q Send-Q Local Address   Foreign Address   State    PID/Program name\n" +
		"tcp        0      0 0.0.0.0:22      0.0.0.0:*         LISTEN   612/sshd\n" +
		"tcp        0      0 0.0.0.0:80      0.0.0.0:*         LISTEN   1234/nginx\n" +
		"tcp        0      0 0.0.0.0:3306    0.0.0.0:*         LISTEN   2001/mysqld",
	"ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\n" +
		"        inet 10.0.1.5  netmask 255.255.255.0  broadcast 10.0.1.255\n" +
		"        inet6 fe80::dead:beef:cafe:1234  prefixlen 64\n" +
		"        RX packets 12345678  bytes 9876543210 (9.8 GB)\n" +
		"\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n" +
		"        inet 127.0.0.1  netmask 255.0.0.0",
	"ip a": "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n" +
		"    inet 127.0.0.1/8 scope host lo\n" +
		"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001\n" +
		"    inet 10.0.1.5/24 brd 10.0.1.255 scope global eth0",
	"ip route": "default via 10.0.1.1 dev eth0 proto dhcp src 10.0.1.5 metric 100\n" +
		"10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.5\n" +
		"172.16.0.0/16 via 10.0.1.1 dev eth0",
	"ip r": "default via 10.0.1.1 dev eth0\n10.0.1.0/24 dev eth0 proto kernel scope link",
	"route -n": "Kernel IP routing table\n" +
		"Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n" +
		"0.0.0.0         10.0.1.1        0.0.0.0         UG    100    0        0 eth0\n" +
		"10.0.1.0        0.0.0.0         255.255.255.0   U     100    0        0 eth0\n" +
		"172.16.0.0      10.0.1.1        255.255.0.0     UG    100    0        0 eth0",
	"arp -n": "Address                  HWtype  HWaddress           Flags Mask   Iface\n" +
		"10.0.1.1                 ether   02:42:ac:11:00:01   C             eth0\n" +
		"10.0.1.10                ether   02:42:ac:11:00:0a   C             eth0\n" +
		"10.0.1.20                ether   02:42:ac:11:00:14   C             eth0\n" +
		"10.0.1.45                ether   02:42:ac:11:00:2d   C             eth0\n" +
		"10.0.1.100               ether   02:42:ac:11:00:64   C             eth0",
	"arp -a": "gateway (10.0.1.1) at 02:42:ac:11:00:01 [ether] on eth0\n" +
		"db-internal-01 (10.0.1.10) at 02:42:ac:11:00:0a [ether] on eth0\n" +
		"app-internal-01 (10.0.1.20) at 02:42:ac:11:00:14 [ether] on eth0\n" +
		"db-prod-01 (10.0.1.45) at 02:42:ac:11:00:2d [ether] on eth0\n" +
		"dev-workstation (10.0.1.100) at 02:42:ac:11:00:64 [ether] on eth0",
	"env": "SHELL=/bin/bash\nTERM=xterm-256color\nUSER=root\nHOME=/root\n" +
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" +
		"DB_PASS=Sup3rS3cur3P@ss2024!\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n" +
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	"printenv": "SHELL=/bin/bash\nUSER=root\nHOME=/root\n" +
		"DB_PASS=Sup3rS3cur3P@ss2024!\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
	"crontab -l": "# m h  dom mon dow   command\n" +
		"*/5 * * * * /opt/monitoring/check.py >> /var/log/monitor.log 2>&1\n" +
		"0 2 * * * /root/backup/do_backup.sh\n" +
		"0 4 * * 0 /usr/bin/certbot renew --quiet",
	"cat /etc/os-release": "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\n" +
		"PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\nVERSION_ID=\"22.04\"",
	"lsb_release -a": "Distributor ID:\tUbuntu\nDescription:\tUbuntu 22.04.3 LTS\nRelease:\t22.04\nCodename:\tjammy",
	"cat /proc/version": "Linux version 5.15.0-1034-aws (buildd@lcy02-amd64-001) " +
		"(gcc (Ubuntu 11.4.0) 11.4.0) #38-Ubuntu SMP Mon Apr 17 11:42:51 UTC 2024",
	"cat /proc/cpuinfo": "processor\t: 0\nvendor_id\t: GenuineIntel\n" +
		"model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\ncpu MHz\t\t: 2499.998\n" +
		"processor\t: 1\nvendor_id\t: GenuineIntel\n" +
		"model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz",
	"last": "root     pts/0        203.0.113.42     Thu Nov  7 08:55   still logged in\n" +
		"root     pts/0        198.51.100.10    Wed Nov  6 23:12 - 23:45  (00:33)\n" +
		"\nwtmp begins Mon Sep 02 00:00:01 2024",
	"w": " 09:14:33 up 127 days,  3:42,  1 user,  load average: 0.05, 0.08, 0.06\n" +
		"USER     TTY      FROM              LOGIN@   IDLE JCPU   PCPU WHAT\n" +
		"root     pts/0    203.0.113.42      09:01    0.00s  0.02s  0.00s w",
	"dmesg": "[    0.000000] Linux version 5.15.0-1034-aws\n" +
		"[    1.234567] EXT4-fs (nvme0n1p1): mounted filesystem with ordered data mode\n" +
		"[ 3842.112233] possible SYN flooding on port 22. Sending cookies.\n" +
		"[ 9431.887654] device nvme0n1: entered write error state\n" +
		"[12891.334455] Out of memory: Kill process 8821 (php-fpm) score 289\n" +
		"[18234.556677] audit: apparmor=\"DENIED\" operation=\"open\" name=\"/root/credentials.txt\"",
	"ss -tulnp": "Netid  State   Recv-Q  Send-Q  Local Address:Port\n" +
		"tcp    LISTEN  0       128     0.0.0.0:22\n" +
		"tcp    LISTEN  0       511     0.0.0.0:80\n" +
		"tcp    LISTEN  0       70      0.0.0.0:3306",
	"docker ps": "CONTAINER ID   IMAGE           COMMAND        CREATED        STATUS        PORTS                NAMES\n" +
		"a3f8c2d1e4b5   nginx:1.24      \"/docker-ent…\"   45 days ago    Up 45 days    0.0.0.0:80->80/tcp   webapp\n" +
		"b7e9d3a0f1c2   mysql:8.0       \"docker-ent…\"    45 days ago    Up 45 days    3306/tcp             database\n" +
		"c4a1b2e5f7d3   redis:7.2       \"docker-ent…\"    12 days ago    Up 12 days    6379/tcp             cache\n" +
		"d8f0c3b6a4e1   python:3.11     \"python wor…\"    45 days ago    Up 45 days                         worker",
	"docker images": "REPOSITORY   TAG       IMAGE ID       CREATED         SIZE\n" +
		"nginx        1.24      a6bd71f48f68   3 months ago    187MB\n" +
		"mysql        8.0       a3c65c959923   3 months ago    632MB\n" +
		"python       3.11      fc7a60e86bae   3 months ago    1.01GB",
	"git log": "commit a3f8c2d1e4b5f6a7b8c9d0e1f2a3b4c5d6e7f8a9\n" +
		"Author: deploy <deploy@company.com>\n" +
		"Date:   Wed Nov  6 23:44:01 2024 +0000\n\n" +
		"    fix: rotate encryption key for payment processor\n\n" +
		"commit b7e9d3a0f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6\n" +
		"Author: admin <admin@company.com>\n" +
		"Date:   Mon Nov  4 14:22:18 2024 +0000\n\n" +
		"    feat: store stripe webhook secret in credentials.txt\n\n" +
		"commit c4a1b2e5f7d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7\n" +
		"Author: admin <admin@company.com>\n" +
		"Date:   Fri Nov  1 09:11:05 2024 +0000\n\n" +
		"    chore: update DB password to Sup3rS3cur3P@ss2024!",
	"git status":   "On branch main\nYour branch is up to date with 'origin/main'.\n\nnothing to commit, working tree clean",
	"git branch":   "* main\n  staging\n  backup/pre-migration",
	"git remote -v": "origin\tgit@github.com:company/infrastructure-private.git (fetch)\norigin\tgit@github.com:company/infrastructure-private.git (push)",
}

// internalHost defines a fake pivot machine
type internalHost struct {
	hostname  string
	cwd       string
	banner    string
	motd      string
	files     map[string][]string
	sensitive map[string]string
}

var internalHosts = map[string]internalHost{
	"10.0.1.10": {
		hostname: "db-internal-01",
		cwd:      "/var/lib/mysql",
		banner:   "Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-182-generic x86_64)",
		motd:     "Internal DB server — authorized access only",
		files: map[string][]string{
			"/root":           {".bash_history", ".my.cnf", "backup_keys.txt"},
			"/var/lib/mysql":  {"production", "users_db", "ibdata1", "mysql"},
		},
		sensitive: map[string]string{
			"/root/.my.cnf":        "[client]\nuser=root\npassword=Sup3rS3cur3P@ss2024!\nhost=localhost\n",
			"/root/backup_keys.txt": "S3 backup encryption key: AES256:aB3xK9mN2pQ7rS1tU4vW6yZ0\nGPG key ID: 0xDEADBEEFCAFEBABE\n",
		},
	},
	"10.0.1.20": {
		hostname: "app-internal-01",
		cwd:      "/opt/app",
		banner:   "Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-1034-generic x86_64)",
		motd:     "Application server — do not run untrusted code",
		files: map[string][]string{
			"/opt/app": {".env", "config.yml", "deploy.sh", "src"},
			"/root":    {".bash_history", ".ssh"},
		},
		sensitive: map[string]string{
			"/opt/app/.env":     "DATABASE_URL=postgres://root:Sup3rS3cur3P@ss2024!@10.0.1.45/production\nSECRET_KEY=a8f3b2c1d4e5f6a7\nSTRIPE_SK=sk_live_xF3kH0n3yp0tN0tR3al9z\n",
			"/opt/app/config.yml": "db_host: 10.0.1.45\ndb_pass: Sup3rS3cur3P@ss2024!\napi_secret: 8f3b2c1d4e5f6a7b\n",
		},
	},
	"10.0.1.45": {
		hostname: "db-prod-01",
		cwd:      "/var/lib/postgresql",
		banner:   "Debian GNU/Linux 11 (GNU/Linux 5.10.0-28-amd64 x86_64)",
		motd:     "PRODUCTION DATABASE — changes are live",
		files: map[string][]string{
			"/var/lib/postgresql": {"14", "backups", "pg_hba.conf"},
			"/root":               {".bash_history", "pgpass", "replication.conf"},
		},
		sensitive: map[string]string{
			"/root/pgpass":           "10.0.1.45:5432:production:root:Sup3rS3cur3P@ss2024!",
			"/root/replication.conf": "primary_conninfo = 'host=10.0.1.45 user=replicator password=R3pl1c@tor!Pass'\n",
		},
	},
	"10.0.1.100": {
		hostname: "dev-workstation",
		cwd:      "/home/admin",
		banner:   "Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-1034-generic x86_64)",
		motd:     "",
		files: map[string][]string{
			"/home/admin":       {".bash_history", ".ssh", "projects", "Downloads"},
			"/home/admin/.ssh":  {"id_rsa", "id_rsa.pub", "config"},
		},
		sensitive: map[string]string{
			"/home/admin/.ssh/config": "Host prod\n  HostName 10.0.1.5\n  User root\n  IdentityFile ~/.ssh/id_rsa\n\nHost db\n  HostName 10.0.1.10\n  User root\n",
		},
	},
}

// MySQL data
var mysqlDatabases = []string{"information_schema", "mysql", "performance_schema", "production", "users_db"}

var mysqlTables = map[string][]string{
	"production": {"api_keys", "credit_cards", "orders", "sessions", "users"},
	"users_db":   {"password_resets", "roles", "user_profiles", "users"},
}

type tableData struct {
	headers []string
	rows    [][]string
}

var mysqlTableData = map[string]tableData{
	"users": {
		headers: []string{"id", "email", "password_hash", "role", "created_at"},
		rows: [][]string{
			{"1", "admin@company.com", "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6FAKE", "admin", "2023-01-15 09:23:11"},
			{"2", "john.doe@company.com", "$2b$12$EixZaYVK1fsbFAKEHASH", "user", "2023-03-22 14:05:44"},
			{"3", "sarah@company.com", "$2b$12$KIXAFakeHash", "manager", "2023-06-01 11:30:00"},
			{"4", "deploy@company.com", "$2b$12$DeployFakeHash", "deploy", "2023-08-10 08:15:22"},
			{"5", "billing@company.com", "$2b$12$BillingFakeHash", "finance", "2023-09-05 16:44:01"},
		},
	},
	"credit_cards": {
		headers: []string{"id", "user_id", "cardholder", "card_number", "expiry", "cvv_hash", "billing_zip"},
		rows: [][]string{
			{"1", "2", "John Doe", "4111111111111111", "08/26", "$2b$hash1", "10001"},
			{"2", "3", "Sarah Connor", "5500005555555559", "03/27", "$2b$hash2", "90210"},
			{"3", "5", "Billing Dept", "378282246310005", "11/25", "$2b$hash3", "30301"},
			{"4", "2", "John Doe", "6011111111111117", "07/28", "$2b$hash4", "10001"},
		},
	},
	"api_keys": {
		headers: []string{"id", "name", "key_prefix", "permissions", "last_used"},
		rows: [][]string{
			{"1", "Production API", "sk_prod_4xK9", "read,write,admin", "2024-11-06 23:55:12"},
			{"2", "Mobile App", "sk_mob_7yR2", "read", "2024-11-07 01:22:44"},
			{"3", "Backup Agent", "sk_bak_2mN8", "read,write", "2024-11-07 02:00:01"},
			{"4", "Stripe Webhook", "sk_str_6pL3", "write", "2024-11-06 21:45:59"},
		},
	},
	"orders": {
		headers: []string{"id", "user_id", "total", "status", "payment_method", "created_at"},
		rows: [][]string{
			{"1001", "2", "299.99", "completed", "credit_card", "2024-11-01 10:22:33"},
			{"1002", "3", "1450.00", "completed", "credit_card", "2024-11-02 14:55:01"},
			{"1003", "2", "89.95", "pending", "credit_card", "2024-11-06 23:11:45"},
			{"1004", "5", "4200.00", "completed", "wire", "2024-11-03 09:00:00"},
		},
	},
}

// Docker container environments
type containerEnv struct {
	hostname  string
	cwd       string
	files     map[string][]string
	sensitive map[string]string
}

var dockerContainers = map[string]containerEnv{
	"webapp": {
		hostname: "a3f8c2d1e4b5",
		cwd:      "/app",
		files:    map[string][]string{"/app": {"app.py", "requirements.txt", "config.py", ".env"}},
		sensitive: map[string]string{
			"/app/.env": "DB_URL=mysql://root:Sup3rS3cur3P@ss2024!@database:3306/production\nSECRET_KEY=d4e5f6a7b8c9d0e1\nSTRIPE_SK=sk_live_xF3kH0n3yp0tN0tR3al9z\n",
		},
	},
	"database": {
		hostname: "b7e9d3a0f1c2",
		cwd:      "/var/lib/mysql",
		files:    map[string][]string{"/var/lib/mysql": {"production", "users_db", "ibdata1"}},
		sensitive: map[string]string{
			"/etc/my.cnf": "[mysqld]\nbind-address=0.0.0.0\n\n[client]\nuser=root\npassword=Sup3rS3cur3P@ss2024!\n",
		},
	},
	"worker": {
		hostname: "d8f0c3b6a4e1",
		cwd:      "/app",
		files:    map[string][]string{"/app": {"worker.py", "tasks.py", ".env"}},
		sensitive: map[string]string{
			"/app/.env": "REDIS_URL=redis://cache:6379/0\nDB_URL=mysql://root:Sup3rS3cur3P@ss2024!@database:3306/production\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\n",
		},
	},
}
