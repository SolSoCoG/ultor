package main

import (
	"fmt"
	mrand "math/rand"
	"strings"
	"sync"
	"time"
)

// serverProfile holds per-run randomised identity values.
type serverProfile struct {
	hostname   string
	ip         string
	sshVersion string
	kernel     string
	uptimeDays int
	uptimeStr  string // e.g. "127 days,  3:42"
	loadStr    string // e.g. "0.05, 0.08, 0.06"
	sshdPID    int
	nginxPID   int
	mysqlPID   int
	lastIP     string // source IP shown in "Last login"
	memTotal   string // e.g. "15Gi"
	memUsed    string // e.g. "4.2Gi"
	diskUsed   int    // percent used on /
	diskSize   int    // GB
}

var (
	srv       serverProfile
	profileMu sync.RWMutex
)

func init() {
	srv = newProfile()
	go startProfileRotation()
}

// getProfile returns a consistent snapshot of the current profile.
// Callers should store the result and use it for the lifetime of a connection.
func getProfile() serverProfile {
	profileMu.RLock()
	defer profileMu.RUnlock()
	return srv
}

func rotateProfile() {
	p := newProfile()
	profileMu.Lock()
	srv = p
	profileMu.Unlock()
	logEvent("INFO", "profile", "rotated server fingerprint: hostname="+p.hostname+" ip="+p.ip)
}

func startProfileRotation() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		rotateProfile()
	}
}

func newProfile() serverProfile {
	hostnames := []string{
		"web-prod-01", "web-01", "api-server-01", "prod-app-01",
		"ubuntu-srv-01", "linux-server", "prod-web-01", "app-node-01",
		"backend-prod", "srv-main-01",
	}
	kernels := []string{
		"5.15.0-1034-aws #38-Ubuntu SMP Mon Apr 17 11:42:51 UTC 2024",
		"5.15.0-107-generic #117-Ubuntu SMP Mon Apr 15 19:16:51 UTC 2024",
		"5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023",
		"5.19.0-1029-aws #30-Ubuntu SMP Mon Mar 27 20:26:52 UTC 2023",
		"6.5.0-35-generic #35~22.04.1-Ubuntu SMP Mon May 06 14:00:04 UTC 2024",
	}
	sshVersions := []string{
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
		"SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6",
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
	}
	lastIPs := []string{
		"203.0.113.42", "198.51.100.10", "192.0.2.15",
		"45.33.32.156", "104.21.8.82", "172.217.14.196",
	}

	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))

	hostname := hostnames[rng.Intn(len(hostnames))]
	kernel := kernels[rng.Intn(len(kernels))]
	sshVer := sshVersions[rng.Intn(len(sshVersions))]
	lastIP := lastIPs[rng.Intn(len(lastIPs))]

	// IP: avoid .1 (gateway) and .10/.20/.45/.100 (pivot hosts)
	reserved := map[int]bool{1: true, 10: true, 20: true, 45: true, 100: true}
	var octet int
	for {
		octet = 2 + rng.Intn(120)
		if !reserved[octet] {
			break
		}
	}
	ip := fmt.Sprintf("10.0.1.%d", octet)

	uptimeDays := 30 + rng.Intn(171) // 30–200
	uptimeHours := rng.Intn(24)
	uptimeMins := rng.Intn(60)
	uptimeStr := fmt.Sprintf("%d days, %2d:%02d", uptimeDays, uptimeHours, uptimeMins)
	load1 := rng.Float64() * 0.8
	load5 := rng.Float64() * 0.6
	load15 := rng.Float64() * 0.4
	loadStr := fmt.Sprintf("%.2f, %.2f, %.2f", load1, load5, load15)

	sshdPID := 500 + rng.Intn(600)
	nginxPID := sshdPID + 100 + rng.Intn(700)
	mysqlPID := nginxPID + 100 + rng.Intn(900)

	memTotalG := []int{8, 16, 32}[rng.Intn(3)]
	memUsedG := 1 + rng.Intn(memTotalG/2)

	diskSize := []int{100, 200, 500}[rng.Intn(3)]
	diskUsed := 20 + rng.Intn(50) // 20–70%

	return serverProfile{
		hostname:   hostname,
		ip:         ip,
		sshVersion: sshVer,
		kernel:     kernel,
		uptimeDays: uptimeDays,
		uptimeStr:  uptimeStr,
		loadStr:    loadStr,
		sshdPID:    sshdPID,
		nginxPID:   nginxPID,
		mysqlPID:   mysqlPID,
		lastIP:     lastIP,
		memTotal:   fmt.Sprintf("%dGi", memTotalG),
		memUsed:    fmt.Sprintf("%dGi", memUsedG),
		diskUsed:   diskUsed,
		diskSize:   diskSize,
	}
}

// kernelShort returns just the kernel release (e.g. "5.15.0-1034-aws").
func (p serverProfile) kernelShort() string {
	return strings.Fields(p.kernel)[0]
}

// kernelBuild returns the build string after the first token.
func (p serverProfile) kernelBuild() string {
	parts := strings.Fields(p.kernel)
	if len(parts) < 2 {
		return p.kernel
	}
	return strings.Join(parts[1:], " ")
}

// currentTimeStr returns current wall time as "HH:MM:SS".
func currentTimeStr() string {
	return time.Now().Format("15:04:05")
}
