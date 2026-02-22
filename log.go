package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	appLog       *log.Logger
	credMu       sync.Mutex
	honeytokMu   sync.Mutex
)

func initLogger() error {
	f, err := os.OpenFile(filepath.Join(logDir, "honeypot.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	appLog = log.New(io.MultiWriter(f, os.Stdout), "", log.LstdFlags)
	return nil
}

func logEvent(level, src, msg string) {
	if appLog != nil {
		appLog.Printf("%-12s %-22s %s", level, src, msg)
	}
}

func logCredential(ip, username, password string) {
	entry := map[string]string{
		"ts":       time.Now().UTC().Format(time.RFC3339Nano),
		"ip":       ip,
		"username": username,
		"password": password,
	}
	b, _ := json.Marshal(entry)
	credMu.Lock()
	appendLine(credLogFile, b)
	credMu.Unlock()
	logEvent("AUTH", ip, fmt.Sprintf("u=%s p=%s", username, password))
}

func logHoneytoken(ip, user, file string) {
	entry := map[string]string{
		"ts":   time.Now().UTC().Format(time.RFC3339Nano),
		"ip":   ip,
		"user": user,
		"file": file,
	}
	b, _ := json.Marshal(entry)
	honeytokMu.Lock()
	appendLine(honeytokenLogFile, b)
	honeytokMu.Unlock()
	logEvent("HONEYTOKEN", ip, fmt.Sprintf("user=%s file=%s", user, file))
}

func appendLine(path string, data []byte) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(data, '\n'))
}

// Per-session log file
type sessionLogger struct {
	f  *os.File
	mu sync.Mutex
}

func newSessionLogger(ip string) (*sessionLogger, error) {
	ts := time.Now().UTC().Format("20060102_150405")
	safe := ""
	for _, c := range ip {
		if c == ':' || c == '.' {
			safe += "_"
		} else {
			safe += string(c)
		}
	}
	path := filepath.Join(sessionDir, safe+"_"+ts+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &sessionLogger{f: f}, nil
}

func (l *sessionLogger) log(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	fmt.Fprintf(l.f, "[%s] %s\n", ts, fmt.Sprintf(format, args...))
}

func (l *sessionLogger) close() {
	if l.f != nil {
		l.f.Close()
	}
}
