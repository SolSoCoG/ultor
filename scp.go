package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// handleSCPUpload implements the SCP sink protocol (scp -t).
// It captures uploaded files to uploadDir/<ip>/ for threat intelligence.
func handleSCPUpload(ch ssh.Channel, ip string) {
	defer ch.Close()

	// Send ready
	if _, err := ch.Write([]byte{0}); err != nil {
		return
	}

	reader := bufio.NewReader(ch)

	// Read SCP header line: "C0644 <size> <filename>\n"
	header, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	header = strings.TrimSpace(header)

	if !strings.HasPrefix(header, "C") {
		return
	}

	parts := strings.SplitN(header, " ", 3)
	if len(parts) < 3 {
		return
	}

	size, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil || size <= 0 || size > scpMaxSize {
		return
	}

	// Sanitize filename — NEVER trust client-supplied paths.
	// filepath.Base strips directory components; allowlist strips everything else.
	rawName := strings.TrimSpace(parts[2])
	filename := filepath.Base(rawName)
	var safeName strings.Builder
	for _, c := range filename {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			safeName.WriteRune(c)
		}
	}
	filename = strings.TrimLeft(safeName.String(), ".")
	if filename == "" {
		filename = fmt.Sprintf("upload_%d", time.Now().Unix())
	}

	// Signal ready for data
	if _, err := ch.Write([]byte{0}); err != nil {
		return
	}

	// Receive exactly <size> bytes
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		logEvent("SCP_ERROR", ip, fmt.Sprintf("read: %v", err))
		return
	}

	// Consume the trailing null byte
	reader.ReadByte()

	// Save to upload directory
	ipSafe := strings.NewReplacer(":", "_", ".", "_", "[", "", "]", "").Replace(ip)
	ipDir := filepath.Join(uploadDir, ipSafe)
	if err := os.MkdirAll(ipDir, 0700); err != nil {
		logEvent("SCP_ERROR", ip, fmt.Sprintf("mkdir: %v", err))
		return
	}

	savePath := filepath.Join(ipDir, filename)
	if err := os.WriteFile(savePath, data, 0600); err != nil {
		logEvent("SCP_ERROR", ip, fmt.Sprintf("write: %v", err))
		return
	}

	logEvent("SCP_UPLOAD", ip, fmt.Sprintf("%s (%d bytes) → %s", filename, size, savePath))

	// Send final ack
	ch.Write([]byte{0})
	ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
}
