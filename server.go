package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	mrand "math/rand"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var hostKey ssh.Signer

func loadOrGenHostKey(path string) (ssh.Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				return ssh.NewSignerFromKey(key)
			}
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	f.Close()
	logEvent("INFO", path, "generated new host key")
	return ssh.NewSignerFromKey(key)
}

func makeSSHConfig(p serverProfile) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		ServerVersion: p.sshVersion,
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			delay := time.Duration(tarpitMin + mrand.Float64()*(tarpitMax-tarpitMin))
			time.Sleep(delay)
			logCredential(conn.RemoteAddr().String(), conn.User(), string(password))
			return &ssh.Permissions{}, nil
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			fp := ssh.FingerprintSHA256(key)
			logCredential(conn.RemoteAddr().String(), conn.User(), "<pubkey:"+fp+">")
			delay := time.Duration(tarpitMin + mrand.Float64()*(tarpitMax-tarpitMin))
			time.Sleep(delay)
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostKey)
	return cfg
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	// Snapshot the profile once — stays consistent for the entire connection.
	p := getProfile()

	cfg := makeSSHConfig(p)
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	ip := sshConn.RemoteAddr().String()
	logEvent("CONNECT", ip, "user="+sshConn.User())

	sess, err := newSessionLogger(ip)
	if err != nil {
		logEvent("ERROR", ip, "session log: "+err.Error())
		return
	}
	defer sess.close()
	sess.log("Auth: user=%s", sshConn.User())

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, reqs2, err := newChan.Accept()
		if err != nil {
			break
		}
		handleSession(ch, reqs2, ip, sshConn.User(), sess, p)
	}
	logEvent("DISCONNECT", ip, "")
}

func handleSession(ch ssh.Channel, reqs <-chan *ssh.Request, ip, username string, sess *sessionLogger, p serverProfile) {
	defer ch.Close()

	var execCmd string
	ptyGranted := false

	for req := range reqs {
		switch req.Type {
		case "pty-req":
			ptyGranted = true
			req.Reply(true, nil)
		case "env":
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
			_ = ptyGranted
			shell := newFakeShell(ch, ip, username, sess, p)
			shell.run()
			return
		case "exec":
			if len(req.Payload) >= 4 {
				n := binary.BigEndian.Uint32(req.Payload[:4])
				if int(n) <= len(req.Payload)-4 {
					execCmd = string(req.Payload[4 : 4+n])
				}
			}
			req.Reply(true, nil)
			sess.log("Exec: %s", execCmd)

			if strings.HasPrefix(execCmd, "scp -t") {
				logEvent("SCP_UPLOAD", ip, execCmd)
				handleSCPUpload(ch, ip)
			} else {
				shell := newFakeShell(ch, ip, username, sess, p)
				out := shell.dispatch(execCmd)
				if out != "" {
					ch.Write([]byte(strings.ReplaceAll(out, "\n", "\r\n") + "\r\n"))
				}
				// Send exit-status 0
				ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			}
			return
		case "window-change":
			req.Reply(false, nil)
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func runServer() error {
	var err error
	hostKey, err = loadOrGenHostKey(hostKeyFile)
	if err != nil {
		return fmt.Errorf("host key: %w", err)
	}

	for _, d := range []string{logDir, sessionDir, uploadDir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	if err := initLogger(); err != nil {
		return fmt.Errorf("logger: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", listenHost, listenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	defer ln.Close()

	logEvent("START", addr, fmt.Sprintf("creds=%s honeytokens=%s maxconns=%d", credLogFile, honeytokenLogFile, maxConns))

	sem := make(chan struct{}, maxConns)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				handleConn(conn)
			}()
		default:
			logEvent("REJECT", conn.RemoteAddr().String(), "connection limit reached")
			conn.Close()
		}
	}
}
