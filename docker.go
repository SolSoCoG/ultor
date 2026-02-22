package main

import (
	"fmt"
	mrand "math/rand"
	"strings"
	"time"
)

type dockerShell struct {
	s         *fakeShell
	container string
	env       containerEnv
	cwd       string
}

func newDockerShell(s *fakeShell, name string) *dockerShell {
	env, ok := dockerContainers[name]
	if !ok {
		env = dockerContainers["webapp"]
	}
	return &dockerShell{s: s, container: name, env: env, cwd: env.cwd}
}

func (d *dockerShell) prompt() string {
	return fmt.Sprintf("root@%s:%s# ", d.env.hostname, d.cwd)
}

func (d *dockerShell) handle(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	d.s.slog.log("DOCKER(%s): %s", d.container, line)

	parts := strings.SplitN(line, " ", 2)
	cmd := parts[0]
	args := ""
	if len(parts) > 1 {
		args = parts[1]
	}

	time.Sleep(time.Duration(30+mrand.Intn(150)) * time.Millisecond)

	switch cmd {
	case "exit", "logout", "quit":
		return "", true
	case "ls":
		entries := d.env.files[d.cwd]
		return strings.Join(entries, "  "), false
	case "ll":
		entries := d.env.files[d.cwd]
		var lines []string
		for _, e := range entries {
			lines = append(lines, fmt.Sprintf("-rw-r--r-- 1 root root %6d Nov  5 12:00 %s", mrand.Intn(65000)+512, e))
		}
		return strings.Join(lines, "\n"), false
	case "pwd":
		return d.cwd, false
	case "cd":
		t := strings.TrimSpace(args)
		if t == "" || t == "~" {
			d.cwd = d.env.cwd
		} else {
			if !strings.HasPrefix(t, "/") {
				t = d.cwd + "/" + t
			}
			if _, ok := d.env.files[t]; ok {
				d.cwd = t
			}
		}
		return "", false
	case "cat":
		target := strings.TrimSpace(args)
		if !strings.HasPrefix(target, "/") {
			target = d.cwd + "/" + target
		}
		if content, ok := d.env.sensitive[target]; ok {
			d.s.logHoneytoken(fmt.Sprintf("docker:%s:%s", d.container, target))
			time.Sleep(time.Duration(200+mrand.Intn(400)) * time.Millisecond)
			return content, false
		}
		return fmt.Sprintf("cat: %s: No such file or directory", args), false
	case "env":
		for path, content := range d.env.sensitive {
			if strings.HasSuffix(path, ".env") {
				return content, false
			}
		}
		return "PATH=/usr/local/bin:/usr/bin:/bin\nHOME=/root", false
	case "id":
		return "uid=0(root) gid=0(root) groups=0(root)", false
	case "whoami":
		return "root", false
	case "ps", "ps aux":
		return "PID TTY          TIME CMD\n  1 ?        00:00:01 python3\n  7 pts/0    00:00:00 bash", false
	case "apt", "apt-get", "yum", "apk":
		return "bash: " + cmd + ": command not found", false
	}

	return fmt.Sprintf("bash: %s: command not found", cmd), false
}

func (d *dockerShell) run() {
	d.s.write("\r\n")
	time.Sleep(300 * time.Millisecond)
	d.s.write(d.prompt())

	var buf []byte
	var escBuf []byte

	for {
		b, ok := d.s.readRaw()
		if !ok {
			return
		}

		// Escape sequences
		if len(escBuf) > 0 {
			escBuf = append(escBuf, b)
			if len(escBuf) >= 3 || (len(escBuf) == 2 && b >= 'A') {
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
			d.s.write("\r\n")
			line := strings.TrimSpace(string(buf))
			buf = buf[:0]
			if line != "" {
				out, quit := d.handle(line)
				if out != "" {
					d.s.write(strings.ReplaceAll(out, "\n", "\r\n") + "\r\n")
				}
				if quit {
					return
				}
			}
			d.s.write(d.prompt())
		case b == 0x7f || b == 0x08:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				d.s.write("\b \b")
			}
		case b == 0x03:
			buf = buf[:0]
			d.s.write("^C\r\n" + d.prompt())
		case b == 0x04:
			return
		case b >= 0x20:
			buf = append(buf, b)
			d.s.write(string([]byte{b}))
		}
	}
}
