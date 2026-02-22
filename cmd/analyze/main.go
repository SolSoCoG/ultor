// analyze — SSH honeypot log analyzer
// Usage: go run ./cmd/analyze [--top N] [--log-dir PATH]
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ── Types ──────────────────────────────────────────────────────────────────────

type credEntry struct {
	TS       string `json:"ts"`
	IP       string `json:"ip"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type tokenEntry struct {
	TS   string `json:"ts"`
	IP   string `json:"ip"`
	User string `json:"user"`
	File string `json:"file"`
}

type counter map[string]int

func (c counter) topN(n int) []kv {
	kvs := make([]kv, 0, len(c))
	for k, v := range c {
		kvs = append(kvs, kv{k, v})
	}
	sort.Slice(kvs, func(i, j int) bool { return kvs[i].V > kvs[j].V })
	if n > 0 && len(kvs) > n {
		kvs = kvs[:n]
	}
	return kvs
}

type kv struct {
	K string
	V int
}

type pairKey struct{ user, pass string }

// ── Loaders ────────────────────────────────────────────────────────────────────

func loadJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var v T
		if err := json.Unmarshal([]byte(line), &v); err == nil {
			out = append(out, v)
		}
	}
	return out, sc.Err()
}

func loadSessions(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".log") {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

// ── Formatting ─────────────────────────────────────────────────────────────────

func printTable(headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	sep := make([]string, len(headers))
	for i, w := range widths {
		sep[i] = strings.Repeat("─", w)
	}
	row2line := func(cells []string) string {
		parts := make([]string, len(headers))
		for i := range headers {
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			parts[i] = fmt.Sprintf("%-*s", widths[i], cell)
		}
		return strings.Join(parts, "  ")
	}
	fmt.Println(row2line(headers))
	fmt.Println(strings.Join(sep, "  "))
	for _, row := range rows {
		fmt.Println(row2line(row))
	}
}

func section(title string) {
	fmt.Printf("\n%s\n%s\n", title, strings.Repeat("─", len(title)))
}

// ── Session analysis ───────────────────────────────────────────────────────────

type sessionSummary struct {
	path     string
	ip       string
	commands []string
	execs    []string
	pivots   []string
	tokens   []string
	payloads []string
}

func analyzeSession(path string) sessionSummary {
	f, err := os.Open(path)
	if err != nil {
		return sessionSummary{path: path}
	}
	defer f.Close()

	sum := sessionSummary{path: path}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// extract content after ] prefix: "[ts] content"
		content := line
		if idx := strings.Index(line, "] "); idx >= 0 {
			content = line[idx+2:]
		}
		switch {
		case strings.HasPrefix(content, "Auth: user="):
			// extract IP from filename: ip_port_date.log
			base := filepath.Base(path)
			sum.ip = base
		case strings.HasPrefix(content, "CMD: "):
			sum.commands = append(sum.commands, strings.TrimPrefix(content, "CMD: "))
		case strings.HasPrefix(content, "Exec: "):
			sum.execs = append(sum.execs, strings.TrimPrefix(content, "Exec: "))
		case strings.HasPrefix(content, "SSH_PIVOT:") || strings.HasPrefix(content, "PIVOT("):
			sum.pivots = append(sum.pivots, content)
		case strings.HasPrefix(content, "BASE64_PAYLOAD:") || strings.HasPrefix(content, "WGET:") || strings.HasPrefix(content, "CURL:"):
			sum.payloads = append(sum.payloads, content)
		case strings.HasPrefix(content, "ATTEMPTED HISTORY CLEAR"):
			sum.commands = append(sum.commands, "[cleared history]")
		case strings.HasPrefix(content, "RM_NUKE:"):
			sum.commands = append(sum.commands, "[rm -rf /]")
		case strings.HasPrefix(content, "PYTHON_"):
			sum.payloads = append(sum.payloads, content)
		}
	}
	return sum
}

// ── Main ───────────────────────────────────────────────────────────────────────

func main() {
	topN := flag.Int("top", 20, "Number of top entries to show")
	logDir := flag.String("log-dir", "./honeypot_logs", "Path to honeypot log directory")
	sessionsFlag := flag.Bool("sessions", false, "Show per-session command detail")
	flag.Parse()

	credPath := filepath.Join(*logDir, "credentials.jsonl")
	tokenPath := filepath.Join(*logDir, "honeytokens.jsonl")
	sessionDir := filepath.Join(*logDir, "sessions")

	now := time.Now().UTC()
	fmt.Printf("\n%s\n", strings.Repeat("═", 62))
	fmt.Printf("  SSH HONEYPOT REPORT  —  %s UTC\n", now.Format("2006-01-02 15:04"))
	fmt.Printf("%s\n", strings.Repeat("═", 62))

	// ── Credentials ──────────────────────────────────────────────
	creds, err := loadJSONL[credEntry](credPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "credentials: %v\n", err)
	}

	if len(creds) == 0 {
		fmt.Println("\nNo credential attempts logged yet.")
	} else {
		ips := make(counter)
		users := make(counter)
		passes := make(counter)
		pairs := make(map[pairKey]int)

		var timestamps []string
		for _, e := range creds {
			// strip port from ip
			ip := e.IP
			if i := strings.LastIndex(ip, ":"); i >= 0 {
				ip = ip[:i]
			}
			ips[ip]++
			users[e.Username]++
			passes[e.Password]++
			pairs[pairKey{e.Username, e.Password}]++
			timestamps = append(timestamps, e.TS)
		}
		sort.Strings(timestamps)

		section("Auth Attempts")
		fmt.Printf("Total attempts    : %d\n", len(creds))
		fmt.Printf("First             : %s\n", timestamps[0])
		fmt.Printf("Last              : %s\n", timestamps[len(timestamps)-1])
		fmt.Printf("Unique IPs        : %d\n", len(ips))
		fmt.Printf("Unique usernames  : %d\n", len(users))
		fmt.Printf("Unique passwords  : %d\n", len(passes))

		section(fmt.Sprintf("Top %d Source IPs", *topN))
		rows := [][]string{}
		for _, kv := range ips.topN(*topN) {
			rows = append(rows, []string{kv.K, fmt.Sprint(kv.V)})
		}
		printTable([]string{"IP", "Attempts"}, rows)

		section(fmt.Sprintf("Top %d Usernames", *topN))
		rows = rows[:0]
		for _, kv := range users.topN(*topN) {
			rows = append(rows, []string{kv.K, fmt.Sprint(kv.V)})
		}
		printTable([]string{"Username", "Count"}, rows)

		section(fmt.Sprintf("Top %d Passwords", *topN))
		rows = rows[:0]
		for _, kv := range passes.topN(*topN) {
			rows = append(rows, []string{kv.K, fmt.Sprint(kv.V)})
		}
		printTable([]string{"Password", "Count"}, rows)

		section(fmt.Sprintf("Top %d Credential Pairs", *topN))
		type pairCount struct {
			user, pass string
			count      int
		}
		pairList := make([]pairCount, 0, len(pairs))
		for pk, cnt := range pairs {
			pairList = append(pairList, pairCount{pk.user, pk.pass, cnt})
		}
		sort.Slice(pairList, func(i, j int) bool { return pairList[i].count > pairList[j].count })
		if *topN > 0 && len(pairList) > *topN {
			pairList = pairList[:*topN]
		}
		rows = rows[:0]
		for _, p := range pairList {
			rows = append(rows, []string{p.user, p.pass, fmt.Sprint(p.count)})
		}
		printTable([]string{"Username", "Password", "Count"}, rows)
	}

	// ── Honeytokens ───────────────────────────────────────────────
	tokens, _ := loadJSONL[tokenEntry](tokenPath)
	section("Honeytoken Access")
	if len(tokens) == 0 {
		fmt.Println("No honeytoken accesses recorded.")
	} else {
		fmt.Printf("Total accesses : %d\n\n", len(tokens))
		rows := [][]string{}
		for _, t := range tokens {
			ip := t.IP
			if i := strings.LastIndex(ip, ":"); i >= 0 {
				ip = ip[:i]
			}
			rows = append(rows, []string{t.TS[:19], ip, t.User, t.File})
		}
		printTable([]string{"Timestamp", "IP", "User", "File"}, rows)
	}

	// ── Sessions ─────────────────────────────────────────────────
	sessionPaths, _ := loadSessions(sessionDir)
	section("Session Logs")
	fmt.Printf("Total sessions : %d\n", len(sessionPaths))

	if len(sessionPaths) > 0 {
		// Aggregate command frequency across all sessions
		cmdFreq := make(counter)
		execFreq := make(counter)
		activeSessions := 0 // sessions with at least one command

		var summaries []sessionSummary
		for _, p := range sessionPaths {
			s := analyzeSession(p)
			if len(s.commands) > 0 || len(s.execs) > 0 {
				activeSessions++
			}
			for _, c := range s.commands {
				// normalize: strip arguments for frequency counting
				cmd := strings.Fields(c)
				if len(cmd) > 0 {
					cmdFreq[cmd[0]]++
				}
			}
			for _, e := range s.execs {
				execFreq[strings.Fields(e)[0]]++
			}
			summaries = append(summaries, s)
		}

		fmt.Printf("Active sessions: %d (ran at least one command)\n", activeSessions)

		if len(cmdFreq) > 0 {
			section(fmt.Sprintf("Top %d Interactive Commands", *topN))
			rows := [][]string{}
			for _, kv := range cmdFreq.topN(*topN) {
				rows = append(rows, []string{kv.K, fmt.Sprint(kv.V)})
			}
			printTable([]string{"Command", "Count"}, rows)
		}

		if len(execFreq) > 0 {
			section(fmt.Sprintf("Top %d Exec Commands (non-interactive)", *topN))
			rows := [][]string{}
			for _, kv := range execFreq.topN(*topN) {
				rows = append(rows, []string{kv.K, fmt.Sprint(kv.V)})
			}
			printTable([]string{"Command", "Count"}, rows)
		}

		// Flag interesting sessions
		section("Notable Sessions")
		notable := 0
		for _, s := range summaries {
			flags := []string{}
			for _, c := range s.commands {
				cl := strings.ToLower(c)
				switch {
				case strings.Contains(cl, "rm -rf") || strings.Contains(cl, "rm -r /"):
					flags = append(flags, "rm-nuke")
				case strings.Contains(cl, "wget") || strings.Contains(cl, "curl"):
					flags = append(flags, "downloader")
				case strings.Contains(cl, "john") || strings.Contains(cl, "hashcat"):
					flags = append(flags, "cracker")
				case strings.Contains(cl, "nmap"):
					flags = append(flags, "scanner")
				case strings.Contains(cl, "history"):
					flags = append(flags, "anti-forensic")
				}
			}
			for _, e := range s.execs {
				el := strings.ToLower(e)
				if strings.Contains(el, "wget") || strings.Contains(el, "curl") || strings.Contains(el, "bash") {
					flags = append(flags, "exec-dropper")
				}
			}
			if len(s.pivots) > 0 {
				flags = append(flags, "pivot")
			}
			if len(s.payloads) > 0 {
				flags = append(flags, "payload")
			}
			if len(flags) == 0 {
				continue
			}
			notable++
			// deduplicate flags
			seen := map[string]bool{}
			uniq := flags[:0]
			for _, f := range flags {
				if !seen[f] {
					seen[f] = true
					uniq = append(uniq, f)
				}
			}
			fmt.Printf("  %-50s [%s]\n", filepath.Base(s.path), strings.Join(uniq, ", "))
		}
		if notable == 0 {
			fmt.Println("  None flagged.")
		}

		// Per-session detail if requested
		if *sessionsFlag {
			section("Per-Session Command Detail")
			for _, s := range summaries {
				if len(s.commands) == 0 && len(s.execs) == 0 {
					continue
				}
				fmt.Printf("\n  %s\n", filepath.Base(s.path))
				for _, c := range s.commands {
					fmt.Printf("    shell> %s\n", c)
				}
				for _, e := range s.execs {
					fmt.Printf("    exec>  %s\n", e)
				}
			}
		}
	}

	fmt.Printf("\n%s\n\n", strings.Repeat("═", 62))
}
