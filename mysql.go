package main

import (
	"fmt"
	mrand "math/rand"
	"strings"
	"time"
)

type mysqlShell struct {
	s  *fakeShell
	db string
}

func newMySQLShell(s *fakeShell, db string) *mysqlShell {
	return &mysqlShell{s: s, db: db}
}

// fmtTable renders a MySQL-style box table
func fmtTable(headers []string, rows [][]string) string {
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

	sep := func() string {
		var b strings.Builder
		b.WriteString("+")
		for _, w := range widths {
			b.WriteString(strings.Repeat("-", w+2))
			b.WriteString("+")
		}
		return b.String()
	}

	row := func(cells []string) string {
		var b strings.Builder
		b.WriteString("|")
		for i, w := range widths {
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			b.WriteString(fmt.Sprintf(" %-*s |", w, cell))
		}
		return b.String()
	}

	var out strings.Builder
	out.WriteString(sep() + "\n")
	out.WriteString(row(headers) + "\n")
	out.WriteString(sep() + "\n")
	for _, r := range rows {
		out.WriteString(row(r) + "\n")
	}
	out.WriteString(sep() + "\n")
	n := len(rows)
	if n == 1 {
		out.WriteString("1 row in set\n")
	} else {
		out.WriteString(fmt.Sprintf("%d rows in set\n", n))
	}
	return out.String()
}

func (m *mysqlShell) handle(line string) (string, bool) {
	line = strings.TrimRight(strings.TrimSpace(line), ";")
	upper := strings.ToUpper(strings.TrimSpace(line))

	m.s.slog.log("MYSQL: %s", line)
	time.Sleep(time.Duration(50+mrand.Intn(400)) * time.Millisecond)

	switch {
	case upper == "EXIT" || upper == "QUIT" || upper == `\Q`:
		return "Bye", true

	case upper == "SHOW DATABASES":
		rows := make([][]string, len(mysqlDatabases))
		for i, d := range mysqlDatabases {
			rows[i] = []string{d}
		}
		return fmtTable([]string{"Database"}, rows), false

	case strings.HasPrefix(upper, "USE "):
		db := strings.TrimSpace(line[4:])
		db = strings.Trim(db, "`'\"")
		for _, d := range mysqlDatabases {
			if strings.EqualFold(db, d) {
				m.db = db
				return "Database changed", false
			}
		}
		return fmt.Sprintf("ERROR 1049 (42000): Unknown database '%s'", db), false

	case upper == "SHOW TABLES":
		if m.db == "" {
			return "ERROR 1046 (3D000): No database selected", false
		}
		tables, ok := mysqlTables[m.db]
		if !ok || len(tables) == 0 {
			return "Empty set", false
		}
		rows := make([][]string, len(tables))
		for i, t := range tables {
			rows[i] = []string{t}
		}
		return fmtTable([]string{"Tables_in_" + m.db}, rows), false

	case strings.HasPrefix(upper, "SELECT VERSION"):
		return fmtTable([]string{"version()"}, [][]string{{"8.0.35"}}), false

	case strings.HasPrefix(upper, "SELECT USER"):
		return fmtTable([]string{"user()"}, [][]string{{"root@localhost"}}), false

	case strings.HasPrefix(upper, "SELECT DATABASE"):
		db := m.db
		if db == "" {
			db = "NULL"
		}
		return fmtTable([]string{"database()"}, [][]string{{db}}), false

	case strings.HasPrefix(upper, "SELECT NOW"):
		return fmtTable([]string{"now()"}, [][]string{{time.Now().Format("2006-01-02 15:04:05")}}), false

	case strings.HasPrefix(upper, "SELECT 1"):
		return fmtTable([]string{"1"}, [][]string{{"1"}}), false

	case strings.HasPrefix(upper, "SELECT") || strings.HasPrefix(upper, "DESCRIBE") || strings.HasPrefix(upper, "DESC "):
		// Find which table is referenced
		for tname, td := range mysqlTableData {
			if strings.Contains(upper, strings.ToUpper(tname)) {
				// Extra delay for juicy tables
				if tname == "credit_cards" || tname == "api_keys" || tname == "sessions" {
					time.Sleep(time.Duration(500+mrand.Intn(1000)) * time.Millisecond)
				}
				// Apply LIMIT if present
				rows := td.rows
				if idx := strings.Index(upper, "LIMIT"); idx >= 0 {
					lim := 0
					fmt.Sscanf(strings.TrimSpace(upper[idx+5:]), "%d", &lim)
					if lim > 0 && lim < len(rows) {
						rows = rows[:lim]
					}
				}
				return fmtTable(td.headers, rows), false
			}
		}
		return "Empty set", false

	case strings.HasPrefix(upper, "INSERT") || strings.HasPrefix(upper, "UPDATE") || strings.HasPrefix(upper, "DELETE"):
		time.Sleep(time.Duration(200+mrand.Intn(600)) * time.Millisecond)
		return "Query OK, 1 row affected (0.01 sec)", false

	case strings.HasPrefix(upper, "CREATE") || strings.HasPrefix(upper, "DROP") || strings.HasPrefix(upper, "ALTER"):
		time.Sleep(time.Duration(300+mrand.Intn(700)) * time.Millisecond)
		return "Query OK, 0 rows affected (0.02 sec)", false

	case strings.HasPrefix(upper, "SHOW"):
		return "Empty set", false

	case strings.HasPrefix(upper, "SET"):
		return "Query OK, 0 rows affected (0.00 sec)", false

	case upper == "" || upper == `\G`:
		return "", false
	}

	return fmt.Sprintf("ERROR 1064 (42000): You have an error in your SQL syntax near '%.20s'", line), false
}

func (m *mysqlShell) prompt() string {
	if m.db != "" {
		return fmt.Sprintf("mysql [%s]> ", m.db)
	}
	return "mysql> "
}

func (m *mysqlShell) run() {
	connID := mrand.Intn(9000) + 1000
	banner := fmt.Sprintf(
		"Welcome to the MySQL monitor.  Commands end with ; or \\g.\r\n"+
			"Your MySQL connection id is %d\r\n"+
			"Server version: 8.0.35 MySQL Community Server - GPL\r\n\r\n"+
			"Type 'help;' or '\\h' for help. Type '\\c' to clear the current input statement.\r\n",
		connID,
	)
	m.s.write(banner)
	m.s.write(m.prompt())

	var buf []byte
	for {
		b, ok := m.s.readRaw()
		if !ok {
			return
		}
		switch {
		case b == '\r' || b == '\n':
			m.s.write("\r\n")
			line := strings.TrimSpace(string(buf))
			buf = buf[:0]
			if line != "" {
				out, quit := m.handle(line)
				if out != "" {
					m.s.write(strings.ReplaceAll(out, "\n", "\r\n") + "\r\n")
				}
				if quit {
					return
				}
			}
			m.s.write(m.prompt())
		case b == 0x7f || b == 0x08:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				m.s.write("\b \b")
			}
		case b == 0x03:
			buf = buf[:0]
			m.s.write("\r\n" + m.prompt())
		case b == 0x04:
			return
		case b >= 0x20:
			buf = append(buf, b)
			m.s.write(string([]byte{b}))
		}
	}
}
