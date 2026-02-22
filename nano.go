package main

import (
	"fmt"
	"strings"
	"time"
)

// nanoEditor is a convincing fake GNU nano editor.
type nanoEditor struct {
	s        *fakeShell
	filename string
	lines    []string // file content
	curRow   int      // 0-based row in lines
	curCol   int      // 0-based column in lines[curRow]
	topRow   int      // first visible row (scroll offset)
	modified bool
	status   string // one-shot status message
	cols     int    // terminal width
	rows     int    // terminal height
}

const (
	nanoVersion  = "6.2"
	nanoTextRows = 21 // rows available for file content (rows - 3: header + 2 footer rows)
)

func newNanoEditor(s *fakeShell, filename string) *nanoEditor {
	n := &nanoEditor{
		s:        s,
		filename: filename,
		cols:     220, // generous default; nano wraps anyway
		rows:     24,
	}

	// Load file content
	var content string
	if filename != "" {
		if c, ok := fakeFiles[filename]; ok {
			content = c
		}
	}
	if content == "" {
		n.lines = []string{""}
	} else {
		n.lines = strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
		// Remove trailing empty line that Split adds for files ending with \n
		if len(n.lines) > 1 && n.lines[len(n.lines)-1] == "" {
			n.lines = n.lines[:len(n.lines)-1]
		}
	}
	return n
}

// ── ANSI helpers ─────────────────────────────────────────────────────────────

func (n *nanoEditor) moveCursor(row, col int) {
	n.s.write(fmt.Sprintf("\x1b[%d;%dH", row, col))
}

func (n *nanoEditor) clearLine() { n.s.write("\x1b[2K") }
func (n *nanoEditor) reverseOn() { n.s.write("\x1b[7m") }
func (n *nanoEditor) reverseOff() { n.s.write("\x1b[m") }
func (n *nanoEditor) bold(s string) string { return "\x1b[1m" + s + "\x1b[m" }

// ── Rendering ─────────────────────────────────────────────────────────────────

func (n *nanoEditor) textRows() int { return n.rows - 3 }

func (n *nanoEditor) render() {
	n.s.write("\x1b[?25l") // hide cursor while drawing
	n.drawHeader()
	n.drawContent()
	n.drawFooter()
	n.placeCursor()
	n.s.write("\x1b[?25h") // show cursor
}

func (n *nanoEditor) drawHeader() {
	n.moveCursor(1, 1)
	n.reverseOn()

	title := fmt.Sprintf("GNU nano %s", nanoVersion)
	filepart := n.filename
	if filepart == "" {
		filepart = "New Buffer"
	}
	mod := ""
	if n.modified {
		mod = " Modified"
	}

	// Layout: title (left), filename (centre), Modified (right)
	centre := fmt.Sprintf("  %s  ", filepart)
	right := mod
	left := title
	padding := n.cols - len(left) - len(centre) - len(right)
	if padding < 0 {
		padding = 0
	}
	leftPad := padding / 2
	rightPad := padding - leftPad

	line := left + strings.Repeat(" ", leftPad) + centre + strings.Repeat(" ", rightPad) + right
	if len(line) > n.cols {
		line = line[:n.cols]
	}
	n.s.write(line)
	n.reverseOff()
}

func (n *nanoEditor) drawContent() {
	textRows := n.textRows()
	for i := 0; i < textRows; i++ {
		n.moveCursor(i+2, 1)
		n.clearLine()
		lineIdx := n.topRow + i
		if lineIdx < len(n.lines) {
			line := n.lines[lineIdx]
			if len(line) > n.cols {
				line = line[:n.cols]
			}
			n.s.write(line)
		}
	}
}

func (n *nanoEditor) drawStatus(msg string) {
	n.moveCursor(n.rows-1, 1)
	n.clearLine()
	if msg != "" {
		n.reverseOn()
		n.s.write(" " + msg + " ")
		n.reverseOff()
	}
}

func (n *nanoEditor) drawFooter() {
	// Status line (row rows-1)
	msg := n.status
	n.status = ""
	n.drawStatus(msg)

	// Shortcut bar (row rows)
	n.moveCursor(n.rows, 1)
	n.clearLine()
	n.reverseOn()
	shortcuts := []string{
		"^G", "Help", "^O", "Write Out", "^W", "Where Is",
		"^K", "Cut", "^T", "Execute", "^C", "Location",
	}
	row2 := []string{
		"^X", "Exit", "^R", "Read File", "^\\", "Replace",
		"^U", "Paste", "^J", "Justify", "^/", "Go To Line",
	}
	n.s.write(n.formatShortcutBar(shortcuts))
	n.reverseOff()
	n.s.write("\r\n")
	n.reverseOn()
	n.s.write(n.formatShortcutBar(row2))
	n.reverseOff()
}

func (n *nanoEditor) formatShortcutBar(pairs []string) string {
	var b strings.Builder
	for i := 0; i+1 < len(pairs); i += 2 {
		key := pairs[i]
		label := pairs[i+1]
		b.WriteString(n.bold(key))
		b.WriteString(fmt.Sprintf(" %-10s", label))
	}
	s := b.String()
	// Strip ANSI for width calculation
	visible := stripANSI(s)
	if len(visible) < n.cols {
		s += strings.Repeat(" ", n.cols-len(visible))
	}
	return s
}

func stripANSI(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			i += 2
			for i < len(s) && !(s[i] >= 0x40 && s[i] <= 0x7e) {
				i++
			}
			i++
		} else {
			out.WriteByte(s[i])
			i++
		}
	}
	return out.String()
}

func (n *nanoEditor) placeCursor() {
	screenRow := n.curRow - n.topRow + 2
	screenCol := n.curCol + 1
	n.moveCursor(screenRow, screenCol)
}

// ── Scroll adjustment ─────────────────────────────────────────────────────────

func (n *nanoEditor) ensureVisible() {
	textRows := n.textRows()
	if n.curRow < n.topRow {
		n.topRow = n.curRow
	} else if n.curRow >= n.topRow+textRows {
		n.topRow = n.curRow - textRows + 1
	}
}

// ── Editing helpers ───────────────────────────────────────────────────────────

func (n *nanoEditor) clampCol() {
	if n.curCol > len(n.lines[n.curRow]) {
		n.curCol = len(n.lines[n.curRow])
	}
}

func (n *nanoEditor) insertChar(ch byte) {
	row := n.lines[n.curRow]
	col := n.curCol
	n.lines[n.curRow] = row[:col] + string(ch) + row[col:]
	n.curCol++
	n.modified = true
}

func (n *nanoEditor) backspace() {
	if n.curCol > 0 {
		row := n.lines[n.curRow]
		n.lines[n.curRow] = row[:n.curCol-1] + row[n.curCol:]
		n.curCol--
		n.modified = true
	} else if n.curRow > 0 {
		// Join with previous line
		prev := n.lines[n.curRow-1]
		n.curCol = len(prev)
		n.lines[n.curRow-1] = prev + n.lines[n.curRow]
		n.lines = append(n.lines[:n.curRow], n.lines[n.curRow+1:]...)
		n.curRow--
		n.modified = true
	}
}

func (n *nanoEditor) insertNewline() {
	row := n.lines[n.curRow]
	before := row[:n.curCol]
	after := row[n.curCol:]
	n.lines[n.curRow] = before
	n.lines = append(n.lines[:n.curRow+1], append([]string{after}, n.lines[n.curRow+1:]...)...)
	n.curRow++
	n.curCol = 0
	n.modified = true
}

func (n *nanoEditor) cutLine() {
	if len(n.lines) == 1 {
		n.lines[0] = ""
		n.curCol = 0
	} else {
		n.lines = append(n.lines[:n.curRow], n.lines[n.curRow+1:]...)
		if n.curRow >= len(n.lines) {
			n.curRow = len(n.lines) - 1
		}
		n.clampCol()
	}
	n.modified = true
}

// ── Save prompt ───────────────────────────────────────────────────────────────

// askSave prompts "Save modified buffer?" and returns true if user chose to save or discard.
// Returns (save, discard) where save=true means write, discard=true means abandon.
func (n *nanoEditor) askSave() (save bool, discard bool) {
	prompt := "Save modified buffer? (Answering \"No\" will DISCARD changes.) "
	n.drawStatus(prompt)
	n.moveCursor(n.rows-1, len(prompt)+3)
	// Show Y/N/C options
	n.moveCursor(n.rows, 1)
	n.clearLine()
	n.reverseOn()
	n.s.write(fmt.Sprintf(" %s Y Yes  %s N No  %s C Cancel",
		n.bold("^"), n.bold("^"), n.bold("^")))
	n.reverseOff()

	// Simpler: just draw it nicely
	n.moveCursor(n.rows-1, 1)
	n.clearLine()
	n.reverseOn()
	n.s.write(" " + prompt)
	n.reverseOff()
	n.moveCursor(n.rows, 1)
	n.clearLine()
	n.reverseOn()
	n.s.write(fmt.Sprintf("  \x1b[1mY\x1b[m Yes    \x1b[1mN\x1b[m No    \x1b[1mC\x1b[m Cancel"))
	n.reverseOff()

	for {
		b, ok := n.s.readRaw()
		if !ok {
			return false, true
		}
		switch b {
		case 'y', 'Y':
			return true, false
		case 'n', 'N':
			return false, true
		case 'c', 'C', 0x03, 0x1b:
			return false, false
		}
	}
}

// doSave performs the fake write-out.
func (n *nanoEditor) doSave() {
	if n.filename == "" {
		// Prompt for filename
		n.moveCursor(n.rows-1, 1)
		n.clearLine()
		n.reverseOn()
		n.s.write(" File Name to Write: ")
		n.reverseOff()
		// Read a filename from the user
		var fname []byte
		for {
			b, ok := n.s.readRaw()
			if !ok {
				return
			}
			if b == '\r' || b == '\n' {
				break
			}
			if (b == 0x7f || b == 0x08) && len(fname) > 0 {
				fname = fname[:len(fname)-1]
				n.s.write("\b \b")
				continue
			}
			if b == 0x03 || b == 0x1b {
				n.status = "Cancelled"
				return
			}
			if b >= 0x20 {
				fname = append(fname, b)
				n.s.write(string([]byte{b}))
			}
		}
		if len(fname) == 0 {
			n.status = "Cancelled"
			return
		}
		n.filename = string(fname)
	}
	time.Sleep(n.s.jitter(80, 250))
	n.modified = false
	n.status = fmt.Sprintf("Wrote %d lines", len(n.lines))
	n.s.slog.log("NANO_SAVE: %s (%d lines)", n.filename, len(n.lines))
}

// ── Main entry ────────────────────────────────────────────────────────────────

func (s *fakeShell) runNano(args string) {
	filename := strings.TrimSpace(args)
	if filename == "" {
		filename = ""
	}

	// Resolve relative paths
	if filename != "" && !strings.HasPrefix(filename, "/") {
		filename = s.cwd + "/" + filename
	}

	// Log honeytoken access
	if filename != "" && honeytokenFiles[filename] {
		s.logHoneytoken(filename)
	}

	n := newNanoEditor(s, filename)

	// Enter alternate screen
	s.write("\x1b[?1049h\x1b[2J\x1b[H")
	defer s.write("\x1b[?1049l")

	n.render()

	var escBuf []byte
	for {
		b, ok := s.readRaw()
		if !ok {
			return
		}

		// Escape sequence handling (arrow keys)
		if len(escBuf) > 0 {
			escBuf = append(escBuf, b)
			if len(escBuf) == 3 && escBuf[1] == '[' {
				switch escBuf[2] {
				case 'A': // Up
					if n.curRow > 0 {
						n.curRow--
						n.clampCol()
					}
				case 'B': // Down
					if n.curRow < len(n.lines)-1 {
						n.curRow++
						n.clampCol()
					}
				case 'C': // Right
					if n.curCol < len(n.lines[n.curRow]) {
						n.curCol++
					} else if n.curRow < len(n.lines)-1 {
						n.curRow++
						n.curCol = 0
					}
				case 'D': // Left
					if n.curCol > 0 {
						n.curCol--
					} else if n.curRow > 0 {
						n.curRow--
						n.curCol = len(n.lines[n.curRow])
					}
				}
				escBuf = escBuf[:0]
				n.ensureVisible()
				n.render()
				continue
			}
			if len(escBuf) >= 4 || (len(escBuf) == 2 && b != '[') {
				escBuf = escBuf[:0]
			}
			continue
		}
		if b == 0x1b {
			escBuf = append(escBuf[:0], b)
			continue
		}

		switch {
		case b == 0x18: // Ctrl+X — exit
			if n.modified {
				save, discard := n.askSave()
				if !discard && !save {
					// Cancelled
					n.render()
					continue
				}
				if save {
					n.doSave()
				}
			}
			return

		case b == 0x0f: // Ctrl+O — write out
			n.doSave()
			n.render()

		case b == 0x0b: // Ctrl+K — cut line
			n.cutLine()
			n.ensureVisible()
			n.render()

		case b == 0x03: // Ctrl+C — show position
			n.status = fmt.Sprintf("line %d/%d, col %d/%d",
				n.curRow+1, len(n.lines), n.curCol+1, len(n.lines[n.curRow])+1)
			n.render()

		case b == 0x07: // Ctrl+G — help (minimal)
			n.status = "GNU nano help: ^X Exit  ^O Save  ^K Cut  ^U Paste  ^W Search"
			n.render()

		case b == 0x17: // Ctrl+W — search (fake: just show prompt and ignore)
			n.moveCursor(n.rows-1, 1)
			n.clearLine()
			n.reverseOn()
			n.s.write(" Search: ")
			n.reverseOff()
			// eat input until Enter or Ctrl+C
			for {
				c, ok := s.readRaw()
				if !ok {
					return
				}
				if c == '\r' || c == '\n' || c == 0x03 || c == 0x1b {
					break
				}
			}
			n.status = "Not found"
			n.render()

		case b == 0x15: // Ctrl+U — paste (no-op, just show message)
			n.status = "(No text to paste)"
			n.render()

		case b == 0x01: // Ctrl+A — beginning of line
			n.curCol = 0
			n.render()

		case b == 0x05: // Ctrl+E — end of line
			n.curCol = len(n.lines[n.curRow])
			n.render()

		case b == '\r' || b == '\n':
			n.insertNewline()
			n.ensureVisible()
			n.render()

		case b == 0x7f || b == 0x08: // Backspace
			n.backspace()
			n.ensureVisible()
			n.render()

		case b >= 0x20: // Printable character
			n.insertChar(b)
			n.ensureVisible()
			// Partial redraw: just the current line + cursor reposition
			screenRow := n.curRow - n.topRow + 2
			n.moveCursor(screenRow, 1)
			n.clearLine()
			line := n.lines[n.curRow]
			if len(line) > n.cols {
				line = line[:n.cols]
			}
			n.s.write(line)
			if n.modified {
				n.drawHeader()
			}
			n.placeCursor()
		}
	}
}
