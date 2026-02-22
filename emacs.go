package main

import (
	"fmt"
	"strings"
	"time"
)

const emacsVersion = "27.2"

// ── Types ──────────────────────────────────────────────────────────────────────

type emacsEditor struct {
	s        *fakeShell
	filename string
	bufName  string   // shown in mode line
	lines    []string
	curRow   int
	curCol   int
	topRow   int
	modified bool
	killRing string // last killed text (simplified single-entry ring)
	msg      string // echo area message, cleared each iteration
	cols     int
	rows     int
}

// ── Constructor ───────────────────────────────────────────────────────────────

func newEmacsEditor(s *fakeShell, filename string) *emacsEditor {
	e := &emacsEditor{
		s:    s,
		cols: 220,
		rows: 24,
	}
	if filename != "" {
		e.filename = filename
		e.bufName = filename
		if c, ok := fakeFiles[filename]; ok {
			e.lines = strings.Split(strings.ReplaceAll(c, "\r\n", "\n"), "\n")
			if len(e.lines) > 1 && e.lines[len(e.lines)-1] == "" {
				e.lines = e.lines[:len(e.lines)-1]
			}
		} else {
			e.lines = []string{""}
		}
	} else {
		e.bufName = "*scratch*"
		e.lines = []string{
			";; This buffer is for text that is not saved, and for Lisp evaluation.",
			";; To create a file, visit it with C-x C-f and enter text in its buffer.",
			"",
		}
	}
	return e
}

// ── Input ─────────────────────────────────────────────────────────────────────

// rawTimeout reads one byte with a deadline. Returns (byte, connected, timedOut).
func (e *emacsEditor) rawTimeout(d time.Duration) (byte, bool, bool) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case b, ok := <-e.s.rawIn:
		return b, ok, false
	case <-e.s.done:
		return 0, false, false
	case <-timer.C:
		return 0, true, true
	}
}

// readKey reads one logical keypress.
// Returns (keycode, isMeta, alive).
// Special keys use the vk* constants from vim.go; printable/control chars are their ASCII value.
// ESC followed by a key within 50 ms is returned as (key, meta=true).
func (e *emacsEditor) readKey() (int, bool, bool) {
	b, ok := e.s.readRaw()
	if !ok {
		return -1, false, false
	}
	if b != 0x1b {
		return int(b), false, true
	}
	// ESC: peek with 50 ms timeout to distinguish Meta+key from bare ESC.
	b2, ok2, timedOut := e.rawTimeout(50 * time.Millisecond)
	if !ok2 {
		return -1, false, false
	}
	if timedOut {
		return 0x1b, false, true // bare ESC
	}
	if b2 == '[' || b2 == 'O' {
		// Arrow / function key sequence
		b3, ok3, to3 := e.rawTimeout(50 * time.Millisecond)
		if !ok3 || to3 {
			return 0x1b, false, true
		}
		switch b3 {
		case 'A':
			return vkUp, false, true
		case 'B':
			return vkDown, false, true
		case 'C':
			return vkRight, false, true
		case 'D':
			return vkLeft, false, true
		case 'H':
			return vkHome, false, true
		case 'F':
			return vkEnd, false, true
		}
		if b3 >= '1' && b3 <= '9' {
			b4, ok4, _ := e.rawTimeout(50 * time.Millisecond)
			if ok4 && b4 == '~' {
				switch b3 {
				case '5':
					return vkPgUp, false, true
				case '6':
					return vkPgDn, false, true
				case '3':
					return vkDel, false, true
				case '1':
					return vkHome, false, true
				case '4':
					return vkEnd, false, true
				}
			}
		}
		return 0x1b, false, true
	}
	// ESC + key = Meta+key
	return int(b2), true, true
}

// ── Rendering ─────────────────────────────────────────────────────────────────

func (e *emacsEditor) moveTo(row, col int) { e.s.write(fmt.Sprintf("\x1b[%d;%dH", row, col)) }
func (e *emacsEditor) contentRows() int    { return e.rows - 2 }

func (e *emacsEditor) render() {
	e.s.write("\x1b[?25l")
	e.drawContent()
	e.drawModeLine()
	e.drawEchoArea()
	e.placeCursor()
	e.s.write("\x1b[?25h")
}

func (e *emacsEditor) drawContent() {
	cr := e.contentRows()
	for i := 0; i < cr; i++ {
		e.moveTo(i+1, 1)
		e.s.write("\x1b[2K")
		lineIdx := e.topRow + i
		if lineIdx < len(e.lines) {
			line := e.lines[lineIdx]
			if len(line) > e.cols {
				line = line[:e.cols]
			}
			e.s.write(line)
		}
		// Emacs shows blank lines (no ~ like vim) past the end of buffer
	}
}

func (e *emacsEditor) drawModeLine() {
	e.moveTo(e.rows-1, 1)
	e.s.write("\x1b[2K\x1b[7m")

	modStr := "----"
	if e.modified {
		modStr = "**--"
	}
	prefix := "-UUU:" + modStr + "  "

	// Scroll position
	cr := e.contentRows()
	var pct string
	switch {
	case len(e.lines) <= cr:
		pct = "All"
	case e.topRow == 0:
		pct = "Top"
	case e.topRow+cr >= len(e.lines):
		pct = "Bot"
	default:
		p := e.topRow * 100 / (len(e.lines) - cr)
		pct = fmt.Sprintf("%2d%%", p)
	}

	lineNum := fmt.Sprintf("L%d", e.curRow+1)
	mode := e.guessMode()
	right := fmt.Sprintf("  %s %s   %s", pct, lineNum, mode)

	// Fill between bufName and right with dashes
	avail := e.cols - len(prefix) - len(e.bufName) - len(right)
	if avail < 2 {
		avail = 2
	}
	line := prefix + e.bufName + strings.Repeat("-", avail) + right
	if len(line) < e.cols {
		line += strings.Repeat("-", e.cols-len(line))
	}
	if len(line) > e.cols {
		line = line[:e.cols]
	}
	e.s.write(line + "\x1b[m")
}

func (e *emacsEditor) guessMode() string {
	switch {
	case strings.HasSuffix(e.filename, ".py"):
		return "(Python)"
	case strings.HasSuffix(e.filename, ".go"):
		return "(Go)"
	case strings.HasSuffix(e.filename, ".sh"):
		return "(Shell-script)"
	case strings.HasSuffix(e.filename, ".json"):
		return "(JavaScript)"
	case strings.HasSuffix(e.filename, ".conf"), strings.HasSuffix(e.filename, ".cfg"):
		return "(Conf)"
	case strings.HasSuffix(e.filename, ".md"):
		return "(Markdown)"
	case e.filename == "":
		return "(Lisp Interaction)"
	default:
		return "(Fundamental)"
	}
}

func (e *emacsEditor) drawEchoArea() {
	e.moveTo(e.rows, 1)
	e.s.write("\x1b[2K")
	if e.msg != "" {
		e.s.write(e.msg)
	}
}

func (e *emacsEditor) placeCursor() {
	e.moveTo(e.curRow-e.topRow+1, e.curCol+1)
}

// ── Scroll / Clamp ────────────────────────────────────────────────────────────

func (e *emacsEditor) ensureVisible() {
	cr := e.contentRows()
	if e.curRow < e.topRow {
		e.topRow = e.curRow
	} else if e.curRow >= e.topRow+cr {
		e.topRow = e.curRow - cr + 1
	}
	if e.topRow < 0 {
		e.topRow = 0
	}
}

// clamp keeps curCol within the current line (insert-mode style: 0..len).
func (e *emacsEditor) clamp() {
	if e.curRow < 0 {
		e.curRow = 0
	}
	if e.curRow >= len(e.lines) {
		e.curRow = len(e.lines) - 1
	}
	if e.curCol > len(e.lines[e.curRow]) {
		e.curCol = len(e.lines[e.curRow])
	}
	if e.curCol < 0 {
		e.curCol = 0
	}
}

// ── Editing operations ────────────────────────────────────────────────────────

func (e *emacsEditor) insertChar(b byte) {
	row := e.lines[e.curRow]
	e.lines[e.curRow] = row[:e.curCol] + string(b) + row[e.curCol:]
	e.curCol++
	e.modified = true
}

func (e *emacsEditor) insertNewline() {
	row := e.lines[e.curRow]
	before, after := row[:e.curCol], row[e.curCol:]
	e.lines[e.curRow] = before
	newLines := make([]string, len(e.lines)+1)
	copy(newLines, e.lines[:e.curRow+1])
	newLines[e.curRow+1] = after
	copy(newLines[e.curRow+2:], e.lines[e.curRow+1:])
	e.lines = newLines
	e.curRow++
	e.curCol = 0
	e.modified = true
}

func (e *emacsEditor) deleteBackward() {
	if e.curCol > 0 {
		row := e.lines[e.curRow]
		e.lines[e.curRow] = row[:e.curCol-1] + row[e.curCol:]
		e.curCol--
		e.modified = true
	} else if e.curRow > 0 {
		prev := e.lines[e.curRow-1]
		e.curCol = len(prev)
		e.lines[e.curRow-1] = prev + e.lines[e.curRow]
		e.lines = append(e.lines[:e.curRow], e.lines[e.curRow+1:]...)
		e.curRow--
		e.modified = true
	}
}

func (e *emacsEditor) deleteForward() {
	row := e.lines[e.curRow]
	if e.curCol < len(row) {
		e.lines[e.curRow] = row[:e.curCol] + row[e.curCol+1:]
		e.modified = true
	} else if e.curRow < len(e.lines)-1 {
		// Join with next line
		e.lines[e.curRow] = row + e.lines[e.curRow+1]
		e.lines = append(e.lines[:e.curRow+1], e.lines[e.curRow+2:]...)
		e.modified = true
	}
}

func (e *emacsEditor) killLine() {
	row := e.lines[e.curRow]
	if e.curCol < len(row) {
		e.killRing = row[e.curCol:]
		e.lines[e.curRow] = row[:e.curCol]
		e.modified = true
	} else if e.curRow < len(e.lines)-1 {
		// At EOL: kill the newline (join lines)
		e.killRing = "\n"
		e.lines[e.curRow] = row + e.lines[e.curRow+1]
		e.lines = append(e.lines[:e.curRow+1], e.lines[e.curRow+2:]...)
		e.modified = true
	}
}

func (e *emacsEditor) yank() {
	if e.killRing == "" {
		e.msg = "Kill ring is empty"
		return
	}
	parts := strings.Split(e.killRing, "\n")
	for i, part := range parts {
		for j := 0; j < len(part); j++ {
			if part[j] >= 0x20 {
				e.insertChar(part[j])
			}
		}
		if i < len(parts)-1 {
			e.insertNewline()
		}
	}
}

func (e *emacsEditor) wordForward() {
	row := e.lines[e.curRow]
	col := e.curCol
	for col < len(row) && !vimIsWord(row[col]) {
		col++
	}
	for col < len(row) && vimIsWord(row[col]) {
		col++
	}
	if col >= len(row) && e.curRow < len(e.lines)-1 {
		e.curRow++
		e.curCol = 0
		return
	}
	e.curCol = col
}

func (e *emacsEditor) wordBack() {
	col := e.curCol
	if col == 0 {
		if e.curRow > 0 {
			e.curRow--
			e.curCol = len(e.lines[e.curRow])
		}
		return
	}
	col--
	row := e.lines[e.curRow]
	for col > 0 && !vimIsWord(row[col]) {
		col--
	}
	for col > 0 && vimIsWord(row[col-1]) {
		col--
	}
	e.curCol = col
}

func (e *emacsEditor) killWord() {
	row := e.lines[e.curRow]
	col := e.curCol
	for col < len(row) && !vimIsWord(row[col]) {
		col++
	}
	for col < len(row) && vimIsWord(row[col]) {
		col++
	}
	e.killRing = row[e.curCol:col]
	e.lines[e.curRow] = row[:e.curCol] + row[col:]
	e.modified = true
}

func (e *emacsEditor) killWordBack() {
	row := e.lines[e.curRow]
	orig := e.curCol
	col := orig
	if col == 0 {
		return
	}
	col--
	for col > 0 && !vimIsWord(row[col]) {
		col--
	}
	for col > 0 && vimIsWord(row[col-1]) {
		col--
	}
	e.killRing = row[col:orig]
	e.lines[e.curRow] = row[:col] + row[orig:]
	e.curCol = col
	e.modified = true
}

// ── Minibuffer / Prompts ──────────────────────────────────────────────────────

// readMiniBuffer shows prompt in the echo area and reads a line of input.
// Returns ("", true) if cancelled via Ctrl+G or ESC.
func (e *emacsEditor) readMiniBuffer(prompt string) (string, bool) {
	e.moveTo(e.rows, 1)
	e.s.write("\x1b[2K\x1b[?25h" + prompt)
	var buf []byte
	for {
		b, ok := e.s.readRaw()
		if !ok {
			return "", true
		}
		switch {
		case b == '\r' || b == '\n':
			return string(buf), false
		case b == 0x07 || b == 0x1b: // Ctrl+G or ESC = cancel
			e.msg = "Quit"
			return "", true
		case b == 0x7f || b == 0x08:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				e.s.write("\b \b")
			} else {
				e.msg = "Quit"
				return "", true
			}
		default:
			if b >= 0x20 {
				buf = append(buf, b)
				e.s.write(string([]byte{b}))
			}
		}
	}
}

// ── Save ──────────────────────────────────────────────────────────────────────

func (e *emacsEditor) doSave(fname string) {
	if fname == "" {
		fname = e.filename
	}
	if fname == "" {
		var cancelled bool
		fname, cancelled = e.readMiniBuffer("File to save in: ")
		if cancelled || fname == "" {
			return
		}
	}
	e.filename = fname
	e.bufName = fname
	time.Sleep(e.s.jitter(60, 200))
	n := 0
	for _, l := range e.lines {
		n += len(l) + 1
	}
	e.modified = false
	e.msg = fmt.Sprintf("Wrote %s", fname)
	e.s.slog.log("EMACS_SAVE: %s (%d lines)", fname, len(e.lines))
}

// ── C-x prefix ────────────────────────────────────────────────────────────────

// handleCtrlX reads and handles the second key of a C-x chord.
// Returns true if the editor should exit.
func (e *emacsEditor) handleCtrlX() bool {
	e.moveTo(e.rows, 1)
	e.s.write("\x1b[2KC-x ")

	key, meta, ok := e.readKey()
	if !ok {
		return true
	}
	_ = meta

	switch key {
	case 0x03: // C-x C-c = save-buffers-kill-emacs
		if e.modified {
			ans, cancelled := e.readMiniBuffer(
				fmt.Sprintf("Save file %s? (y, n, !, ., q, C-r, d or C-h) ", e.filename))
			if cancelled {
				return false
			}
			if ans == "y" || ans == "Y" || ans == "!" {
				e.doSave("")
			}
		}
		return true

	case 0x13: // C-x C-s = save-buffer
		e.doSave("")

	case 0x17: // C-x C-w = write-file
		fname, cancelled := e.readMiniBuffer("Write file: ")
		if !cancelled && fname != "" {
			e.doSave(fname)
		}

	case 0x06: // C-x C-f = find-file
		fname, cancelled := e.readMiniBuffer("Find file: ")
		if !cancelled && fname != "" {
			if !strings.HasPrefix(fname, "/") {
				fname = e.s.cwd + "/" + fname
			}
			e.filename = fname
			e.bufName = fname
			if c, ok2 := fakeFiles[fname]; ok2 {
				e.lines = strings.Split(strings.ReplaceAll(c, "\r\n", "\n"), "\n")
				if len(e.lines) > 1 && e.lines[len(e.lines)-1] == "" {
					e.lines = e.lines[:len(e.lines)-1]
				}
				e.msg = fmt.Sprintf(`"%s" %dL`, fname, len(e.lines))
			} else {
				e.lines = []string{""}
				e.msg = "(New file)"
			}
			e.curRow, e.curCol, e.topRow = 0, 0, 0
			e.modified = false
		}

	case int('b'): // C-x b = switch-to-buffer
		name, cancelled := e.readMiniBuffer("Switch to buffer (default *scratch*): ")
		if !cancelled {
			if name == "" {
				name = "*scratch*"
			}
			e.msg = fmt.Sprintf("No buffer named \"%s\"", name)
		}

	case int('k'): // C-x k = kill-buffer
		_, cancelled := e.readMiniBuffer(fmt.Sprintf("Kill buffer (default %s): ", e.bufName))
		if !cancelled {
			e.msg = fmt.Sprintf("Killed buffer %s", e.bufName)
		}

	case int('1'): // C-x 1 = delete-other-windows (no-op)
		// no-op, single-window

	case int('2'): // C-x 2 = split-window-below (fake)
		e.msg = "[Split window: only one window supported]"

	case int('0'): // C-x 0 = delete-window
		e.msg = "Quit"

	case int('u'): // C-x u = undo
		e.msg = "Undo! (No further undo information)"

	case 0x18: // C-x C-x = exchange-point-and-mark
		e.msg = "Mark activated"

	default:
		e.msg = fmt.Sprintf("C-x %s is undefined", string(rune(key)))
	}
	return false
}

// ── Meta key bindings ─────────────────────────────────────────────────────────

// handleMeta handles a Meta+key combination. Returns true if editor should exit.
func (e *emacsEditor) handleMeta(key int) bool {
	cr := e.contentRows()
	switch key {
	case int('f'), int('F'):
		e.wordForward()
	case int('b'), int('B'):
		e.wordBack()
	case int('d'), int('D'):
		e.killWord()
	case 0x7f, 0x08: // M-DEL / M-Backspace = backward-kill-word
		e.killWordBack()
	case int('v'), int('V'): // M-v = scroll-down (page up)
		e.curRow -= cr
		if e.curRow < 0 {
			e.curRow = 0
		}
		e.clamp()
	case int('w'), int('W'): // M-w = kill-ring-save (copy current line as approximation)
		e.killRing = e.lines[e.curRow]
		e.msg = "Mark deactivated"
	case int('<'): // M-< = beginning-of-buffer
		e.curRow, e.curCol = 0, 0
	case int('>'): // M-> = end-of-buffer
		e.curRow = len(e.lines) - 1
		e.curCol = len(e.lines[e.curRow])
	case int('x'), int('X'): // M-x = execute-extended-command
		return e.handleMX()
	case int('g'), int('G'): // M-g (goto-line prefix; M-g g = goto-line)
		lineStr, cancelled := e.readMiniBuffer("Goto line: ")
		if !cancelled {
			var n int
			fmt.Sscanf(lineStr, "%d", &n)
			if n > 0 {
				e.curRow = n - 1
				if e.curRow >= len(e.lines) {
					e.curRow = len(e.lines) - 1
				}
				e.curCol = 0
			}
		}
	case int('%'): // M-% = query-replace
		from, cancelled := e.readMiniBuffer("Query replace: ")
		if !cancelled {
			to, cancelled2 := e.readMiniBuffer(fmt.Sprintf("Query replace %s with: ", from))
			if !cancelled2 && to != "" {
				e.modified = true
				e.msg = "Replaced 1 occurrence"
			}
		}
	case int('/'): // M-/ = dabbrev-expand (fake)
		e.msg = "No dynamic expansion for \"\" found"
	case int('q'): // M-q = fill-paragraph (fake)
		e.msg = "Filling paragraph..."
	case int('u'): // M-u = upcase-word
		row := e.lines[e.curRow]
		col := e.curCol
		for col < len(row) && !vimIsWord(row[col]) {
			col++
		}
		start := col
		for col < len(row) && vimIsWord(row[col]) {
			col++
		}
		upper := strings.ToUpper(row[start:col])
		e.lines[e.curRow] = row[:start] + upper + row[col:]
		e.curCol = col
		e.modified = true
	case int('l'), int('L'): // M-l = downcase-word
		row := e.lines[e.curRow]
		col := e.curCol
		for col < len(row) && !vimIsWord(row[col]) {
			col++
		}
		start := col
		for col < len(row) && vimIsWord(row[col]) {
			col++
		}
		lower := strings.ToLower(row[start:col])
		e.lines[e.curRow] = row[:start] + lower + row[col:]
		e.curCol = col
		e.modified = true
	case 0x1b: // ESC ESC ESC = keyboard-quit
		e.msg = "Quit"
	}
	return false
}

// ── M-x extended commands ─────────────────────────────────────────────────────

// handleMX handles M-x extended-command dispatch. Returns true if editor should exit.
func (e *emacsEditor) handleMX() bool {
	cmd, cancelled := e.readMiniBuffer("M-x ")
	if cancelled {
		return false
	}
	cmd = strings.TrimSpace(strings.ToLower(cmd))
	switch cmd {
	case "save-buffer":
		e.doSave("")
	case "write-file":
		fname, c := e.readMiniBuffer("Write file: ")
		if !c && fname != "" {
			e.doSave(fname)
		}
	case "kill-emacs":
		return true
	case "find-file":
		fname, c := e.readMiniBuffer("Find file: ")
		if !c && fname != "" {
			if !strings.HasPrefix(fname, "/") {
				fname = e.s.cwd + "/" + fname
			}
			e.filename = fname
			e.bufName = fname
			if content, ok := fakeFiles[fname]; ok {
				e.lines = strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
				if len(e.lines) > 1 && e.lines[len(e.lines)-1] == "" {
					e.lines = e.lines[:len(e.lines)-1]
				}
			} else {
				e.lines = []string{""}
				e.msg = "(New file)"
			}
			e.curRow, e.curCol, e.topRow = 0, 0, 0
			e.modified = false
		}
	case "goto-line":
		lineStr, c := e.readMiniBuffer("Goto line: ")
		if !c {
			var n int
			fmt.Sscanf(lineStr, "%d", &n)
			if n > 0 {
				e.curRow = n - 1
				if e.curRow >= len(e.lines) {
					e.curRow = len(e.lines) - 1
				}
				e.curCol = 0
			}
		}
	case "replace-string":
		from, c := e.readMiniBuffer("Replace string: ")
		if !c {
			_, c2 := e.readMiniBuffer(fmt.Sprintf("Replace string %s with: ", from))
			if !c2 {
				e.modified = true
				e.msg = "Replaced 1 occurrence"
			}
		}
	case "query-replace":
		from, c := e.readMiniBuffer("Query replace: ")
		if !c {
			_, c2 := e.readMiniBuffer(fmt.Sprintf("Query replace %s with: ", from))
			if !c2 {
				e.modified = true
				e.msg = "Replaced 1 occurrence"
			}
		}
	case "line-number-mode", "linum-mode", "display-line-numbers-mode":
		e.msg = "Line numbers toggled"
	case "whitespace-mode":
		e.msg = "whitespace-mode enabled"
	case "undo":
		e.msg = "Undo! (No further undo information)"
	case "indent-region":
		e.msg = "Indenting region..."
	case "comment-region":
		e.modified = true
		e.msg = "Commented region"
	case "eval-buffer":
		e.msg = "Buffer evaluated"
	case "eval-region":
		e.msg = "Region evaluated"
	case "shell":
		e.msg = "Shell: *shell*"
	case "eshell":
		e.msg = "Welcome to the Emacs shell"
	case "term", "ansi-term":
		e.msg = "Terminal: /bin/bash"
	case "list-packages":
		e.msg = "Contacting elpa.gnu.org... done"
	case "package-install":
		pkg, c := e.readMiniBuffer("Install package: ")
		if !c {
			time.Sleep(e.s.jitter(400, 800))
			e.msg = fmt.Sprintf("Package `%s' installed", pkg)
		}
	case "describe-key", "describe-function", "describe-variable":
		e.msg = fmt.Sprintf("You can run the command `%s' with ...", cmd)
	case "set-fill-column":
		e.msg = "fill-column set to 70"
	default:
		if cmd != "" {
			e.msg = fmt.Sprintf("Symbol's function definition is void: %s", cmd)
		}
	}
	return false
}

// ── Isearch ───────────────────────────────────────────────────────────────────

func (e *emacsEditor) handleIsearch(forward bool) {
	dir := "I-search"
	if !forward {
		dir = "I-search backward"
	}
	e.moveTo(e.rows, 1)
	e.s.write("\x1b[2K" + dir + ": ")

	var query []byte
	for {
		b, ok := e.s.readRaw()
		if !ok {
			return
		}
		switch {
		case b == '\r' || b == '\n':
			// Confirm search
			if len(query) > 0 {
				e.msg = fmt.Sprintf("Failing I-search: %s", string(query))
			}
			return
		case b == 0x13 || b == 0x12: // C-s / C-r again: cycle (fake)
			if len(query) > 0 {
				e.msg = fmt.Sprintf("Failing I-search: %s", string(query))
			}
			return
		case b == 0x07 || b == 0x1b: // Ctrl+G / ESC = cancel
			e.msg = "Quit"
			return
		case b == 0x7f || b == 0x08:
			if len(query) > 0 {
				query = query[:len(query)-1]
				e.moveTo(e.rows, 1)
				e.s.write("\x1b[2K" + dir + ": " + string(query))
			}
		default:
			if b >= 0x20 {
				query = append(query, b)
				e.s.write(string([]byte{b}))
			}
		}
	}
}

// ── Main entry ────────────────────────────────────────────────────────────────

func (s *fakeShell) runEmacs(args string) {
	filename := strings.TrimSpace(args)
	if filename != "" && !strings.HasPrefix(filename, "/") {
		filename = s.cwd + "/" + filename
	}
	if filename != "" && honeytokenFiles[filename] {
		s.logHoneytoken(filename)
	}

	e := newEmacsEditor(s, filename)

	s.write("\x1b[?1049h\x1b[2J\x1b[H")
	defer s.write("\x1b[?1049l")

	// Welcome / open message
	if filename != "" {
		if _, ok := fakeFiles[filename]; ok {
			n := 0
			for _, l := range e.lines {
				n += len(l) + 1
			}
			e.msg = fmt.Sprintf(`Wrote %d chars to "%s"`, n, filename)
		} else {
			e.msg = "(New file)"
		}
	} else {
		e.msg = fmt.Sprintf("Welcome to GNU Emacs %s.", emacsVersion)
	}

	e.render()

	for {
		e.msg = ""

		key, meta, ok := e.readKey()
		if !ok {
			return
		}

		if meta {
			if e.handleMeta(key) {
				return
			}
			e.ensureVisible()
			e.render()
			continue
		}

		var exit bool

		switch key {
		// ── Navigation ─────────────────────────────────────────────────────────
		case 0x01: // C-a = beginning-of-line
			e.curCol = 0
		case 0x05: // C-e = end-of-line
			e.curCol = len(e.lines[e.curRow])
		case 0x06, vkRight: // C-f / Right = forward-char
			if e.curCol < len(e.lines[e.curRow]) {
				e.curCol++
			} else if e.curRow < len(e.lines)-1 {
				e.curRow++
				e.curCol = 0
			}
		case 0x02, vkLeft: // C-b / Left = backward-char
			if e.curCol > 0 {
				e.curCol--
			} else if e.curRow > 0 {
				e.curRow--
				e.curCol = len(e.lines[e.curRow])
			}
		case 0x0e, vkDown: // C-n / Down = next-line
			if e.curRow < len(e.lines)-1 {
				e.curRow++
				e.clamp()
			}
		case 0x10, vkUp: // C-p / Up = previous-line
			if e.curRow > 0 {
				e.curRow--
				e.clamp()
			}
		case vkHome:
			e.curCol = 0
		case vkEnd:
			e.curCol = len(e.lines[e.curRow])
		case 0x16, vkPgDn: // C-v / PgDn = scroll-up (page down in emacs terminology)
			cr := e.contentRows()
			e.curRow += cr
			if e.curRow >= len(e.lines) {
				e.curRow = len(e.lines) - 1
			}
			e.clamp()
		case vkPgUp:
			cr := e.contentRows()
			e.curRow -= cr
			if e.curRow < 0 {
				e.curRow = 0
			}
			e.clamp()

		// ── Editing ────────────────────────────────────────────────────────────
		case 0x08, 0x7f: // Backspace / C-h (delete-backward-char)
			e.deleteBackward()
		case 0x04, vkDel: // C-d / Del = delete-char
			e.deleteForward()
		case 0x0b: // C-k = kill-line
			e.killLine()
		case 0x19: // C-y = yank
			e.yank()
		case int('\r'), int('\n'):
			e.insertNewline()
		case 0x09: // Tab = indent (insert spaces)
			for i := 0; i < 4; i++ {
				e.insertChar(' ')
			}

		// ── Commands ───────────────────────────────────────────────────────────
		case 0x07: // C-g = keyboard-quit
			e.msg = "Quit"
		case 0x0c: // C-l = recenter-top-bottom
			e.s.write("\x1b[2J")
		case 0x13: // C-s = isearch-forward
			e.handleIsearch(true)
		case 0x12: // C-r = isearch-backward
			e.handleIsearch(false)
		case 0x18: // C-x = prefix key
			exit = e.handleCtrlX()
		case 0x1f: // C-_ / C-/ = undo
			e.msg = "Undo! (No further undo information)"
		case 0x00: // C-Space / C-@ = set-mark
			e.msg = "Mark set"
		case 0x11: // C-q = quoted-insert (insert next char literally)
			next, ok2 := e.s.readRaw()
			if !ok2 {
				exit = true
				break
			}
			if next >= 0x20 {
				e.insertChar(next)
			}
		case 0x1b: // bare ESC (not followed by another key)
			e.msg = "ESC"

		default:
			if key >= 0x20 && key <= 0x7e {
				e.insertChar(byte(key))
			}
		}

		if exit {
			return
		}
		e.ensureVisible()
		e.render()
	}
}
