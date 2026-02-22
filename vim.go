package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ── Types ──────────────────────────────────────────────────────────────────────

type vimMode int

const (
	vimNormal  vimMode = iota
	vimInsert
	vimCommand
)

// Special key codes returned by readVimKey (above 0xFF to avoid ASCII collision).
const (
	vkUp    = 0x101
	vkDown  = 0x102
	vkLeft  = 0x103
	vkRight = 0x104
	vkHome  = 0x105
	vkEnd   = 0x106
	vkPgUp  = 0x107
	vkPgDn  = 0x108
	vkDel   = 0x109
)

type vimEditor struct {
	s        *fakeShell
	filename string
	lines    []string
	curRow   int
	curCol   int
	topRow   int
	modified bool
	mode     vimMode
	cmdBuf   string   // accumulated :command text
	yankBuf  []string // lines yanked by dd/yy
	msg      string   // shown in command line for one iteration
	lineNums bool
	cols     int
	rows     int
	pending  rune // first char of two-char sequences: g,d,y,Z,r,c
}

// ── Constructor ───────────────────────────────────────────────────────────────

func newVimEditor(s *fakeShell, filename string) *vimEditor {
	v := &vimEditor{
		s:        s,
		filename: filename,
		cols:     220,
		rows:     24,
	}
	var content string
	if filename != "" {
		if c, ok := fakeFiles[filename]; ok {
			content = c
		}
	}
	if content == "" {
		v.lines = []string{""}
	} else {
		v.lines = strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
		if len(v.lines) > 1 && v.lines[len(v.lines)-1] == "" {
			v.lines = v.lines[:len(v.lines)-1]
		}
	}
	return v
}

// ── Input ─────────────────────────────────────────────────────────────────────

// rawTimeout reads one byte from rawIn with a deadline. Returns (byte, ok, timedOut).
func (v *vimEditor) rawTimeout(d time.Duration) (byte, bool, bool) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case b, ok := <-v.s.rawIn:
		return b, ok, false
	case <-v.s.done:
		return 0, false, false
	case <-timer.C:
		return 0, true, true
	}
}

// readVimKey reads one logical keypress, translating escape sequences into vk* constants.
// For bare ESC (e.g. exit insert mode) it uses a 50 ms timeout before declaring it lone.
func (v *vimEditor) readVimKey() (int, bool) {
	b, ok := v.s.readRaw()
	if !ok {
		return -1, false
	}
	if b != 0x1b {
		return int(b), true
	}
	// Peek for CSI '[' with 50 ms timeout — bare ESC arrives alone.
	b2, ok2, timedOut := v.rawTimeout(50 * time.Millisecond)
	if !ok2 {
		return -1, false
	}
	if timedOut || (b2 != '[' && b2 != 'O') {
		return 0x1b, true // bare ESC
	}
	b3, ok3, to3 := v.rawTimeout(50 * time.Millisecond)
	if !ok3 || to3 {
		return 0x1b, true
	}
	switch b3 {
	case 'A':
		return vkUp, true
	case 'B':
		return vkDown, true
	case 'C':
		return vkRight, true
	case 'D':
		return vkLeft, true
	case 'H':
		return vkHome, true
	case 'F':
		return vkEnd, true
	}
	// Sequences ending in ~ (PgUp=5, PgDn=6, Del=3, Home=1, End=4)
	if b3 >= '1' && b3 <= '9' {
		b4, ok4, _ := v.rawTimeout(50 * time.Millisecond)
		if ok4 && b4 == '~' {
			switch b3 {
			case '5':
				return vkPgUp, true
			case '6':
				return vkPgDn, true
			case '3':
				return vkDel, true
			case '1':
				return vkHome, true
			case '4':
				return vkEnd, true
			}
		}
	}
	return 0x1b, true
}

// ── Rendering ─────────────────────────────────────────────────────────────────

func (v *vimEditor) moveTo(row, col int) { v.s.write(fmt.Sprintf("\x1b[%d;%dH", row, col)) }
func (v *vimEditor) contentRows() int    { return v.rows - 2 }

func (v *vimEditor) gutterWidth() int {
	if !v.lineNums {
		return 0
	}
	d := len(fmt.Sprintf("%d", len(v.lines)))
	if d < 4 {
		d = 4
	}
	return d + 1
}

func (v *vimEditor) render() {
	v.s.write("\x1b[?25l")
	v.drawContent()
	v.drawStatusLine()
	v.drawCmdLine()
	v.placeCursor()
	v.s.write("\x1b[?25h")
}

func (v *vimEditor) drawContent() {
	cr := v.contentRows()
	gw := v.gutterWidth()
	for i := 0; i < cr; i++ {
		v.moveTo(i+1, 1)
		v.s.write("\x1b[2K")
		lineIdx := v.topRow + i
		if lineIdx < len(v.lines) {
			if v.lineNums {
				v.s.write(fmt.Sprintf("\x1b[90m%*d \x1b[m", gw-1, lineIdx+1))
			}
			line := v.lines[lineIdx]
			avail := v.cols - gw
			if avail > 0 && len(line) > avail {
				line = line[:avail]
			}
			v.s.write(line)
		} else {
			v.s.write("\x1b[34m~\x1b[m")
		}
	}
}

func (v *vimEditor) drawStatusLine() {
	v.moveTo(v.rows-1, 1)
	v.s.write("\x1b[2K\x1b[7m")

	fname := v.filename
	if fname == "" {
		fname = "[No Name]"
	} else {
		fname = `"` + fname + `"`
	}
	if v.modified {
		fname += " [+]"
	}

	row := v.curRow + 1
	col := v.curCol + 1
	right := fmt.Sprintf("%d,%-4d%s", row, col, v.pctStr())

	pad := v.cols - len(fname) - len(right)
	if pad < 1 {
		pad = 1
	}
	line := fname + strings.Repeat(" ", pad) + right
	if len(line) > v.cols {
		line = line[:v.cols]
	}
	v.s.write(line + "\x1b[m")
}

func (v *vimEditor) pctStr() string {
	cr := v.contentRows()
	if len(v.lines) <= cr {
		return "  All"
	}
	if v.topRow == 0 {
		return "  Top"
	}
	if v.topRow+cr >= len(v.lines) {
		return "  Bot"
	}
	p := v.topRow * 100 / (len(v.lines) - cr)
	return fmt.Sprintf(" %2d%%", p)
}

func (v *vimEditor) drawCmdLine() {
	v.moveTo(v.rows, 1)
	v.s.write("\x1b[2K")
	switch v.mode {
	case vimInsert:
		v.s.write("\x1b[1m-- INSERT --\x1b[m")
	case vimCommand:
		v.s.write(":" + v.cmdBuf)
	default:
		v.s.write(v.msg)
	}
}

func (v *vimEditor) placeCursor() {
	gw := v.gutterWidth()
	if v.mode == vimCommand {
		v.moveTo(v.rows, len(v.cmdBuf)+2)
		return
	}
	v.moveTo(v.curRow-v.topRow+1, v.curCol+gw+1)
}

// ── Scroll / clamp ────────────────────────────────────────────────────────────

func (v *vimEditor) ensureVisible() {
	cr := v.contentRows()
	if v.curRow < v.topRow {
		v.topRow = v.curRow
	} else if v.curRow >= v.topRow+cr {
		v.topRow = v.curRow - cr + 1
	}
	if v.topRow < 0 {
		v.topRow = 0
	}
}

// clampNormal keeps curCol within [0, len-1] (vim normal mode).
func (v *vimEditor) clampNormal() {
	if v.curRow < 0 {
		v.curRow = 0
	}
	if v.curRow >= len(v.lines) {
		v.curRow = len(v.lines) - 1
	}
	max := len(v.lines[v.curRow]) - 1
	if max < 0 {
		max = 0
	}
	if v.curCol > max {
		v.curCol = max
	}
}

// clampInsert keeps curCol within [0, len] (insert mode allows one past end).
func (v *vimEditor) clampInsert() {
	if v.curRow < 0 {
		v.curRow = 0
	}
	if v.curRow >= len(v.lines) {
		v.curRow = len(v.lines) - 1
	}
	if v.curCol > len(v.lines[v.curRow]) {
		v.curCol = len(v.lines[v.curRow])
	}
}

// ── Editing helpers ───────────────────────────────────────────────────────────

func (v *vimEditor) insertChar(b byte) {
	row := v.lines[v.curRow]
	v.lines[v.curRow] = row[:v.curCol] + string(b) + row[v.curCol:]
	v.curCol++
	v.modified = true
}

func (v *vimEditor) backspace() {
	if v.curCol > 0 {
		row := v.lines[v.curRow]
		v.lines[v.curRow] = row[:v.curCol-1] + row[v.curCol:]
		v.curCol--
		v.modified = true
	} else if v.curRow > 0 {
		prev := v.lines[v.curRow-1]
		v.curCol = len(prev)
		v.lines[v.curRow-1] = prev + v.lines[v.curRow]
		v.lines = append(v.lines[:v.curRow], v.lines[v.curRow+1:]...)
		v.curRow--
		v.modified = true
	}
}

func (v *vimEditor) insertNewline() {
	row := v.lines[v.curRow]
	before, after := row[:v.curCol], row[v.curCol:]
	v.lines[v.curRow] = before
	newLines := make([]string, len(v.lines)+1)
	copy(newLines, v.lines[:v.curRow+1])
	newLines[v.curRow+1] = after
	copy(newLines[v.curRow+2:], v.lines[v.curRow+1:])
	v.lines = newLines
	v.curRow++
	v.curCol = 0
	v.modified = true
}

func (v *vimEditor) deleteChar() {
	row := v.lines[v.curRow]
	if len(row) == 0 {
		return
	}
	col := v.curCol
	if col >= len(row) {
		col = len(row) - 1
	}
	v.lines[v.curRow] = row[:col] + row[col+1:]
	v.modified = true
	v.clampNormal()
}

func (v *vimEditor) deleteLine() {
	v.yankBuf = []string{v.lines[v.curRow]}
	if len(v.lines) == 1 {
		v.lines[0] = ""
		v.curCol = 0
	} else {
		v.lines = append(v.lines[:v.curRow], v.lines[v.curRow+1:]...)
		if v.curRow >= len(v.lines) {
			v.curRow = len(v.lines) - 1
		}
	}
	v.clampNormal()
	v.modified = true
	v.msg = "1 line deleted"
}

func (v *vimEditor) yankLine() {
	v.yankBuf = []string{v.lines[v.curRow]}
	v.msg = "1 line yanked"
}

func (v *vimEditor) paste(after bool) {
	if len(v.yankBuf) == 0 {
		return
	}
	at := v.curRow
	if after {
		at++
	}
	tail := make([]string, len(v.lines[at:]))
	copy(tail, v.lines[at:])
	v.lines = append(v.lines[:at], append(v.yankBuf, tail...)...)
	v.curRow = at
	v.curCol = 0
	v.modified = true
}

// ── Word navigation ───────────────────────────────────────────────────────────

func vimIsWord(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func (v *vimEditor) wordForward() {
	row := v.lines[v.curRow]
	col := v.curCol
	if col < len(row) && vimIsWord(row[col]) {
		for col < len(row) && vimIsWord(row[col]) {
			col++
		}
	} else {
		for col < len(row) && !vimIsWord(row[col]) {
			col++
		}
	}
	if col >= len(row) && v.curRow < len(v.lines)-1 {
		v.curRow++
		v.curCol = 0
		return
	}
	v.curCol = col
}

func (v *vimEditor) wordBack() {
	col := v.curCol
	if col == 0 {
		if v.curRow > 0 {
			v.curRow--
			v.curCol = len(v.lines[v.curRow])
			if v.curCol > 0 {
				v.curCol--
			}
		}
		return
	}
	col--
	row := v.lines[v.curRow]
	for col > 0 && !vimIsWord(row[col]) {
		col--
	}
	for col > 0 && vimIsWord(row[col-1]) {
		col--
	}
	v.curCol = col
}

// ── Save / Quit ───────────────────────────────────────────────────────────────

func (v *vimEditor) doSave(fname string) bool {
	if fname == "" {
		fname = v.filename
	}
	if fname == "" {
		v.msg = "E32: No file name"
		return false
	}
	v.filename = fname
	time.Sleep(v.s.jitter(60, 200))
	n := 0
	for _, l := range v.lines {
		n += len(l) + 1
	}
	v.modified = false
	v.msg = fmt.Sprintf(`"%s" %dL, %dB written`, fname, len(v.lines), n)
	v.s.slog.log("VIM_SAVE: %s (%d lines)", fname, len(v.lines))
	return true
}

func (v *vimEditor) canQuit(force bool) bool {
	if v.modified && !force {
		v.msg = "E37: No write since last change (add ! to override)"
		return false
	}
	return true
}

// ── Command execution ─────────────────────────────────────────────────────────

// execCmd handles a :command string. Returns true if the editor should exit.
func (v *vimEditor) execCmd(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	// Line number jump
	if n, err := strconv.Atoi(cmd); err == nil {
		v.curRow = n - 1
		if v.curRow < 0 {
			v.curRow = 0
		}
		if v.curRow >= len(v.lines) {
			v.curRow = len(v.lines) - 1
		}
		v.curCol = 0
		v.ensureVisible()
		return false
	}
	switch {
	case cmd == "q":
		return v.canQuit(false)
	case cmd == "q!" || cmd == "quit!":
		return v.canQuit(true)
	case cmd == "w":
		v.doSave("")
	case strings.HasPrefix(cmd, "w "):
		v.doSave(strings.TrimSpace(cmd[2:]))
	case cmd == "wq" || cmd == "x" || cmd == "wq!" || cmd == "xa":
		v.doSave("")
		return true
	case strings.HasPrefix(cmd, "wq ") || strings.HasPrefix(cmd, "x "):
		v.doSave(strings.TrimSpace(strings.SplitN(cmd, " ", 2)[1]))
		return true
	case cmd == "set number" || cmd == "set nu":
		v.lineNums = true
	case cmd == "set nonumber" || cmd == "set nonu":
		v.lineNums = false
	case strings.HasPrefix(cmd, "set "):
		// accept silently
	case strings.HasPrefix(cmd, "syntax "), strings.HasPrefix(cmd, "colorscheme "):
		// no-op
	case cmd == "noh" || cmd == "nohlsearch":
		// no-op
	case cmd == "help" || cmd == "h" || strings.HasPrefix(cmd, "help "):
		v.msg = `type  :q<CR>  to exit  |  :w<CR>  to write  |  i  to insert  |  /  to search`
	case strings.HasPrefix(cmd, "%s/") || strings.HasPrefix(cmd, "s/"):
		v.modified = true
		v.msg = fmt.Sprintf("%d substitution on %d line", 1, 1)
	case cmd == "retab":
		v.modified = true
		v.msg = fmt.Sprintf("%d line changed", len(v.lines))
	case cmd == "e!":
		v.modified = false
		v.msg = fmt.Sprintf(`"%s" %dL`, v.filename, len(v.lines))
	case strings.HasPrefix(cmd, "e "):
		newFile := strings.TrimSpace(cmd[2:])
		if !strings.HasPrefix(newFile, "/") {
			newFile = v.s.cwd + "/" + newFile
		}
		v.filename = newFile
		if c, ok := fakeFiles[newFile]; ok {
			v.lines = strings.Split(strings.ReplaceAll(c, "\r\n", "\n"), "\n")
			if len(v.lines) > 1 && v.lines[len(v.lines)-1] == "" {
				v.lines = v.lines[:len(v.lines)-1]
			}
		} else {
			v.lines = []string{""}
		}
		v.curRow, v.curCol, v.topRow = 0, 0, 0
		v.modified = false
		v.msg = fmt.Sprintf(`"%s" %dL`, newFile, len(v.lines))
	default:
		v.msg = fmt.Sprintf("E492: Not an editor command: %s", cmd)
	}
	return false
}

// ── Search prompt ─────────────────────────────────────────────────────────────

func (v *vimEditor) handleSearchPrompt(prefix rune) {
	v.moveTo(v.rows, 1)
	v.s.write("\x1b[2K" + string(prefix))
	var query []byte
	for {
		b, ok := v.s.readRaw()
		if !ok {
			return
		}
		if b == '\r' || b == '\n' {
			break
		}
		if b == 0x1b || b == 0x03 {
			return
		}
		if (b == 0x7f || b == 0x08) && len(query) > 0 {
			query = query[:len(query)-1]
			v.s.write("\b \b")
			continue
		}
		if b >= 0x20 {
			query = append(query, b)
			v.s.write(string([]byte{b}))
		}
	}
	if len(query) > 0 {
		v.msg = fmt.Sprintf("E486: Pattern not found: %s", string(query))
	}
}

// ── Normal mode ───────────────────────────────────────────────────────────────

// handleNormalPending handles the second char of a two-char normal command.
// Returns true if the editor should exit.
func (v *vimEditor) handleNormalPending(key int) bool {
	pending := v.pending
	v.pending = 0
	switch pending {
	case 'g':
		if key == int('g') {
			v.curRow, v.curCol = 0, 0
		}
	case 'd':
		if key == int('d') {
			v.deleteLine()
		}
	case 'y':
		if key == int('y') {
			v.yankLine()
		}
	case 'Z':
		switch key {
		case int('Z'):
			v.doSave("")
			return true
		case int('Q'):
			return v.canQuit(true)
		}
	case 'r':
		// Replace char under cursor with the typed character.
		if key >= 0x20 && key <= 0x7e {
			row := v.lines[v.curRow]
			if len(row) > 0 {
				col := v.curCol
				if col >= len(row) {
					col = len(row) - 1
				}
				v.lines[v.curRow] = row[:col] + string(rune(key)) + row[col+1:]
				v.modified = true
			}
		}
	case 'c':
		// cc — change line (clear + insert mode)
		if key == int('c') {
			v.lines[v.curRow] = ""
			v.curCol = 0
			v.modified = true
			v.mode = vimInsert
		}
	}
	return false
}

// handleNormal handles one keypress in normal mode.
// Returns true if the editor should exit.
func (v *vimEditor) handleNormal(key int) bool {
	cr := v.contentRows()
	switch key {
	// ── Movement ──────────────────────────────────────────────────────────────
	case int('h'), vkLeft:
		if v.curCol > 0 {
			v.curCol--
		}
	case int('l'), vkRight:
		if v.curCol < len(v.lines[v.curRow])-1 {
			v.curCol++
		}
	case int('j'), vkDown:
		if v.curRow < len(v.lines)-1 {
			v.curRow++
			v.clampNormal()
		}
	case int('k'), vkUp:
		if v.curRow > 0 {
			v.curRow--
			v.clampNormal()
		}
	case int('0'), vkHome:
		v.curCol = 0
	case int('$'), vkEnd:
		v.curCol = len(v.lines[v.curRow]) - 1
		if v.curCol < 0 {
			v.curCol = 0
		}
	case int('^'):
		row := v.lines[v.curRow]
		for i := 0; i < len(row); i++ {
			if row[i] != ' ' && row[i] != '\t' {
				v.curCol = i
				break
			}
		}
	case int('G'):
		v.curRow = len(v.lines) - 1
		v.clampNormal()
	case int('w'):
		v.wordForward()
		v.clampNormal()
	case int('b'):
		v.wordBack()
	case int('e'):
		row := v.lines[v.curRow]
		col := v.curCol
		for col < len(row)-1 && !vimIsWord(row[col]) {
			col++
		}
		for col < len(row)-1 && vimIsWord(row[col+1]) {
			col++
		}
		v.curCol = col
	case 0x06: // Ctrl+F — page down
		v.curRow += cr
		if v.curRow >= len(v.lines) {
			v.curRow = len(v.lines) - 1
		}
		v.clampNormal()
	case 0x02: // Ctrl+B — page up
		v.curRow -= cr
		if v.curRow < 0 {
			v.curRow = 0
		}
		v.clampNormal()
	case 0x04: // Ctrl+D — half page down
		v.curRow += cr / 2
		if v.curRow >= len(v.lines) {
			v.curRow = len(v.lines) - 1
		}
		v.clampNormal()
	case 0x15: // Ctrl+U — half page up
		v.curRow -= cr / 2
		if v.curRow < 0 {
			v.curRow = 0
		}
		v.clampNormal()
	case vkPgDn:
		v.curRow += cr
		if v.curRow >= len(v.lines) {
			v.curRow = len(v.lines) - 1
		}
		v.clampNormal()
	case vkPgUp:
		v.curRow -= cr
		if v.curRow < 0 {
			v.curRow = 0
		}
		v.clampNormal()

	// ── Editing ───────────────────────────────────────────────────────────────
	case int('x'):
		v.deleteChar()
	case vkDel:
		v.deleteChar()
	case int('p'):
		v.paste(true)
	case int('P'):
		v.paste(false)
	case int('J'):
		if v.curRow < len(v.lines)-1 {
			v.lines[v.curRow] = v.lines[v.curRow] + " " + v.lines[v.curRow+1]
			v.lines = append(v.lines[:v.curRow+1], v.lines[v.curRow+2:]...)
			v.modified = true
		}
	case int('D'):
		v.lines[v.curRow] = v.lines[v.curRow][:v.curCol]
		v.modified = true
	case int('~'):
		row := v.lines[v.curRow]
		if len(row) > 0 && v.curCol < len(row) {
			b := row[v.curCol]
			if b >= 'a' && b <= 'z' {
				b -= 32
			} else if b >= 'A' && b <= 'Z' {
				b += 32
			}
			v.lines[v.curRow] = row[:v.curCol] + string(b) + row[v.curCol+1:]
			v.modified = true
			if v.curCol < len(v.lines[v.curRow])-1 {
				v.curCol++
			}
		}

	// ── Two-char sequences ────────────────────────────────────────────────────
	case int('g'), int('d'), int('y'), int('Z'), int('r'), int('c'):
		v.pending = rune(key)

	// ── Enter insert/replace modes ────────────────────────────────────────────
	case int('i'):
		v.mode = vimInsert
	case int('I'):
		v.curCol = 0
		v.mode = vimInsert
	case int('a'):
		if v.curCol < len(v.lines[v.curRow]) {
			v.curCol++
		}
		v.mode = vimInsert
	case int('A'):
		v.curCol = len(v.lines[v.curRow])
		v.mode = vimInsert
	case int('o'):
		newLines := make([]string, len(v.lines)+1)
		copy(newLines, v.lines[:v.curRow+1])
		newLines[v.curRow+1] = ""
		copy(newLines[v.curRow+2:], v.lines[v.curRow+1:])
		v.lines = newLines
		v.curRow++
		v.curCol = 0
		v.modified = true
		v.mode = vimInsert
	case int('O'):
		newLines := make([]string, len(v.lines)+1)
		copy(newLines, v.lines[:v.curRow])
		newLines[v.curRow] = ""
		copy(newLines[v.curRow+1:], v.lines[v.curRow:])
		v.lines = newLines
		v.curCol = 0
		v.modified = true
		v.mode = vimInsert
	case int('s'):
		v.deleteChar()
		v.mode = vimInsert
	case int('S'):
		v.lines[v.curRow] = ""
		v.curCol = 0
		v.modified = true
		v.mode = vimInsert
	case int('C'):
		v.lines[v.curRow] = v.lines[v.curRow][:v.curCol]
		v.modified = true
		v.mode = vimInsert

	// ── Fake undo/redo ────────────────────────────────────────────────────────
	case int('u'):
		v.msg = "Already at oldest change"
	case 0x12: // Ctrl+R
		v.msg = "Already at newest change"

	// ── Search ────────────────────────────────────────────────────────────────
	case int('/'):
		v.handleSearchPrompt('/')
	case int('?'):
		v.handleSearchPrompt('?')
	case int('n'):
		v.msg = "search hit BOTTOM, continuing at TOP"
	case int('N'):
		v.msg = "search hit TOP, continuing at BOTTOM"
	case int('*'):
		v.msg = "E486: Pattern not found"

	// ── Command mode ──────────────────────────────────────────────────────────
	case int(':'):
		v.mode = vimCommand
		v.cmdBuf = ""

	// ── Misc ──────────────────────────────────────────────────────────────────
	case 0x0c: // Ctrl+L — redraw
		v.s.write("\x1b[2J")
	case 0x1b: // ESC — clear pending/message
		v.pending = 0
	case int('v'):
		v.msg = "-- VISUAL --"
	case int('V'):
		v.msg = "-- VISUAL LINE --"
	}
	return false
}

// ── Insert mode ───────────────────────────────────────────────────────────────

func (v *vimEditor) handleInsert(key int) bool {
	switch key {
	case 0x1b: // ESC — back to normal; vim moves cursor left one
		v.mode = vimNormal
		if v.curCol > 0 {
			v.curCol--
		}
		v.clampNormal()
	case int('\r'), int('\n'):
		v.insertNewline()
	case 0x7f, 0x08: // Backspace
		v.backspace()
		v.clampInsert()
	case vkUp:
		if v.curRow > 0 {
			v.curRow--
		}
		v.clampInsert()
	case vkDown:
		if v.curRow < len(v.lines)-1 {
			v.curRow++
		}
		v.clampInsert()
	case vkLeft:
		if v.curCol > 0 {
			v.curCol--
		}
	case vkRight:
		if v.curCol < len(v.lines[v.curRow]) {
			v.curCol++
		}
	case vkHome:
		v.curCol = 0
	case vkEnd:
		v.curCol = len(v.lines[v.curRow])
	case vkDel:
		row := v.lines[v.curRow]
		if v.curCol < len(row) {
			v.lines[v.curRow] = row[:v.curCol] + row[v.curCol+1:]
			v.modified = true
		}
	case 0x17: // Ctrl+W — delete word backwards
		row := v.lines[v.curRow]
		col := v.curCol
		for col > 0 && (row[col-1] == ' ' || row[col-1] == '\t') {
			col--
		}
		for col > 0 && row[col-1] != ' ' && row[col-1] != '\t' {
			col--
		}
		v.lines[v.curRow] = row[:col] + row[v.curCol:]
		v.curCol = col
		v.modified = true
	case 0x15: // Ctrl+U — delete to start of line
		row := v.lines[v.curRow]
		v.lines[v.curRow] = row[v.curCol:]
		v.curCol = 0
		v.modified = true
	default:
		if key >= 0x20 && key <= 0x7e {
			v.insertChar(byte(key))
		}
	}
	return false
}

// ── Command mode ──────────────────────────────────────────────────────────────

func (v *vimEditor) handleCommandMode(key int) bool {
	switch key {
	case int('\r'), int('\n'):
		cmd := v.cmdBuf
		v.cmdBuf = ""
		v.mode = vimNormal
		return v.execCmd(cmd)
	case 0x1b, 0x03:
		v.cmdBuf = ""
		v.mode = vimNormal
	case 0x7f, 0x08:
		if len(v.cmdBuf) > 0 {
			v.cmdBuf = v.cmdBuf[:len(v.cmdBuf)-1]
		} else {
			v.mode = vimNormal // backspace on empty cmd cancels
		}
	default:
		if key >= 0x20 && key <= 0x7e {
			v.cmdBuf += string(rune(key))
		}
	}
	return false
}

// ── Main entry ────────────────────────────────────────────────────────────────

func (s *fakeShell) runVim(args string) {
	filename := strings.TrimSpace(args)
	if filename != "" && !strings.HasPrefix(filename, "/") {
		filename = s.cwd + "/" + filename
	}
	if filename != "" && honeytokenFiles[filename] {
		s.logHoneytoken(filename)
	}

	v := newVimEditor(s, filename)

	// Enter alternate screen
	s.write("\x1b[?1049h\x1b[2J\x1b[H")
	defer s.write("\x1b[?1049l")

	// Initial message (shown in command line on first render)
	if filename != "" {
		if _, ok := fakeFiles[filename]; ok {
			n := 0
			for _, l := range v.lines {
				n += len(l) + 1
			}
			v.msg = fmt.Sprintf(`"%s" %dL, %dB`, filename, len(v.lines), n)
		} else {
			v.msg = fmt.Sprintf(`"%s" [New File]`, filename)
		}
	}

	v.render()

	for {
		// Clear transient message at the start of each iteration
		// (it was already drawn by the previous render).
		v.msg = ""

		key, ok := v.readVimKey()
		if !ok {
			return
		}

		var exit bool
		switch v.mode {
		case vimNormal:
			if v.pending != 0 {
				exit = v.handleNormalPending(key)
			} else {
				exit = v.handleNormal(key)
			}
		case vimInsert:
			exit = v.handleInsert(key)
		case vimCommand:
			exit = v.handleCommandMode(key)
		}
		if exit {
			return
		}

		v.ensureVisible()
		v.render()
	}
}
