package workspace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Workspace manages output files and evidence for a single engagement.
type Workspace struct {
	Dir    string
	domain string
}

// New creates (or opens) a workspace directory for the given domain.
func New(base, domain string) (*Workspace, error) {
	dir := filepath.Join(base, sanitize(domain))
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("workspace mkdir: %w", err)
	}
	return &Workspace{Dir: dir, domain: domain}, nil
}

// SaveJSON marshals v to a pretty-printed JSON file in the workspace.
func (w *Workspace) SaveJSON(filename string, v any) error {
	path := filepath.Join(w.Dir, filename)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// SaveText writes raw text to a file in the workspace.
func (w *Workspace) SaveText(filename, content string) error {
	return os.WriteFile(filepath.Join(w.Dir, filename), []byte(content), 0640)
}

// AppendText appends a line to a file in the workspace.
func (w *Workspace) AppendText(filename, line string) error {
	f, err := os.OpenFile(filepath.Join(w.Dir, filename), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, line)
	return err
}

// LogEvent appends a timestamped event to the engagement log.
func (w *Workspace) LogEvent(format string, args ...any) {
	line := fmt.Sprintf("[%s] %s", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
	_ = w.AppendText("engagement.log", line)
}

// Path returns the full path to a file in the workspace.
func (w *Workspace) Path(filename string) string {
	return filepath.Join(w.Dir, filename)
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, s)
}
