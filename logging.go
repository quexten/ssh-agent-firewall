package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ProcessInfo holds structured information about a connecting process.
type ProcessInfo struct {
	PID            int    `json:"pid"`
	ProcessName    string `json:"process_name,omitempty"`
	Username       string `json:"username,omitempty"`
	SandboxRuntime string `json:"sandbox_runtime,omitempty"` // "flatpak", "snap", or ""
	SandboxApp     string `json:"sandbox_app,omitempty"`     // e.g. "org.mozilla.Firefox"
}

// String returns a human-readable representation of the process info.
func (p ProcessInfo) String() string {
	if p.PID == 0 {
		return "unknown process"
	}
	info := fmt.Sprintf("PID %d", p.PID)
	if p.Username != "" {
		info = fmt.Sprintf("%s (%s)", p.Username, info)
	}
	if p.ProcessName != "" {
		info = fmt.Sprintf("%s [%s]", p.ProcessName, info)
	}
	if p.SandboxRuntime != "" {
		info = fmt.Sprintf("%s [%s: %s]", info, p.SandboxRuntime, p.SandboxApp)
	}
	return info
}

// Event represents a single structured log event.
type Event struct {
	Timestamp      time.Time `json:"timestamp"`
	Socket         string    `json:"socket"`
	Action         string    `json:"action"`
	PID            int       `json:"pid"`
	ProcessName    string    `json:"process_name,omitempty"`
	Username       string    `json:"username,omitempty"`
	KeyFingerprint string    `json:"key_fingerprint,omitempty"`
	KeysReturned   int       `json:"keys_returned,omitempty"`
	Allowed        *bool     `json:"allowed,omitempty"`
	DestHost       string    `json:"dest_host,omitempty"`
	Message        string    `json:"message,omitempty"`
}

func (e Event) String() string {
	s := fmt.Sprintf("%s - %s: %s (PID %d, process=%s, user=%s, key=%s, keys_returned=%d, allowed=%v",
		e.Timestamp.Format(time.RFC3339), e.Socket, e.Action, e.PID, e.ProcessName, e.Username,
		e.KeyFingerprint, e.KeysReturned, e.Allowed)
	if e.DestHost != "" {
		s += fmt.Sprintf(", dest_host=%s", e.DestHost)
	}
	s += ")"
	return s
}

// EventLogger writes structured JSON-lines events to a file.
type EventLogger struct {
	mu   sync.Mutex
	file *os.File
}

// DefaultLogPath returns the fixed default path for the event log file.
func DefaultLogPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config directory: %w", err)
	}
	return filepath.Join(configDir, "ssh-proxy", "events.jsonl"), nil
}

// NewEventLogger creates a new EventLogger that appends to the given path.
// It creates parent directories if they don't exist.
func NewEventLogger(path string) (*EventLogger, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return &EventLogger{file: f}, nil
}

// LogEvent marshals the event to JSON and writes it as a single line.
func (l *EventLogger) LogEvent(event Event) {
	if l == nil {
		return
	}
	logInfo("Logging event: %s", event.String())

	data, err := json.Marshal(event)
	if err != nil {
		logError("Failed to marshal event: %v", err)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.file.Write(append(data, '\n')); err != nil {
		logError("Failed to write event log: %v", err)
	}
}

// Close closes the underlying log file.
func (l *EventLogger) Close() error {
	if l == nil {
		return nil
	}
	return l.file.Close()
}
