package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"
	"time"

	"github.com/martinlindhe/notify"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"tailscale.com/ipn/ipnauth"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

// logColored prints a colored log message
func logColored(socketName, action, message string, actionColor string) {
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("%s%s%s %s[%s]%s %s%s%s %s\n",
		colorGray, timestamp, colorReset,
		colorCyan, socketName, colorReset,
		actionColor, action, colorReset,
		message)
}

// logInfo prints an info log message
func logInfo(format string, args ...interface{}) {
	timestamp := time.Now().Format("15:04:05")
	message := fmt.Sprintf(format, args...)
	fmt.Printf("%s%s%s %s%s%s %s\n",
		colorGray, timestamp, colorReset,
		colorBlue, "INFO", colorReset,
		message)
}

// logError prints an error log message
func logError(format string, args ...interface{}) {
	timestamp := time.Now().Format("15:04:05")
	message := fmt.Sprintf(format, args...)
	fmt.Printf("%s%s%s %s%s%s %s\n",
		colorGray, timestamp, colorReset,
		colorRed, "ERROR", colorReset,
		message)
}

// LoggingAgent is a wrapper around an ssh agent that logs requests.
// It implements agent.ExtendedAgent to support SignWithFlags and Extension messages
// (including session-bind@openssh.com forwarding and host-bound authentication).
type LoggingAgent struct {
	upstream    agent.ExtendedAgent
	conn        net.Conn
	socketName  string
	allowedKeys map[string]bool // Set of allowed key fingerprints (SHA256). If nil/empty, all keys are allowed.
	eventLogger *EventLogger
	knownHosts  *KnownHostsIndex
}

// List logs the List request and forwards it to the upstream agent.
func (a *LoggingAgent) List() ([]*agent.Key, error) {
	pinfo := getProcessInfoStruct(a.conn)
	processInfo := pinfo.String()
	logColored(a.socketName, "List", fmt.Sprintf("from %s", processInfo), colorGreen)

	keys, err := a.upstream.List()
	if err != nil {
		return nil, err
	}

	// If no allowed keys configured, return all keys
	if len(a.allowedKeys) == 0 {
		a.eventLogger.LogEvent(Event{
			Timestamp:    time.Now(),
			Socket:       a.socketName,
			Action:       "list",
			PID:          pinfo.PID,
			ProcessName:  pinfo.ProcessName,
			Username:     pinfo.Username,
			KeysReturned: len(keys),
		})
		return keys, nil
	}

	// Filter keys based on allowed fingerprints
	var filtered []*agent.Key
	for _, key := range keys {
		fp := keyFingerprint(key.Blob)
		if a.allowedKeys[fp] {
			filtered = append(filtered, key)
		}
	}

	a.eventLogger.LogEvent(Event{
		Timestamp:    time.Now(),
		Socket:       a.socketName,
		Action:       "list",
		PID:          pinfo.PID,
		ProcessName:  pinfo.ProcessName,
		Username:     pinfo.Username,
		KeysReturned: len(filtered),
	})

	return filtered, nil
}

// Sign logs the Sign request and forwards it to the upstream agent.
func (a *LoggingAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	pinfo := getProcessInfoStruct(a.conn)
	processInfo := pinfo.String()
	fp := keyFingerprint(key.Marshal())
	logColored(a.socketName, "Sign", fmt.Sprintf("from %s key=%s", processInfo, fp), colorYellow)

	// Check if key is allowed
	if len(a.allowedKeys) > 0 {
		if !a.allowedKeys[fp] {
			allowed := false
			a.eventLogger.LogEvent(Event{
				Timestamp:      time.Now(),
				Socket:         a.socketName,
				Action:         "sign",
				PID:            pinfo.PID,
				ProcessName:    pinfo.ProcessName,
				Username:       pinfo.Username,
				KeyFingerprint: fp,
				Allowed:        &allowed,
				Message:        "key not allowed for this socket",
			})
			return nil, fmt.Errorf("key not allowed for this socket")
		}
	}

	// Try to parse authentication info from the signing data
	if authInfo, err := parseAuthData(data); err == nil && authInfo != nil {
		authDetails := formatAuthRequestInfo(authInfo, a.knownHosts)
		logColored(a.socketName, "Auth", fmt.Sprintf("from %s %s", processInfo, authDetails), colorPurple)
		notify.Notify("SSH Agent", "Authenticate", signNotificationMessage(a.socketName, processInfo, authInfo, a.knownHosts), "")
	} else {
		notify.Notify("SSH Agent", "Authenticate", fmt.Sprintf("[%s] Signing key=%s from %s", a.socketName, fp, processInfo), "")
	}

	sig, err := a.upstream.Sign(key, data)
	allowed := err == nil
	event := Event{
		Timestamp:      time.Now(),
		Socket:         a.socketName,
		Action:         "sign",
		PID:            pinfo.PID,
		ProcessName:    pinfo.ProcessName,
		Username:       pinfo.Username,
		KeyFingerprint: fp,
		Allowed:        &allowed,
	}
	if err != nil {
		event.Message = err.Error()
	}
	a.eventLogger.LogEvent(event)
	return sig, err
}

// Add is a pass-through to the upstream agent.
func (a *LoggingAgent) Add(key agent.AddedKey) error {
	pinfo := getProcessInfoStruct(a.conn)
	logColored(a.socketName, "Add", fmt.Sprintf("key added by %s", pinfo.String()), colorPurple)
	a.eventLogger.LogEvent(Event{
		Timestamp:   time.Now(),
		Socket:      a.socketName,
		Action:      "add",
		PID:         pinfo.PID,
		ProcessName: pinfo.ProcessName,
		Username:    pinfo.Username,
	})
	return a.upstream.Add(key)
}

// Remove is a pass-through to the upstream agent.
func (a *LoggingAgent) Remove(key ssh.PublicKey) error {
	pinfo := getProcessInfoStruct(a.conn)
	fp := keyFingerprint(key.Marshal())
	logColored(a.socketName, "Remove", fmt.Sprintf("key removed by %s key=%s", pinfo.String(), fp), colorRed)
	a.eventLogger.LogEvent(Event{
		Timestamp:      time.Now(),
		Socket:         a.socketName,
		Action:         "remove",
		PID:            pinfo.PID,
		ProcessName:    pinfo.ProcessName,
		Username:       pinfo.Username,
		KeyFingerprint: fp,
	})
	return a.upstream.Remove(key)
}

// RemoveAll is a pass-through to the upstream agent.
func (a *LoggingAgent) RemoveAll() error {
	pinfo := getProcessInfoStruct(a.conn)
	logColored(a.socketName, "RemoveAll", fmt.Sprintf("all keys removed by %s", pinfo.String()), colorRed)
	a.eventLogger.LogEvent(Event{
		Timestamp:   time.Now(),
		Socket:      a.socketName,
		Action:      "remove_all",
		PID:         pinfo.PID,
		ProcessName: pinfo.ProcessName,
		Username:    pinfo.Username,
	})
	return a.upstream.RemoveAll()
}

// Lock is a pass-through to the upstream agent.
func (a *LoggingAgent) Lock(passphrase []byte) error {
	pinfo := getProcessInfoStruct(a.conn)
	logColored(a.socketName, "Lock", fmt.Sprintf("agent locked by %s", pinfo.String()), colorYellow)
	a.eventLogger.LogEvent(Event{
		Timestamp:   time.Now(),
		Socket:      a.socketName,
		Action:      "lock",
		PID:         pinfo.PID,
		ProcessName: pinfo.ProcessName,
		Username:    pinfo.Username,
	})
	return a.upstream.Lock(passphrase)
}

// Unlock is a pass-through to the upstream agent.
func (a *LoggingAgent) Unlock(passphrase []byte) error {
	pinfo := getProcessInfoStruct(a.conn)
	logColored(a.socketName, "Unlock", fmt.Sprintf("agent unlocked by %s", pinfo.String()), colorGreen)
	a.eventLogger.LogEvent(Event{
		Timestamp:   time.Now(),
		Socket:      a.socketName,
		Action:      "unlock",
		PID:         pinfo.PID,
		ProcessName: pinfo.ProcessName,
		Username:    pinfo.Username,
	})
	return a.upstream.Unlock(passphrase)
}

// SignWithFlags logs the SignWithFlags request and forwards it to the upstream agent.
// This handles sign requests with flags (e.g. RSA SHA-256/SHA-512).
func (a *LoggingAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	pinfo := getProcessInfoStruct(a.conn)
	processInfo := pinfo.String()
	fp := keyFingerprint(key.Marshal())
	logColored(a.socketName, "SignFlags", fmt.Sprintf("from %s key=%s flags=%d", processInfo, fp, flags), colorYellow)

	// Try to parse authentication info from the signing data
	if authInfo, err := parseAuthData(data); err == nil && authInfo != nil {
		authDetails := formatAuthRequestInfo(authInfo, a.knownHosts)
		logColored(a.socketName, "Auth", fmt.Sprintf("from %s %s", processInfo, authDetails), colorPurple)
		notify.Notify("SSH Agent", "Sign", signNotificationMessage(a.socketName, processInfo, authInfo, a.knownHosts), "")
	} else {
		notify.Notify("SSH Agent", "Sign", fmt.Sprintf("[%s] Signing key=%s from %s", a.socketName, fp, processInfo), "")
	}

	a.eventLogger.LogEvent(Event{
		Timestamp:      time.Now(),
		Socket:         a.socketName,
		Action:         "sign_with_flags",
		PID:            pinfo.PID,
		ProcessName:    pinfo.ProcessName,
		Username:       pinfo.Username,
		KeyFingerprint: fp,
		Message:        fmt.Sprintf("flags=%d", flags),
	})

	return a.upstream.SignWithFlags(key, data, flags)
}

// Extension handles agent protocol extension messages.
// It parses and logs session-bind@openssh.com forwarding messages and
// other extension types, then forwards them to the upstream agent.
func (a *LoggingAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	pinfo := getProcessInfoStruct(a.conn)
	processInfo := pinfo.String()

	switch extensionType {
	case "session-bind@openssh.com":
		bindInfo, err := parseSessionBind(contents)
		if err != nil {
			logColored(a.socketName, "SessionBind", fmt.Sprintf("from %s (parse error: %v)", processInfo, err), colorYellow)
		} else {
			details := formatSessionBindInfo(bindInfo, a.knownHosts)
			logColored(a.socketName, "SessionBind", fmt.Sprintf("from %s %s", processInfo, details), colorPurple)
		}
		destHost := ""
		if bindInfo != nil && a.knownHosts != nil {
			if hosts := a.knownHosts.Lookup(bindInfo.HostKeyFingerprint); len(hosts) > 0 {
				destHost = strings.Join(hosts, ", ")
			}
		}
		a.eventLogger.LogEvent(Event{
			Timestamp:   time.Now(),
			Socket:      a.socketName,
			Action:      "session_bind",
			PID:         pinfo.PID,
			ProcessName: pinfo.ProcessName,
			Username:    pinfo.Username,
			DestHost:    destHost,
			Message:     fmt.Sprintf("extension=%s", extensionType),
		})
	default:
		logColored(a.socketName, "Extension", fmt.Sprintf("from %s type=%s", processInfo, extensionType), colorBlue)
		a.eventLogger.LogEvent(Event{
			Timestamp:   time.Now(),
			Socket:      a.socketName,
			Action:      "extension",
			PID:         pinfo.PID,
			ProcessName: pinfo.ProcessName,
			Username:    pinfo.Username,
			Message:     fmt.Sprintf("extension=%s", extensionType),
		})
	}

	return a.upstream.Extension(extensionType, contents)
}

// Signers is a pass-through to the upstream agent.
func (a *LoggingAgent) Signers() ([]ssh.Signer, error) {
	pinfo := getProcessInfoStruct(a.conn)
	logColored(a.socketName, "Signers", fmt.Sprintf("signers requested by %s", pinfo.String()), colorBlue)
	a.eventLogger.LogEvent(Event{
		Timestamp:   time.Now(),
		Socket:      a.socketName,
		Action:      "signers",
		PID:         pinfo.PID,
		ProcessName: pinfo.ProcessName,
		Username:    pinfo.Username,
	})
	return a.upstream.Signers()
}

// getProcessInfoStruct returns structured information about the connecting process.
func getProcessInfoStruct(conn net.Conn) ProcessInfo {
	ci, err := ipnauth.GetConnIdentity(log.Printf, conn)
	if err != nil {
		return ProcessInfo{}
	}

	pid := ci.Pid()
	if pid == 0 {
		return ProcessInfo{}
	}

	pinfo := ProcessInfo{PID: int(pid)}

	// Try to get user info
	if creds := ci.Creds(); creds != nil {
		if uid, ok := creds.UserID(); ok {
			if u, err := user.LookupId(uid); err == nil {
				pinfo.Username = u.Username
			}
		}
	}

	// Try to get process name from /proc
	if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		processName := string(cmdline)
		if len(processName) > 0 && processName[len(processName)-1] == '\n' {
			processName = processName[:len(processName)-1]
		}
		pinfo.ProcessName = processName
	}

	// Detect sandbox (Flatpak / Snap)
	if sandbox := detectSandbox(int(pid)); sandbox.Sandboxed {
		pinfo.SandboxRuntime = sandbox.Runtime
		pinfo.SandboxApp = sandbox.AppName
	}

	return pinfo
}

// getProcessInfo returns a human-readable string about the connecting process.
func getProcessInfo(conn net.Conn) string {
	return getProcessInfoStruct(conn).String()
}

// keyFingerprint returns the SHA256 fingerprint of a key in the format "SHA256:..."
func keyFingerprint(keyBlob []byte) string {
	hash := sha256.Sum256(keyBlob)
	return "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])
}

func runProxyActual(inputSocketPath, outputSocketPath, socketName string, allowedKeys map[string]bool, listener net.Listener, eventLogger *EventLogger, knownHosts *KnownHostsIndex) error {
	logInfo("[%s%s%s] Listening on %s%s%s", colorCyan, socketName, colorReset, colorGreen, outputSocketPath, colorReset)

	// Graceful shutdown
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		logInfo("%sShutting down...%s", colorYellow, colorReset)
		listener.Close()
		os.Remove(outputSocketPath)
		os.Exit(0)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// When listener is closed, Accept() returns an error.
			// We break the loop to allow the program to exit gracefully.
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				logError("[%s] Temporary error accepting connection: %v", socketName, err)
				continue
			}
			return err // Return the error when the listener is closed or a non-temporary error occurs
		}

		// Connect to the upstream agent for each incoming connection
		upstreamConn, err := net.Dial("unix", inputSocketPath)
		if err != nil {
			logError("[%s] Failed to connect to upstream socket %s: %v", socketName, inputSocketPath, err)
			conn.Close()
			continue
		}
		upstreamAgent := agent.NewClient(upstreamConn)

		loggingAgent := &LoggingAgent{upstream: upstreamAgent, conn: conn, socketName: socketName, allowedKeys: allowedKeys, eventLogger: eventLogger, knownHosts: knownHosts}
		go func() {
			agent.ServeAgent(loggingAgent, conn)
			upstreamConn.Close()
		}()
	}
}

// runProxy is a helper for main to ensure socket cleanup.
// It calls runProxyActual.
func runProxy(inputSocketPath, outputSocketPath, socketName string, allowedKeys []string, eventLogger *EventLogger, knownHosts *KnownHostsIndex) error {
	// Clean up the output socket path if it already exists
	if _, err := os.Stat(outputSocketPath); err == nil {
		if err := os.Remove(outputSocketPath); err != nil {
			return fmt.Errorf("failed to remove existing output socket: %v", err)
		}
	}

	listener, err := net.Listen("unix", outputSocketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on output socket: %v", err)
	}
	defer listener.Close()
	defer os.Remove(outputSocketPath) // Ensure socket file is removed on main exit

	// Build allowed keys map
	allowedKeysMap := make(map[string]bool)
	for _, fp := range allowedKeys {
		allowedKeysMap[fp] = true
	}

	return runProxyActual(inputSocketPath, outputSocketPath, socketName, allowedKeysMap, listener, eventLogger, knownHosts)
}

// runProxyForTest is an internal helper for testing that signals when the proxy is ready.
func runProxyForTest(inputSocketPath, outputSocketPath, socketName string, allowedKeys map[string]bool, listener net.Listener, ready chan<- struct{}, eventLogger *EventLogger, knownHosts *KnownHostsIndex) error {
	// Signal that the proxy is ready to accept connections
	close(ready)
	return runProxyActual(inputSocketPath, outputSocketPath, socketName, allowedKeys, listener, eventLogger, knownHosts)
}

// runServe starts the SSH agent proxy server
func runServe() error {
	configPath, err := DefaultConfigPath()
	if err != nil {
		return fmt.Errorf("failed to get default config path: %v", err)
	}

	// Load config
	config, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	// Set up event logger
	logPath, err := DefaultLogPath()
	if err != nil {
		return fmt.Errorf("failed to get log path: %v", err)
	}
	eventLogger, err := NewEventLogger(logPath)
	if err != nil {
		return fmt.Errorf("failed to create event logger: %v", err)
	}
	defer eventLogger.Close()

	logInfo("Using config from %s%s%s", colorCyan, configPath, colorReset)
	// Load known_hosts index for hostname resolution
	knownHosts := LoadKnownHostsIndex()

	logInfo("Event log: %s%s%s", colorCyan, logPath, colorReset)
	logInfo("Input socket: %s%s%s", colorGreen, config.InputPath, colorReset)
	logInfo("Output sockets: %s%d configured%s", colorPurple, len(config.Outputs), colorReset)

	if len(config.Outputs) == 0 {
		return fmt.Errorf("no outputs configured")
	}

	// Set up error channel for goroutines
	errChan := make(chan error, len(config.Outputs))

	// Start a proxy for each output
	for _, output := range config.Outputs {
		go func(out OutputConfig) {
			logInfo("Starting proxy for output '%s%s%s' at %s%s%s", colorCyan, out.Name, colorReset, colorGreen, out.Path, colorReset)
			if len(out.AllowedKeys) > 0 {
				logInfo("[%s%s%s] Filtering to %s%d%s allowed keys", colorCyan, out.Name, colorReset, colorPurple, len(out.AllowedKeys), colorReset)
			}
			if err := runProxy(config.InputPath, out.Path, out.Name, out.AllowedKeys, eventLogger, knownHosts); err != nil {
				errChan <- fmt.Errorf("proxy '%s' exited with error: %v", out.Name, err)
			}
		}(output)
	}

	// Wait for any proxy to exit with an error
	err = <-errChan
	return fmt.Errorf("proxy exited: %v", err)
}

func main() {
	if err := runCommand(); err != nil {
		logError("%v", err)
		os.Exit(1)
	}
}
