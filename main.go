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
	"syscall"

	"github.com/martinlindhe/notify"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"tailscale.com/ipn/ipnauth"
)

// LoggingAgent is a wrapper around an ssh agent that logs requests.
type LoggingAgent struct {
	upstream    agent.Agent
	conn        net.Conn
	socketName  string
	allowedKeys map[string]bool // Set of allowed key fingerprints (SHA256). If nil/empty, all keys are allowed.
}

// List logs the List request and forwards it to the upstream agent.
func (a *LoggingAgent) List() ([]*agent.Key, error) {
	processInfo := getProcessInfo(a.conn)
	log.Printf("[%s] Received request: List from %s", a.socketName, processInfo)
	notify.Notify("SSH Agent", "List", fmt.Sprintf("[%s] Key list request from %s", a.socketName, processInfo), "")

	keys, err := a.upstream.List()
	if err != nil {
		return nil, err
	}

	// If no allowed keys configured, return all keys
	if len(a.allowedKeys) == 0 {
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
	return filtered, nil
}

// Sign logs the Sign request and forwards it to the upstream agent.
func (a *LoggingAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	processInfo := getProcessInfo(a.conn)
	log.Printf("[%s] Received request: Sign from %s", a.socketName, processInfo)
	notify.Notify("SSH Agent", "Sign", fmt.Sprintf("[%s] Signing request from %s", a.socketName, processInfo), "")

	// Check if key is allowed
	if len(a.allowedKeys) > 0 {
		fp := keyFingerprint(key.Marshal())
		if !a.allowedKeys[fp] {
			return nil, fmt.Errorf("key not allowed for this socket")
		}
	}

	return a.upstream.Sign(key, data)
}

// Add is a pass-through to the upstream agent.
func (a *LoggingAgent) Add(key agent.AddedKey) error {
	log.Printf("[%s] Received request: Add", a.socketName)
	return a.upstream.Add(key)
}

// Remove is a pass-through to the upstream agent.
func (a *LoggingAgent) Remove(key ssh.PublicKey) error {
	log.Printf("[%s] Received request: Remove", a.socketName)
	return a.upstream.Remove(key)
}

// RemoveAll is a pass-through to the upstream agent.
func (a *LoggingAgent) RemoveAll() error {
	log.Printf("[%s] Received request: RemoveAll", a.socketName)
	return a.upstream.RemoveAll()
}

// Lock is a pass-through to the upstream agent.
func (a *LoggingAgent) Lock(passphrase []byte) error {
	log.Printf("[%s] Received request: Lock", a.socketName)
	return a.upstream.Lock(passphrase)
}

// Unlock is a pass-through to the upstream agent.
func (a *LoggingAgent) Unlock(passphrase []byte) error {
	log.Printf("[%s] Received request: Unlock", a.socketName)
	return a.upstream.Unlock(passphrase)
}

// Signers is a pass-through to the upstream agent.
func (a *LoggingAgent) Signers() ([]ssh.Signer, error) {
	log.Printf("[%s] Received request: Signers", a.socketName)
	return a.upstream.Signers()
}

// getProcessInfo returns information about the connecting process.
func getProcessInfo(conn net.Conn) string {
	ci, err := ipnauth.GetConnIdentity(log.Printf, conn)
	if err != nil {
		return "unknown process"
	}

	pid := ci.Pid()
	if pid == 0 {
		return "unknown process"
	}

	info := fmt.Sprintf("PID %d", pid)

	// Try to get user info
	if creds := ci.Creds(); creds != nil {
		if uid, ok := creds.UserID(); ok {
			if u, err := user.LookupId(uid); err == nil {
				info = fmt.Sprintf("%s (%s)", u.Username, info)
			}
		}
	}

	// Try to get process name from /proc
	if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		processName := string(cmdline)
		if len(processName) > 0 && processName[len(processName)-1] == '\n' {
			processName = processName[:len(processName)-1]
		}
		info = fmt.Sprintf("%s [%s]", processName, info)
	}

	return info
}

// keyFingerprint returns the SHA256 fingerprint of a key in the format "SHA256:..."
func keyFingerprint(keyBlob []byte) string {
	hash := sha256.Sum256(keyBlob)
	return "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])
}

func runProxyActual(inputSocketPath, outputSocketPath, socketName string, allowedKeys map[string]bool, listener net.Listener) error {
	// Connect to the upstream agent
	upstreamConn, err := net.Dial("unix", inputSocketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to upstream socket %s: %v", inputSocketPath, err)
	}
	defer upstreamConn.Close()
	upstreamAgent := agent.NewClient(upstreamConn)

	log.Printf("[%s] Listening on %s", socketName, outputSocketPath)

	// Graceful shutdown
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		log.Println("Shutting down...")
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
				log.Printf("[%s] Temporary error accepting connection: %v", socketName, err)
				continue
			}
			return err // Return the error when the listener is closed or a non-temporary error occurs
		}
		loggingAgent := &LoggingAgent{upstream: upstreamAgent, conn: conn, socketName: socketName, allowedKeys: allowedKeys}
		go agent.ServeAgent(loggingAgent, conn)
	}
}

// runProxy is a helper for main to ensure socket cleanup.
// It calls runProxyActual.
func runProxy(inputSocketPath, outputSocketPath, socketName string, allowedKeys []string) error {
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

	return runProxyActual(inputSocketPath, outputSocketPath, socketName, allowedKeysMap, listener)
}

// runProxyForTest is an internal helper for testing that signals when the proxy is ready.
func runProxyForTest(inputSocketPath, outputSocketPath, socketName string, allowedKeys map[string]bool, listener net.Listener, ready chan<- struct{}) error {
	// Signal that the proxy is ready to accept connections
	close(ready)
	return runProxyActual(inputSocketPath, outputSocketPath, socketName, allowedKeys, listener)
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

	log.Printf("Using config from %s", configPath)
	log.Printf("Input socket: %s", config.InputPath)
	log.Printf("Output sockets: %d configured", len(config.Outputs))

	if len(config.Outputs) == 0 {
		return fmt.Errorf("no outputs configured")
	}

	// Set up error channel for goroutines
	errChan := make(chan error, len(config.Outputs))

	// Start a proxy for each output
	for _, output := range config.Outputs {
		go func(out OutputConfig) {
			log.Printf("Starting proxy for output '%s' at %s", out.Name, out.Path)
			if len(out.AllowedKeys) > 0 {
				log.Printf("[%s] Filtering to %d allowed keys", out.Name, len(out.AllowedKeys))
			}
			if err := runProxy(config.InputPath, out.Path, out.Name, out.AllowedKeys); err != nil {
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
		log.Fatalf("Error: %v", err)
	}
}
