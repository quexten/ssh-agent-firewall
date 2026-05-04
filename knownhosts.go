package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KnownHostsIndex provides a reverse lookup from host key fingerprint to hostnames.
// It is built once at startup by parsing ~/.ssh/known_hosts.
type KnownHostsIndex struct {
	// fingerprints maps SHA256 fingerprints (e.g. "SHA256:...") to a list of hostnames.
	fingerprints map[string][]string
}

// LoadKnownHostsIndex reads the user's known_hosts file and builds a reverse
// index from host key fingerprint to hostnames. Hashed hostname entries are
// skipped since they cannot be reverse-looked-up.
func LoadKnownHostsIndex() *KnownHostsIndex {
	idx := &KnownHostsIndex{fingerprints: make(map[string][]string)}

	home, err := os.UserHomeDir()
	if err != nil {
		logError("known_hosts: failed to get home directory: %v", err)
		return idx
	}

	path := filepath.Join(home, ".ssh", "known_hosts")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			logInfo("known_hosts: %s not found, hostname resolution disabled", path)
		} else {
			logError("known_hosts: failed to open %s: %v", path, err)
		}
		return idx
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	entries := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip marker lines (@cert-authority, @revoked) — just strip the marker
		if strings.HasPrefix(line, "@") {
			if spaceIdx := strings.IndexByte(line, ' '); spaceIdx != -1 {
				line = line[spaceIdx+1:]
			} else {
				continue
			}
		}

		// Format: hostnames keytype base64key [comment]
		// Split into at least 3 fields
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		hostsField := fields[0]
		keyTypeAndData := fields[1] + " " + fields[2]

		// Parse hostnames — skip hashed entries (|1|salt|hash)
		hosts := parseHostnames(hostsField)
		if len(hosts) == 0 {
			continue
		}

		// Parse the public key using ssh.ParseAuthorizedKey
		// which expects "keytype base64key" format
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyTypeAndData))
		if err != nil {
			continue
		}

		fp := keyFingerprint(pubKey.Marshal())
		for _, host := range hosts {
			idx.addEntry(fp, host)
		}
		entries++
	}

	if err := scanner.Err(); err != nil {
		logError("known_hosts: error reading file: %v", err)
	}

	logInfo("known_hosts: loaded %d entries mapping to %d unique fingerprints from %s",
		entries, len(idx.fingerprints), path)

	return idx
}

// addEntry adds a hostname for a given fingerprint, avoiding duplicates.
func (idx *KnownHostsIndex) addEntry(fingerprint, host string) {
	for _, existing := range idx.fingerprints[fingerprint] {
		if existing == host {
			return
		}
	}
	idx.fingerprints[fingerprint] = append(idx.fingerprints[fingerprint], host)
}

// Lookup returns the list of hostnames associated with the given fingerprint,
// or nil if no match is found.
func (idx *KnownHostsIndex) Lookup(fingerprint string) []string {
	if idx == nil {
		return nil
	}
	return idx.fingerprints[fingerprint]
}

// FormatHosts returns a human-readable string of hostnames for a fingerprint.
// Returns "unknown host" if no match is found, or a comma-separated list of hosts.
func (idx *KnownHostsIndex) FormatHosts(fingerprint string) string {
	hosts := idx.Lookup(fingerprint)
	if len(hosts) == 0 {
		return "unknown host"
	}
	return strings.Join(hosts, ", ")
}

// parseHostnames splits the hostname field of a known_hosts line into
// individual hostnames. Hashed hostnames (starting with |1|) are skipped.
func parseHostnames(field string) []string {
	parts := strings.Split(field, ",")
	var hosts []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Skip hashed hostnames — they start with |1| and cannot be reversed
		if strings.HasPrefix(p, "|") {
			continue
		}
		// Strip brackets and port from [host]:port format
		host := normalizeHost(p)
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// normalizeHost cleans up a known_hosts hostname entry.
// Handles [host]:port and plain host formats.
func normalizeHost(s string) string {
	// [host]:port format
	if strings.HasPrefix(s, "[") {
		if idx := strings.Index(s, "]:"); idx != -1 {
			return s[1:idx]
		}
		// [host] without port
		if strings.HasSuffix(s, "]") {
			return s[1 : len(s)-1]
		}
	}
	return s
}
