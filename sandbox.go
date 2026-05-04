//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// SandboxInfo describes the sandbox environment of a process, if any.
type SandboxInfo struct {
	Sandboxed bool   // true if the process is running inside a sandbox
	Runtime   string // "flatpak", "snap", or ""
	AppName   string // e.g. "org.mozilla.Firefox", "firefox"
}

// String returns a human-readable representation of the sandbox info.
func (s SandboxInfo) String() string {
	if !s.Sandboxed {
		return ""
	}
	return fmt.Sprintf("[%s: %s]", s.Runtime, s.AppName)
}

// detectSandbox checks whether the process with the given PID is running
// inside a Flatpak or Snap sandbox and returns the sandbox info.
func detectSandbox(pid int) SandboxInfo {
	if name, ok := detectFlatpak(pid); ok {
		return SandboxInfo{Sandboxed: true, Runtime: "flatpak", AppName: name}
	}
	if name, ok := detectSnap(pid); ok {
		return SandboxInfo{Sandboxed: true, Runtime: "snap", AppName: name}
	}
	return SandboxInfo{}
}

// detectFlatpak checks whether the process is running inside a Flatpak sandbox
// by reading /proc/<PID>/root/.flatpak-info. This file exists inside every
// Flatpak sandbox and contains an INI-like [Application] section with a name= field.
func detectFlatpak(pid int) (string, bool) {
	path := fmt.Sprintf("/proc/%d/root/.flatpak-info", pid)
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	inAppSection := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Track INI sections
		if strings.HasPrefix(line, "[") {
			inAppSection = strings.EqualFold(line, "[Application]")
			continue
		}

		if inAppSection && strings.HasPrefix(line, "name=") {
			name := strings.TrimPrefix(line, "name=")
			name = strings.TrimSpace(name)
			if name != "" {
				return name, true
			}
		}
	}
	return "", false
}

// detectSnap checks whether the process is running inside a Snap sandbox.
// It uses two methods:
//  1. Parse /proc/<PID>/cgroup for snap scope patterns (e.g. snap.firefox.firefox).
//  2. Fallback: parse /proc/<PID>/attr/apparmor/current for AppArmor profile
//     names matching snap.<name>.<command>.
func detectSnap(pid int) (string, bool) {
	// Method 1: cgroup
	if name, ok := detectSnapFromCgroup(pid); ok {
		return name, true
	}
	// Method 2: AppArmor profile
	if name, ok := detectSnapFromAppArmor(pid); ok {
		return name, true
	}
	return "", false
}

// detectSnapFromCgroup reads /proc/<PID>/cgroup and looks for lines containing
// a snap scope pattern like "snap.firefox.firefox" or "snap-firefox-*.scope".
func detectSnapFromCgroup(pid int) (string, bool) {
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if name := extractSnapNameFromCgroup(line); name != "" {
			return name, true
		}
	}
	return "", false
}

// extractSnapNameFromCgroup tries to extract a snap name from a cgroup line.
// Typical cgroup lines look like:
//
//	0::/user.slice/user-1000.slice/user@1000.service/app.slice/snap.firefox.firefox-<uuid>.scope
//	0::/system.slice/snap.lxd.daemon.service
func extractSnapNameFromCgroup(line string) string {
	// Find "snap." followed by the snap name and command
	idx := strings.Index(line, "snap.")
	if idx < 0 {
		return ""
	}
	// Extract everything after "snap."
	rest := line[idx+len("snap."):]

	// The format is <snapname>.<command>... — extract the snap name (first dot-separated part)
	dotIdx := strings.IndexByte(rest, '.')
	if dotIdx <= 0 {
		return ""
	}
	name := rest[:dotIdx]
	// Validate: snap names are lowercase alphanumeric + hyphens
	if name == "" || strings.ContainsAny(name, " \t/\\") {
		return ""
	}
	return name
}

// detectSnapFromAppArmor reads the current AppArmor profile from
// /proc/<PID>/attr/apparmor/current (or the legacy /proc/<PID>/attr/current)
// and checks for snap profile names like "snap.firefox.firefox".
func detectSnapFromAppArmor(pid int) (string, bool) {
	// Try the modern path first, then legacy
	paths := []string{
		fmt.Sprintf("/proc/%d/attr/apparmor/current", pid),
		fmt.Sprintf("/proc/%d/attr/current", pid),
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		profile := strings.TrimSpace(string(data))
		// Remove mode suffix like " (enforce)" or " (complain)"
		if idx := strings.IndexByte(profile, ' '); idx > 0 {
			profile = profile[:idx]
		}
		if strings.HasPrefix(profile, "snap.") {
			// snap.<name>.<command>
			parts := strings.SplitN(profile, ".", 3)
			if len(parts) >= 2 && parts[1] != "" {
				return parts[1], true
			}
		}
	}
	return "", false
}
