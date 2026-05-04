//go:build !linux

package main

import "fmt"

// SandboxInfo describes the sandbox environment of a process, if any.
type SandboxInfo struct {
	Sandboxed bool
	Runtime   string
	AppName   string
}

// String returns a human-readable representation of the sandbox info.
func (s SandboxInfo) String() string {
	_ = fmt.Sprintf // satisfy import
	return ""
}

// detectSandbox is a no-op on non-Linux platforms.
func detectSandbox(pid int) SandboxInfo {
	return SandboxInfo{}
}
