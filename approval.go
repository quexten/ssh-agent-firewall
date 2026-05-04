package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// ApprovalRequest holds the information needed to request user approval for a sign operation.
type ApprovalRequest struct {
	SocketName     string
	KeyFingerprint string
	ProcessInfo    string
	DestHost       string
	Timestamp      time.Time
}

// requestApproval prompts the user for approval to sign with a key.
// It returns true if approved, false if denied or timeout occurs.
// On platforms without a dialog system, it falls back to a CLI prompt.
func requestApproval(req ApprovalRequest, timeout time.Duration) (approved bool, decision string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Build message for user
	message := fmt.Sprintf("SSH Agent Firewall\n\nSocket: %s\nKey: %s\nProcess: %s",
		req.SocketName, truncate(req.KeyFingerprint, 20), req.ProcessInfo)
	if req.DestHost != "" {
		message += fmt.Sprintf("\nHost: %s", req.DestHost)
	}
	message += "\n\nAllow this key to be used for signing?"

	// Platform-specific dialog
	switch runtime.GOOS {
	case "darwin":
		return showMacDialog(ctx, message)
	case "linux":
		return showLinuxDialog(ctx, message)
	default:
		return showCLIPrompt(ctx, message)
	}
}

// showMacDialog displays an interactive dialog on macOS using osascript.
func showMacDialog(ctx context.Context, message string) (bool, string) {
	script := fmt.Sprintf(`
display dialog %q buttons {"Deny", "Allow"} default button 2 with icon note
set answer to button returned of result
if answer is equal to "Allow" then
  return "approved"
else
  return "denied"
end if
`, message)

	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		// Check if context timeout
		if ctx.Err() == context.DeadlineExceeded {
			return false, "timeout"
		}
		// Any error -> deny
		return false, "denied"
	}

	// Parse response
	response := bytes.TrimSpace(out.Bytes())
	if bytes.Equal(response, []byte("approved")) {
		return true, "granted"
	}
	return false, "denied"
}

// showLinuxDialog displays an interactive dialog on Linux using zenity if available.
// Falls back to CLI prompt if zenity is not installed.
func showLinuxDialog(ctx context.Context, message string) (bool, string) {
	// Try zenity first
	if hasCommand("zenity") {
		return showZenityDialog(ctx, message)
	}

	// Fallback to CLI prompt
	return showCLIPrompt(ctx, message)
}

// showZenityDialog displays a dialog using zenity.
func showZenityDialog(ctx context.Context, message string) (bool, string) {
	cmd := exec.CommandContext(ctx, "zenity",
		"--question",
		"--title", "SSH Agent Firewall",
		"--text", message,
		"--ok-label", "Allow",
		"--cancel-label", "Deny",
		"--no-wrap",
	)

	err := cmd.Run()
	if err != nil {
		// Check if context timeout
		if ctx.Err() == context.DeadlineExceeded {
			return false, "timeout"
		}
		// zenity returns exit code 1 for "No" / "Deny"
		return false, "denied"
	}

	// Exit code 0 means "Yes" / "Allow"
	return true, "granted"
}

// showCLIPrompt displays a text prompt in the terminal (non-blocking).
// Returns false immediately to allow SSH operations to proceed,
// but logs a message for user awareness.
func showCLIPrompt(ctx context.Context, message string) (bool, string) {
	// Non-blocking fallback: just print to stderr and deny
	// This prevents hanging SSH operations while still logging the request
	fmt.Fprintf(os.Stderr, "\n=== SSH Agent Firewall Approval Request ===\n%s\n[Auto-denying due to no interactive dialog available]\n\n", message)
	return false, "denied"
}

// hasCommand checks if a command is available in PATH.
func hasCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// truncate shortens a string to maxLen characters, adding "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
