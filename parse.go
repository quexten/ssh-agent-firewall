package main

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SessionBindInfo holds parsed information from a session-bind@openssh.com extension message.
type SessionBindInfo struct {
	HostKey      []byte
	SessionID    []byte
	Signature    []byte
	IsForwarding bool

	HostKeyFingerprint string
	HostKeyType        string
}

// parseSessionBind parses the contents of a session-bind@openssh.com extension message.
func parseSessionBind(contents []byte) (*SessionBindInfo, error) {
	info := &SessionBindInfo{}

	hostKey, rest, err := parseSSHString(contents)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hostkey: %w", err)
	}
	info.HostKey = hostKey

	sessionID, rest, err := parseSSHString(rest)
	if err != nil {
		return nil, fmt.Errorf("failed to parse session identifier: %w", err)
	}
	info.SessionID = sessionID

	signature, rest, err := parseSSHString(rest)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature: %w", err)
	}
	info.Signature = signature

	if len(rest) < 1 {
		return nil, fmt.Errorf("missing is_forwarding flag")
	}
	info.IsForwarding = rest[0] != 0

	info.HostKeyFingerprint = keyFingerprint(info.HostKey)
	pubKey, err := ssh.ParsePublicKey(info.HostKey)
	if err == nil {
		info.HostKeyType = pubKey.Type()
	}

	return info, nil
}

// AuthRequestInfo holds parsed information from SSH user authentication signing data.
type AuthRequestInfo struct {
	SessionID     []byte
	Username      string
	Service       string
	Method        string
	HasSignature  bool
	PubKeyAlg     string
	PubKey        []byte
	ServerHostKey []byte

	PubKeyFingerprint        string
	ServerHostKeyFingerprint string
	ServerHostKeyType        string
	IsHostBound              bool
}

const (
	msgUserAuthRequest = 50
	methodPublicKey    = "publickey"
	methodHostBound    = "publickey-hostbound-v00@openssh.com"
)

// parseAuthData attempts to parse SSH user authentication signing data.
// Returns nil, nil if the data is not a recognized auth request.
func parseAuthData(data []byte) (*AuthRequestInfo, error) {
	if len(data) < 5 {
		return nil, nil
	}

	info := &AuthRequestInfo{}

	sessionID, rest, err := parseSSHString(data)
	if err != nil {
		return nil, nil
	}
	info.SessionID = sessionID

	if len(rest) < 1 || rest[0] != msgUserAuthRequest {
		return nil, nil
	}
	rest = rest[1:]

	username, rest, err := parseSSHString(rest)
	if err != nil {
		return nil, nil
	}
	info.Username = string(username)

	service, rest, err := parseSSHString(rest)
	if err != nil {
		return nil, nil
	}
	info.Service = string(service)

	method, rest, err := parseSSHString(rest)
	if err != nil {
		return nil, nil
	}
	info.Method = string(method)

	if info.Method != methodPublicKey && info.Method != methodHostBound {
		return nil, nil
	}

	if len(rest) < 1 {
		return nil, nil
	}
	info.HasSignature = rest[0] != 0
	rest = rest[1:]

	pkalg, rest, err := parseSSHString(rest)
	if err != nil {
		return nil, nil
	}
	info.PubKeyAlg = string(pkalg)

	pubkey, rest, err := parseSSHString(rest)
	if err != nil {
		return nil, nil
	}
	info.PubKey = pubkey
	info.PubKeyFingerprint = keyFingerprint(info.PubKey)

	info.IsHostBound = info.Method == methodHostBound
	if info.IsHostBound && len(rest) > 4 {
		serverHostKey, _, err := parseSSHString(rest)
		if err == nil && len(serverHostKey) > 0 {
			info.ServerHostKey = serverHostKey
			info.ServerHostKeyFingerprint = keyFingerprint(info.ServerHostKey)
			pk, err := ssh.ParsePublicKey(info.ServerHostKey)
			if err == nil {
				info.ServerHostKeyType = pk.Type()
			}
		}
	}

	return info, nil
}

// parseSSHString reads an SSH wire-format string (uint32 length + data) from buf.
func parseSSHString(buf []byte) ([]byte, []byte, error) {
	if len(buf) < 4 {
		return nil, nil, fmt.Errorf("buffer too short for string length")
	}
	length := binary.BigEndian.Uint32(buf[:4])
	if uint64(length) > uint64(len(buf)-4) {
		return nil, nil, fmt.Errorf("string length %d exceeds buffer size %d", length, len(buf)-4)
	}
	return buf[4 : 4+length], buf[4+length:], nil
}

// signNotificationMessage builds a desktop notification message for a sign operation,
// resolving the destination hostname when available.
func signNotificationMessage(socketName, processInfo string, authInfo *AuthRequestInfo, knownHosts *KnownHostsIndex) string {
	host := ""
	if authInfo.IsHostBound && authInfo.ServerHostKeyFingerprint != "" && knownHosts != nil {
		if hosts := knownHosts.Lookup(authInfo.ServerHostKeyFingerprint); len(hosts) > 0 {
			host = strings.Join(hosts, ", ")
		}
	}
	if host != "" {
		return fmt.Sprintf("[%s] Signing %s@%s (%s)", socketName, authInfo.Username, host, processInfo)
	}
	return fmt.Sprintf("[%s] Signing %s (%s)", socketName, authInfo.Username, processInfo)
}

// formatSessionBindInfo returns a human-readable summary of a session bind message.
func formatSessionBindInfo(info *SessionBindInfo, knownHosts *KnownHostsIndex) string {
	bindType := "authentication"
	if info.IsForwarding {
		bindType = "forwarding"
	}
	keyType := info.HostKeyType
	if keyType == "" {
		keyType = "unknown"
	}
	if knownHosts != nil {
		if hosts := knownHosts.Lookup(info.HostKeyFingerprint); len(hosts) > 0 {
			return fmt.Sprintf("type=%s host=%s", bindType, strings.Join(hosts, ", "))
		}
	}
	return fmt.Sprintf("type=%s hostkey=%s (%s)", bindType, info.HostKeyFingerprint, keyType)
}

// formatAuthRequestInfo returns a human-readable summary of an auth request.
func formatAuthRequestInfo(info *AuthRequestInfo, knownHosts *KnownHostsIndex) string {
	msg := fmt.Sprintf("user=%s service=%s method=%s key=%s",
		info.Username, info.Service, info.Method, info.PubKeyFingerprint)
	if info.IsHostBound && info.ServerHostKeyFingerprint != "" {
		if knownHosts != nil {
			if hosts := knownHosts.Lookup(info.ServerHostKeyFingerprint); len(hosts) > 0 {
				msg += fmt.Sprintf(" dest_host=%s", strings.Join(hosts, ", "))
				return msg
			}
		}
		serverKeyType := info.ServerHostKeyType
		if serverKeyType == "" {
			serverKeyType = "unknown"
		}
		msg += fmt.Sprintf(" dest_hostkey=%s (%s)", info.ServerHostKeyFingerprint, serverKeyType)
	}
	return msg
}
