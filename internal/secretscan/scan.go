package secretscan

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

const maxScanBytes = 1 << 20

var forbiddenExtensions = []string{
	".wtinvite",
	".pem",
	".key",
	".p12",
	".pfx",
}

var privateKeyMarkers = []string{
	"-----BEGIN " + "OPENSSH PRIVATE KEY-----",
	"-----BEGIN " + "PRIVATE KEY-----",
	"-----BEGIN " + "ENCRYPTED PRIVATE KEY-----",
	"-----BEGIN " + "RSA PRIVATE KEY-----",
	"-----BEGIN " + "EC PRIVATE KEY-----",
	"-----BEGIN " + "DSA PRIVATE KEY-----",
}

var skipDirectoryNames = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	".cache":       {},
	".astro":       {},
	"dist":         {},
	"bin":          {},
}

// Finding is one secret-pattern match.
type Finding struct {
	Path   string
	Reason string
}

type inviteShape struct {
	Kind  string `json:"kind"`
	Nonce string `json:"nonce"`
	MAC   string `json:"mac"`
}

// ScanTree reports invite files, private-key material, and invite JSON secrets.
func ScanTree(root string) ([]Finding, error) {
	var findings []Finding
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name := entry.Name()
		if entry.IsDir() {
			if _, skip := skipDirectoryNames[name]; skip && path != root {
				return fs.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		lowerName := strings.ToLower(name)
		for _, ext := range forbiddenExtensions {
			if strings.HasSuffix(lowerName, ext) {
				findings = append(findings, Finding{Path: rel, Reason: "forbidden credential extension " + ext})
				return nil
			}
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() == 0 || info.Size() > maxScanBytes {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(raw)
		for _, marker := range privateKeyMarkers {
			if strings.Contains(text, marker) {
				findings = append(findings, Finding{Path: rel, Reason: "private key block"})
				return nil
			}
		}
		if looksLikeInviteSecret(raw) {
			findings = append(findings, Finding{Path: rel, Reason: "invite mac and nonce"})
		}
		return nil
	})
	return findings, err
}

func looksLikeInviteSecret(raw []byte) bool {
	var invite inviteShape
	if err := json.Unmarshal(raw, &invite); err != nil {
		return false
	}
	if invite.Kind != "warptweet.invite" {
		return false
	}
	return isHexSecret(invite.Nonce) && isHexSecret(invite.MAC)
}

func isHexSecret(value string) bool {
	if len(value) < 32 || len(value)%2 != 0 {
		return false
	}
	for _, r := range value {
		if !unicode.Is(unicode.ASCII_Hex_Digit, r) {
			return false
		}
		if r >= 'A' && r <= 'F' {
			return false
		}
	}
	return true
}
