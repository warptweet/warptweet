package command

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"warptweet.com/warptweet/internal/server"
)

const (
	hostDesiredKind = "warptweet.host-desired-revision"
	hostAppliedKind = "warptweet.host-applied-receipt"
	hostRevisionVer = 1
	desiredFileName = "desired-revision.json"
	appliedFileName = "applied-receipt.json"
)

type hostRevision struct {
	Kind           string `json:"kind"`
	SchemaVersion  int    `json:"schema_version"`
	NetworkSHA256  string `json:"network_sha256"`
	CertLeafSHA256 string `json:"cert_leaf_sha256"`
}

func (rev hostRevision) equal(other hostRevision) bool {
	return rev.NetworkSHA256 == other.NetworkSHA256 && rev.CertLeafSHA256 == other.CertLeafSHA256
}

func computeHostRevision(kind string, network server.Network, certPath string) (hostRevision, error) {
	networkHash, err := canonicalNetworkSHA256(network)
	if err != nil {
		return hostRevision{}, err
	}
	leaf, err := certLeafSHA256(certPath)
	if err != nil {
		return hostRevision{}, err
	}
	return hostRevision{
		Kind:           kind,
		SchemaVersion:  hostRevisionVer,
		NetworkSHA256:  networkHash,
		CertLeafSHA256: leaf,
	}, nil
}

func canonicalNetworkSHA256(network server.Network) (string, error) {
	encoded, err := json.Marshal(network)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func certLeafSHA256(path string) (string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("enrollment certificate %q is not a PEM CERTIFICATE", path)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", fmt.Errorf("parse enrollment certificate: %w", err)
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

func desiredRevisionPath(stateDir string) string {
	return filepath.Join(stateDir, desiredFileName)
}

func appliedReceiptPath(stateDir string) string {
	return filepath.Join(stateDir, appliedFileName)
}

func writeHostRevision(path string, rev hostRevision) error {
	return writeFileAtomicJSON(path, rev, 0o600)
}

func loadHostRevision(path string) (hostRevision, bool, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return hostRevision{}, false, nil
		}
		return hostRevision{}, false, err
	}
	var rev hostRevision
	if err := json.Unmarshal(contents, &rev); err != nil {
		return hostRevision{}, false, err
	}
	return rev, true, nil
}

func writeFileAtomicJSON(path string, value any, mode os.FileMode) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return writeFileAtomic(path, encoded, mode)
}
