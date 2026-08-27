package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warptweet.com/warptweet/internal/command"
	"warptweet.com/warptweet/internal/engine"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/knownhosts"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
)

const openSSHPrefixEnvironment = "WARPTWEET_OPENSSH_PREFIX"

func TestPinnedOpenSSHStagedCryptoAndRendering(t *testing.T) {
	prefix := os.Getenv(openSSHPrefixEnvironment)
	if prefix == "" {
		t.Skipf("set %s to a staged OpenSSH prefix to run", openSSHPrefixEnvironment)
	}
	if !filepath.IsAbs(prefix) || filepath.Clean(prefix) != prefix {
		t.Fatalf("%s must be a clean absolute path", openSSHPrefixEnvironment)
	}

	sshPath := stagedInstalledPath(t, prefix, installlayout.SSHPath)
	keygenPath := stagedInstalledPath(t, prefix, installlayout.SSHKeygenPath)
	sshdPath := stagedInstalledPath(t, prefix, installlayout.SSHDPath)
	bundleManifestPath := stagedInstalledPath(t, prefix, installlayout.OpenSSHBundleManifestPath)
	directory := t.TempDir()
	clientKeyPath := filepath.Join(directory, "client")
	hostKeyPath := filepath.Join(directory, "host")
	generateCompositeKey(t, keygenPath, clientKeyPath, "warptweet-integration-client")
	generateCompositeKey(t, keygenPath, hostKeyPath, "warptweet-integration-host")
	verifyCompositeSSHSIG(t, keygenPath, clientKeyPath)

	clientPublicKey := readFile(t, clientKeyPath+".pub")
	hostPublicKey := readFile(t, hostKeyPath+".pub")
	hostPin, err := knownhosts.RenderManagedHost("integration", hostPublicKey)
	if err != nil {
		t.Fatalf("render real host pin: %v", err)
	}
	if !bytes.HasSuffix(hostPin, []byte(" warptweet-managed-host\n")) {
		t.Fatalf("managed host marker is missing: %q", hostPin)
	}

	serverManifest := server.Config{
		Kind:                        server.ManifestKind,
		SchemaVersion:               server.CurrentSchemaVersion,
		ProfileID:                   profile.CurrentID,
		SSHDBinarySHA256:            fileSHA256(t, sshdPath),
		OpenSSHBundleManifestSHA256: fileSHA256(t, bundleManifestPath),
		Network:                     server.PublicationNetwork(netip.MustParseAddr("127.0.0.1"), 2222, 29722),
		Target: server.Endpoint{
			Address: netip.MustParseAddr("10.0.0.20"),
			Port:    5432,
		},
		DedicatedUser:      server.DefaultDedicatedUser,
		HostKeyPath:        installlayout.ServerHostKeyPath,
		AuthorizedKeysPath: installlayout.AuthorizedKeysDirectory + "/" + server.DefaultDedicatedUser,
	}
	authorizedKey, err := server.RenderAuthorizedKey(serverManifest, clientPublicKey, time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("render real authorized key: %v", err)
	}
	if _, err := server.ValidateAuthorizedKeys(serverManifest, authorizedKey); err != nil {
		t.Fatalf("rendered authorized key failed production validation: %v (%q)", err, authorizedKey)
	}
	if !bytes.Contains(authorizedKey, []byte(`permitopen="10.0.0.20:5432"`)) ||
		!bytes.Contains(authorizedKey, []byte(`permitopen="127.0.0.1:29723"`)) ||
		!bytes.HasSuffix(authorizedKey, []byte(" warptweet-managed-client\n")) {
		t.Fatalf("unexpected managed authorized key: %q", authorizedKey)
	}
	serverManifestBytes, err := json.Marshal(serverManifest)
	if err != nil {
		t.Fatalf("marshal server manifest: %v", err)
	}
	serverManifestPath := filepath.Join(directory, "server.wt")
	writePrivateFile(t, serverManifestPath, serverManifestBytes)
	expectedServerConfig, err := server.Render(serverManifest)
	if err != nil {
		t.Fatalf("render server configuration: %v", err)
	}
	if rendered := runCLI(t,
		"render-server",
		"--config", serverManifestPath,
	); !bytes.Equal(rendered, expectedServerConfig) {
		t.Fatalf("CLI server configuration differs from renderer output")
	}
	if rendered := runCLI(t,
		"render-authorized-key",
		"--config", serverManifestPath,
		"--public-key", clientKeyPath+".pub",
		"--not-after", "2026-09-15T12:00:00Z",
	); !bytes.Equal(rendered, authorizedKey) {
		t.Fatalf("CLI authorized key differs from renderer output")
	}

	knownHostsPath := filepath.Join(directory, "known_hosts")
	globalKnownHostsPath := filepath.Join(directory, "known_hosts.empty")
	writePrivateFile(t, knownHostsPath, hostPin)
	writePrivateFile(t, globalKnownHostsPath, nil)

	selectedProfile, err := profile.Lookup(profile.CurrentID)
	if err != nil {
		t.Fatalf("lookup profile: %v", err)
	}
	clientSpec := engine.ClientSpec{
		TunnelID:             "integration",
		ServerAddress:        netip.MustParseAddr("192.0.2.10"),
		ServerPort:           2222,
		ServerUser:           server.DefaultDedicatedUser,
		ListenAddress:        netip.MustParseAddr("127.0.0.1"),
		ListenPort:           15432,
		TargetAddress:        netip.MustParseAddr("10.0.0.20"),
		TargetPort:           5432,
		IdentityFile:         clientKeyPath,
		KnownHostsFile:       knownHostsPath,
		GlobalKnownHostsFile: globalKnownHostsPath,
		Profile:              selectedProfile,
	}
	clientConfig, err := engine.RenderClientConfig(clientSpec)
	if err != nil {
		t.Fatalf("render client config: %v", err)
	}
	if !strings.Contains(clientConfig, "Host warptweet-peer\n") ||
		!strings.Contains(clientConfig, "    LocalForward ") {
		t.Fatalf("diagnostic client policy is incomplete:\n%s", clientConfig)
	}
	arguments, err := engine.Arguments(clientSpec)
	if err != nil {
		t.Fatalf("build closed client arguments: %v", err)
	}
	effectiveOutput, effectiveErr := exec.Command(sshPath, append([]string{"-G"}, arguments...)...).CombinedOutput()
	if effectiveErr != nil {
		t.Fatalf("resolve real effective config: %v: %s", effectiveErr, effectiveOutput)
	}
	for _, required := range []string{
		"kexalgorithms " + selectedProfile.KeyExchangeAlgorithm,
		"hostkeyalgorithms " + selectedProfile.AuthenticationKeyType,
		"pubkeyacceptedalgorithms " + selectedProfile.AuthenticationKeyType,
		"ciphers " + strings.Join(selectedProfile.Ciphers, ","),
		"localforward [127.0.0.1]:15432 [10.0.0.20]:5432",
	} {
		if !bytes.Contains(effectiveOutput, []byte(required+"\n")) {
			t.Fatalf("staged ssh -G output omits %q:\n%s", required, effectiveOutput)
		}
	}
}

func stagedInstalledPath(t *testing.T, prefix, installedPath string) string {
	t.Helper()

	installedPrefix := filepath.Clean(filepath.FromSlash(installlayout.OpenSSHPrefix))
	if !strings.HasSuffix(prefix, installedPrefix) {
		t.Fatalf("%s must end in the fixed OpenSSH prefix %s", openSSHPrefixEnvironment, installedPrefix)
	}
	stageRoot := strings.TrimSuffix(prefix, installedPrefix)
	if stageRoot == "" {
		stageRoot = string(filepath.Separator)
	}
	cleanInstalledPath := filepath.Clean(filepath.FromSlash(installedPath))
	if !filepath.IsAbs(cleanInstalledPath) {
		t.Fatalf("installed path must be absolute: %s", installedPath)
	}
	return filepath.Join(stageRoot, strings.TrimPrefix(cleanInstalledPath, string(filepath.Separator)))
}

func generateCompositeKey(t *testing.T, keygenPath, destination, comment string) {
	t.Helper()
	command := exec.Command(
		keygenPath,
		"-q",
		"-t", "mldsa44-ed25519",
		"-N", "",
		"-C", comment,
		"-f", destination,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate composite key: %v: %s", err, output)
	}
}

func verifyCompositeSSHSIG(t *testing.T, keygenPath, privateKeyPath string) {
	t.Helper()
	payload := []byte("WarpTweet composite signature integration vector\n")
	payloadPath := filepath.Join(filepath.Dir(privateKeyPath), "payload.txt")
	writePrivateFile(t, payloadPath, payload)

	signer := exec.Command(
		keygenPath,
		"-Y", "sign",
		"-f", privateKeyPath,
		"-n", "warptweet-integration",
		payloadPath,
	)
	if output, err := signer.CombinedOutput(); err != nil {
		t.Fatalf("sign integration payload: %v: %s", err, output)
	}

	publicKey := strings.TrimSpace(string(readFile(t, privateKeyPath+".pub")))
	allowedSignersPath := filepath.Join(filepath.Dir(privateKeyPath), "allowed_signers")
	writePrivateFile(
		t,
		allowedSignersPath,
		[]byte("warptweet-integration "+publicKey+"\n"),
	)
	signaturePath := payloadPath + ".sig"
	verify := func(input []byte) error {
		process := exec.Command(
			keygenPath,
			"-Y", "verify",
			"-f", allowedSignersPath,
			"-I", "warptweet-integration",
			"-n", "warptweet-integration",
			"-s", signaturePath,
		)
		process.Stdin = bytes.NewReader(input)
		output, err := process.CombinedOutput()
		if err != nil {
			return fmt.Errorf("verify integration signature: %w: %s", err, output)
		}
		return nil
	}
	if err := verify(payload); err != nil {
		t.Fatal(err)
	}
	if err := verify(append(append([]byte(nil), payload...), '!')); err == nil {
		t.Fatal("composite SSHSIG verification accepted a modified payload")
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return contents
}

func writePrivateFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %q for hashing: %v", path, err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		t.Fatalf("hash %q: %v", path, err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func runCLI(t *testing.T, arguments ...string) []byte {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := command.Run(context.Background(), arguments, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("warptweet %s failed with code %d: %s", strings.Join(arguments, " "), code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("warptweet %s wrote unexpected stderr: %s", strings.Join(arguments, " "), stderr.String())
	}
	return stdout.Bytes()
}
