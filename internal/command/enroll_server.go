package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/installlayout"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
)

const (
	enrollmentRateLimitWindow     = time.Minute
	enrollmentRateLimitMax        = 30
	enrollmentRateLimitMaxSources = 4096
)

func runServerEnrollListen(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("server enroll-listen", stderr)
	listen := onceStringFlag{name: "--listen"}
	flags.Var(&listen, "listen", "numeric enrollment listen address:port")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}

	manifest, err := server.Load(installlayout.ServerManifestPath)
	if err != nil {
		return err
	}
	listenEndpoint, err := resolveEnrollListen(listen.value, manifest)
	if err != nil {
		return err
	}

	hostPublicKey, err := deriveHostPublicKey(ctx, manifest.HostKeyPath)
	if err != nil {
		return err
	}

	handler := newEnrollmentHandler(manifest, hostPublicKey, listenEndpoint.Port())
	httpServer := &http.Server{
		Addr:              listenEndpoint.String(),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    4 << 10,
	}

	listener, err := net.Listen("tcp", listenEndpoint.String())
	if err != nil {
		return fmt.Errorf("listen for enrollment: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpServer.Serve(listener)
	}()

	fmt.Fprintf(stdout, "enrollment listening\nlisten   %s\npath     POST /v1/enroll\npath     POST /v1/revoke\npath     POST /v1/rotate\n", listenEndpoint)
	if abs, err := enrollment.EnrollmentURL(listenEndpoint.Addr().String(), listenEndpoint.Port()); err == nil {
		fmt.Fprintf(stdout, "url      %s\n", abs)
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func runServerAcceptEnrollment(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("server accept-enrollment", stderr)
	requestPath := onceStringFlag{name: "--request"}
	flags.Var(&requestPath, "request", "path to enrollment request JSON")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if requestPath.value == "" {
		return errors.New("server accept-enrollment requires --request <path>")
	}
	raw, err := os.ReadFile(requestPath.value)
	if err != nil {
		return err
	}
	if len(raw) > enrollment.MaxEnrollmentRequestBytes {
		return fmt.Errorf("enrollment request exceeds %d bytes", enrollment.MaxEnrollmentRequestBytes)
	}
	var request enrollment.EnrollmentRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return fmt.Errorf("parse enrollment request: %w", err)
	}
	manifest, err := server.Load(installlayout.ServerManifestPath)
	if err != nil {
		return err
	}
	hostPublicKey, err := deriveHostPublicKey(ctx, manifest.HostKeyPath)
	if err != nil {
		return err
	}
	proof, err := acceptAndAuthorize(manifest, hostPublicKey, request, time.Now().UTC())
	if err != nil {
		return err
	}
	return writeJSON(stdout, proof)
}

func resolveEnrollListen(flagValue string, manifest server.Config) (netip.AddrPort, error) {
	if flagValue != "" {
		return parseEndpoint(flagValue)
	}
	return netip.AddrPortFrom(manifest.Listen.Address, enrollment.DefaultEnrollmentPort), nil
}

func newEnrollmentHandler(manifest server.Config, hostPublicKey string, enrollPort uint16) http.Handler {
	limiter := newEnrollmentRateLimiter(enrollmentRateLimitWindow, enrollmentRateLimitMax)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/enroll", func(writer http.ResponseWriter, request *http.Request) {
		writeEnrollmentJSON(writer, request, "enroll", limiter, func(body []byte) (any, error) {
			var enrollRequest enrollment.EnrollmentRequest
			if err := json.Unmarshal(body, &enrollRequest); err != nil {
				return nil, err
			}
			return acceptAndAuthorize(manifest, hostPublicKey, enrollRequest, time.Now().UTC())
		})
	})
	mux.HandleFunc("/v1/revoke", func(writer http.ResponseWriter, request *http.Request) {
		writeEnrollmentJSON(writer, request, "revoke", limiter, func(body []byte) (any, error) {
			var manage enrollment.ManagementRequest
			if err := json.Unmarshal(body, &manage); err != nil {
				return nil, err
			}
			record, err := enrollment.RevokeClient(installlayout.ClientsDirectory, manage, time.Now().UTC())
			if err != nil {
				return nil, err
			}
			if err := removeAuthorizedKeyForPublicKey(manifest.AuthorizedKeysPath, record.PublicKey); err != nil {
				return nil, err
			}
			return map[string]any{
				"status":     "revoked",
				"client_id":  record.ClientID,
				"tunnel_id":  record.TunnelID,
				"revoked_at": record.RevokedAt,
			}, nil
		})
	})
	mux.HandleFunc("/v1/rotate", func(writer http.ResponseWriter, request *http.Request) {
		writeEnrollmentJSON(writer, request, "rotate", limiter, func(body []byte) (any, error) {
			var manage enrollment.ManagementRequest
			if err := json.Unmarshal(body, &manage); err != nil {
				return nil, err
			}
			if manage.NewPublicKey == "" {
				return nil, fmt.Errorf("%w: new_public_key is required", enrollment.ErrInvalidInvite)
			}
			line, err := server.RenderAuthorizedKey(manifest, []byte(manage.NewPublicKey))
			if err != nil {
				return nil, fmt.Errorf("%w: %v", enrollment.ErrInvalidInvite, err)
			}
			prior, err := enrollment.LoadClient(installlayout.ClientsDirectory, manage.ClientID)
			if err != nil {
				return nil, fmt.Errorf("%w: unknown client", enrollment.ErrInvalidInvite)
			}
			record, token, err := enrollment.RotateClientPublicKey(
				installlayout.ClientsDirectory,
				manage,
				manage.NewPublicKey,
				time.Now().UTC(),
			)
			if err != nil {
				return nil, err
			}
			if err := replaceAuthorizedKeyForPublicKey(manifest.AuthorizedKeysPath, prior.PublicKey, line); err != nil {
				return nil, err
			}
			return enrollment.EnrollmentProof{
				InviteID:        record.InviteID,
				ClientID:        record.ClientID,
				HostPublicKey:   hostPublicKey,
				PublicKey:       record.PublicKey,
				Target:          fmt.Sprintf("%s:%d", manifest.Target.Address, manifest.Target.Port),
				Principal:       record.Principal,
				ProfileID:       record.ProfileID,
				Nonce:           "",
				AcceptedAt:      time.Now().UTC().Format(time.RFC3339Nano),
				ManagementToken: token,
				ServerAddress:   record.ServerAddress,
				EnrollPort:      enrollPort,
			}, nil
		})
	})
	return mux
}

func writeEnrollmentJSON(
	writer http.ResponseWriter,
	request *http.Request,
	operation string,
	limiter *enrollmentRateLimiter,
	handle func([]byte) (any, error),
) {
	source := requestSource(request)
	if request.Method != http.MethodPost {
		auditEnrollment(operation, source, "rejected", "method_not_allowed")
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if limiter != nil && !limiter.allow(source) {
		auditEnrollment(operation, source, "rejected", "rate_limited")
		http.Error(writer, "rate limited", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, int64(enrollment.MaxEnrollmentRequestBytes)+1))
	if err != nil {
		auditEnrollment(operation, source, "rejected", "read_body")
		http.Error(writer, "read body", http.StatusBadRequest)
		return
	}
	if len(body) > enrollment.MaxEnrollmentRequestBytes {
		auditEnrollment(operation, source, "rejected", "request_too_large")
		http.Error(writer, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	result, err := handle(body)
	if err != nil {
		status := http.StatusBadRequest
		message := "enrollment request failed"
		reason := "request_failed"
		if errors.Is(err, enrollment.ErrInvalidInvite) {
			status = http.StatusForbidden
			message = "enrollment forbidden"
			reason = "forbidden"
		}
		auditEnrollment(operation, source, "rejected", reason)
		http.Error(writer, message, status)
		return
	}
	auditEnrollment(operation, source, "accepted", "")
	writer.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(result)
}

type enrollmentRateLimiter struct {
	mu         sync.Mutex
	window     time.Duration
	max        int
	maxSources int
	entries    map[string][]time.Time
}

func newEnrollmentRateLimiter(window time.Duration, max int) *enrollmentRateLimiter {
	return &enrollmentRateLimiter{
		window:     window,
		max:        max,
		maxSources: enrollmentRateLimitMaxSources,
		entries:    map[string][]time.Time{},
	}
}

func (limiter *enrollmentRateLimiter) allow(source string) bool {
	if source == "" {
		source = "unknown"
	}
	now := time.Now()
	cutoff := now.Add(-limiter.window)
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	// Evict inactive sources globally so unique remotes cannot grow without bound.
	for key, events := range limiter.entries {
		kept := events[:0]
		for _, event := range events {
			if event.After(cutoff) {
				kept = append(kept, event)
			}
		}
		if len(kept) == 0 {
			delete(limiter.entries, key)
			continue
		}
		limiter.entries[key] = kept
	}

	events := limiter.entries[source]
	if len(events) >= limiter.max {
		return false
	}
	if _, exists := limiter.entries[source]; !exists {
		for len(limiter.entries) >= limiter.maxSources {
			if !limiter.evictOldestSourceLocked() {
				return false
			}
		}
	}
	limiter.entries[source] = append(events, now)
	return true
}

func (limiter *enrollmentRateLimiter) evictOldestSourceLocked() bool {
	if len(limiter.entries) == 0 {
		return false
	}
	var oldestKey string
	var oldestTime time.Time
	first := true
	for key, events := range limiter.entries {
		if len(events) == 0 {
			delete(limiter.entries, key)
			return true
		}
		// Most recent event approximates source activity within the window.
		last := events[len(events)-1]
		if first || last.Before(oldestTime) {
			oldestKey = key
			oldestTime = last
			first = false
		}
	}
	if oldestKey == "" {
		return false
	}
	delete(limiter.entries, oldestKey)
	return true
}

func requestSource(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return host
}

func auditEnrollment(operation, source, outcome, reason string) {
	attrs := []any{
		"operation", operation,
		"source", source,
		"outcome", outcome,
	}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	slog.Info("enrollment_audit", attrs...)
}

func acceptAndAuthorize(
	manifest server.Config,
	hostPublicKey string,
	request enrollment.EnrollmentRequest,
	now time.Time,
) (enrollment.EnrollmentProof, error) {
	line, err := server.RenderAuthorizedKey(manifest, []byte(request.PublicKey))
	if err != nil {
		return enrollment.EnrollmentProof{}, fmt.Errorf("%w: %v", enrollment.ErrInvalidInvite, err)
	}
	if err := os.MkdirAll(installlayout.ClientsDirectory, 0o700); err != nil {
		return enrollment.EnrollmentProof{}, err
	}
	result, err := enrollment.Accept(enrollment.AcceptInput{
		Directory:        inviteDirectory,
		ClientsDirectory: installlayout.ClientsDirectory,
		Request:          request,
		HostPublicKey:    hostPublicKey,
		Principal:        manifest.DedicatedUser,
		ProfileID:        profile.CurrentID,
		TargetAddress:    manifest.Target.Address.String(),
		TargetPort:       uint16(manifest.Target.Port),
		ServerAddress:    manifest.Listen.Address.String(),
		Now:              now,
	})
	if err != nil {
		return enrollment.EnrollmentProof{}, err
	}
	if err := appendAuthorizedKey(manifest.AuthorizedKeysPath, line); err != nil {
		return enrollment.EnrollmentProof{}, fmt.Errorf("install authorized_keys: %w", err)
	}
	return result.Proof, nil
}

func authorizedKeyBlob(publicKey string) string {
	fields := strings.Fields(strings.TrimSpace(publicKey))
	if len(fields) < 2 {
		return ""
	}
	// Plain public-key line: type blob [comment...]
	// Managed authorized_keys line: options type blob comment
	if strings.Contains(fields[0], ",") || strings.HasPrefix(fields[0], "restrict") {
		if len(fields) < 3 {
			return ""
		}
		return fields[2]
	}
	return fields[1]
}

func readAuthorizedKeyLines(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines = append(lines, line)
	}
	return lines, nil
}

func writeAuthorizedKeyLines(path string, lines []string) error {
	var builder strings.Builder
	for _, line := range lines {
		builder.WriteString(line)
		if !strings.HasSuffix(line, "\n") {
			builder.WriteByte('\n')
		}
	}
	return writeFileAtomic(path, []byte(builder.String()), 0o600)
}

func authorizedKeysLockName(path string) string {
	return "." + filepath.Base(path) + ".lock"
}

func withAuthorizedKeysLock(path string, fn func() error) error {
	return enrollment.WithExclusiveLock(filepath.Dir(path), authorizedKeysLockName(path), fn)
}

func appendAuthorizedKey(path string, line []byte) error {
	return withAuthorizedKeysLock(path, func() error {
		lines, err := readAuthorizedKeyLines(path)
		if err != nil {
			return err
		}
		entry := strings.TrimRight(string(line), "\n")
		blob := authorizedKeyBlob(entry)
		if blob != "" {
			for _, existing := range lines {
				if authorizedKeyBlob(existing) == blob {
					return nil
				}
			}
		}
		lines = append(lines, entry)
		return writeAuthorizedKeyLines(path, lines)
	})
}

func replaceAuthorizedKeyForPublicKey(path, oldPublicKey string, newLine []byte) error {
	return withAuthorizedKeysLock(path, func() error {
		lines, err := readAuthorizedKeyLines(path)
		if err != nil {
			return err
		}
		oldBlob := authorizedKeyBlob(oldPublicKey)
		entry := strings.TrimRight(string(newLine), "\n")
		replaced := false
		for i, existing := range lines {
			if oldBlob != "" && authorizedKeyBlob(existing) == oldBlob {
				lines[i] = entry
				replaced = true
				break
			}
		}
		if !replaced {
			lines = append(lines, entry)
		}
		return writeAuthorizedKeyLines(path, lines)
	})
}

func removeAuthorizedKeyForPublicKey(path, publicKey string) error {
	return withAuthorizedKeysLock(path, func() error {
		lines, err := readAuthorizedKeyLines(path)
		if err != nil {
			return err
		}
		blob := authorizedKeyBlob(publicKey)
		if blob == "" {
			return nil
		}
		filtered := lines[:0]
		for _, existing := range lines {
			if authorizedKeyBlob(existing) == blob {
				continue
			}
			filtered = append(filtered, existing)
		}
		return writeAuthorizedKeyLines(path, filtered)
	})
}
