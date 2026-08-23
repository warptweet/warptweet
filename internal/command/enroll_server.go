package command

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/grant"
	"warptweet.com/warptweet/internal/grantsession"
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
	now := time.Now().UTC()
	if grant.ClockIsBlocked(installlayout.HostClockBlockedPath) {
		return fmt.Errorf("host clock: blocked until warptweet server clock-recover")
	}
	if _, err := grant.ObserveClock(installlayout.HostClockObservationPath, now); err != nil {
		if closeErr := enterBlockedClock(manifest, err); closeErr != nil {
			return closeErr
		}
		return fmt.Errorf("host clock: %w", err)
	}
	if err := reconcileExpiredGrants(manifest, now); err != nil {
		return fmt.Errorf("reconcile expired grants: %w", err)
	}
	if err := reconcileManagedAuthorizations(manifest); err != nil {
		return fmt.Errorf("reconcile managed authorizations: %w", err)
	}
	listenEndpoint, err := resolveEnrollListen(listen.value, manifest)
	if err != nil {
		return err
	}

	hostPublicKey, err := deriveHostPublicKey(ctx, manifest.HostKeyPath)
	if err != nil {
		return err
	}
	if _, _, _, err := enrollment.EnsureTLSIdentity(
		installlayout.ServerEnrollmentTLSCertPath,
		installlayout.ServerEnrollmentTLSKeyPath,
		[]net.IP{net.IP(manifest.Listen.Address.AsSlice())},
		time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("ensure enrollment TLS identity: %w", err)
	}

	handler := newEnrollmentHandler(manifest, hostPublicKey, listenEndpoint.Port())
	tlsConfig, err := enrollment.LoadServerTLSConfig(
		installlayout.ServerEnrollmentTLSCertPath,
		installlayout.ServerEnrollmentTLSKeyPath,
	)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:              listenEndpoint.String(),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    4 << 10,
	}

	tcpListener, err := net.Listen("tcp", listenEndpoint.String())
	if err != nil {
		return fmt.Errorf("listen for enrollment: %w", err)
	}
	listener := tls.NewListener(newLimitedListener(tcpListener, enrollmentAcceptLimit), tlsConfig)

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpServer.Serve(listener)
	}()

	fmt.Fprintf(stdout, "enrollment TLS listening\nlisten   %s\npath     POST /v1/enroll\n", listenEndpoint)
	if abs, err := enrollment.EnrollmentURL(listenEndpoint.Addr().String(), listenEndpoint.Port()); err == nil {
		fmt.Fprintf(stdout, "url      %s\n", abs)
	}

	go idleEnrollWhenInvitesGone(ctx, httpServer)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
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
		}, nil)
	})
	return mux
}

func newManagementHandler(manifest server.Config, hostPublicKey string) http.Handler {
	limiter := newEnrollmentRateLimiter(enrollmentRateLimitWindow, enrollmentRateLimitMax)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/revoke", func(writer http.ResponseWriter, request *http.Request) {
		authority := productionGrantAuthority()
		var revoked enrollment.ClientRecord
		writeEnrollmentJSON(writer, request, "revoke", limiter, func(body []byte) (any, error) {
			var manage enrollment.ManagementRequest
			if err := json.Unmarshal(body, &manage); err != nil {
				return nil, err
			}
			record, err := enrollment.RevokeClient(
				installlayout.ClientsDirectory,
				manage,
				time.Now().UTC(),
				func(publicKey string) error {
					return removeAuthorizedKeyForPublicKey(manifest.AuthorizedKeysPath, publicKey)
				},
				enrollment.SessionEnforcement{},
			)
			if err != nil {
				return nil, err
			}
			revoked = record
			return map[string]any{
				"status":     "revoked",
				"client_id":  record.ClientID,
				"tunnel_id":  record.TunnelID,
				"revoked_at": record.RevokedAt,
			}, nil
		}, func() {
			if revoked.ClientID == "" {
				return
			}
			if err := authority.Terminate(revoked.ClientID, "", ""); err != nil {
				slog.Error("revoke session terminate failed", "client_id", revoked.ClientID, "err", err)
			}
			if err := authority.VerifyGone(revoked.ClientID, "", ""); err != nil {
				slog.Error("revoke session still present", "client_id", revoked.ClientID, "err", err)
			}
		})
	})
	mux.HandleFunc("/v1/rotate", func(writer http.ResponseWriter, request *http.Request) {
		authority := productionGrantAuthority()
		var rotated enrollment.ClientRecord
		writeEnrollmentJSON(writer, request, "rotate", limiter, func(body []byte) (any, error) {
			var manage enrollment.ManagementRequest
			if err := json.Unmarshal(body, &manage); err != nil {
				return nil, err
			}
			if manage.NewPublicKey == "" {
				return nil, fmt.Errorf("%w: new_public_key is required", enrollment.ErrInvalidInvite)
			}
			existing, err := enrollment.LoadClient(installlayout.ClientsDirectory, manage.ClientID)
			if err != nil {
				return nil, err
			}
			notAfter, err := grant.ParseUTC(existing.AuthorizationNotAfter)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", enrollment.ErrInvalidInvite, err)
			}
			line, err := server.RenderAuthorizedKey(manifest, []byte(manage.NewPublicKey), notAfter)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", enrollment.ErrInvalidInvite, err)
			}
			record, err := enrollment.RotateClientPublicKey(
				installlayout.ClientsDirectory,
				manage,
				manage.NewPublicKey,
				time.Now().UTC(),
				func(oldPublicKey, _ string) error {
					return replaceAuthorizedKeyForPublicKey(manifest.AuthorizedKeysPath, oldPublicKey, line)
				},
			)
			if err != nil {
				return nil, err
			}
			rotated = record
			return enrollment.EnrollmentProof{
				InviteID:                     record.InviteID,
				ClientID:                     record.ClientID,
				HostPublicKey:                hostPublicKey,
				PublicKey:                    record.PublicKey,
				Target:                       fmt.Sprintf("%s:%d", manifest.Target.Address, manifest.Target.Port),
				Principal:                    record.Principal,
				ProfileID:                    record.ProfileID,
				Nonce:                        "",
				AcceptedAt:                   record.AcceptedAt,
				AuthorizationNotAfter:        record.AuthorizationNotAfter,
				AuthorizationDurationSeconds: record.AuthorizationDurationSeconds,
				ServerAddress:                record.ServerAddress,
				EnrollPort:                   enrollment.DefaultEnrollmentPort,
			}, nil
		}, func() {
			if err := enrollment.EvictPreviousKeySessions(rotated, enrollment.SessionEnforcement{
				TerminateSession:  authority.Terminate,
				VerifySessionGone: authority.VerifyGone,
			}); err != nil {
				slog.Error("rotate old-key eviction failed", "client_id", rotated.ClientID, "err", err)
			}
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
	afterSuccess func(),
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
	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	}
	if afterSuccess != nil {
		afterSuccess()
	}
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

type enrollmentRateLimiter struct {
	mu         sync.Mutex
	rate       float64
	burst      float64
	maxSources int
	buckets    map[string]*tokenBucket
	order      []string
}

func newEnrollmentRateLimiter(window time.Duration, max int) *enrollmentRateLimiter {
	seconds := window.Seconds()
	if seconds <= 0 {
		seconds = 1
	}
	return &enrollmentRateLimiter{
		rate:       float64(max) / seconds,
		burst:      float64(max),
		maxSources: enrollmentRateLimitMaxSources,
		buckets:    map[string]*tokenBucket{},
	}
}

func (limiter *enrollmentRateLimiter) allow(source string) bool {
	if source == "" {
		source = "unknown"
	}
	now := time.Now()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	bucket := limiter.touchLocked(source, now)
	elapsed := now.Sub(bucket.last).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	bucket.tokens += elapsed * limiter.rate
	if bucket.tokens > limiter.burst {
		bucket.tokens = limiter.burst
	}
	bucket.last = now
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func (limiter *enrollmentRateLimiter) touchLocked(source string, now time.Time) *tokenBucket {
	if bucket, ok := limiter.buckets[source]; ok {
		for i, key := range limiter.order {
			if key == source {
				limiter.order = append(limiter.order[:i], limiter.order[i+1:]...)
				break
			}
		}
		limiter.order = append(limiter.order, source)
		return bucket
	}
	for len(limiter.buckets) >= limiter.maxSources && len(limiter.order) > 0 {
		oldest := limiter.order[0]
		limiter.order = limiter.order[1:]
		delete(limiter.buckets, oldest)
	}
	bucket := &tokenBucket{tokens: limiter.burst, last: now}
	limiter.buckets[source] = bucket
	limiter.order = append(limiter.order, source)
	return bucket
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
	var proof enrollment.EnrollmentProof
	err := withHostStateLock(func() error {
		accepted, acceptErr := acceptAndAuthorizeLocked(manifest, hostPublicKey, request, now)
		if acceptErr != nil {
			return acceptErr
		}
		proof = accepted
		return nil
	})
	if err != nil {
		return proof, err
	}
	return proof, nil
}

func acceptAndAuthorizeLocked(
	manifest server.Config,
	hostPublicKey string,
	request enrollment.EnrollmentRequest,
	now time.Time,
) (enrollment.EnrollmentProof, error) {
	if grant.ClockIsBlocked(installlayout.HostClockBlockedPath) {
		return enrollment.EnrollmentProof{}, errors.New("host clock is blocked")
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
		InstallAuthorization: func(publicKey string, notAfter time.Time) error {
			line, err := server.RenderAuthorizedKey(manifest, []byte(publicKey), notAfter)
			if err != nil {
				return fmt.Errorf("%w: %v", enrollment.ErrInvalidInvite, err)
			}
			return appendAuthorizedKey(manifest.AuthorizedKeysPath, line)
		},
	})
	if err != nil {
		return enrollment.EnrollmentProof{}, err
	}
	return result.Proof, nil
}

func reconcileExpiredGrants(manifest server.Config, now time.Time) error {
	if err := enrollment.ReconcilePendingRevocations(
		installlayout.ClientsDirectory,
		now,
		func(publicKey string) error {
			return removeAuthorizedKeyForPublicKey(manifest.AuthorizedKeysPath, publicKey)
		},
		enrollment.SessionEnforcement{
			TerminateSession: func(clientID, generation, publicKeySHA256 string) error {
				return productionGrantAuthority().Terminate(clientID, generation, publicKeySHA256)
			},
			VerifySessionGone: func(clientID, generation, publicKeySHA256 string) error {
				return productionGrantAuthority().VerifyGone(clientID, generation, publicKeySHA256)
			},
		},
	); err != nil {
		return err
	}
	return enrollment.ReconcileExpiredClients(installlayout.ClientsDirectory, now, func(record enrollment.ClientRecord) grant.ExpireOps {
		return grantExpireOps(manifest, record)
	})
}

func grantExpireOps(manifest server.Config, record enrollment.ClientRecord) grant.ExpireOps {
	return grant.ExpireOps{
		RemoveAuthorization: func(publicKey string) error {
			return removeAuthorizedKeyForPublicKey(manifest.AuthorizedKeysPath, publicKey)
		},
		VerifyAuthorizationGone: func(publicKey string) error {
			return verifyAuthorizedKeyAbsent(manifest.AuthorizedKeysPath, publicKey)
		},
		TerminateSession: func(clientID, generation, publicKeySHA256 string) error {
			return productionGrantAuthority().Terminate(clientID, generation, publicKeySHA256)
		},
		VerifySessionGone: func(clientID, generation, publicKeySHA256 string) error {
			return productionGrantAuthority().VerifyGone(clientID, generation, publicKeySHA256)
		},
		BurnManagementToken: func() (string, error) {
			token, err := enrollment.GenerateManagementToken()
			if err != nil {
				return "", err
			}
			return enrollment.HashManagementToken(token), nil
		},
	}
}

func verifyAuthorizedKeyAbsent(path, publicKey string) error {
	lines, err := readAuthorizedKeyLines(path)
	if err != nil {
		return err
	}
	blob := authorizedKeyBlob(publicKey)
	if blob == "" {
		return fmt.Errorf("authorized key is unparsable; cannot prove absence")
	}
	for _, existing := range lines {
		if authorizedKeyBlob(existing) == blob {
			return fmt.Errorf("authorized key for grant is still present")
		}
	}
	return nil
}

func reconcileGrantsUntil(ctx context.Context, manifest server.Config) {
	records, _ := enrollment.ListClients(installlayout.ClientsDirectory)
	timer := time.NewTimer(nextGrantReconcileDelay(time.Now().UTC(), records))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			now := time.Now().UTC()
			records, listErr := enrollment.ListClients(installlayout.ClientsDirectory)
			if _, err := grant.ObserveClock(installlayout.HostClockObservationPath, now); err != nil {
				if closeErr := enterBlockedClock(manifest, err); closeErr != nil {
					slog.Error("host clock fail-close incomplete", "err", closeErr)
				}
			} else if err := reconcileExpiredGrants(manifest, now); err != nil {
				slog.Error("grant expiry reconcile failed", "err", err)
			} else if err := reconcileManagedAuthorizations(manifest); err != nil {
				slog.Error("authorization reconcile failed", "err", err)
			}
			if listErr != nil {
				records = nil
			}
			timer.Reset(nextGrantReconcileDelay(now, records))
		}
	}
}

func nextGrantReconcileDelay(now time.Time, records []enrollment.ClientRecord) time.Duration {
	const maximum = time.Minute
	if records == nil {
		return maximum
	}
	delay := maximum
	for _, record := range records {
		if record.Status != enrollment.ClientStatusActive && record.Status != enrollment.ClientStatusExpirationPending && record.Status != enrollment.ClientStatusRotationPending {
			continue
		}
		if record.AuthorizationNotAfter == "" {
			continue
		}
		notAfter, err := grant.ParseUTC(record.AuthorizationNotAfter)
		if err != nil || !notAfter.After(now) {
			return time.Second
		}
		remaining := notAfter.Sub(now)
		if remaining < delay {
			delay = remaining
		}
	}
	if delay < time.Second {
		return time.Second
	}
	return delay
}

func productionGrantAuthority() *grantsession.Authority {
	return &grantsession.Authority{
		Root:        installlayout.GrantSessionsDirectory,
		Clients:     installlayout.ClientsDirectory,
		LockPath:    installlayout.GrantAuthorityLockPath,
		ExpectedExe: installlayout.ControllerPath,
	}
}

func serveGrantSessions(ctx context.Context) {
	server := grantsession.Server{
		Socket:    installlayout.GrantSessionSocket,
		Authority: productionGrantAuthority(),
	}
	if err := server.Serve(ctx); err != nil {
		slog.Error("grant session authority stopped", "err", err)
	}
}

func enterBlockedClock(manifest server.Config, reason error) error {
	if err := grant.WriteBlockedClock(installlayout.HostClockBlockedPath, reason.Error(), time.Now().UTC()); err != nil {
		return err
	}
	if err := withAuthorizedKeysLock(manifest.AuthorizedKeysPath, func() error {
		return writeAuthorizedKeyLines(manifest.AuthorizedKeysPath, nil)
	}); err != nil {
		return err
	}
	if err := productionGrantAuthority().TerminateAll(); err != nil {
		return err
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		cmd := exec.Command("systemctl", "stop", "warptweet-sshd.service")
		cmd.Env = []string{"LANG=C", "LC_ALL=C"}
		_ = cmd.Run()
	}
	return fmt.Errorf("host clock blocked: %w", reason)
}

func grantTarget(record enrollment.ClientRecord) (netip.AddrPort, error) {
	addr, err := netip.ParseAddr(record.TargetAddress)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("grant target address: %w", err)
	}
	if record.TargetPort == 0 {
		return netip.AddrPort{}, fmt.Errorf("grant target port is missing")
	}
	return netip.AddrPortFrom(addr, record.TargetPort), nil
}

func signalPID(pid int, signal syscall.Signal) error {
	if pid <= 0 {
		return nil
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Signal(signal)
}

func processAlivePID(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

func liveDataPlaneSessionCount() (int, error) {
	entries, err := os.ReadDir(installlayout.GrantSessionsDirectory)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		count++
	}
	return count, nil
}

func reconcileManagedAuthorizations(manifest server.Config) error {
	return withAuthorizedKeysLock(manifest.AuthorizedKeysPath, func() error {
		records, err := enrollment.ListClients(installlayout.ClientsDirectory)
		if err != nil {
			return err
		}
		lines := make([]string, 0, len(records))
		seen := make(map[string]struct{}, len(records))
		for _, record := range records {
			switch record.Status {
			case enrollment.ClientStatusActive, enrollment.ClientStatusRotationPending:
				if record.AuthorizationNotAfter == "" {
					continue
				}
				notAfter, err := grant.ParseUTC(record.AuthorizationNotAfter)
				if err != nil {
					return fmt.Errorf("client %s: %w", record.ClientID, err)
				}
				if grant.ReadyToExpire(notAfter, time.Now().UTC()) {
					continue
				}
				grantTarget, err := grantTarget(record)
				if err != nil {
					return fmt.Errorf("client %s: %w", record.ClientID, err)
				}
				manifestTarget := netip.AddrPortFrom(manifest.Target.Address, uint16(manifest.Target.Port))
				if grantTarget != manifestTarget {
					return fmt.Errorf("client %s grant target %s does not match host target %s", record.ClientID, grantTarget, manifestTarget)
				}
				line, err := server.RenderAuthorizedKeyForTarget(manifest, []byte(record.PublicKey), grantTarget, notAfter)
				if err != nil {
					return fmt.Errorf("client %s: %w", record.ClientID, err)
				}
				entry := strings.TrimRight(string(line), "\n")
				blob := authorizedKeyBlob(entry)
				if _, ok := seen[blob]; ok {
					continue
				}
				seen[blob] = struct{}{}
				lines = append(lines, entry)
			case enrollment.ClientStatusEnrollmentPending,
				enrollment.ClientStatusExpirationPending,
				enrollment.ClientStatusExpired,
				enrollment.ClientStatusRevocationPending,
				enrollment.ClientStatusRevoked:
				// These states are deliberately unauthorized during recovery.
			default:
				return fmt.Errorf("client %s has unsupported status %q", record.ClientID, record.Status)
			}
		}
		return writeAuthorizedKeyLines(manifest.AuthorizedKeysPath, lines)
	})
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
	// 0644 root-owned: sshd privilege separation must read this path outside home.
	return writeFileAtomic(path, []byte(builder.String()), 0o644)
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
		newBlob := authorizedKeyBlob(entry)
		filtered := make([]string, 0, len(lines)+1)
		for _, existing := range lines {
			blob := authorizedKeyBlob(existing)
			if (oldBlob != "" && blob == oldBlob) || (newBlob != "" && blob == newBlob) {
				continue
			}
			filtered = append(filtered, existing)
		}
		filtered = append(filtered, entry)
		return writeAuthorizedKeyLines(path, filtered)
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

const enrollmentAcceptLimit = 64

func idleEnrollWhenInvitesGone(ctx context.Context, httpServer *http.Server) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if hasUnexpiredIssuedInvite() {
				continue
			}
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = httpServer.Shutdown(shutdownCtx)
			cancel()
			return
		}
	}
}

func hasUnexpiredIssuedInvite() bool {
	records, err := enrollment.List(inviteDirectory)
	if err != nil {
		return true
	}
	now := time.Now().UTC()
	for _, record := range records {
		if record.Status != enrollment.StatusIssued {
			continue
		}
		expires, err := time.Parse(time.RFC3339Nano, record.ExpiresAt)
		if err != nil {
			expires, err = time.Parse(time.RFC3339, record.ExpiresAt)
		}
		if err != nil || expires.After(now) {
			return true
		}
	}
	return false
}

func runServerMgmtListen(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("server mgmt-listen", stderr)
	listen := onceStringFlag{name: "--listen"}
	flags.Var(&listen, "listen", "localhost management listen address:port")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	manifest, err := server.Load(installlayout.ServerManifestPath)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if grant.ClockIsBlocked(installlayout.HostClockBlockedPath) {
		return fmt.Errorf("host clock: blocked until warptweet server clock-recover")
	}
	if _, err := grant.ObserveClock(installlayout.HostClockObservationPath, now); err != nil {
		if closeErr := enterBlockedClock(manifest, err); closeErr != nil {
			return closeErr
		}
		return fmt.Errorf("host clock: %w", err)
	}
	if err := reconcileExpiredGrants(manifest, now); err != nil {
		return fmt.Errorf("reconcile expired grants: %w", err)
	}
	if err := reconcileManagedAuthorizations(manifest); err != nil {
		return fmt.Errorf("reconcile managed authorizations: %w", err)
	}
	hostPublicKey, err := deriveHostPublicKey(ctx, manifest.HostKeyPath)
	if err != nil {
		return err
	}
	endpoint := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", enrollment.DefaultManagementPort))
	if listen.value != "" {
		parsed, err := parseEndpoint(listen.value)
		if err != nil {
			return err
		}
		if parsed != endpoint {
			return fmt.Errorf("management RPC must listen on %s", endpoint)
		}
	}
	httpServer := &http.Server{
		Addr:              endpoint.String(),
		Handler:           newManagementHandler(manifest, hostPublicKey),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    4 << 10,
	}
	listener, err := net.Listen("tcp", endpoint.String())
	if err != nil {
		return fmt.Errorf("listen for management RPC: %w", err)
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- httpServer.Serve(listener)
	}()
	fmt.Fprintf(stdout, "management RPC listening\nlisten   %s\npath     POST /v1/revoke\npath     POST /v1/rotate\n", endpoint)
	go reconcileGrantsUntil(ctx, manifest)
	go serveGrantSessions(ctx)
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
		return ctx.Err()
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

type limitedListener struct {
	net.Listener
	limit  chan struct{}
	closed chan struct{}
	once   sync.Once
}

type limitedConn struct {
	net.Conn
	release sync.Once
	limit   chan struct{}
}

func newLimitedListener(inner net.Listener, slots int) *limitedListener {
	return &limitedListener{
		Listener: inner,
		limit:    make(chan struct{}, slots),
		closed:   make(chan struct{}),
	}
}

func (listener *limitedListener) Accept() (net.Conn, error) {
	select {
	case <-listener.closed:
		return nil, net.ErrClosed
	case listener.limit <- struct{}{}:
	}
	connection, err := listener.Listener.Accept()
	if err != nil {
		<-listener.limit
		return nil, err
	}
	return &limitedConn{Conn: connection, limit: listener.limit}, nil
}

func (listener *limitedListener) Close() error {
	listener.once.Do(func() {
		close(listener.closed)
	})
	return listener.Listener.Close()
}

func (connection *limitedConn) Close() error {
	connection.release.Do(func() {
		<-connection.limit
	})
	return connection.Conn.Close()
}
