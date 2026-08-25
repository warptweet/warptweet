package enrollment

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"warptweet.com/warptweet/internal/locator"
)

// SubmitEnrollment posts one enrollment request to the invite-pinned hybrid TLS
// endpoint and returns the binding proof.
func SubmitEnrollment(ctx context.Context, invite Invite, request EnrollmentRequest) (EnrollmentProof, error) {
	proof, _, err := SubmitEnrollmentPlan(ctx, invite, request, locator.ResolveOptions{})
	return proof, err
}

// SubmitEnrollmentPlan resolves the enrollment locator once, dials a selected
// candidate without using the default resolver, and returns the proof plus the
// selected address.
func SubmitEnrollmentPlan(
	ctx context.Context,
	invite Invite,
	request EnrollmentRequest,
	options locator.ResolveOptions,
) (EnrollmentProof, netip.Addr, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	host, err := locator.ParseDialHost(invite.Enrollment.Host)
	if err != nil {
		return EnrollmentProof{}, netip.Addr{}, fmt.Errorf("%w: enrollment host: %v", ErrInvalidInvite, err)
	}
	if host.IP.IsValid() && host.IP.IsLoopback() {
		options.AllowLoopback = true
	}
	plan, err := locator.Resolve(ctx, host, options)
	if err != nil {
		return EnrollmentProof{}, netip.Addr{}, err
	}
	selected, err := locator.Select(ctx, plan, invite.EnrollmentPort(), options)
	if err != nil {
		return EnrollmentProof{}, netip.Addr{}, err
	}
	url, err := EnrollmentURL(selected.String(), invite.EnrollmentPort())
	if err != nil {
		return EnrollmentProof{}, netip.Addr{}, err
	}
	body, err := EncodeEnrollmentRequest(request)
	if err != nil {
		return EnrollmentProof{}, netip.Addr{}, err
	}
	payload, err := postJSONTo(ctx, url, body, invite.EnrollmentTLSSPKISHA256(), selected, invite.EnrollmentPort())
	if err != nil {
		return EnrollmentProof{}, netip.Addr{}, err
	}
	var proof EnrollmentProof
	if err := json.Unmarshal(payload, &proof); err != nil {
		return EnrollmentProof{}, netip.Addr{}, fmt.Errorf("%w: decode enrollment proof: %v", ErrInvalidInvite, err)
	}
	if err := ValidateEnrollmentProof(proof, invite, request.PublicKey); err != nil {
		return EnrollmentProof{}, netip.Addr{}, locator.Classified(locator.ClassInviteAuthorization, "invite_authorization", err)
	}
	return proof, selected, nil
}

// SubmitRevoke asks the pinned host to revoke one enrolled client.
func SubmitRevoke(ctx context.Context, serverAddress string, enrollPort uint16, enrollmentTLSSPKISHA256 string, request ManagementRequest) error {
	url, err := managementURL(serverAddress, enrollPort, "revoke", enrollmentTLSSPKISHA256)
	if err != nil {
		return err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	_, err = postJSON(ctx, url, body, enrollmentTLSSPKISHA256)
	return err
}

// SubmitRotate asks the pinned host to install a new client public key.
func SubmitRotate(ctx context.Context, serverAddress string, enrollPort uint16, enrollmentTLSSPKISHA256 string, request ManagementRequest) (EnrollmentProof, error) {
	url, err := managementURL(serverAddress, enrollPort, "rotate", enrollmentTLSSPKISHA256)
	if err != nil {
		return EnrollmentProof{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return EnrollmentProof{}, err
	}
	payload, err := postJSON(ctx, url, body, enrollmentTLSSPKISHA256)
	if err != nil {
		return EnrollmentProof{}, err
	}
	var proof EnrollmentProof
	if err := json.Unmarshal(payload, &proof); err != nil {
		return EnrollmentProof{}, fmt.Errorf("%w: decode rotate proof: %v", ErrInvalidInvite, err)
	}
	if proof.ClientID == "" || proof.PublicKey == "" || proof.PublicKey != strings.TrimSpace(request.NewPublicKey) {
		return EnrollmentProof{}, fmt.Errorf("%w: rotate proof incomplete", ErrInvalidInvite)
	}
	return proof, nil
}

func managementURL(serverAddress string, enrollPort uint16, action, enrollmentTLSSPKISHA256 string) (string, error) {
	if enrollPort == 0 {
		enrollPort = DefaultManagementPort
	}
	addr, err := parseHostForURL(serverAddress)
	if err != nil {
		return "", err
	}
	scheme := "https"
	if enrollmentTLSSPKISHA256 == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/v1/%s", scheme, joinHostPort(addr, enrollPort), action), nil
}

func postJSON(ctx context.Context, url string, body []byte, enrollmentTLSSPKISHA256 string) ([]byte, error) {
	return postJSONTo(ctx, url, body, enrollmentTLSSPKISHA256, netip.Addr{}, 0)
}

func postJSONTo(ctx context.Context, url string, body []byte, enrollmentTLSSPKISHA256 string, selected netip.Addr, port uint16) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.ContentLength = int64(len(body))

	transport := &http.Transport{Proxy: nil}
	if selected.IsValid() && port != 0 {
		endpoint := netip.AddrPortFrom(selected, port).String()
		transport.DialContext = func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 2 * time.Second}
			return dialer.DialContext(dialCtx, network, endpoint)
		}
	}
	if !strings.HasPrefix(url, "http://") {
		tlsConfig, err := PinnedClientTLSConfig(enrollmentTLSSPKISHA256, time.Now)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConfig
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, classifyEnrollmentTransport(err)
	}
	defer response.Body.Close()

	limited := io.LimitReader(response.Body, MaxEnrollmentRequestBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read enrollment response: %w", err)
	}
	if len(payload) > MaxEnrollmentRequestBytes {
		return nil, fmt.Errorf("%w: enrollment response too large", ErrInvalidInvite)
	}
	if response.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(payload))
		if message == "" {
			message = response.Status
		}
		return nil, locator.Classified(
			locator.ClassInviteAuthorization,
			"invite_authorization",
			fmt.Errorf("%w: enrollment rejected: %s", ErrInvalidInvite, message),
		)
	}
	return payload, nil
}

func classifyEnrollmentTransport(err error) error {
	if err == nil {
		return nil
	}
	if class := locator.ErrorClass(err); class != "" {
		return err
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return locator.Classified(locator.ClassTLSNegotiate, "tls_negotiate", err)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return locator.Classified(locator.ClassTCPConnect, "tcp_connect", err)
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "SPKI pin mismatch"):
		return locator.Classified(locator.ClassTLSSPKI, "tls_spki", err)
	case strings.Contains(message, "tls:") ||
		strings.Contains(message, "TLS") ||
		strings.Contains(message, "x509:") ||
		strings.Contains(strings.ToLower(message), "handshake"):
		return locator.Classified(locator.ClassTLSNegotiate, "tls_negotiate", err)
	case strings.Contains(strings.ToLower(message), "connection refused") ||
		strings.Contains(strings.ToLower(message), "i/o timeout") ||
		strings.Contains(strings.ToLower(message), "network is unreachable") ||
		strings.Contains(strings.ToLower(message), "connect:"):
		return locator.Classified(locator.ClassTCPConnect, "tcp_connect", err)
	default:
		return fmt.Errorf("enrollment request: %w", err)
	}
}
