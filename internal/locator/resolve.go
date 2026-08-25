package locator

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	maxAnswersPerFamily = 4
	maxAnswersTotal     = 8

	resolveTimeout        = 5 * time.Second
	candidateTimeout      = 2 * time.Second
	connectAggregateLimit = 8 * time.Second
)

// Class names recorded on the client for locator and launch failures.
// These appear in client logs, client status, and package evidence.
// They do not appear on host status.
const (
	ClassDNSResolution       = "dns_resolution"
	ClassTCPConnect          = "tcp_connect"
	ClassTLSNegotiate        = "tls_negotiate"
	ClassTLSSPKI             = "tls_spki"
	ClassInviteAuthorization = "invite_authorization"
	ClassSSHHostKey          = "ssh_host_key"
	ClassForwardTarget       = "forward_target"
)

// ClientErrorClasses is the frozen client-only error class list.
func ClientErrorClasses() []string {
	return []string{
		ClassDNSResolution,
		ClassTCPConnect,
		ClassTLSNegotiate,
		ClassTLSSPKI,
		ClassInviteAuthorization,
		ClassSSHHostKey,
		ClassForwardTarget,
	}
}

// ResolvedDialPlan is one resolve-once result. Callers construct one immutable
// ClientSpec per attempted candidate and never re-resolve.
type ResolvedDialPlan struct {
	Host       DialHost
	Candidates []netip.Addr
}

// LookupFunc returns addresses for an absolute DNS name (already trailing-dot).
type LookupFunc func(ctx context.Context, absoluteName string) ([]netip.Addr, error)

// DialFunc connects to one already-resolved candidate.
type DialFunc func(ctx context.Context, addr netip.Addr, port uint16, timeout time.Duration) error

// ResolveOptions controls lookup, filtering, and connect. Tests inject Lookup
// and Dial; production uses the Go resolver and a unicast TCP dialer.
type ResolveOptions struct {
	AllowLoopback bool
	Lookup        LookupFunc
	Dial          DialFunc
}

// ClassifiedError is a locator failure with a stable client error class.
type ClassifiedError struct {
	Class   string
	Message string
	Err     error
}

func (err *ClassifiedError) Error() string {
	if err.Err != nil {
		return err.Message + ": " + err.Err.Error()
	}
	return err.Message
}

func (err *ClassifiedError) Unwrap() error {
	return err.Err
}

// Classified returns a stable client error class wrapping err.
func Classified(class, message string, err error) error {
	return &ClassifiedError{Class: class, Message: message, Err: err}
}

// Resolve maps a dial host into a bounded, filtered candidate list.
// IP literals do not query DNS. DNS queries canonicalName + "." with no search.
func Resolve(ctx context.Context, host DialHost, options ResolveOptions) (ResolvedDialPlan, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	canonical, err := host.Canonical()
	if err != nil {
		return ResolvedDialPlan{}, Classified(ClassDNSResolution, "dial host", err)
	}
	if host.IP.IsValid() {
		addr := canonicalAddr(host.IP)
		if err := validateAnswer(addr, options.AllowLoopback); err != nil {
			return ResolvedDialPlan{}, Classified(ClassDNSResolution, "dial host", err)
		}
		return ResolvedDialPlan{Host: host, Candidates: []netip.Addr{addr}}, nil
	}

	lookup := options.Lookup
	if lookup == nil {
		lookup = defaultLookup
	}
	lookupCtx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	raw, err := lookup(lookupCtx, canonical+".")
	if err != nil {
		return ResolvedDialPlan{}, Classified(ClassDNSResolution, "dns_resolution", err)
	}
	candidates := FilterAnswers(raw, options.AllowLoopback)
	if len(candidates) == 0 {
		return ResolvedDialPlan{}, Classified(ClassDNSResolution, "dns_resolution", errors.New("no usable addresses"))
	}
	return ResolvedDialPlan{Host: DialHost{Name: canonical}, Candidates: candidates}, nil
}

// FilterAnswers unmaps, rejects unsafe addresses, deduplicates, and caps
// answers. Extra answers after the cap are dropped.
func FilterAnswers(answers []netip.Addr, allowLoopback bool) []netip.Addr {
	var v6, v4 []netip.Addr
	seen := make(map[netip.Addr]struct{}, len(answers))
	for _, answer := range answers {
		addr := canonicalAddr(answer)
		if err := validateAnswer(addr, allowLoopback); err != nil {
			continue
		}
		if _, exists := seen[addr]; exists {
			continue
		}
		seen[addr] = struct{}{}
		if addr.Is6() {
			if len(v6) >= maxAnswersPerFamily {
				continue
			}
			v6 = append(v6, addr)
		} else {
			if len(v4) >= maxAnswersPerFamily {
				continue
			}
			v4 = append(v4, addr)
		}
	}
	interleaved := InterleaveFamilies(v6, v4)
	if len(interleaved) > maxAnswersTotal {
		interleaved = interleaved[:maxAnswersTotal]
	}
	return interleaved
}

// InterleaveFamilies walks IPv6[0], IPv4[0], IPv6[1], IPv4[1], ...
func InterleaveFamilies(v6, v4 []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(v6)+len(v4))
	limit := len(v6)
	if len(v4) > limit {
		limit = len(v4)
	}
	for i := 0; i < limit; i++ {
		if i < len(v6) {
			out = append(out, v6[i])
		}
		if i < len(v4) {
			out = append(out, v4[i])
		}
	}
	return out
}

// Select connects to plan candidates in order until one succeeds.
// Per-candidate timeout is 2s; aggregate timeout is 8s. No happy-eyeballs.
func Select(ctx context.Context, plan ResolvedDialPlan, port uint16, options ResolveOptions) (netip.Addr, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if port == 0 {
		return netip.Addr{}, Classified(ClassTCPConnect, "tcp_connect", errors.New("port must be nonzero"))
	}
	if len(plan.Candidates) == 0 {
		return netip.Addr{}, Classified(ClassTCPConnect, "tcp_connect", errors.New("no candidates"))
	}
	dial := options.Dial
	if dial == nil {
		dial = defaultDial
	}
	deadline := time.Now().Add(connectAggregateLimit)
	var last error
	for _, candidate := range plan.Candidates {
		if err := ctx.Err(); err != nil {
			return netip.Addr{}, Classified(ClassTCPConnect, "tcp_connect", err)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		timeout := candidateTimeout
		if remaining < timeout {
			timeout = remaining
		}
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		err := dial(attemptCtx, candidate, port, timeout)
		cancel()
		if err == nil {
			return candidate, nil
		}
		last = err
		if err := ctx.Err(); err != nil {
			return netip.Addr{}, Classified(ClassTCPConnect, "tcp_connect", err)
		}
	}
	if last == nil {
		last = errors.New("connect aggregate timeout")
	}
	return netip.Addr{}, Classified(ClassTCPConnect, "tcp_connect", last)
}

func validateAnswer(addr netip.Addr, allowLoopback bool) error {
	if !addr.IsValid() {
		return errors.New("address is invalid")
	}
	if addr.Zone() != "" {
		return errors.New("IPv6 zones are not permitted")
	}
	addr = canonicalAddr(addr)
	if addr.IsUnspecified() {
		return errors.New("unspecified addresses are not permitted")
	}
	if addr.IsMulticast() {
		return errors.New("multicast addresses are not permitted")
	}
	if addr.Is4() && addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return errors.New("the IPv4 broadcast address is not permitted")
	}
	if addr.IsLinkLocalUnicast() {
		return errors.New("link-local addresses are not permitted")
	}
	if addr.IsLoopback() && !allowLoopback {
		return errors.New("loopback addresses are not permitted")
	}
	return nil
}

func defaultLookup(ctx context.Context, absoluteName string) ([]netip.Addr, error) {
	resolver := &net.Resolver{PreferGo: true}
	return resolver.LookupNetIP(ctx, "ip", absoluteName)
}

func defaultDial(ctx context.Context, addr netip.Addr, port uint16, timeout time.Duration) error {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, port).String())
	if err != nil {
		return err
	}
	return conn.Close()
}

// ErrorClass returns the client error class for err, or empty.
func ErrorClass(err error) string {
	if err == nil {
		return ""
	}
	var classifiedErr *ClassifiedError
	if errors.As(err, &classifiedErr) {
		return classifiedErr.Class
	}
	return classifyClientMessage(err.Error())
}

func classifyClientMessage(message string) string {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "spki pin mismatch") || strings.Contains(lower, "tls_spki"):
		return ClassTLSSPKI
	case strings.Contains(lower, "host key verification") ||
		strings.Contains(lower, "remote host identification has changed") ||
		strings.Contains(lower, "ssh_host_key"):
		return ClassSSHHostKey
	case strings.Contains(lower, "administratively prohibited") ||
		strings.Contains(lower, "connect failed to") ||
		strings.Contains(lower, "channel open failed") ||
		strings.Contains(lower, "forward_target"):
		return ClassForwardTarget
	case strings.Contains(lower, "invite_authorization") ||
		strings.Contains(lower, "enrollment rejected") ||
		strings.Contains(lower, "enrollment forbidden") ||
		strings.Contains(lower, "enrollment proof"):
		return ClassInviteAuthorization
	case strings.Contains(lower, "tls_negotiate") ||
		strings.Contains(lower, "tls:") ||
		strings.Contains(lower, "tls handshake") ||
		strings.Contains(lower, "first record does not look like a tls"):
		return ClassTLSNegotiate
	case strings.Contains(lower, "dns_resolution") || strings.Contains(lower, "no such host"):
		return ClassDNSResolution
	case strings.Contains(lower, "tcp_connect") ||
		strings.Contains(lower, "connection refused") ||
		strings.Contains(lower, "i/o timeout") ||
		strings.Contains(lower, "network is unreachable"):
		return ClassTCPConnect
	default:
		return ""
	}
}
