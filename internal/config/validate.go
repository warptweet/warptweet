package config

import (
	"fmt"
	"net/netip"
	"time"
	"unicode"
	"unicode/utf8"

	"warptweet.com/warptweet/internal/profile"
)

const (
	// MinSupervisionBackoff prevents a failed tunnel from entering a hot
	// restart loop.
	MinSupervisionBackoff = 250 * time.Millisecond

	// MaxSupervisionBackoff bounds how long a supervisor may remain idle after
	// a recoverable failure.
	MaxSupervisionBackoff = 5 * time.Minute

	maxTunnelIDBytes = 64
	maxUnixUserBytes = 32
)

var requiredListenerAddress = netip.MustParseAddr("127.0.0.1")

// ValidationError identifies one invalid configuration field without
// exposing any secret file contents.
type ValidationError struct {
	Field   string
	Problem string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid %s: %s", e.Field, e.Problem)
}

// Validate enforces the complete client configuration contract.
func Validate(value Config) error {
	if err := validateSafeString("kind", value.Kind); err != nil {
		return err
	}
	if value.Kind != ClientTunnelsKind {
		return invalid("kind", "must be %q", ClientTunnelsKind)
	}
	if value.SchemaVersion != CurrentSchemaVersion {
		return invalid("schema_version", "must be %d", CurrentSchemaVersion)
	}
	if err := validateSafeString("profile_id", value.ProfileID); err != nil {
		return err
	}
	if _, err := profile.Lookup(value.ProfileID); err != nil {
		return invalid("profile_id", "must be immutable profile %q", profile.CurrentID)
	}

	if err := validateSHA256(value.SSHBinarySHA256); err != nil {
		return err
	}
	if err := validateServer(value.Server); err != nil {
		return err
	}
	if len(value.Tunnels) == 0 {
		return invalid("tunnels", "must contain at least one tunnel")
	}

	ids := make(map[string]struct{}, len(value.Tunnels))
	listenPorts := make(map[Port]string, len(value.Tunnels))
	for index, tunnel := range value.Tunnels {
		field := fmt.Sprintf("tunnels[%d]", index)
		if err := validateTunnel(field, tunnel); err != nil {
			return err
		}
		if _, exists := ids[tunnel.ID]; exists {
			return invalid(field+".id", "duplicate tunnel ID %q", tunnel.ID)
		}
		ids[tunnel.ID] = struct{}{}
		if previousID, exists := listenPorts[tunnel.Listen.Port]; exists {
			return invalid(field+".listen.port", "already used by tunnel %q", previousID)
		}
		listenPorts[tunnel.Listen.Port] = tunnel.ID
	}

	if err := validateSupervision(value.Supervision); err != nil {
		return err
	}
	return nil
}

// Validate applies the same validation as the package-level function.
func (value Config) Validate() error {
	return Validate(value)
}

func validateServer(server Server) error {
	if err := validateAddress("server.address", server.Address); err != nil {
		return err
	}
	if err := validatePort("server.port", server.Port); err != nil {
		return err
	}
	if err := validateUnixUser(server.User); err != nil {
		return err
	}
	return nil
}

func validateTunnel(field string, tunnel Tunnel) error {
	if err := validateTunnelID(field+".id", tunnel.ID); err != nil {
		return err
	}
	if err := validateAddress(field+".listen.address", tunnel.Listen.Address); err != nil {
		return err
	}
	if tunnel.Listen.Address != requiredListenerAddress {
		return invalid(field+".listen.address", "must be 127.0.0.1")
	}
	if err := validatePort(field+".listen.port", tunnel.Listen.Port); err != nil {
		return err
	}
	if err := validateAddress(field+".target.address", tunnel.Target.Address); err != nil {
		return err
	}
	if err := validatePort(field+".target.port", tunnel.Target.Port); err != nil {
		return err
	}
	return nil
}

func validateAddress(field string, address netip.Addr) error {
	if !address.IsValid() {
		return invalid(field, "must be a numeric IP address")
	}
	if address.Zone() != "" {
		return invalid(field, "must not contain an IPv6 zone")
	}
	if address.Is4In6() {
		return invalid(field, "must use canonical IPv4 notation")
	}
	if address.IsUnspecified() {
		return invalid(field, "must not be an unspecified address")
	}
	if address.IsMulticast() {
		return invalid(field, "must not be a multicast address")
	}
	if address.Is4() && address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return invalid(field, "must not be the IPv4 broadcast address")
	}
	return nil
}

func validatePort(field string, port Port) error {
	if port == 0 {
		return invalid(field, "must be between 1 and 65535")
	}
	return nil
}

func validateSHA256(value string) error {
	const encodedSHA256Bytes = 64
	if len(value) != encodedSHA256Bytes {
		return invalid("ssh_binary_sha256", "must contain exactly 64 lowercase hexadecimal characters")
	}
	for _, character := range []byte(value) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return invalid("ssh_binary_sha256", "must contain exactly 64 lowercase hexadecimal characters")
		}
	}
	return nil
}

func validateTunnelID(field, value string) error {
	if err := validateSafeString(field, value); err != nil {
		return err
	}
	if len(value) == 0 || len(value) > maxTunnelIDBytes {
		return invalid(field, "must be between 1 and %d ASCII bytes", maxTunnelIDBytes)
	}
	if !isLowerASCIILetter(value[0]) {
		return invalid(field, "must start with a lowercase ASCII letter")
	}
	for index, character := range []byte(value)[1:] {
		index++
		if isLowerASCIIAlphaNumeric(character) {
			continue
		}
		if index > 0 && index < len(value)-1 && (character == '-' || character == '_') {
			continue
		}
		return invalid(field, "must use lowercase ASCII letters, digits, and internal '-' or '_'")
	}
	return nil
}

// ValidateTunnelID applies the same tunnel identifier contract used by .wt
// client manifests. Callers that derive aliases or resource names from a
// tunnel ID must validate it before adding their own fixed prefix.
func ValidateTunnelID(value string) error {
	return validateTunnelID("tunnel_id", value)
}

func validateUnixUser(value string) error {
	const field = "server.user"
	if err := validateSafeString(field, value); err != nil {
		return err
	}
	if len(value) == 0 || len(value) > maxUnixUserBytes {
		return invalid(field, "must be between 1 and %d ASCII bytes", maxUnixUserBytes)
	}
	for index, character := range []byte(value) {
		if index == 0 {
			if isLowerASCIILetter(character) || character == '_' {
				continue
			}
			return invalid(field, "must start with a lowercase ASCII letter or '_'")
		}
		if isLowerASCIIAlphaNumeric(character) || character == '_' || character == '-' {
			continue
		}
		return invalid(field, "must be a safe Unix user name")
	}
	return nil
}

func validateSupervision(supervision Supervision) error {
	initial := supervision.InitialBackoff.Value()
	maximum := supervision.MaxBackoff.Value()
	if initial < MinSupervisionBackoff || initial > MaxSupervisionBackoff {
		return invalid(
			"supervision.initial_backoff",
			"must be between %s and %s",
			MinSupervisionBackoff,
			MaxSupervisionBackoff,
		)
	}
	if maximum < MinSupervisionBackoff || maximum > MaxSupervisionBackoff {
		return invalid(
			"supervision.max_backoff",
			"must be between %s and %s",
			MinSupervisionBackoff,
			MaxSupervisionBackoff,
		)
	}
	if maximum < initial {
		return invalid("supervision.max_backoff", "must be greater than or equal to initial_backoff")
	}
	return nil
}

func validateSafeString(field, value string) error {
	if !utf8.ValidString(value) {
		return invalid(field, "must be valid UTF-8")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return invalid(field, "must not contain control characters")
		}
	}
	return nil
}

func isLowerASCIILetter(value byte) bool {
	return value >= 'a' && value <= 'z'
}

func isLowerASCIIAlphaNumeric(value byte) bool {
	return isLowerASCIILetter(value) || (value >= '0' && value <= '9')
}

func invalid(field, format string, arguments ...any) error {
	return &ValidationError{
		Field:   field,
		Problem: fmt.Sprintf(format, arguments...),
	}
}
