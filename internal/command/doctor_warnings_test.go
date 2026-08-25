package command

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/engine"
	"warptweet.com/warptweet/internal/lifecycle"
	"warptweet.com/warptweet/internal/locator"
	"warptweet.com/warptweet/internal/profile"
	"warptweet.com/warptweet/internal/server"
)

func TestPublicationWarningsJSONOnlyAndExcludeLoopback(t *testing.T) {
	t.Parallel()

	loopback := server.Config{Network: server.PublicationNetwork(netip.MustParseAddr("127.0.0.1"), 2222, 29722)}
	if warnings := publicationWarnings(loopback); len(warnings) != 0 {
		t.Fatalf("loopback bind=dial warned: %+v", warnings)
	}

	private := server.Config{Network: server.PublicationNetwork(netip.MustParseAddr("10.168.0.2"), 2222, 29722)}
	warnings := publicationWarnings(private)
	if len(warnings) == 0 {
		t.Fatal("private bind=dial produced no warnings")
	}
	codes := map[string]bool{}
	for _, warning := range warnings {
		codes[warning.Code] = true
		if strings.Contains(strings.ToLower(warning.Message), "san") ||
			strings.Contains(warning.Message, "IPAddresses") ||
			strings.Contains(warning.Message, "DNSNames") {
			t.Fatalf("doctor compared SAN to dial: %+v", warning)
		}
		if regexp.MustCompile(`(?i)\bpin\b`).MatchString(warning.Message) {
			t.Fatalf("doctor called a locator a pin: %+v", warning)
		}
	}
	if !codes["private_dial_equals_bind"] || !codes["cannot_create_inbound"] {
		t.Fatalf("missing expected data warnings: %+v", warnings)
	}
	if !codes["private_enrollment_dial_equals_bind"] || !codes["cannot_create_enrollment_inbound"] {
		t.Fatalf("missing expected enrollment warnings: %+v", warnings)
	}
	inbound := warningByCode(warnings, "cannot_create_inbound")
	if inbound == nil || !strings.Contains(inbound.Message, "outbound-only NAT is unsupported") {
		t.Fatalf("private dial=bind omitted outbound-only diagnosis: %+v", warnings)
	}

	nat := server.Config{Network: server.PublicationNetwork(netip.MustParseAddr("10.168.0.2"), 2222, 29722)}
	nat.Network.Data.Dial = server.DialEndpoint{Host: server.IPDialHost(netip.MustParseAddr("34.20.174.226")), Port: 2222}
	nat.Network.Enrollment.Dial = server.DialEndpoint{Host: server.IPDialHost(netip.MustParseAddr("34.20.174.226")), Port: 29722}
	natWarnings := publicationWarnings(nat)
	natCodes := map[string]bool{}
	for _, warning := range natWarnings {
		natCodes[warning.Code] = true
		if strings.Contains(warning.Message, "outbound-only NAT") {
			t.Fatalf("1:1 NAT diagnosed as outbound-only: %+v", warning)
		}
	}
	if natCodes["private_dial_equals_bind"] {
		t.Fatalf("public advertise warned as private dial=bind: %+v", natWarnings)
	}
	if !natCodes["cannot_create_inbound"] {
		t.Fatalf("1:1 NAT omitted cannot_create_inbound: %+v", natWarnings)
	}

	output := newServerDoctorOutput(engine.ServerPreflightReport{
		Profile:            profile.CurrentID,
		EngineVersion:      "OpenSSH_10.4p1",
		OpenSSLVersion:     "3.5.7",
		OpenSSLVersionText: "OpenSSL 3.5.7 9 Jun 2026",
		OpenSSLLinkage:     "static",
		ExecutableFormat:   "ELF",
	}, profile.AuthenticationBindingOpenSSHVendor, profile.SupportStatusPublishedMatrix, warnings)
	if output.Status != "preflight_ready" {
		t.Fatalf("warnings changed status: %s", output.Status)
	}
	raw, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(raw)
	if !strings.Contains(encoded, `"status":"preflight_ready"`) || !strings.Contains(encoded, `"warnings"`) {
		t.Fatalf("doctor JSON: %s", encoded)
	}
	if strings.Contains(encoded, "SAN") || strings.Contains(encoded, "IPAddresses") {
		t.Fatalf("doctor JSON mentioned certificate SAN: %s", encoded)
	}
}

func TestEnrollmentURLUsesDialNotListen(t *testing.T) {
	t.Parallel()

	enrollHost, err := locator.ParseDialHost("enroll.example.com")
	if err != nil {
		t.Fatal(err)
	}
	manifest := server.Config{
		Network: server.Network{
			PublishedEndpointGeneration: 1,
			Data: server.ServiceEndpoints{
				Listen: server.BindEndpoint{Address: netip.MustParseAddr("10.168.0.2"), Port: 2222},
				Dial:   server.DialEndpoint{Host: server.IPDialHost(netip.MustParseAddr("34.20.174.226")), Port: 2222},
			},
			Enrollment: server.ServiceEndpoints{
				Listen: server.BindEndpoint{Address: netip.MustParseAddr("10.168.0.2"), Port: 29722},
				Dial:   server.DialEndpoint{Host: enrollHost, Port: 8443},
			},
		},
	}
	url, err := enrollmentURLForManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://enroll.example.com:8443/v1/enroll" {
		t.Fatalf("url=%s", url)
	}
	if strings.Contains(url, "10.168.0.2") {
		t.Fatalf("enrollment URL used bind: %s", url)
	}
}

func TestRouteStatusPayloadIncludesClientErrorClass(t *testing.T) {
	t.Parallel()

	payload := routeStatusPayload("lab-db", lifecycle.State{
		TunnelID:     "lab-db",
		Phase:        lifecycle.PhaseFailed,
		TargetHealth: lifecycle.TargetHealthNotChecked,
		Error:        "Host key verification failed.",
		ErrorClass:   locator.ClassSSHHostKey,
	})
	if payload["error_class"] != locator.ClassSSHHostKey {
		t.Fatalf("payload=%v", payload)
	}
	inferred := routeStatusPayload("lab-db", lifecycle.State{
		TunnelID:     "lab-db",
		Phase:        lifecycle.PhaseFailed,
		TargetHealth: lifecycle.TargetHealthNotChecked,
		Error:        "tls: handshake failure",
	})
	if inferred["error_class"] != locator.ClassTLSNegotiate {
		t.Fatalf("inferred=%v", inferred)
	}
}

func TestApplyManifestToServerStatusUsesEnrollmentDialPort(t *testing.T) {
	t.Parallel()

	enrollHost, err := locator.ParseDialHost("enroll.example.com")
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]any{}
	applyManifestToServerStatus(status, server.Config{
		ProfileID:     profile.CurrentID,
		DedicatedUser: server.DefaultDedicatedUser,
		Network: server.Network{
			PublishedEndpointGeneration: 1,
			Data: server.ServiceEndpoints{
				Listen: server.BindEndpoint{Address: netip.MustParseAddr("10.168.0.2"), Port: 2222},
				Dial:   server.DialEndpoint{Host: server.IPDialHost(netip.MustParseAddr("34.20.174.226")), Port: 2222},
			},
			Enrollment: server.ServiceEndpoints{
				Listen: server.BindEndpoint{Address: netip.MustParseAddr("10.168.0.2"), Port: 29722},
				Dial:   server.DialEndpoint{Host: enrollHost, Port: 8443},
			},
		},
		Target: server.Endpoint{Address: netip.MustParseAddr("127.0.0.1"), Port: 5432},
	})
	if status["enroll_port"] != uint16(8443) {
		t.Fatalf("enroll_port=%v, want 8443", status["enroll_port"])
	}
	url, _ := status["enroll_url"].(string)
	if url != "https://enroll.example.com:8443/v1/enroll" {
		t.Fatalf("enroll_url=%q", url)
	}
}

func warningByCode(warnings []serverDoctorWarning, code string) *serverDoctorWarning {
	for i := range warnings {
		if warnings[i].Code == code {
			return &warnings[i]
		}
	}
	return nil
}
