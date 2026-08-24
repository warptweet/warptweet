package enrollment

import (
	"net/netip"
	"testing"

	"warptweet.com/warptweet/internal/locator"
)

const (
	testEnrollmentTLSSPKIPin = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testManagementToken      = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testNextManagementToken  = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func testCreateInput() CreateInput {
	return CreateInput{
		ClientName:                  "laptop-1",
		DataHost:                    "192.0.2.10",
		DataPort:                    2222,
		EnrollmentHost:              "192.0.2.10",
		EnrollmentPort:              DefaultEnrollmentPort,
		EnrollmentTLSSPKISHA256:     testEnrollmentTLSSPKIPin,
		PublishedEndpointGeneration: 1,
		TargetAddress:               netip.MustParseAddr("198.51.100.20"),
		TargetPort:                  5432,
		Principal:                   "warptweet",
		ProfileID:                   "profile-v1",
		ArtifactProfileID:           "linux-amd64",
		HostPublicKey:               "ssh-mldsa44-ed25519@openssh.com AAAA host",
	}
}

func publishedFromInvite(t *testing.T, invite Invite) locator.PublishedEndpointSet {
	t.Helper()
	set, err := invite.PublishedSet()
	if err != nil {
		t.Fatal(err)
	}
	return set
}
