package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SubmitEnrollment posts one enrollment request to the gateway enroll endpoint
// and returns the binding proof. Transport is plain HTTP on the invite's enroll
// port; invite possession is the single-use authorization. Credentials and
// request bodies travel in cleartext and require a trusted network segment
// until a pinned TLS profile exists.
func SubmitEnrollment(ctx context.Context, invite Invite, request EnrollmentRequest) (EnrollmentProof, error) {
	url, err := EnrollmentURL(invite.ServerAddress, invite.EnrollmentPort())
	if err != nil {
		return EnrollmentProof{}, err
	}
	body, err := EncodeEnrollmentRequest(request)
	if err != nil {
		return EnrollmentProof{}, err
	}
	payload, err := postJSON(ctx, url, body)
	if err != nil {
		return EnrollmentProof{}, err
	}
	var proof EnrollmentProof
	if err := json.Unmarshal(payload, &proof); err != nil {
		return EnrollmentProof{}, fmt.Errorf("%w: decode enrollment proof: %v", ErrInvalidInvite, err)
	}
	if err := ValidateEnrollmentProof(proof, invite, request.PublicKey); err != nil {
		return EnrollmentProof{}, err
	}
	if proof.ManagementToken == "" {
		return EnrollmentProof{}, fmt.Errorf("%w: enrollment proof missing management_token", ErrInvalidInvite)
	}
	if proof.ServerAddress == "" {
		proof.ServerAddress = invite.ServerAddress
	}
	if proof.EnrollPort == 0 {
		proof.EnrollPort = invite.EnrollmentPort()
	}
	return proof, nil
}

// SubmitRevoke asks the gateway to revoke one enrolled client.
// management_token is transmitted in cleartext over plain HTTP and is
// long-lived; callers must use a trusted network segment and protect the token.
func SubmitRevoke(ctx context.Context, serverAddress string, enrollPort uint16, request ManagementRequest) error {
	url, err := managementURL(serverAddress, enrollPort, "revoke")
	if err != nil {
		return err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	_, err = postJSON(ctx, url, body)
	return err
}

// SubmitRotate asks the gateway to install a new client public key.
// management_token is transmitted in cleartext over plain HTTP and is
// long-lived; callers must use a trusted network segment and protect the token.
func SubmitRotate(ctx context.Context, serverAddress string, enrollPort uint16, request ManagementRequest) (EnrollmentProof, error) {
	url, err := managementURL(serverAddress, enrollPort, "rotate")
	if err != nil {
		return EnrollmentProof{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return EnrollmentProof{}, err
	}
	payload, err := postJSON(ctx, url, body)
	if err != nil {
		return EnrollmentProof{}, err
	}
	var proof EnrollmentProof
	if err := json.Unmarshal(payload, &proof); err != nil {
		return EnrollmentProof{}, fmt.Errorf("%w: decode rotate proof: %v", ErrInvalidInvite, err)
	}
	if proof.ManagementToken == "" || proof.ClientID == "" || proof.PublicKey == "" {
		return EnrollmentProof{}, fmt.Errorf("%w: rotate proof incomplete", ErrInvalidInvite)
	}
	if proof.EnrollPort == 0 {
		proof.EnrollPort = enrollPort
	}
	if proof.EnrollPort == 0 {
		proof.EnrollPort = DefaultEnrollmentPort
	}
	return proof, nil
}

func managementURL(serverAddress string, enrollPort uint16, action string) (string, error) {
	if enrollPort == 0 {
		enrollPort = DefaultEnrollmentPort
	}
	addr, err := parseHostForURL(serverAddress)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("http://%s/v1/%s", joinHostPort(addr, enrollPort), action), nil
}

func postJSON(ctx context.Context, url string, body []byte) ([]byte, error) {
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

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enrollment request: %w", err)
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
		return nil, fmt.Errorf("%w: enrollment rejected: %s", ErrInvalidInvite, message)
	}
	return payload, nil
}
