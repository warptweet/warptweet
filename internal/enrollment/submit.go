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

// SubmitEnrollment posts one enrollment request to the invite-pinned hybrid TLS
// endpoint and returns the binding proof.
func SubmitEnrollment(ctx context.Context, invite Invite, request EnrollmentRequest) (EnrollmentProof, error) {
	url, err := EnrollmentURL(invite.ServerAddress, invite.EnrollmentPort())
	if err != nil {
		return EnrollmentProof{}, err
	}
	body, err := EncodeEnrollmentRequest(request)
	if err != nil {
		return EnrollmentProof{}, err
	}
	payload, err := postJSON(ctx, url, body, invite.EnrollmentTLSSPKISHA256)
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
	if proof.ServerAddress == "" {
		proof.ServerAddress = invite.ServerAddress
	}
	if proof.EnrollPort == 0 {
		proof.EnrollPort = invite.EnrollmentPort()
	}
	return proof, nil
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
