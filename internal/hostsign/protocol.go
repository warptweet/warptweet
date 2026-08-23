package hostsign

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	ProtocolVersion = 1
	maxFrame        = 16 << 10
	OpPublic        = "public"
	OpSign          = "sign"
)

type Request struct {
	Version uint32 `json:"v"`
	Op      string `json:"op"`
	Message []byte `json:"msg,omitempty"`
}

type Response struct {
	Version   uint32 `json:"v"`
	Public    []byte `json:"public,omitempty"`
	Signature []byte `json:"sig,omitempty"`
	Error     string `json:"error,omitempty"`
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrame {
		return fmt.Errorf("hostsign frame is %d bytes, want at most %d", len(payload), maxFrame)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > maxFrame {
		return nil, fmt.Errorf("hostsign frame length %d is invalid", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func roundTrip(conn net.Conn, req Request) (Response, error) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	raw, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	if err := writeFrame(conn, raw); err != nil {
		return Response{}, err
	}
	reply, err := readFrame(conn)
	if err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.Unmarshal(reply, &resp); err != nil {
		return Response{}, err
	}
	if resp.Error != "" {
		return Response{}, fmt.Errorf("hostsign: %s", resp.Error)
	}
	return resp, nil
}
