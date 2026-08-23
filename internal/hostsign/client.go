package hostsign

import (
	"fmt"
	"net"
)

// Client signs host-key operations over a local socket.
type Client struct {
	Path string
}

func (c Client) Public() ([]byte, error) {
	resp, err := c.call(Request{Version: ProtocolVersion, Op: OpPublic})
	if err != nil {
		return nil, err
	}
	if len(resp.Public) == 0 {
		return nil, fmt.Errorf("hostsign returned an empty public key")
	}
	return resp.Public, nil
}

func (c Client) Sign(message []byte) ([]byte, error) {
	resp, err := c.call(Request{Version: ProtocolVersion, Op: OpSign, Message: message})
	if err != nil {
		return nil, err
	}
	if len(resp.Signature) == 0 {
		return nil, fmt.Errorf("hostsign returned an empty signature")
	}
	return resp.Signature, nil
}

func (c Client) call(req Request) (Response, error) {
	conn, err := net.Dial("unix", c.Path)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	return roundTrip(conn, req)
}
