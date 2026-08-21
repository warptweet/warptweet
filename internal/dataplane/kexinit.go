package dataplane

import (
	"crypto/rand"
	"encoding/binary"
)

const (
	sshMsgKexInit           = 20
	disconnectProtocolError = 2
)

func (policy Policy) marshalKexInit() ([]byte, error) {
	cookie := make([]byte, 16)
	if _, err := rand.Read(cookie); err != nil {
		return nil, err
	}
	payload := []byte{sshMsgKexInit}
	payload = append(payload, cookie...)
	payload = appendNameList(payload, policy.Profile.KeyExchangeAlgorithm)
	payload = appendNameList(payload, policy.Profile.AuthenticationKeyType)
	payload = appendNameList(payload, "aes256-gcm@openssh.com")
	payload = appendNameList(payload, "aes256-gcm@openssh.com")
	payload = appendNameList(payload, "none")
	payload = appendNameList(payload, "none")
	payload = appendNameList(payload, "none")
	payload = appendNameList(payload, "none")
	payload = appendNameList(payload, "")
	payload = appendNameList(payload, "")
	payload = append(payload, 0)
	payload = binary.BigEndian.AppendUint32(payload, 0)
	return payload, nil
}

func appendNameList(dst []byte, names string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(names)))
	return append(dst, names...)
}

func marshalDisconnect(description string) []byte {
	payload := []byte{sshMsgDisconnect}
	payload = binary.BigEndian.AppendUint32(payload, disconnectProtocolError)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(description)))
	payload = append(payload, description...)
	payload = binary.BigEndian.AppendUint32(payload, 0)
	return payload
}
