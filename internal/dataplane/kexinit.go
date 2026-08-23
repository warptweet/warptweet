package dataplane

import (
	"crypto/rand"
	"encoding/binary"
)

const (
	sshMsgKexInit           = 20
	disconnectProtocolError = 2
	strictKEXServer         = "kex-strict-s-v00@openssh.com"
	strictKEXClient         = "kex-strict-c-v00@openssh.com"
)

func (policy Policy) marshalKexInit() ([]byte, error) {
	return policy.marshalKexInitList(policy.Profile.KeyExchangeAlgorithm + "," + strictKEXServer)
}

func (policy Policy) marshalKexInitClient() ([]byte, error) {
	return policy.marshalKexInitList(policy.Profile.KeyExchangeAlgorithm + "," + strictKEXClient)
}

func (policy Policy) marshalKexInitList(kexNames string) ([]byte, error) {
	cookie := make([]byte, 16)
	if _, err := rand.Read(cookie); err != nil {
		return nil, err
	}
	payload := []byte{sshMsgKexInit}
	payload = append(payload, cookie...)
	payload = appendNameList(payload, kexNames)
	payload = appendNameList(payload, policy.Profile.AuthenticationKeyType)
	cipher := policy.Profile.Ciphers[0]
	payload = appendNameList(payload, cipher)
	payload = appendNameList(payload, cipher)
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
