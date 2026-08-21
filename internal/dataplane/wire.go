package dataplane

import (
	"encoding/binary"

	"warptweet.com/warptweet/internal/composite"
	"warptweet.com/warptweet/internal/sshwire"
)

func sshString(value []byte) []byte {
	return sshwire.AppendString(nil, value)
}

func sshMpint(value []byte) []byte {
	i := 0
	for i < len(value) && value[i] == 0 {
		i++
	}
	value = value[i:]
	if len(value) == 0 {
		return []byte{0, 0, 0, 0}
	}
	if value[0]&0x80 != 0 {
		out := make([]byte, 0, 5+len(value))
		out = binary.BigEndian.AppendUint32(out, uint32(len(value)+1))
		out = append(out, 0)
		return append(out, value...)
	}
	return sshString(value)
}

func consumeSSHString(input []byte) (value, rest []byte, err error) {
	rest, value, err = sshwire.ConsumeString(input)
	if err != nil {
		return nil, nil, errTruncated
	}
	return value, rest, nil
}

func consumeUint32(input []byte) (uint32, []byte, error) {
	if len(input) < 4 {
		return 0, nil, errTruncated
	}
	return binary.BigEndian.Uint32(input[:4]), input[4:], nil
}

func consumeBool(input []byte) (bool, []byte, error) {
	if len(input) < 1 {
		return false, nil, errTruncated
	}
	return input[0] != 0, input[1:], nil
}

func hostKeyBlob(rawPub []byte) []byte {
	return append(sshString([]byte(composite.Algorithm)), sshString(rawPub)...)
}

func signatureBlob(rawSig []byte) []byte {
	return append(sshString([]byte(composite.Algorithm)), sshString(rawSig)...)
}
