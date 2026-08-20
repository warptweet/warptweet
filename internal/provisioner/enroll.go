package provisioner

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
)

func writeRequestFile(directory, pattern string, payload []byte) (string, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if _, err := file.Write(append(bytes.TrimSpace(payload), '\n')); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func enrollControllerArgs(invitePath, proofPath string, request Request) []string {
	arguments := []string{"enroll", "--yes"}
	if request.PrepareOnly {
		arguments = append(arguments, "--prepare-only")
	}
	if request.ListenPort != 0 {
		arguments = append(arguments, "--listen-port", strconv.Itoa(int(request.ListenPort)))
	}
	if request.RestartPolicy != "" {
		arguments = append(arguments, "--restart", request.RestartPolicy)
	}
	if proofPath != "" {
		arguments = append(arguments, "--proof", proofPath)
	}
	return append(arguments, invitePath)
}

func materializeEnrollInputs(requestRoot string, request Request) (invitePath, proofPath string, err error) {
	invitePath, err = writeRequestFile(requestRoot, ".invite-*", request.Invite)
	if err != nil {
		return "", "", err
	}
	if len(request.Proof) == 0 {
		return invitePath, "", nil
	}
	proofPath, err = writeRequestFile(requestRoot, ".proof-*", request.Proof)
	if err != nil {
		_ = os.Remove(invitePath)
		return "", "", err
	}
	return invitePath, proofPath, nil
}

func enrollRequestRoot(platformRoot string) string {
	return filepath.Join(platformRoot, "requests")
}
