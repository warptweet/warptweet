package command

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxGrantSessionBytes = 4 << 10

type grantSessionRef struct {
	ClientID        string `json:"client_id"`
	Generation      string `json:"generation"`
	PublicKeySHA256 string `json:"public_key_sha256"`
	PID             int    `json:"pid"`
}

type grantSessionStore struct {
	root string
}

func (store grantSessionStore) lookup(clientID, generation, publicKeySHA256 string) ([]grantSessionRef, error) {
	entries, err := os.ReadDir(store.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var refs []grantSessionRef
	var deferred error
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		ref, err := readGrantSession(filepath.Join(store.root, entry.Name()))
		if err != nil {
			if deferred == nil {
				deferred = err
			}
			continue
		}
		if ref.ClientID == clientID && ref.Generation == generation && ref.PublicKeySHA256 == publicKeySHA256 {
			refs = append(refs, ref)
		}
	}
	return refs, deferred
}

func (store grantSessionStore) clear(clientID, generation, publicKeySHA256 string) error {
	entries, err := os.ReadDir(store.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var deferred error
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(store.root, entry.Name())
		ref, err := readGrantSession(path)
		if err != nil {
			if !os.IsNotExist(err) && deferred == nil {
				deferred = err
			}
			continue
		}
		if ref.ClientID == clientID && ref.Generation == generation && ref.PublicKeySHA256 == publicKeySHA256 {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return deferred
}

func readGrantSession(path string) (grantSessionRef, error) {
	file, err := os.Open(path)
	if err != nil {
		return grantSessionRef{}, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, int64(maxGrantSessionBytes)+1))
	if err != nil {
		return grantSessionRef{}, err
	}
	if len(contents) == 0 || len(contents) > maxGrantSessionBytes {
		return grantSessionRef{}, fmt.Errorf("grant session document is empty or exceeds %d bytes", maxGrantSessionBytes)
	}
	var ref grantSessionRef
	if err := json.Unmarshal(contents, &ref); err != nil {
		return grantSessionRef{}, err
	}
	return ref, nil
}
