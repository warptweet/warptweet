package grantsession

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"warptweet.com/warptweet/internal/installlayout"
)

func isDataPlaneExe(exe string) bool {
	return exe == installlayout.ControllerPath || strings.HasSuffix(exe, "/bin/warptweet")
}

func dropDataPlaneSessions(keySHA256 string) error {
	conn, err := net.DialTimeout("unix", installlayout.DataPlaneControlSocket, time.Second)
	if err != nil {
		return fmt.Errorf("data-plane control socket: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	request := Request{Version: ProtocolVersion, Action: ActionDrop, KeySHA256: keySHA256}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return err
	}
	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return err
	}
	if !response.OK {
		if response.Error == "" {
			return fmt.Errorf("data-plane drop refused")
		}
		return fmt.Errorf("data-plane drop: %s", response.Error)
	}
	return nil
}
