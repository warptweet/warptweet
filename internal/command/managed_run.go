package command

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

func requireDedicatedServiceRun(userName, groupName string, requiredUID, requiredGID int, controllerPath string) error {
	if userName == "" || groupName == "" || controllerPath == "" {
		return managedRunUnauthorized()
	}
	account, err := user.Lookup(userName)
	if err != nil {
		return managedRunUnauthorized()
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return managedRunUnauthorized()
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid <= 0 {
		return managedRunUnauthorized()
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid <= 0 {
		return managedRunUnauthorized()
	}
	if requiredUID > 0 && uid != requiredUID {
		return managedRunUnauthorized()
	}
	if requiredGID > 0 && gid != requiredGID {
		return managedRunUnauthorized()
	}
	if account.Gid != group.Gid {
		return managedRunUnauthorized()
	}
	if os.Geteuid() != uid || os.Getegid() != gid {
		return managedRunUnauthorized()
	}
	if !runningPackagedController(controllerPath) {
		return managedRunUnauthorized()
	}
	return nil
}

func runningPackagedController(controllerPath string) bool {
	executable, err := os.Executable()
	if err != nil {
		return false
	}
	resolvedExecutable, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return false
	}
	resolvedController, err := filepath.EvalSymlinks(controllerPath)
	if err != nil {
		return false
	}
	return filepath.Clean(resolvedExecutable) == filepath.Clean(resolvedController)
}
