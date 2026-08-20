package command

import (
	"os"
	"testing"
)

func TestRequireDedicatedServiceRunRejectsCurrentProcess(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("root can assume any service identity")
	}
	err := requireDedicatedServiceRun("nobody", "nobody", 0, 0, "/nonexistent/warptweet")
	if err == nil {
		t.Fatal("authorized an unprivileged developer process")
	}
	if err.Error() != managedRunUnauthorized().Error() {
		t.Fatalf("err=%v", err)
	}
}

func TestRunningPackagedControllerRejectsOtherPath(t *testing.T) {
	t.Parallel()

	if runningPackagedController("/nonexistent/warptweet") {
		t.Fatal("accepted a controller path that is not this executable")
	}
}
