package command

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGrantTickerObservesClockBeforeDelaySkip(t *testing.T) {
	t.Parallel()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	contents, err := os.ReadFile(filepath.Join(filepath.Dir(file), "enroll_server.go"))
	if err != nil {
		t.Fatal(err)
	}
	fn := string(contents)
	start := strings.Index(fn, "func reconcileGrantsUntil")
	if start < 0 {
		t.Fatal("reconcileGrantsUntil missing")
	}
	fn = fn[start:]
	end := strings.Index(fn, "\nfunc nextGrantReconcileDelay")
	if end < 0 {
		t.Fatal("nextGrantReconcileDelay missing")
	}
	fn = fn[:end]
	observe := strings.Index(fn, "ObserveClock")
	delay := strings.Index(fn, "nextGrantReconcileDelay")
	if observe < 0 || delay < 0 {
		t.Fatal("ticker must observe the host clock and compute reconcile delay")
	}
	if observe > delay {
		t.Fatal("ObserveClock must run even when no grant is due to expire")
	}
}

func TestRotateResponseFlushesBeforeSessionEviction(t *testing.T) {
	t.Parallel()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	contents, err := os.ReadFile(filepath.Join(filepath.Dir(file), "enroll_server.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(contents)
	start := strings.Index(src, "func writeEnrollmentJSON")
	if start < 0 {
		t.Fatal("writeEnrollmentJSON missing")
	}
	fn := src[start:]
	end := strings.Index(fn, "\ntype tokenBucket")
	if end < 0 {
		t.Fatal("writeEnrollmentJSON terminator missing")
	}
	fn = fn[:end]
	flush := strings.Index(fn, "Flush()")
	after := strings.Index(fn, "time.AfterFunc(sessionEvictAfterHTTP")
	if flush < 0 || after < 0 {
		t.Fatal("rotate/revoke must Flush the HTTP body and defer session eviction")
	}
	if after < flush {
		t.Fatal("session eviction must run after the JSON body is flushed")
	}
	if strings.Contains(fn, "afterSuccess()") {
		t.Fatal("afterSuccess must not drop the management channel inline")
	}
}
