package command

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"warptweet.com/warptweet/internal/enrollment"
	"warptweet.com/warptweet/internal/outcome"
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

func TestWriteEnrollmentJSONMapsHostBusyToUnavailable(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`{}`))
	recorder := httptest.NewRecorder()
	writeEnrollmentJSON(recorder, request, "enroll", nil, func([]byte) (any, error) {
		return nil, fmt.Errorf("%w: another host command holds lock", outcome.ErrHostBusy)
	}, nil)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "host busy") {
		t.Fatalf("body=%s", recorder.Body.String())
	}
}

func TestEnrollmentAcceptDoesNotConsumeWhenHostLockHeld(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	held := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = enrollment.WithExclusiveLock(dir, hostStateLockName, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	consumed := false
	request := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`{}`))
	recorder := httptest.NewRecorder()
	writeEnrollmentJSON(recorder, request, "enroll", nil, func([]byte) (any, error) {
		err := enrollment.WithNonBlockingExclusiveLock(dir, hostStateLockName, func() error {
			consumed = true
			return nil
		})
		if errors.Is(err, enrollment.ErrBusy) {
			return nil, fmt.Errorf("%w: host operation in progress", outcome.ErrHostBusy)
		}
		return nil, err
	}, nil)
	close(release)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if consumed {
		t.Fatal("accept consumed while host lock was held")
	}
}
