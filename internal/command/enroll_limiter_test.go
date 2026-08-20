package command

import (
	"testing"
	"time"
)

func TestEnrollmentLimiterIsPerSourceTokenBucket(t *testing.T) {
	t.Parallel()

	limiter := newEnrollmentRateLimiter(time.Hour, 2)
	if !limiter.allow("10.0.0.1") || !limiter.allow("10.0.0.1") {
		t.Fatal("burst of 2 should be allowed")
	}
	if limiter.allow("10.0.0.1") {
		t.Fatal("third request in the burst window should be denied")
	}
	if !limiter.allow("10.0.0.2") {
		t.Fatal("a different source should have its own bucket")
	}
}

func TestEnrollmentLimiterEvictsLRUSource(t *testing.T) {
	t.Parallel()

	limiter := newEnrollmentRateLimiter(time.Hour, 1)
	limiter.maxSources = 1
	if !limiter.allow("10.0.0.1") {
		t.Fatal("first source should be admitted")
	}
	if !limiter.allow("10.0.0.2") {
		t.Fatal("new source should evict the idle LRU entry")
	}
	if limiter.allow("10.0.0.2") {
		t.Fatal("evicted replacement should still honor its own burst")
	}
}
