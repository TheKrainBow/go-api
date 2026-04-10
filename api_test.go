package apiManager

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseRetryAfterSeconds(t *testing.T) {
	delay, ok := parseRetryAfter("3", time.Now())
	if !ok {
		t.Fatalf("expected Retry-After seconds to parse")
	}
	if delay != 3*time.Second {
		t.Fatalf("expected 3s delay, got %v", delay)
	}
}

func TestParseRetryAfterHTTPDate(t *testing.T) {
	now := time.Date(2026, time.April, 10, 10, 0, 0, 0, time.UTC)
	value := now.Add(2 * time.Second).Format(http.TimeFormat)
	delay, ok := parseRetryAfter(value, now)
	if !ok {
		t.Fatalf("expected Retry-After date to parse")
	}
	if delay != 2*time.Second {
		t.Fatalf("expected 2s delay, got %v", delay)
	}
}

func TestClientRetriesTooManyRequests(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := attempts.Add(1)
		if count < 3 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	client, err := NewBasicAPIClient("test-retry", "user", "pass", server.URL, "/", false)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	resp, err := client.Get("/")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after retries, got %s", resp.Status)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}
