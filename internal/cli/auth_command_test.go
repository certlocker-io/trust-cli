package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthURLSelectsDeployment(t *testing.T) {
	requests := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.URL.Path
		http.NotFound(w, r)
	}))
	defer server.Close()
	for _, args := range [][]string{{"auth", "--url", server.URL, "--no-browser"}, {"auth", "login", "--url", server.URL, "--no-browser"}} {
		cmd := New()
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "CLI sign-in is unavailable") {
			t.Fatalf("args %v: expected endpoint error, got %v", args, err)
		}
		if path := <-requests; path != "/rest/security/v1/cli-token" {
			t.Fatalf("unexpected endpoint %q", path)
		}
	}
}

func TestAuthURLRejectsInvalidDeployment(t *testing.T) {
	for _, base := range []string{"", "example.com", "ftp://example.com", "https://example.com?token=x", "https://user@example.com"} {
		cmd := New()
		cmd.SetArgs([]string{"auth", "--url", base})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--url must be") {
			t.Fatalf("URL %q: got %v", base, err)
		}
	}
}
