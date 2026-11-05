package edge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRenewAndRetry(t *testing.T) {
	var sawRenewToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != "CertLocker-Trust-CLI/1.0" {
			t.Errorf("unexpected user agent %q", r.UserAgent())
		}
		switch r.URL.Path {
		case "/edge/rest/host/paged":
			if r.Header.Get("Authorization") != "Bearer renewed" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"expired"}`))
				return
			}
			_, _ = w.Write([]byte(`{"content":[],"total":0}`))
		case "/edge/rest/security/v1/session-renew":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode renew: %v", err)
			}
			sawRenewToken = body["user_token"]
			_, _ = w.Write([]byte(`{"session_token":"renewed","idle_timeout":1000}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var renewed string
	client := &Client{
		EdgeURL:      server.URL + "/edge/rest",
		SessionToken: "old",
		UserToken:    "user-1",
		HTTP:         server.Client(),
		OnRenew: func(session string, idle int64, _ string) {
			renewed = session
			if idle != 1000 {
				t.Errorf("idle %d", idle)
			}
		},
	}
	raw, err := client.Post(context.Background(), "host/paged", map[string]any{"limit": 1})
	if err != nil {
		t.Fatal(err)
	}
	if sawRenewToken != "user-1" {
		t.Fatalf("renew token %q", sawRenewToken)
	}
	if renewed != "renewed" {
		t.Fatalf("session %q", renewed)
	}
	if client.SessionToken != "renewed" {
		t.Fatalf("client session %q", client.SessionToken)
	}
	if string(raw) != `{"content":[],"total":0}` {
		t.Fatalf("body %s", raw)
	}
}
