package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Darren-Certlocker/trust-cli/internal/auth"
)

// Test actual Cobra commands through credential loading and the HTTP transport.
// All tokens and assets are synthetic; no live endpoint is contacted.
func TestCommandHTTPContracts(t *testing.T) {
	tests := []struct {
		args   []string
		path   string
		fields map[string]any
	}{}
	for plural, singular := range map[string]string{"hosts": "host", "secrets": "secret", "probes": "probe", "tokens": "token", "agents": "ai-agent", "certificates": "cert"} {
		tests = append(tests, struct {
			args   []string
			path   string
			fields map[string]any
		}{[]string{plural, "list", "--limit", "7", "--skip", "2", "--group", "ops"}, singular + "/paged", map[string]any{"limit": float64(7), "skip": float64(2), "ins": []any{map[string]any{"field": "groups", "values": []any{"ops"}}}}})
		tests = append(tests, struct {
			args   []string
			path   string
			fields map[string]any
		}{[]string{plural, "get", "asset-1"}, singular + "/detail/asset-1", nil})
		if plural == "certificates" {
			continue
		}
		for command, action := range map[string]string{"suspend": "suspend", "resume": "resume", "unsuspend": "resume", "revoke": "revoke"} {
			tests = append(tests, struct {
				args   []string
				path   string
				fields map[string]any
			}{[]string{plural, command, "asset-1"}, singular + "/" + action, map[string]any{"id": "asset-1"}})
		}
	}
	tests = append(tests, []struct {
		args   []string
		path   string
		fields map[string]any
	}{
		{[]string{"hosts", "create", "--name", "fixture", "--ip", "127.0.0.1", "--port", "22"}, "host/create", map[string]any{"name": "fixture", "ip_address": "127.0.0.1", "port": float64(22)}},
		{[]string{"secrets", "create", "--name", "fixture", "--type", "password", "--secret", "synthetic-value"}, "secret/create", map[string]any{"secret_type": "PASSWORD", "secret": "synthetic-value"}},
		{[]string{"tokens", "create", "--name", "fixture", "--type", "secret", "--duration", "1", "--unit", "hours"}, "token/create", map[string]any{"token_type": "SECRET", "duration": map[string]any{"interval": float64(1), "unit": "HOURS"}}},
		{[]string{"probes", "create", "--name", "fixture", "--frequency", "daily"}, "probe/create", map[string]any{"frequency": "DAILY"}},
		{[]string{"agents", "create", "--name", "fixture", "--role", "reader"}, "ai-agent/create", map[string]any{"role_ids": []any{"reader"}}},
		{[]string{"hosts", "revoke", "asset-1", "--remove-associated"}, "host/revoke", map[string]any{"remove_associated_items": true}},
		{[]string{"probes", "run", "asset-1"}, "probe/probe", map[string]any{"id": "asset-1"}},
		{[]string{"automations", "run", "asset-1", "--type", "certificate", "--certificate", "cert-1"}, "acme/automation-run/asset-1", map[string]any{"type": "CERTIFICATE", "certificate_id": "cert-1"}},
	}...)
	for _, test := range tests {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "POST" || r.URL.Path != "/edge/rest/"+test.path {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer fixture-session" {
					t.Error("missing session")
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				for key, want := range test.fields {
					if !reflect.DeepEqual(body[key], want) {
						t.Errorf("%s: got %#v want %#v", key, body[key], want)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"id":"fixture","content":[],"total":0}`)
			}))
			defer server.Close()
			if err := auth.Save(auth.Credentials{SessionToken: "fixture-session", EdgeURL: server.URL + "/edge/rest"}); err != nil {
				t.Fatal(err)
			}
			root := New()
			root.SetArgs(append([]string{"--edge", server.URL + "/edge/rest", "--output", "json"}, test.args...))
			if err := root.ExecuteContext(context.Background()); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("calls %d", calls)
			}
		})
	}
}

func TestCommandDeniedAndInvalidInput(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = io.WriteString(w, `{"message":"permission denied"}`)
	}))
	defer server.Close()
	if err := auth.Save(auth.Credentials{SessionToken: "fixture-session"}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"hosts", "list"}, {"hosts", "get"}, {"tokens", "create", "--name", "missing-type"}, {"automations", "run", "id", "--type", "certificate"}} {
		root := New()
		root.SetArgs(append([]string{"--edge", server.URL}, args...))
		if err := root.ExecuteContext(context.Background()); err == nil {
			t.Fatalf("expected failure for %v", args)
		}
	}
}

func TestUpdateAliases(t *testing.T) {
	for _, action := range []string{"update", "modify", "put"} {
		for _, asset := range []string{"hosts", "secrets", "probes", "tokens", "agents", "certificates"} {
			t.Run(asset+"/"+action, func(t *testing.T) {
				t.Setenv("XDG_CONFIG_HOME", t.TempDir())
				paths := map[string]string{"hosts": "host", "secrets": "secret", "probes": "probe", "tokens": "token", "agents": "ai-agent", "certificates": "cert"}
				calls := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if r.Method != "POST" || r.URL.Path != "/"+paths[asset]+"/modify" {
						t.Errorf("bad update route %s", r.URL.Path)
					}
					var body map[string]any
					_ = json.NewDecoder(r.Body).Decode(&body)
					if body["id"] != "fixture" || body["description"] != "updated" {
						t.Errorf("bad body %v", body)
					}
					_, _ = io.WriteString(w, `{"success":true}`)
				}))
				defer server.Close()
				if err := auth.Save(auth.Credentials{SessionToken: "fixture-session"}); err != nil {
					t.Fatal(err)
				}
				root := New()
				root.SetIn(strings.NewReader(`{"name":"fixture","description":"updated"}`))
				root.SetArgs([]string{"--edge", server.URL, asset, action, "fixture", "--body", "-"})
				if err := root.ExecuteContext(context.Background()); err != nil {
					t.Fatal(err)
				}
				if calls != 1 {
					t.Fatal("missing update")
				}
			})
		}
	}
}

func TestUpdateRejectsInvalidFormsWithoutHTTP(t *testing.T) {
	for _, body := range []string{"null", "[]", "invalid", `{"id":"different"}`} {
		root := New()
		root.SetIn(strings.NewReader(body))
		root.SetArgs([]string{"secrets", "update", "fixture", "--body", "-"})
		if err := root.ExecuteContext(context.Background()); err == nil || !strings.Contains(err.Error(), "body") {
			t.Fatalf("expected form validation error for %s: %v", body, err)
		}
	}
}
