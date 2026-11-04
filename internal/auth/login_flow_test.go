package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBrowserCallbackAndPKCEExchange(t *testing.T) {
	for _, validState := range []bool{true, false} {
		t.Run(map[bool]string{true: "valid", false: "wrong-state"}[validState], func(t *testing.T) {
			var challenge, redirect, state string
			exchanges := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				exchanges++
				if r.Method != "POST" || r.URL.Path != "/edge/rest/security/v1/cli-token" {
					t.Errorf("unexpected exchange %s %s", r.Method, r.URL.Path)
				}
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if Challenge(body["code_verifier"]) != challenge || body["state"] != state || body["redirect_uri"] != redirect || body["code"] != "fixture-code" {
					t.Error("PKCE/callback binding mismatch")
				}
				_, _ = io.WriteString(w, `{"session_token":"fixture-session","user_token":"fixture-renewal","email":"tester@example.test","permissions":["SECRET_VIEW"]}`)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			login := Login{EdgeURL: server.URL + "/edge/rest", UIURL: server.URL, Stderr: io.Discard, Open: func(raw string) error {
				u, err := url.Parse(raw)
				if err != nil {
					return err
				}
				query := u.Query()
				challenge = query.Get("code_challenge")
				redirect = query.Get("redirect_uri")
				state = query.Get("state")
				returnedState := state
				if !validState {
					returnedState = "wrong-state"
				}
				response, err := http.Get(redirect + "?code=fixture-code&state=" + url.QueryEscape(returnedState))
				if err == nil {
					response.Body.Close()
				}
				return err
			}}
			creds, err := login.Run(ctx)
			if validState {
				if err != nil {
					t.Fatal(err)
				}
				if exchanges != 1 || creds.SessionToken != "fixture-session" || creds.UserToken != "fixture-renewal" {
					t.Fatal("login did not produce expected session")
				}
			} else if err == nil || !strings.Contains(err.Error(), "state") || exchanges != 0 {
				t.Fatalf("wrong state must not exchange: %v", err)
			}
		})
	}
}
