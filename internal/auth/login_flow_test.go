package auth

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
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
				if r.Method != "POST" || r.URL.Path != "/edge/rest/security/v1/cli-token" {
					t.Errorf("unexpected exchange %s %s", r.Method, r.URL.Path)
				}
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if len(body) == 0 {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				exchanges++
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

func TestUnavailableEndpointDoesNotOpenBrowser(t *testing.T) {
	for _, status := range []int{404, 405, 200, 302, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Location", "/redirect-target")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "private response content")
			}))
			defer server.Close()
			opened := false
			_, err := (Login{EdgeURL: server.URL, UIURL: server.URL, Open: func(string) error {
				opened = true
				return nil
			}}).Run(context.Background())
			if err == nil || opened || requests != 1 || strings.Contains(err.Error(), "private response content") {
				t.Fatalf("expected safe early failure: err=%v opened=%v requests=%d", err, opened, requests)
			}
		})
	}
}

func TestPrintedURLSupportsManualLoginAndBrowserFailure(t *testing.T) {
	for _, manual := range []bool{true, false} {
		t.Run(map[bool]string{true: "no-browser", false: "browser-failure"}[manual], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]string
				_ = json.NewDecoder(r.Body).Decode(&body)
				w.Header().Set("Content-Type", "application/json")
				if len(body) == 0 {
					w.WriteHeader(401)
					return
				}
				_, _ = io.WriteString(w, `{"session_token":"fixture-session"}`)
			}))
			defer server.Close()
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			callback := make(chan error, 1)
			go func() {
				scanner := bufio.NewScanner(reader)
				for scanner.Scan() {
					if strings.HasPrefix(scanner.Text(), "http://") {
						link, err := url.Parse(scanner.Text())
						if err != nil {
							callback <- err
							continue
						}
						q := link.Query()
						response, err := http.Get(q.Get("redirect_uri") + "?code=fixture-code&state=" + url.QueryEscape(q.Get("state")))
						if err == nil {
							response.Body.Close()
						}
						callback <- err
					}
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			opened := false
			creds, err := (Login{EdgeURL: server.URL, UIURL: server.URL, NoBrowser: manual, Stderr: writer, Open: func(string) error {
				opened = true
				return errors.New("browser launcher failed")
			}}).Run(ctx)
			if err != nil || creds.SessionToken != "fixture-session" || opened == manual {
				t.Fatalf("manual URL login failed: %v opened=%v", err, opened)
			}
			if err := <-callback; err != nil {
				t.Fatal(err)
			}
		})
	}
}
