package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/browser"
)

var OpenBrowser = browser.OpenURL

type Login struct {
	EdgeURL   string
	UIURL     string
	Open      func(string) error
	Stdout    io.Writer
	Stderr    io.Writer
	NoBrowser bool
}

func (l Login) Run(ctx context.Context) (Credentials, error) {
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	if err := checkCLIEndpoint(ctx, client, l.EdgeURL); err != nil {
		return Credentials{}, err
	}
	verifier, err := NewVerifier()
	if err != nil {
		return Credentials{}, err
	}
	state, err := NewState()
	if err != nil {
		return Credentials{}, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Credentials{}, err
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	loginURL, err := LoginURL(l.UIURL, redirect, state, Challenge(verifier))
	if err != nil {
		return Credentials{}, err
	}

	type callback struct {
		code string
		err  error
	}
	done := make(chan callback, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		query := r.URL.Query()
		if query.Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			select {
			case done <- callback{err: fmt.Errorf("login state did not match")}:
			default:
			}
			return
		}
		code := query.Get("code")
		if code == "" {
			message := query.Get("error")
			if message == "" {
				message = "login did not return a code"
			}
			http.Error(w, message, http.StatusBadRequest)
			select {
			case done <- callback{err: fmt.Errorf("%s", message)}:
			default:
			}
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!DOCTYPE html><html><body><p>Signed in. You can close this window.</p></body></html>")
		go func() {
			select {
			case done <- callback{code: code}:
			default:
			}
		}()
	})}
	go server.Serve(listener)
	defer server.Shutdown(context.Background())

	stderr := l.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	fmt.Fprintln(stderr, "Sign in with your browser. CertLocker 2FA runs on the Edge login page.")
	fmt.Fprintf(stderr, "Open this URL in a browser on this machine:\n%s\n", loginURL)
	open := l.Open
	if open == nil {
		open = OpenBrowser
	}
	if !l.NoBrowser {
		if err := open(loginURL); err != nil {
			fmt.Fprintln(stderr, "Could not open the browser automatically; use the URL above.")
		}
	}

	var result callback
	select {
	case <-ctx.Done():
		return Credentials{}, fmt.Errorf("timed out waiting for browser login")
	case result = <-done:
	}
	if result.err != nil {
		return Credentials{}, result.err
	}

	body, err := json.Marshal(map[string]string{
		"code":          result.code,
		"code_verifier": verifier,
		"redirect_uri":  redirect,
		"state":         state,
	})
	if err != nil {
		return Credentials{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(l.EdgeURL, "/")+"/security/v1/cli-token", strings.NewReader(string(body)))
	if err != nil {
		return Credentials{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "CertLocker-Trust-CLI/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return Credentials{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return Credentials{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Credentials{}, fmt.Errorf("%s", apiMessage(raw, resp.StatusCode))
	}
	creds, err := credentialsFromToken(raw)
	if err != nil {
		return Credentials{}, err
	}
	creds.EdgeURL = strings.TrimRight(l.EdgeURL, "/")
	return creds, nil
}

// An empty exchange is rejected by a CLI-enabled Edge before any grant can be
// minted. Detect missing routes before asking the user to complete browser 2FA.
func checkCLIEndpoint(ctx context.Context, client *http.Client, edgeURL string) error {
	endpoint := strings.TrimRight(edgeURL, "/") + "/security/v1/cli-token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "CertLocker-Trust-CLI/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach Edge CLI sign-in: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return fmt.Errorf("Edge CLI sign-in is unavailable at %s (HTTP %d); check --edge and deploy an Edge build with CLI authentication support", endpoint, resp.StatusCode)
	}
	if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized) &&
		strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") {
		return nil
	}
	return fmt.Errorf("cannot confirm Edge CLI sign-in at %s (HTTP %d); expected a JSON rejection of an empty exchange; check the Edge URL and routing", endpoint, resp.StatusCode)
}

func LoginURL(uiBase, redirectURI, state, challenge string) (string, error) {
	u, err := url.Parse(strings.TrimRight(uiBase, "/"))
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("UI URL must include a scheme and host")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/login"
	query := u.Query()
	query.Set("redirect_uri", redirectURI)
	query.Set("state", state)
	query.Set("code_challenge", challenge)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func credentialsFromToken(raw []byte) (Credentials, error) {
	var body struct {
		SessionToken string          `json:"session_token"`
		UserToken    string          `json:"user_token"`
		UserID       string          `json:"user_id"`
		Email        string          `json:"email"`
		DisplayName  string          `json:"display_name"`
		Permissions  []string        `json:"permissions"`
		Groups       []string        `json:"groups"`
		SuperUser    bool            `json:"super_user"`
		IdleTimeout  int64           `json:"idle_timeout"`
		ExpiryDate   json.RawMessage `json:"expiry_date"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return Credentials{}, err
	}
	if body.SessionToken == "" {
		return Credentials{}, fmt.Errorf("login did not return a session")
	}
	return Credentials{
		SessionToken: body.SessionToken,
		UserToken:    body.UserToken,
		UserID:       body.UserID,
		Email:        body.Email,
		DisplayName:  body.DisplayName,
		Permissions:  body.Permissions,
		Groups:       body.Groups,
		SuperUser:    body.SuperUser,
		IdleTimeout:  body.IdleTimeout,
		ExpiryDate:   rawString(body.ExpiryDate),
	}, nil
}

func rawString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	return string(raw)
}

func apiMessage(raw []byte, status int) string {
	var body map[string]any
	if json.Unmarshal(raw, &body) == nil {
		for _, key := range []string{"error_message", "message"} {
			if text, ok := body[key].(string); ok && strings.TrimSpace(text) != "" {
				return text
			}
		}
	}
	text := strings.TrimSpace(string(raw))
	if text != "" {
		return text
	}
	return fmt.Sprintf("edge returned HTTP %d", status)
}
