package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("edge returned HTTP %d", e.Status)
}

type Client struct {
	EdgeURL      string
	SessionToken string
	UserToken    string
	HTTP         *http.Client
	OnRenew      func(sessionToken string, idleTimeout int64, expiry string)
}

func (c *Client) Post(ctx context.Context, path string, body any) (json.RawMessage, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	raw, status, err := c.do(ctx, path, body, c.SessionToken)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized && c.UserToken != "" && path != "security/v1/session-renew" {
		if renewErr := c.renew(ctx); renewErr == nil {
			raw, status, err = c.do(ctx, path, body, c.SessionToken)
			if err != nil {
				return nil, err
			}
		}
	}
	if status < 200 || status >= 300 {
		return nil, &APIError{Status: status, Message: messageFrom(raw, status)}
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return json.RawMessage("{}"), nil
	}
	return json.RawMessage(raw), nil
}

func (c *Client) renew(ctx context.Context) error {
	raw, status, err := c.do(ctx, "security/v1/session-renew", map[string]string{"user_token": c.UserToken}, "")
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return &APIError{Status: status, Message: messageFrom(raw, status)}
	}
	var resp struct {
		SessionToken string          `json:"session_token"`
		IdleTimeout  int64           `json:"idle_timeout"`
		ExpiryDate   json.RawMessage `json:"expiry_date"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	if resp.SessionToken == "" {
		return fmt.Errorf("session renew returned no token")
	}
	c.SessionToken = resp.SessionToken
	if c.OnRenew != nil {
		c.OnRenew(resp.SessionToken, resp.IdleTimeout, rawString(resp.ExpiryDate))
	}
	return nil
}

func (c *Client) do(ctx context.Context, path string, body any, token string) ([]byte, int, error) {
	if body == nil {
		body = map[string]any{}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(path), bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "CertLocker-Trust-CLI/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return raw, resp.StatusCode, nil
}

func (c *Client) endpoint(path string) string {
	return strings.TrimRight(c.EdgeURL, "/") + "/" + strings.TrimLeft(path, "/")
}

func messageFrom(raw []byte, status int) string {
	var body map[string]any
	if json.Unmarshal(raw, &body) == nil {
		for _, key := range []string{"error_message", "message"} {
			if text, ok := body[key].(string); ok && strings.TrimSpace(text) != "" {
				return text
			}
		}
		if nested, ok := body["error"].(map[string]any); ok {
			for _, key := range []string{"error_message", "message"} {
				if text, ok := nested[key].(string); ok && strings.TrimSpace(text) != "" {
					return text
				}
			}
		}
	}
	text := strings.TrimSpace(string(raw))
	if text != "" {
		return text
	}
	return fmt.Sprintf("edge returned HTTP %d", status)
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
