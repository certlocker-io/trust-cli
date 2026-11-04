package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/certlocker-io/trust-cli/internal/auth"
	"github.com/certlocker-io/trust-cli/internal/config"
	"github.com/certlocker-io/trust-cli/internal/edge"
	"github.com/certlocker-io/trust-cli/internal/output"
)

func newAuth() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Sign in to Edge and inspect the saved session",
	}
	login := &cobra.Command{
		Use:   "login",
		Short: "Open a browser, complete Edge sign-in and 2FA, and store the session",
		RunE:  runLogin,
	}
	login.Flags().Duration("timeout", 5*time.Minute, "How long to wait for the browser to finish sign-in")
	login.Flags().Bool("no-browser", false, "Print the login URL without launching a browser")
	cmd.AddCommand(login)
	cmd.AddCommand(&cobra.Command{
		Use:   "logout",
		Short: "Sign out of Edge and remove the saved session",
		RunE:  runLogout,
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "whoami",
		Short: "Show the signed-in user and permissions",
		RunE:  runWhoami,
	})
	return cmd
}

func runLogin(cmd *cobra.Command, args []string) error {
	edgeURL, uiURL, err := config.Resolve(flagEdge, flagUI)
	if err != nil {
		return err
	}
	timeout, _ := cmd.Flags().GetDuration("timeout")
	noBrowser, _ := cmd.Flags().GetBool("no-browser")
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()
	creds, err := (auth.Login{EdgeURL: edgeURL, UIURL: uiURL, NoBrowser: noBrowser}).Run(ctx)
	if err != nil {
		return err
	}
	if err := auth.Save(creds); err != nil {
		return err
	}
	if err := config.Save(config.File{EdgeURL: edgeURL, UIURL: uiURL}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Signed in as %s\n", creds.Email)
	return output.Write(mustJSON(map[string]any{
		"email":        creds.Email,
		"display_name": creds.DisplayName,
		"permissions":  creds.Permissions,
		"groups":       creds.Groups,
		"edge_url":     creds.EdgeURL,
	}))
}

func runLogout(cmd *cobra.Command, args []string) error {
	var signOutErr error
	if creds, err := auth.Load(); err == nil && creds.SessionToken != "" {
		client, _, clientErr := apiClient()
		if clientErr != nil {
			signOutErr = clientErr
		} else {
			_, signOutErr = client.Post(cmd.Context(), "security/v1/sign-out", map[string]any{})
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := auth.Delete(); err != nil {
		return err
	}
	if signOutErr != nil {
		return fmt.Errorf("removed local credentials; Edge sign-out failed: %w", signOutErr)
	}
	fmt.Fprintln(os.Stderr, "Signed out.")
	return nil
}

func runWhoami(cmd *cobra.Command, args []string) error {
	creds, err := auth.Load()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("not logged in; run trust auth login")
		}
		return err
	}
	edgeURL, err := currentEdge(creds)
	if err != nil {
		return err
	}
	return output.Write(mustJSON(map[string]any{
		"email":        creds.Email,
		"display_name": creds.DisplayName,
		"user_id":      creds.UserID,
		"super_user":   creds.SuperUser,
		"groups":       creds.Groups,
		"permissions":  creds.Permissions,
		"edge_url":     edgeURL,
		"expiry_date":  creds.ExpiryDate,
	}))
}

func apiClient() (*edge.Client, auth.Credentials, error) {
	creds, err := auth.Load()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, creds, fmt.Errorf("not logged in; run trust auth login")
		}
		return nil, creds, err
	}
	if creds.SessionToken == "" {
		return nil, creds, fmt.Errorf("not logged in; run trust auth login")
	}
	edgeURL, err := currentEdge(creds)
	if err != nil {
		return nil, creds, err
	}
	client := &edge.Client{
		EdgeURL:      edgeURL,
		SessionToken: creds.SessionToken,
		UserToken:    creds.UserToken,
		OnRenew: func(session string, idle int64, expiry string) {
			creds.SessionToken = session
			if idle != 0 {
				creds.IdleTimeout = idle
			}
			if expiry != "" {
				creds.ExpiryDate = expiry
			}
			_ = auth.Save(creds)
		},
	}
	return client, creds, nil
}

func currentEdge(creds auth.Credentials) (string, error) {
	if flagEdge != "" {
		return trimURL(flagEdge), nil
	}
	if value := strings.TrimSpace(os.Getenv("TRUST_EDGE_URL")); value != "" {
		return trimURL(value), nil
	}
	file, err := config.Load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if file.EdgeURL != "" {
		return trimURL(file.EdgeURL), nil
	}
	if creds.EdgeURL != "" {
		return trimURL(creds.EdgeURL), nil
	}
	return config.DefaultEdgeURL, nil
}

func post(cmd *cobra.Command, path string, body any) ([]byte, error) {
	client, _, err := apiClient()
	if err != nil {
		return nil, err
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return client.Post(ctx, path, body)
}

func postPrint(cmd *cobra.Command, path string, body any) error {
	raw, err := post(cmd, path, body)
	if err != nil {
		return err
	}
	return output.Write(raw)
}
