package auth

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/certlocker-io/trust-cli/internal/config"
)

const credentialsFile = "credentials.json"

type Credentials struct {
	EdgeURL      string   `json:"edge_url,omitempty"`
	SessionToken string   `json:"session_token"`
	UserToken    string   `json:"user_token,omitempty"`
	UserID       string   `json:"user_id,omitempty"`
	Email        string   `json:"email,omitempty"`
	DisplayName  string   `json:"display_name,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	SuperUser    bool     `json:"super_user,omitempty"`
	IdleTimeout  int64    `json:"idle_timeout,omitempty"`
	ExpiryDate   string   `json:"expiry_date,omitempty"`
}

func Load() (Credentials, error) {
	dir, err := config.Dir()
	if err != nil {
		return Credentials{}, err
	}
	return LoadFrom(dir)
}

func LoadFrom(dir string) (Credentials, error) {
	raw, err := os.ReadFile(filepath.Join(dir, credentialsFile))
	if err != nil {
		return Credentials{}, err
	}
	var creds Credentials
	if err := json.Unmarshal(raw, &creds); err != nil {
		return Credentials{}, err
	}
	return creds, nil
}

func Save(creds Credentials) error {
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	return SaveTo(dir, creds)
}

func SaveTo(dir string, creds Credentials) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	path := filepath.Join(dir, credentialsFile)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func Delete() error {
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	err = os.Remove(filepath.Join(dir, credentialsFile))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
