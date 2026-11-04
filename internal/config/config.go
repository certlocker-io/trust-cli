package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultEdgeURL = "https://trust.certlocker.io/rest"
	DefaultUIURL   = "https://trust.certlocker.io"
	dirName        = "trust"
	fileName       = "config.json"
)

type File struct {
	EdgeURL string `json:"edge_url,omitempty"`
	UIURL   string `json:"ui_url,omitempty"`
}

var dirOverride string

func SetDir(dir string) {
	dirOverride = dir
}

func Dir() (string, error) {
	if dirOverride != "" {
		return dirOverride, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, dirName), nil
}

func Load() (File, error) {
	dir, err := Dir()
	if err != nil {
		return File{}, err
	}
	return LoadFrom(dir)
}

func LoadFrom(dir string) (File, error) {
	raw, err := os.ReadFile(filepath.Join(dir, fileName))
	if err != nil {
		return File{}, err
	}
	var file File
	if err := json.Unmarshal(raw, &file); err != nil {
		return File{}, err
	}
	return file, nil
}

func Save(file File) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	return SaveTo(dir, file)
}

func SaveTo(dir string, file File) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	path := filepath.Join(dir, fileName)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func Resolve(flagEdge, flagUI string) (edgeURL, uiURL string, err error) {
	file, loadErr := Load()
	if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
		return "", "", loadErr
	}
	edgeURL = firstURL(flagEdge, os.Getenv("TRUST_EDGE_URL"), file.EdgeURL, DefaultEdgeURL)
	uiURL = firstURL(flagUI, os.Getenv("TRUST_UI_URL"), file.UIURL, DefaultUIURL)
	return edgeURL, uiURL, nil
}

func firstURL(values ...string) string {
	for _, value := range values {
		value = strings.TrimRight(strings.TrimSpace(value), "/")
		if value != "" {
			return value
		}
	}
	return ""
}
