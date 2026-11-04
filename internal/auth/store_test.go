package auth

import (
	"os"
	"runtime"
	"testing"

	"github.com/certlocker-io/trust-cli/internal/config"
)

func TestCredentialsFileMode(t *testing.T) {
	dir := t.TempDir()
	config.SetDir(dir)
	t.Cleanup(func() { config.SetDir("") })

	err := SaveTo(dir, Credentials{SessionToken: "sess", Email: "ada@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(dir + "/credentials.json")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	loaded, err := LoadFrom(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SessionToken != "sess" || loaded.Email != "ada@example.test" {
		t.Fatalf("%+v", loaded)
	}
}
