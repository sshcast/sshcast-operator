package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
	kongtoml "github.com/alecthomas/kong-toml"
	"stingr.net/go/sshcast-operator/internal/config"
)

func TestKongTOMLAndCLIFlagOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	tomlPath := filepath.Join(tmpDir, "operator.toml")
	pwHash, err := config.HashPassword("secret-pass")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	tomlContent := `
listen_addr = "unix:/run/sshcast/operator.sock"
base_path = "/ops"
default_expires_days = 180

[[users]]
username = "alice"
password_hash = "` + pwHash + `"

[user_passwords]
bob = "` + pwHash + `"
`
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0600); err != nil {
		t.Fatalf("WriteFile operator.toml: %v", err)
	}

	var parsed cli
	parser, err := kong.New(&parsed, kong.Configuration(kongtoml.Loader))
	if err != nil {
		t.Fatalf("kong.New: %v", err)
	}
	_, err = parser.Parse([]string{
		"--config", tomlPath,
		"--listen", "127.0.0.1:8090",
		"--base-path", "/admin/",
	})
	if err != nil {
		t.Fatalf("parser.Parse: %v", err)
	}

	if parsed.ListenAddr != "127.0.0.1:8090" {
		t.Fatalf("expected CLI --listen override 127.0.0.1:8090, got %q", parsed.ListenAddr)
	}
	if parsed.BasePath != "/admin" {
		t.Fatalf("expected normalized CLI --base-path override /admin, got %q", parsed.BasePath)
	}
	if parsed.DefaultExpiresDays != 180 {
		t.Fatalf("expected TOML default_expires_days 180, got %d", parsed.DefaultExpiresDays)
	}
	if parsed.UserCount() != 2 || !parsed.VerifyPassword("alice", "secret-pass") || !parsed.VerifyPassword("bob", "secret-pass") {
		t.Fatalf("expected both [[users]] and [user_passwords] from TOML to be loaded and verified, userCount=%d", parsed.UserCount())
	}
}
