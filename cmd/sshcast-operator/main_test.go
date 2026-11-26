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
listen_addr = "unix:/run/sshcast-operator/operator.sock"
base_path = "/ops"
default_expires_days = 180
db_path = "` + filepath.Join(tmpDir, "op.db") + `"
public_url = "https://ops.example.com/"
auto_approve = false
min_github_account_age_days = 45

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
	if parsed.AutoApprove {
		t.Fatalf("expected TOML auto_approve=false, got true")
	}
	if parsed.MinGitHubAccountAgeDays != 45 {
		t.Fatalf("expected TOML min_github_account_age_days 45, got %d", parsed.MinGitHubAccountAgeDays)
	}
	if parsed.PublicURL != "https://ops.example.com" {
		t.Fatalf("expected normalized public_url https://ops.example.com, got %q", parsed.PublicURL)
	}
	if parsed.DBPath != filepath.Join(tmpDir, "op.db") {
		t.Fatalf("expected db_path %q, got %q", filepath.Join(tmpDir, "op.db"), parsed.DBPath)
	}
	if parsed.UserCount() != 2 || !parsed.VerifyPassword("alice", "secret-pass") || !parsed.VerifyPassword("bob", "secret-pass") {
		t.Fatalf("expected both [[users]] and [user_passwords] from TOML to be loaded and verified, userCount=%d", parsed.UserCount())
	}
}
