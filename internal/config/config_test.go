package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigDefaultsAndEnvFallbacks(t *testing.T) {
	tmp := t.TempDir()
	sysconfigPath := filepath.Join(tmp, "sysconfig")
	if _, _, err := InitSysconfigFile(sysconfigPath); err != nil {
		t.Fatalf("InitSysconfigFile: %v", err)
	}

	t.Setenv("STATE_DIRECTORY", "")
	t.Setenv("SSHCAST_GITHUB_CLIENT_ID", "")
	t.Setenv("SSHCAST_GITHUB_CLIENT_SECRET", "")

	cfg, err := Load("", sysconfigPath)
	if err != nil {
		t.Fatalf("Load defaults: %v", err)
	}
	if cfg.DefaultExpiresDays != 7 {
		t.Fatalf("expected DefaultExpiresDays 7, got %d", cfg.DefaultExpiresDays)
	}
	if cfg.DBPath != "/var/lib/sshcast-operator/operator.db" {
		t.Fatalf("expected default DBPath /var/lib/sshcast-operator/operator.db, got %q", cfg.DBPath)
	}
	if !cfg.AutoApprove {
		t.Fatalf("expected default AutoApprove true")
	}
	if cfg.MinGitHubAccountAgeDays != 30 {
		t.Fatalf("expected default MinGitHubAccountAgeDays 30, got %d", cfg.MinGitHubAccountAgeDays)
	}

	stateDir := filepath.Join(tmp, "state")
	t.Setenv("STATE_DIRECTORY", stateDir+":/ignored/second")
	t.Setenv("SSHCAST_GITHUB_CLIENT_ID", "env-client-id")
	t.Setenv("SSHCAST_GITHUB_CLIENT_SECRET", "env-client-secret")

	tomlPath := filepath.Join(tmp, "operator.toml")
	if err := os.WriteFile(tomlPath, []byte(`
public_url = "https://sshcast.example.com/"
auto_approve = false
min_github_account_age_days = 14
`), 0600); err != nil {
		t.Fatalf("WriteFile operator.toml: %v", err)
	}

	cfg2, err := Load(tomlPath, sysconfigPath)
	if err != nil {
		t.Fatalf("Load with overrides: %v", err)
	}
	if cfg2.DBPath != filepath.Join(stateDir, "operator.db") {
		t.Fatalf("expected DBPath under STATE_DIRECTORY, got %q", cfg2.DBPath)
	}
	if cfg2.PublicURL != "https://sshcast.example.com" {
		t.Fatalf("expected trimmed PublicURL, got %q", cfg2.PublicURL)
	}
	if cfg2.AutoApprove {
		t.Fatalf("expected AutoApprove false from TOML")
	}
	if cfg2.MinGitHubAccountAgeDays != 14 {
		t.Fatalf("expected MinGitHubAccountAgeDays 14, got %d", cfg2.MinGitHubAccountAgeDays)
	}
	if cfg2.GitHubClientID != "env-client-id" || cfg2.GitHubClientSecret != "env-client-secret" {
		t.Fatalf("expected GitHub env fallbacks, got id=%q secret=%q", cfg2.GitHubClientID, cfg2.GitHubClientSecret)
	}
}
