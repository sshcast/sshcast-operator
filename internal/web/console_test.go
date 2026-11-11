package web

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stingr.net/go/sshcast-operator/internal/config"
	"stingr.net/go/sshcast-proto/pkg/auth"
)

func TestConsoleLoginAndKeySigningFlow(t *testing.T) {
	tmp := t.TempDir()
	sysconfigPath := filepath.Join(tmp, "sshcast-operator.sysconfig")
	pubTok, created, err := config.InitSysconfigFile(sysconfigPath)
	if err != nil || !created || !strings.HasPrefix(pubTok, "sc_op_pub_") {
		t.Fatalf("InitSysconfigFile: created=%v pubTok=%q err=%v", created, pubTok, err)
	}

	pwHash, err := config.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	cfgPath := filepath.Join(tmp, "operator.toml")
	tomlData := `
listen_addr = "unix:/run/sshcast-operator/operator.sock"
base_path = "/console"
default_expires_days = 365

[[users]]
username = "admin"
password_hash = "` + pwHash + `"
`
	if err := os.WriteFile(cfgPath, []byte(tomlData), 0600); err != nil {
		t.Fatalf("WriteFile operator.toml: %v", err)
	}

	cfg, err := config.Load(cfgPath, sysconfigPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	srv := NewConsoleServer(cfg)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// 1. Unauthenticated GET /console/ redirects to /console/login
	resp, err := client.Get(ts.URL + "/console/")
	if err != nil {
		t.Fatalf("GET /console/: %v", err)
	}
	_ = resp.Body.Close()
	if !strings.HasSuffix(resp.Request.URL.Path, "/console/login") {
		t.Fatalf("expected redirect to /console/login, got %s", resp.Request.URL.Path)
	}

	// 2. Wrong password returns 401
	badResp, err := client.PostForm(ts.URL+"/console/login", url.Values{
		"username": {"admin"},
		"password": {"wrong-password"},
	})
	if err != nil {
		t.Fatalf("POST /console/login wrong password: %v", err)
	}
	_ = badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong password, got %d", badResp.StatusCode)
	}

	// 3. Valid login sets session cookie and redirects to /console/
	loginResp, err := client.PostForm(ts.URL+"/console/login", url.Values{
		"username": {"admin"},
		"password": {"correct-horse-battery-staple"},
	})
	if err != nil {
		t.Fatalf("POST /console/login valid: %v", err)
	}
	bodyBytes, _ := io.ReadAll(loginResp.Body)
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK || !strings.Contains(string(bodyBytes), pubTok) {
		t.Fatalf("expected portal HTML containing operator pubkey %s, status=%d", pubTok, loginResp.StatusCode)
	}

	// 4. Sign a user's Ed25519 public key via HTML form POST /console/sign
	userPub, _, _ := ed25519.GenerateKey(rand.Reader)
	userPubToken := "sc_pub_" + hex.EncodeToString(userPub)

	signResp, err := client.PostForm(ts.URL+"/console/sign", url.Values{
		"user_pubkey":  {userPubToken},
		"user_id":      {"paul"},
		"expires_days": {"90"},
	})
	if err != nil {
		t.Fatalf("POST /console/sign: %v", err)
	}
	signHTML, _ := io.ReadAll(signResp.Body)
	_ = signResp.Body.Close()
	if signResp.StatusCode != http.StatusOK || !strings.Contains(string(signHTML), "sc_cert_") {
		t.Fatalf("expected signed sc_cert_ token in HTML response, status=%d", signResp.StatusCode)
	}

	// 5. Sign via JSON API POST /console/api/sign and verify with auth.DecodeUserCertToken + auth.VerifyUserCert
	reqBody, _ := json.Marshal(map[string]any{
		"user_pubkey":  userPubToken,
		"user_id":      "paul",
		"expires_days": 30,
	})
	apiResp, err := client.Post(ts.URL+"/console/api/sign", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /console/api/sign: %v", err)
	}
	var apiOut struct {
		OK        bool   `json:"ok"`
		CertToken string `json:"cert_token"`
		UserID    string `json:"user_id"`
	}
	if err := json.NewDecoder(apiResp.Body).Decode(&apiOut); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	_ = apiResp.Body.Close()
	if !apiOut.OK || !strings.HasPrefix(apiOut.CertToken, "sc_cert_") {
		t.Fatalf("unexpected API response: %+v", apiOut)
	}

	cert, err := auth.DecodeUserCertToken(apiOut.CertToken)
	if err != nil {
		t.Fatalf("DecodeUserCertToken: %v", err)
	}
	if err := auth.VerifyUserCert(cert, userPub, uint64(time.Now().Unix())); err != nil {
		t.Fatalf("VerifyUserCert failed: %v", err)
	}
	if !bytes.Equal(cert.GetOperatorPubkey(), cfg.OperatorPubKey) {
		t.Fatalf("operator pubkey mismatch in signed cert")
	}
}
