package web

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"stingr.net/go/sshcast-operator/internal/config"
	"stingr.net/go/sshcast-operator/internal/db"
	sshcastv1 "stingr.net/go/sshcast-proto/gen/go/sshcast/v1"
	"stingr.net/go/sshcast-proto/pkg/auth"
)

type testEnv struct {
	t        *testing.T
	cfg      *config.Config
	queries  *db.Queries
	srv      *ConsoleServer
	ts       *httptest.Server
	mockGH   *httptest.Server
	nextUser atomic.Value // holds mockGHUser
}

type mockGHUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	CreatedAt string `json:"created_at"`
}

func newTestEnv(t *testing.T, opts ...func(*config.Config)) *testEnv {
	t.Helper()
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

	dbPath := filepath.Join(tmp, "state", "operator.db")
	cfgPath := filepath.Join(tmp, "operator.toml")
	tomlData := `
listen_addr = "unix:/run/sshcast-operator/operator.sock"
base_path = "/console"
default_expires_days = 7
db_path = "` + dbPath + `"
auto_approve = true
min_github_account_age_days = 30
github_client_id = "test-gh-client-id"
github_client_secret = "test-gh-client-secret"

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
	for _, opt := range opts {
		opt(cfg)
	}

	sqlDB, queries, err := db.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	env := &testEnv{
		t:       t,
		cfg:     cfg,
		queries: queries,
	}
	env.nextUser.Store(mockGHUser{
		ID:        1001,
		Login:     "mature-user",
		CreatedAt: time.Now().UTC().Add(-90 * 24 * time.Hour).Format(time.RFC3339),
	})

	ghMux := http.NewServeMux()
	ghMux.HandleFunc("GET /login/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != cfg.GitHubClientID {
			http.Error(w, "bad client_id", http.StatusBadRequest)
			return
		}
		if q.Get("scope") != "read:user" {
			http.Error(w, "bad scope", http.StatusBadRequest)
			return
		}
		redir := q.Get("redirect_uri")
		if redir == "" {
			http.Error(w, "missing redirect_uri", http.StatusBadRequest)
			return
		}
		target := redir + "?code=mock-oauth-code&state=" + url.QueryEscape(q.Get("state"))
		http.Redirect(w, r, target, http.StatusFound)
	})
	ghMux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.FormValue("client_id") != cfg.GitHubClientID || r.FormValue("client_secret") != cfg.GitHubClientSecret {
			http.Error(w, "bad client credentials", http.StatusUnauthorized)
			return
		}
		if r.FormValue("code") != "mock-oauth-code" {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-gh-token",
			"token_type":   "bearer",
			"scope":        "read:user",
		})
	})
	ghMux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mock-gh-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("User-Agent") != "sshcast-operator" {
			http.Error(w, "missing User-Agent", http.StatusBadRequest)
			return
		}
		u := env.nextUser.Load().(mockGHUser)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(u)
	})

	env.mockGH = httptest.NewServer(ghMux)
	t.Cleanup(env.mockGH.Close)

	srv := NewConsoleServer(cfg, queries)
	srv.GitHubOAuthBaseURL = env.mockGH.URL
	srv.GitHubAPIBaseURL = env.mockGH.URL
	srv.HTTPClient = env.mockGH.Client()

	env.srv = srv
	env.ts = httptest.NewServer(srv)
	t.Cleanup(env.ts.Close)
	return env
}

func (e *testEnv) adminClient() *http.Client {
	e.t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.PostForm(e.ts.URL+"/console/login", url.Values{
		"username": {"admin"},
		"password": {"correct-horse-battery-staple"},
	})
	if err != nil {
		e.t.Fatalf("admin login: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("admin login status=%d", resp.StatusCode)
	}
	return client
}

func (e *testEnv) startEnrollment(userPubToken string) (state, pollToken, authURL string) {
	e.t.Helper()
	payload, _ := json.Marshal(map[string]string{"user_pubkey": userPubToken})
	resp, err := http.Post(e.ts.URL+"/api/v1/enroll/start", "application/json", bytes.NewReader(payload))
	if err != nil {
		e.t.Fatalf("enroll/start: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		e.t.Fatalf("enroll/start status=%d body=%s", resp.StatusCode, b)
	}
	var out struct {
		OK        bool   `json:"ok"`
		State     string `json:"state"`
		PollToken string `json:"poll_token"`
		AuthURL   string `json:"auth_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		e.t.Fatalf("decode enroll/start: %v", err)
	}
	if !out.OK || out.State == "" || out.PollToken == "" || out.AuthURL == "" {
		e.t.Fatalf("unexpected enroll/start response: %+v", out)
	}
	return out.State, out.PollToken, out.AuthURL
}

func (e *testEnv) pollEnrollment(state, pollToken string) (int, map[string]any) {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/enroll/poll?state="+url.QueryEscape(state), nil)
	if pollToken != "" {
		req.Header.Set("Authorization", "Bearer "+pollToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("enroll/poll: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		e.t.Fatalf("decode enroll/poll: %v", err)
	}
	return resp.StatusCode, out
}

func buildSignedNodeAuth(t *testing.T, userPub ed25519.PublicKey, userPriv ed25519.PrivateKey, embeddedCert *sshcastv1.UserCert) *sshcastv1.NodeAuth {
	t.Helper()
	nodePub, nodePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey node: %v", err)
	}
	now := time.Now().UTC()
	grant := &sshcastv1.NodeGrant{
		UserId:           auth.DeriveUserID(userPub),
		UserPubkey:       userPub,
		NodeId:           "laptop-test",
		Role:             sshcastv1.NodeRole_NODE_ROLE_CLIENT,
		NodePubkey:       nodePub,
		IssuedAtUnixSec:  uint64(now.Add(-1 * time.Hour).Unix()),
		ExpiresAtUnixSec: uint64(now.Add(24 * time.Hour).Unix()),
		UserCert:         embeddedCert,
	}
	if err := auth.SignNodeGrant(grant, userPriv); err != nil {
		t.Fatalf("SignNodeGrant: %v", err)
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	nodeAuth := &sshcastv1.NodeAuth{
		Grant:           grant,
		TimestampUnixMs: uint64(now.UnixMilli()),
		Nonce:           nonce,
	}
	if err := auth.SignNodeAuth(nodeAuth, nodePriv); err != nil {
		t.Fatalf("SignNodeAuth: %v", err)
	}
	return nodeAuth
}

func TestConsoleLoginAndKeySigningFlow(t *testing.T) {
	env := newTestEnv(t, func(cfg *config.Config) {
		cfg.DefaultExpiresDays = 365
	})

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// 1. Unauthenticated GET /console/ redirects to /console/login
	resp, err := client.Get(env.ts.URL + "/console/")
	if err != nil {
		t.Fatalf("GET /console/: %v", err)
	}
	_ = resp.Body.Close()
	if !strings.HasSuffix(resp.Request.URL.Path, "/console/login") {
		t.Fatalf("expected redirect to /console/login, got %s", resp.Request.URL.Path)
	}

	// 2. Wrong password returns 401
	badResp, err := client.PostForm(env.ts.URL+"/console/login", url.Values{
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
	loginResp, err := client.PostForm(env.ts.URL+"/console/login", url.Values{
		"username": {"admin"},
		"password": {"correct-horse-battery-staple"},
	})
	if err != nil {
		t.Fatalf("POST /console/login valid: %v", err)
	}
	bodyBytes, _ := io.ReadAll(loginResp.Body)
	_ = loginResp.Body.Close()
	pubTok := env.cfg.OperatorPubKeyToken()
	if loginResp.StatusCode != http.StatusOK || !strings.Contains(string(bodyBytes), pubTok) {
		t.Fatalf("expected portal HTML containing operator pubkey %s, status=%d", pubTok, loginResp.StatusCode)
	}

	// 4. Sign a user's Ed25519 public key via HTML form POST /console/sign
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	userPubToken := "sc_pub_" + hex.EncodeToString(userPub)

	signResp, err := client.PostForm(env.ts.URL+"/console/sign", url.Values{
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

	// Manually signed user must be registered in SQLite as active for auto-renewal.
	dbUser, err := env.queries.GetUserByPubkey(t.Context(), userPubToken)
	if err != nil || dbUser.Status != "active" || dbUser.UserID != "paul" {
		t.Fatalf("expected manually signed user persisted as active/paul, got user=%+v err=%v", dbUser, err)
	}

	// 5. Sign via JSON API POST /console/api/sign and verify with auth.DecodeUserCertToken + auth.VerifyUserCert
	reqBody, _ := json.Marshal(map[string]any{
		"user_pubkey":  userPubToken,
		"user_id":      "paul",
		"expires_days": 30,
	})
	apiResp, err := client.Post(env.ts.URL+"/console/api/sign", "application/json", bytes.NewReader(reqBody))
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
	if !bytes.Equal(cert.GetOperatorPubkey(), env.cfg.OperatorPubKey) {
		t.Fatalf("operator pubkey mismatch in signed cert")
	}

	// Manually signed key can immediately renew via /api/v1/renew.
	nodeAuth := buildSignedNodeAuth(t, userPub, userPriv, cert)
	rawAuth, _ := proto.Marshal(nodeAuth)
	renewPayload, _ := json.Marshal(map[string]string{
		"node_auth_proto_b64": base64.StdEncoding.EncodeToString(rawAuth),
	})
	renewResp, err := http.Post(env.ts.URL+"/api/v1/renew", "application/json", bytes.NewReader(renewPayload))
	if err != nil {
		t.Fatalf("POST /api/v1/renew: %v", err)
	}
	defer renewResp.Body.Close()
	if renewResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(renewResp.Body)
		t.Fatalf("expected 200 renew for manually signed user, got %d: %s", renewResp.StatusCode, b)
	}
}

func TestGitHubOAuthAutoApproveMatureUser(t *testing.T) {
	env := newTestEnv(t)
	userPub, _, _ := ed25519.GenerateKey(rand.Reader)
	userPubToken := "sc_pub_" + hex.EncodeToString(userPub)

	state, pollToken, authURL := env.startEnrollment(userPubToken)

	// Poll before OAuth callback -> pending; wrong bearer -> 401.
	badCode, _ := env.pollEnrollment(state, "wrong-poll-token")
	if badCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad poll token, got %d", badCode)
	}
	code, pollOut := env.pollEnrollment(state, pollToken)
	if code != http.StatusOK || pollOut["status"] != "pending" {
		t.Fatalf("expected pending before OAuth callback, got status=%d body=%+v", code, pollOut)
	}

	// Follow auth_url through mock GitHub OAuth into /auth/github/callback.
	oauthResp, err := http.Get(authURL)
	if err != nil {
		t.Fatalf("GET auth_url: %v", err)
	}
	oauthHTMLBytes, _ := io.ReadAll(oauthResp.Body)
	_ = oauthResp.Body.Close()
	if oauthResp.StatusCode != http.StatusOK || !strings.Contains(string(oauthHTMLBytes), "Enrollment Approved") {
		t.Fatalf("expected approved HTML page, status=%d body=%s", oauthResp.StatusCode, oauthHTMLBytes)
	}

	// Poll now receives signed UserCert.
	code, pollOut = env.pollEnrollment(state, pollToken)
	if code != http.StatusOK || pollOut["ok"] != true || pollOut["status"] != "approved" {
		t.Fatalf("expected approved poll result, got status=%d body=%+v", code, pollOut)
	}
	certToken, _ := pollOut["cert_token"].(string)
	cert, err := auth.DecodeUserCertToken(certToken)
	if err != nil {
		t.Fatalf("DecodeUserCertToken: %v", err)
	}
	if err := auth.VerifyUserCert(cert, userPub, uint64(time.Now().Unix())); err != nil {
		t.Fatalf("VerifyUserCert: %v", err)
	}
	if cert.GetUserId() != "gh:mature-user" {
		t.Fatalf("expected UserId gh:mature-user, got %q", cert.GetUserId())
	}
	if cert.GetExpiresAtUnixSec() <= cert.GetIssuedAtUnixSec() {
		t.Fatalf("expected non-zero expiry on issued cert")
	}
}

func TestGitHubOAuthYoungAccountManualApprovalAndPolicyToggle(t *testing.T) {
	env := newTestEnv(t)
	env.nextUser.Store(mockGHUser{
		ID:        2002,
		Login:     "young-user",
		CreatedAt: time.Now().UTC().Add(-2 * 24 * time.Hour).Format(time.RFC3339),
	})

	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	userPubToken := "sc_pub_" + hex.EncodeToString(userPub)

	state, pollToken, authURL := env.startEnrollment(userPubToken)

	oauthResp, err := http.Get(authURL)
	if err != nil {
		t.Fatalf("GET auth_url: %v", err)
	}
	oauthHTMLBytes, _ := io.ReadAll(oauthResp.Body)
	_ = oauthResp.Body.Close()
	if oauthResp.StatusCode != http.StatusOK || !strings.Contains(string(oauthHTMLBytes), "Awaiting Administrator Approval") {
		t.Fatalf("expected awaiting approval HTML, status=%d body=%s", oauthResp.StatusCode, oauthHTMLBytes)
	}

	// Poll returns awaiting_approval with no cert_token yet.
	code, pollOut := env.pollEnrollment(state, pollToken)
	if code != http.StatusOK || pollOut["status"] != "awaiting_approval" || pollOut["cert_token"] != nil {
		t.Fatalf("expected awaiting_approval, got status=%d body=%+v", code, pollOut)
	}

	// Renew while pending must return 403 status=pending.
	nodeAuth := buildSignedNodeAuth(t, userPub, userPriv, nil)
	rawAuth, _ := proto.Marshal(nodeAuth)
	renewPayload, _ := json.Marshal(map[string]string{
		"node_auth_proto_b64": base64.StdEncoding.EncodeToString(rawAuth),
	})
	pendingRenewResp, err := http.Post(env.ts.URL+"/api/v1/renew", "application/json", bytes.NewReader(renewPayload))
	if err != nil {
		t.Fatalf("renew while pending: %v", err)
	}
	var pendingRenewBody map[string]any
	_ = json.NewDecoder(pendingRenewResp.Body).Decode(&pendingRenewBody)
	_ = pendingRenewResp.Body.Close()
	if pendingRenewResp.StatusCode != http.StatusForbidden || pendingRenewBody["status"] != "pending" {
		t.Fatalf("expected 403 status=pending, got %d %+v", pendingRenewResp.StatusCode, pendingRenewBody)
	}

	// Admin approves user via /console/users/status.
	admin := env.adminClient()
	dbUser, err := env.queries.GetUserByPubkey(t.Context(), userPubToken)
	if err != nil {
		t.Fatalf("GetUserByPubkey: %v", err)
	}
	portalResp, err := admin.Get(env.ts.URL + "/console/")
	if err != nil {
		t.Fatalf("GET /console/: %v", err)
	}
	portalBytes, _ := io.ReadAll(portalResp.Body)
	_ = portalResp.Body.Close()
	if !strings.Contains(string(portalBytes), "@young-user") {
		t.Fatalf("expected @young-user listed on console portal")
	}

	approveResp, err := admin.PostForm(env.ts.URL+"/console/users/status", url.Values{
		"id":     {strconv.FormatInt(dbUser.ID, 10)},
		"status": {"active"},
	})
	if err != nil {
		t.Fatalf("POST /console/users/status: %v", err)
	}
	_ = approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after redirect from approve, got %d", approveResp.StatusCode)
	}

	// Poll now detects active status, mints UserCert, and returns approved!
	code, pollOut = env.pollEnrollment(state, pollToken)
	if code != http.StatusOK || pollOut["ok"] != true || pollOut["status"] != "approved" {
		t.Fatalf("expected approved after admin approval, got status=%d body=%+v", code, pollOut)
	}
	certToken, _ := pollOut["cert_token"].(string)
	cert, err := auth.DecodeUserCertToken(certToken)
	if err != nil {
		t.Fatalf("DecodeUserCertToken: %v", err)
	}
	if err := auth.VerifyUserCert(cert, userPub, uint64(time.Now().Unix())); err != nil {
		t.Fatalf("VerifyUserCert: %v", err)
	}

	// Admin toggles auto_approve=false via /console/settings/auto-approve; mature GitHub user now requires approval.
	toggleResp, err := admin.PostForm(env.ts.URL+"/console/settings/auto-approve", url.Values{
		"auto_approve": {"false"},
	})
	if err != nil {
		t.Fatalf("POST /console/settings/auto-approve: %v", err)
	}
	_ = toggleResp.Body.Close()

	env.nextUser.Store(mockGHUser{
		ID:        2003,
		Login:     "mature-when-disabled",
		CreatedAt: time.Now().UTC().Add(-365 * 24 * time.Hour).Format(time.RFC3339),
	})
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	state2, poll2, authURL2 := env.startEnrollment("sc_pub_" + hex.EncodeToString(pub2))
	r2, err := http.Get(authURL2)
	if err != nil {
		t.Fatalf("GET authURL2: %v", err)
	}
	_ = r2.Body.Close()
	code2, pollOut2 := env.pollEnrollment(state2, poll2)
	if code2 != http.StatusOK || pollOut2["status"] != "awaiting_approval" {
		t.Fatalf("expected awaiting_approval when auto_approve toggled off, got %d %+v", code2, pollOut2)
	}
}

func TestRenewWithExpiredUserCertAndBanEnforcement(t *testing.T) {
	env := newTestEnv(t)

	// Verify CORS preflight on OPTIONS /api/v1/renew
	optReq, _ := http.NewRequest(http.MethodOptions, env.ts.URL+"/api/v1/renew", nil)
	optResp, err := http.DefaultClient.Do(optReq)
	if err != nil {
		t.Fatalf("OPTIONS /api/v1/renew: %v", err)
	}
	_ = optResp.Body.Close()
	if optResp.StatusCode != http.StatusNoContent || optResp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("unexpected OPTIONS response: status=%d cors=%q", optResp.StatusCode, optResp.Header.Get("Access-Control-Allow-Origin"))
	}

	// Unregistered key -> 403 status=unregistered
	unregPub, unregPriv, _ := ed25519.GenerateKey(rand.Reader)
	unregAuth := buildSignedNodeAuth(t, unregPub, unregPriv, nil)
	unregRaw, _ := proto.Marshal(unregAuth)
	unregPayload, _ := json.Marshal(map[string]string{
		"node_auth_proto_b64": base64.StdEncoding.EncodeToString(unregRaw),
	})
	unregResp, err := http.Post(env.ts.URL+"/api/v1/renew", "application/json", bytes.NewReader(unregPayload))
	if err != nil {
		t.Fatalf("renew unregistered: %v", err)
	}
	var unregOut map[string]any
	_ = json.NewDecoder(unregResp.Body).Decode(&unregOut)
	_ = unregResp.Body.Close()
	if unregResp.StatusCode != http.StatusForbidden || unregOut["status"] != "unregistered" {
		t.Fatalf("expected 403 status=unregistered, got %d %+v", unregResp.StatusCode, unregOut)
	}

	// Register an active user via GitHub OAuth.
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	userPubToken := "sc_pub_" + hex.EncodeToString(userPub)
	state, pollToken, authURL := env.startEnrollment(userPubToken)
	r, err := http.Get(authURL)
	if err != nil {
		t.Fatalf("GET auth_url: %v", err)
	}
	_ = r.Body.Close()
	_, pollOut := env.pollEnrollment(state, pollToken)
	if pollOut["status"] != "approved" {
		t.Fatalf("expected approved enrollment, got %+v", pollOut)
	}

	// Construct an ALREADY-EXPIRED UserCert signed by the operator and embed it in NodeAuth!
	past := time.Now().UTC().Add(-48 * time.Hour)
	expiredCert := &sshcastv1.UserCert{
		UserId:           "gh:mature-user",
		UserPubkey:       userPub,
		IssuedAtUnixSec:  uint64(past.Add(-7 * 24 * time.Hour).Unix()),
		ExpiresAtUnixSec: uint64(past.Unix()),
	}
	if err := auth.SignUserCert(expiredCert, env.cfg.OperatorPrivKey); err != nil {
		t.Fatalf("SignUserCert expired: %v", err)
	}
	nodeAuthWithExpiredCert := buildSignedNodeAuth(t, userPub, userPriv, expiredCert)

	// Confirm direct auth.VerifyNodeAuth rejects the embedded expired cert (regression guard).
	if err := auth.VerifyNodeAuth(nodeAuthWithExpiredCert, sshcastv1.NodeRole_NODE_ROLE_UNSPECIFIED, uint64(time.Now().UnixMilli()), auth.DefaultMaxClockSkewMs); !errors.Is(err, auth.ErrUserCertExpired) {
		t.Fatalf("expected direct VerifyNodeAuth to fail with ErrUserCertExpired, got %v", err)
	}

	rawAuth, _ := proto.Marshal(nodeAuthWithExpiredCert)

	// Test both StdEncoding and RawURLEncoding, plus /console/api/v1/renew prefix.
	for _, tc := range []struct {
		endpoint string
		encoded  string
	}{
		{"/api/v1/renew", base64.StdEncoding.EncodeToString(rawAuth)},
		{"/console/api/v1/renew", base64.RawURLEncoding.EncodeToString(rawAuth)},
	} {
		payload, _ := json.Marshal(map[string]string{"node_auth_proto_b64": tc.encoded})
		resp, err := http.Post(env.ts.URL+tc.endpoint, "application/json", bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("POST %s: %v", tc.endpoint, err)
		}
		var out struct {
			OK               bool   `json:"ok"`
			CertToken        string `json:"cert_token"`
			UserID           string `json:"user_id"`
			IssuedAtUnixSec  uint64 `json:"issued_at_unix_sec"`
			ExpiresAtUnixSec uint64 `json:"expires_at_unix_sec"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode %s: %v", tc.endpoint, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("expected 200 + CORS * from %s, got %d cors=%q", tc.endpoint, resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
		}
		if !out.OK || !strings.HasPrefix(out.CertToken, "sc_cert_") || out.UserID != "gh:mature-user" {
			t.Fatalf("unexpected renew response from %s: %+v", tc.endpoint, out)
		}
		freshCert, err := auth.DecodeUserCertToken(out.CertToken)
		if err != nil {
			t.Fatalf("DecodeUserCertToken: %v", err)
		}
		if err := auth.VerifyUserCert(freshCert, userPub, uint64(time.Now().Unix())); err != nil {
			t.Fatalf("VerifyUserCert on renewed cert: %v", err)
		}
	}

	dbUser, err := env.queries.GetUserByPubkey(t.Context(), userPubToken)
	if err != nil || dbUser.LastRenewedAt == 0 {
		t.Fatalf("expected last_renewed_at updated, user=%+v err=%v", dbUser, err)
	}

	// Admin bans the user -> renew returns 403 status=banned.
	admin := env.adminClient()
	banResp, err := admin.PostForm(env.ts.URL+"/console/users/status", url.Values{
		"id":     {strconv.FormatInt(dbUser.ID, 10)},
		"status": {"banned"},
	})
	if err != nil {
		t.Fatalf("ban user: %v", err)
	}
	_ = banResp.Body.Close()

	banPayload, _ := json.Marshal(map[string]string{
		"node_auth_proto_b64": base64.StdEncoding.EncodeToString(rawAuth),
	})
	bannedRenewResp, err := http.Post(env.ts.URL+"/api/v1/renew", "application/json", bytes.NewReader(banPayload))
	if err != nil {
		t.Fatalf("renew while banned: %v", err)
	}
	var bannedOut map[string]any
	_ = json.NewDecoder(bannedRenewResp.Body).Decode(&bannedOut)
	_ = bannedRenewResp.Body.Close()
	if bannedRenewResp.StatusCode != http.StatusForbidden || bannedOut["status"] != "banned" {
		t.Fatalf("expected 403 status=banned, got %d %+v", bannedRenewResp.StatusCode, bannedOut)
	}
}

func TestBannedGitHubUserCannotBypassWithFreshKey(t *testing.T) {
	env := newTestEnv(t)
	env.nextUser.Store(mockGHUser{
		ID:        3003,
		Login:     "bad-actor",
		CreatedAt: time.Now().UTC().Add(-120 * 24 * time.Hour).Format(time.RFC3339),
	})

	// Initial enrollment with key1.
	key1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key1Token := "sc_pub_" + hex.EncodeToString(key1Pub)
	state1, poll1, authURL1 := env.startEnrollment(key1Token)
	r1, err := http.Get(authURL1)
	if err != nil {
		t.Fatalf("GET authURL1: %v", err)
	}
	_ = r1.Body.Close()
	_, out1 := env.pollEnrollment(state1, poll1)
	if out1["status"] != "approved" {
		t.Fatalf("expected initial enrollment approved, got %+v", out1)
	}

	// Admin bans bad-actor.
	admin := env.adminClient()
	dbUser, err := env.queries.GetUserByPubkey(t.Context(), key1Token)
	if err != nil {
		t.Fatalf("GetUserByPubkey: %v", err)
	}
	banResp, err := admin.PostForm(env.ts.URL+"/console/users/status", url.Values{
		"id":     {strconv.FormatInt(dbUser.ID, 10)},
		"status": {"banned"},
	})
	if err != nil {
		t.Fatalf("ban user: %v", err)
	}
	_ = banResp.Body.Close()

	// Banned GitHub user generates a brand new key2 and tries to re-enroll!
	key2Pub, key2Priv, _ := ed25519.GenerateKey(rand.Reader)
	key2Token := "sc_pub_" + hex.EncodeToString(key2Pub)
	state2, poll2, authURL2 := env.startEnrollment(key2Token)

	r2, err := http.Get(authURL2)
	if err != nil {
		t.Fatalf("GET authURL2: %v", err)
	}
	b2, _ := io.ReadAll(r2.Body)
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusForbidden || !strings.Contains(string(b2), "Account Banned") {
		t.Fatalf("expected 403 Account Banned HTML, got %d: %s", r2.StatusCode, b2)
	}

	pollCode, pollOut := env.pollEnrollment(state2, poll2)
	if pollCode != http.StatusForbidden || pollOut["status"] != "banned" {
		t.Fatalf("expected 403 status=banned on poll, got %d %+v", pollCode, pollOut)
	}

	// Confirm key2 was NOT registered and key1 stays banned.
	if _, err := env.queries.GetUserByPubkey(t.Context(), key2Token); err == nil {
		t.Fatalf("expected key2 NOT to be registered in users table")
	}
	stillBanned, err := env.queries.GetUserByPubkey(t.Context(), key1Token)
	if err != nil || stillBanned.Status != "banned" {
		t.Fatalf("expected key1 still banned, got %+v err=%v", stillBanned, err)
	}

	// Attempting to renew with key2 fails with 403 unregistered.
	key2Auth := buildSignedNodeAuth(t, key2Pub, key2Priv, nil)
	rawKey2Auth, _ := proto.Marshal(key2Auth)
	renewPayload, _ := json.Marshal(map[string]string{
		"node_auth_proto_b64": base64.StdEncoding.EncodeToString(rawKey2Auth),
	})
	renewResp, err := http.Post(env.ts.URL+"/api/v1/renew", "application/json", bytes.NewReader(renewPayload))
	if err != nil {
		t.Fatalf("renew key2: %v", err)
	}
	var renewOut map[string]any
	_ = json.NewDecoder(renewResp.Body).Decode(&renewOut)
	_ = renewResp.Body.Close()
	if renewResp.StatusCode != http.StatusForbidden || renewOut["status"] != "unregistered" {
		t.Fatalf("expected 403 unregistered for key2, got %d %+v", renewResp.StatusCode, renewOut)
	}
}
