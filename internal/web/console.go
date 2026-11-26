package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"stingr.net/go/sshcast-operator/internal/config"
	"stingr.net/go/sshcast-operator/internal/db"
	sshcastv1 "stingr.net/go/sshcast-proto/gen/go/sshcast/v1"
	"stingr.net/go/sshcast-proto/pkg/auth"
)

const (
	sessionCookieName = "sshcast_operator_session"
	sessionDuration   = 12 * time.Hour
	oauthSessionTTL   = 15 * time.Minute

	defaultGitHubOAuthBaseURL = "https://github.com"
	defaultGitHubAPIBaseURL   = "https://api.github.com"

	settingAutoApprove = "auto_approve"
)

type ConsoleServer struct {
	cfg        *config.Config
	queries    *db.Queries
	cookieKey  []byte
	loginTmpl  *template.Template
	portalTmpl *template.Template
	oauthTmpl  *template.Template
	mux        *http.ServeMux

	GitHubOAuthBaseURL string
	GitHubAPIBaseURL   string
	HTTPClient         *http.Client
}

type SignedCertResult struct {
	CertToken     string
	UserID        string
	UserPubKeyHex string
	OperatorPub   string
	IssuedAtStr   string
	ExpiresAtStr  string
}

type userRowView struct {
	ID            int64
	UserID        string
	PubKeyShort   string
	PubKeyFull    string
	GitHubDisplay string
	Status        string
	LastRenewed   string
	CreatedAt     string
}

type portalPageData struct {
	BasePath                string
	Username                string
	OperatorPubKey          string
	DefaultExpiresDays      uint64
	AutoApprove             bool
	MinGitHubAccountAgeDays uint64
	GitHubConfigured        bool
	UserPubKeyInput         string
	UserIDInput             string
	ExpiresDaysInput        string
	ErrorMsg                string
	Result                  *SignedCertResult
	Users                   []userRowView
}

type loginPageData struct {
	BasePath string
	ErrorMsg string
	NoUsers  bool
}

type oauthPageData struct {
	Title   string
	Heading string
	Message string
	IsError bool
	IsOK    bool
}

// NewConsoleServer constructs the operator web console, enrollment, and renewal HTTP handler.
func NewConsoleServer(cfg *config.Config, queries *db.Queries) *ConsoleServer {
	salt := make([]byte, 32)
	_, _ = rand.Read(salt)
	mac := hmac.New(sha256.New, salt)
	mac.Write(cfg.OperatorPrivKey)
	cookieKey := mac.Sum(nil)

	s := &ConsoleServer{
		cfg:                cfg,
		queries:            queries,
		cookieKey:          cookieKey,
		loginTmpl:          template.Must(template.New("login").Parse(loginHTML)),
		portalTmpl:         template.Must(template.New("portal").Parse(portalHTML)),
		oauthTmpl:          template.Must(template.New("oauth").Parse(oauthHTML)),
		mux:                http.NewServeMux(),
		GitHubOAuthBaseURL: defaultGitHubOAuthBaseURL,
		GitHubAPIBaseURL:   defaultGitHubAPIBaseURL,
		HTTPClient:         &http.Client{Timeout: 15 * time.Second},
	}

	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET "+cfg.BasePath+"/healthz", s.handleHealthz)

	// Support both Nginx passing /console/... intact OR Nginx stripping /console prefix.
	for _, prefix := range []string{"", cfg.BasePath} {
		s.mux.HandleFunc("GET "+prefix+"/{$}", s.handlePortal)
		s.mux.HandleFunc("GET "+prefix+"/login", s.handleLoginGet)
		s.mux.HandleFunc("POST "+prefix+"/login", s.handleLoginPost)
		s.mux.HandleFunc("POST "+prefix+"/logout", s.handleLogout)
		s.mux.HandleFunc("GET "+prefix+"/sign", s.handleSignGet)
		s.mux.HandleFunc("POST "+prefix+"/sign", s.handleSignForm)
		s.mux.HandleFunc("POST "+prefix+"/api/sign", s.handleSignAPI)
		s.mux.HandleFunc("POST "+prefix+"/settings/auto-approve", s.handleSetAutoApprove)
		s.mux.HandleFunc("POST "+prefix+"/users/status", s.handleSetUserStatus)

		s.mux.HandleFunc("POST "+prefix+"/api/v1/renew", s.handleRenew)
		s.mux.HandleFunc("OPTIONS "+prefix+"/api/v1/renew", s.handleRenewOptions)
		s.mux.HandleFunc("POST "+prefix+"/api/v1/enroll/start", s.handleEnrollStart)
		s.mux.HandleFunc("OPTIONS "+prefix+"/api/v1/enroll/start", s.handleEnrollOptions)
		s.mux.HandleFunc("GET "+prefix+"/api/v1/enroll/poll", s.handleEnrollPoll)
		s.mux.HandleFunc("OPTIONS "+prefix+"/api/v1/enroll/poll", s.handleEnrollOptions)
		s.mux.HandleFunc("GET "+prefix+"/auth/github/start", s.handleGitHubStart)
		s.mux.HandleFunc("GET "+prefix+"/auth/github/callback", s.handleGitHubCallback)
	}

	return s
}

func (s *ConsoleServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	s.mux.ServeHTTP(w, r)
}

func (s *ConsoleServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintln(w, "ok")
}

func (s *ConsoleServer) httpClient() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return http.DefaultClient
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func setCORSHeaders(w http.ResponseWriter, methods string) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", methods)
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func (s *ConsoleServer) externalBaseURL(r *http.Request) string {
	if pub := strings.TrimRight(strings.TrimSpace(s.cfg.PublicURL), "/"); pub != "" {
		return pub
	}
	scheme := "http"
	if protoHeader := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); protoHeader != "" {
		first := strings.TrimSpace(strings.Split(protoHeader, ",")[0])
		if first == "http" || first == "https" {
			scheme = first
		}
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host != "" {
		host = strings.TrimSpace(strings.Split(host, ",")[0])
	}
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

func randomHexToken(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func sha256Hex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty base64 payload")
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64 payload")
}

func (s *ConsoleServer) createSessionToken(username string, expiresAt time.Time) string {
	payload := fmt.Sprintf("%s|%d", username, expiresAt.Unix())
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, s.cookieKey)
	mac.Write([]byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payloadB64 + "." + sigB64
}

func (s *ConsoleServer) verifySessionRequest(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 {
		return "", false
	}
	payloadB64, sigB64 := parts[0], parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, s.cookieKey)
	mac.Write([]byte(payloadB64))
	if !hmac.Equal(sigBytes, mac.Sum(nil)) {
		return "", false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", false
	}
	user, expStr, ok := strings.Cut(string(payloadBytes), "|")
	if !ok || user == "" {
		return "", false
	}
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > expUnix {
		return "", false
	}
	return user, true
}

func (s *ConsoleServer) effectiveAutoApprove(ctx context.Context) bool {
	if s.queries != nil {
		if setting, err := s.queries.GetSetting(ctx, settingAutoApprove); err == nil {
			switch strings.ToLower(strings.TrimSpace(setting.Value)) {
			case "true", "1", "on":
				return true
			case "false", "0", "off":
				return false
			}
		}
	}
	return s.cfg.AutoApprove
}

func (s *ConsoleServer) githubConfigured() bool {
	return strings.TrimSpace(s.cfg.GitHubClientID) != "" && strings.TrimSpace(s.cfg.GitHubClientSecret) != ""
}

func formatPubKeyShort(pub string) string {
	if len(pub) <= 22 {
		return pub
	}
	return pub[:15] + "..." + pub[len(pub)-6:]
}

func formatUnixUTC(ts int64, zeroLabel string) string {
	if ts <= 0 {
		return zeroLabel
	}
	return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04 UTC")
}

func (s *ConsoleServer) buildPortalData(ctx context.Context, username string) portalPageData {
	data := portalPageData{
		BasePath:                s.cfg.BasePath,
		Username:                username,
		OperatorPubKey:          s.cfg.OperatorPubKeyToken(),
		DefaultExpiresDays:      s.cfg.DefaultExpiresDays,
		AutoApprove:             s.effectiveAutoApprove(ctx),
		MinGitHubAccountAgeDays: s.cfg.MinGitHubAccountAgeDays,
		GitHubConfigured:        s.githubConfigured(),
		ExpiresDaysInput:        strconv.FormatUint(s.cfg.DefaultExpiresDays, 10),
	}
	if s.queries != nil {
		if users, err := s.queries.ListUsers(ctx); err == nil {
			rows := make([]userRowView, 0, len(users))
			for _, u := range users {
				ghDisplay := "manual"
				if u.GithubLogin != "" {
					ghDisplay = "@" + u.GithubLogin
				} else if u.GithubID.Valid {
					ghDisplay = fmt.Sprintf("id:%d", u.GithubID.Int64)
				}
				rows = append(rows, userRowView{
					ID:            u.ID,
					UserID:        u.UserID,
					PubKeyShort:   formatPubKeyShort(u.UserPubkey),
					PubKeyFull:    u.UserPubkey,
					GitHubDisplay: ghDisplay,
					Status:        u.Status,
					LastRenewed:   formatUnixUTC(u.LastRenewedAt, "Never"),
					CreatedAt:     formatUnixUTC(u.CreatedAt, "-"),
				})
			}
			data.Users = rows
		}
	}
	return data
}

func (s *ConsoleServer) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.verifySessionRequest(r); ok {
		http.Redirect(w, r, s.cfg.BasePath+"/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.loginTmpl.Execute(w, loginPageData{
		BasePath: s.cfg.BasePath,
		NoUsers:  s.cfg.UserCount() == 0,
	})
}

func (s *ConsoleServer) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if !s.cfg.VerifyPassword(username, password) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_ = s.loginTmpl.Execute(w, loginPageData{
			BasePath: s.cfg.BasePath,
			ErrorMsg: "Invalid username or password.",
			NoUsers:  s.cfg.UserCount() == 0,
		})
		return
	}

	expiresAt := time.Now().Add(sessionDuration)
	token := s.createSessionToken(username, expiresAt)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
	})
	http.Redirect(w, r, s.cfg.BasePath+"/", http.StatusFound)
}

func (s *ConsoleServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.Redirect(w, r, s.cfg.BasePath+"/login", http.StatusFound)
}

func (s *ConsoleServer) handlePortal(w http.ResponseWriter, r *http.Request) {
	user, ok := s.verifySessionRequest(r)
	if !ok {
		http.Redirect(w, r, s.cfg.BasePath+"/login", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.portalTmpl.Execute(w, s.buildPortalData(r.Context(), user))
}

func (s *ConsoleServer) mintUserCert(userPub []byte, userID string, expiresDays uint64, now time.Time) (*sshcastv1.UserCert, string, error) {
	uid := strings.TrimSpace(userID)
	if uid == "" {
		uid = auth.DeriveUserID(userPub)
	}
	utcNow := now.UTC()
	nowSec := uint64(utcNow.Unix())
	var expSec uint64
	if expiresDays > 0 {
		expSec = uint64(utcNow.Add(time.Duration(expiresDays) * 24 * time.Hour).Unix())
	}
	cert := &sshcastv1.UserCert{
		UserId:           uid,
		UserPubkey:       userPub,
		IssuedAtUnixSec:  nowSec,
		ExpiresAtUnixSec: expSec,
	}
	if err := auth.SignUserCert(cert, s.cfg.OperatorPrivKey); err != nil {
		return nil, "", err
	}
	token, err := auth.EncodeUserCertToken(cert)
	if err != nil {
		return nil, "", err
	}
	return cert, token, nil
}

func (s *ConsoleServer) signKeyInternal(ctx context.Context, rawUserPub, rawUserID, rawExpiresDays string) (*SignedCertResult, error) {
	userPub, err := config.ParseUserPubKey(rawUserPub)
	if err != nil {
		return nil, err
	}
	expiresDays := s.cfg.DefaultExpiresDays
	if strings.TrimSpace(rawExpiresDays) != "" {
		parsed, err := strconv.ParseUint(strings.TrimSpace(rawExpiresDays), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid validity days %q", rawExpiresDays)
		}
		expiresDays = parsed
	}
	now := time.Now().UTC()
	cert, token, err := s.mintUserCert(userPub, rawUserID, expiresDays, now)
	if err != nil {
		return nil, err
	}
	expStr := "Never (0)"
	if expiresDays > 0 {
		expTime := now.Add(time.Duration(expiresDays) * 24 * time.Hour)
		expStr = fmt.Sprintf("%s (%d days)", expTime.Format("2006-01-02 15:04:05 UTC"), expiresDays)
	}
	canonicalPub := "sc_pub_" + hex.EncodeToString(userPub)
	if s.queries != nil {
		nowUnix := now.Unix()
		if _, err := s.queries.UpsertManualUser(ctx, db.UpsertManualUserParams{
			UserPubkey: canonicalPub,
			UserID:     cert.GetUserId(),
			Note:       "manual",
			CreatedAt:  nowUnix,
			UpdatedAt:  nowUnix,
		}); err != nil {
			return nil, fmt.Errorf("persist user in sqlite: %w", err)
		}
	}
	return &SignedCertResult{
		CertToken:     token,
		UserID:        cert.GetUserId(),
		UserPubKeyHex: canonicalPub,
		OperatorPub:   s.cfg.OperatorPubKeyToken(),
		IssuedAtStr:   now.Format("2006-01-02 15:04:05 UTC"),
		ExpiresAtStr:  expStr,
	}, nil
}

func (s *ConsoleServer) handleSignGet(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.cfg.BasePath+"/", http.StatusFound)
}

func (s *ConsoleServer) handleSignForm(w http.ResponseWriter, r *http.Request) {
	user, ok := s.verifySessionRequest(r)
	if !ok {
		http.Redirect(w, r, s.cfg.BasePath+"/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}
	pubIn := strings.TrimSpace(r.FormValue("user_pubkey"))
	uidIn := strings.TrimSpace(r.FormValue("user_id"))
	daysIn := strings.TrimSpace(r.FormValue("expires_days"))

	res, err := s.signKeyInternal(r.Context(), pubIn, uidIn, daysIn)
	data := s.buildPortalData(r.Context(), user)
	data.UserPubKeyInput = pubIn
	data.UserIDInput = uidIn
	data.ExpiresDaysInput = daysIn
	data.Result = res
	if err != nil {
		data.ErrorMsg = err.Error()
		w.WriteHeader(http.StatusBadRequest)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.portalTmpl.Execute(w, data)
}

func (s *ConsoleServer) handleSignAPI(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.verifySessionRequest(r); !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok":    false,
			"error": "unauthorized",
		})
		return
	}
	var body struct {
		UserPubkey  string `json:"user_pubkey"`
		UserID      string `json:"user_id"`
		ExpiresDays *uint64 `json:"expires_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid JSON body",
		})
		return
	}
	daysStr := ""
	if body.ExpiresDays != nil {
		daysStr = strconv.FormatUint(*body.ExpiresDays, 10)
	}
	res, err := s.signKeyInternal(r.Context(), body.UserPubkey, body.UserID, daysStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"cert_token":      res.CertToken,
		"user_id":         res.UserID,
		"user_pubkey":     res.UserPubKeyHex,
		"operator_pubkey": res.OperatorPub,
		"issued_at":       res.IssuedAtStr,
		"expires_at":      res.ExpiresAtStr,
	})
}

func (s *ConsoleServer) handleSetAutoApprove(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.verifySessionRequest(r); !ok {
		http.Redirect(w, r, s.cfg.BasePath+"/login", http.StatusFound)
		return
	}
	if s.queries == nil {
		http.Error(w, "database not initialized", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}
	raw := strings.ToLower(strings.TrimSpace(r.FormValue("auto_approve")))
	var val string
	switch raw {
	case "true", "1", "on":
		val = "true"
	case "false", "0", "off":
		val = "false"
	default:
		http.Error(w, "invalid auto_approve value", http.StatusBadRequest)
		return
	}
	if _, err := s.queries.UpsertSetting(r.Context(), db.UpsertSettingParams{
		Key:       settingAutoApprove,
		Value:     val,
		UpdatedAt: time.Now().UTC().Unix(),
	}); err != nil {
		http.Error(w, "failed to update setting", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.cfg.BasePath+"/", http.StatusSeeOther)
}

func (s *ConsoleServer) handleSetUserStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.verifySessionRequest(r); !ok {
		http.Redirect(w, r, s.cfg.BasePath+"/login", http.StatusFound)
		return
	}
	if s.queries == nil {
		http.Error(w, "database not initialized", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}
	idStr := strings.TrimSpace(r.FormValue("id"))
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	status := strings.ToLower(strings.TrimSpace(r.FormValue("status")))
	switch status {
	case "active", "banned", "pending":
	default:
		http.Error(w, "invalid user status", http.StatusBadRequest)
		return
	}
	if _, err := s.queries.SetUserStatus(r.Context(), db.SetUserStatusParams{
		Status:    status,
		UpdatedAt: time.Now().UTC().Unix(),
		ID:        id,
	}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to update user status", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.cfg.BasePath+"/", http.StatusSeeOther)
}

func (s *ConsoleServer) handleRenewOptions(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, "POST, OPTIONS")
	w.WriteHeader(http.StatusNoContent)
}

func (s *ConsoleServer) handleRenew(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, "POST, OPTIONS")
	if s.queries == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":    false,
			"error": "database not initialized",
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var body struct {
		NodeAuthProtoB64 string `json:"node_auth_proto_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid JSON body",
		})
		return
	}
	rawAuth, err := decodeBase64Flexible(body.NodeAuthProtoB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	nodeAuth := &sshcastv1.NodeAuth{}
	if err := proto.Unmarshal(rawAuth, nodeAuth); err != nil || nodeAuth.GetGrant() == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid NodeAuth protobuf",
		})
		return
	}

	// Clone NodeAuth and clear UserCert before VerifyNodeAuth because
	// CanonicalNodeGrantBytes and CanonicalNodeAuthBytes do not cover UserCert,
	// and an expired embedded UserCert must still be renewable.
	clonedAuth := proto.Clone(nodeAuth).(*sshcastv1.NodeAuth)
	if clonedAuth.GetGrant() != nil {
		clonedAuth.Grant.UserCert = nil
	}
	now := time.Now().UTC()
	nowMs := uint64(now.UnixMilli())
	if err := auth.VerifyNodeAuth(clonedAuth, sshcastv1.NodeRole_NODE_ROLE_UNSPECIFIED, nowMs, auth.DefaultMaxClockSkewMs); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok":    false,
			"error": fmt.Sprintf("node auth verification failed: %v", err),
		})
		return
	}

	userPubBytes := clonedAuth.GetGrant().GetUserPubkey()
	userPubHex := "sc_pub_" + hex.EncodeToString(userPubBytes)

	user, err := s.queries.GetUserByPubkey(r.Context(), userPubHex)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"ok":     false,
				"status": "unregistered",
				"error":  "user public key is not registered",
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "failed to query user",
		})
		return
	}

	if user.Status != "active" {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":     false,
			"status": user.Status,
			"error":  fmt.Sprintf("user status is %s", user.Status),
		})
		return
	}

	cert, certToken, err := s.mintUserCert(userPubBytes, user.UserID, s.cfg.DefaultExpiresDays, now)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "failed to mint certificate",
		})
		return
	}

	nowUnix := now.Unix()
	if err := s.queries.TouchUserRenewed(r.Context(), db.TouchUserRenewedParams{
		LastRenewedAt: nowUnix,
		UpdatedAt:     nowUnix,
		ID:            user.ID,
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "failed to update renewal timestamp",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                  true,
		"cert_token":          certToken,
		"user_id":             cert.GetUserId(),
		"issued_at_unix_sec":  cert.GetIssuedAtUnixSec(),
		"expires_at_unix_sec": cert.GetExpiresAtUnixSec(),
	})
}

func (s *ConsoleServer) handleEnrollOptions(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, "GET, POST, OPTIONS")
	w.WriteHeader(http.StatusNoContent)
}

func (s *ConsoleServer) handleEnrollStart(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, "GET, POST, OPTIONS")
	if s.queries == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":    false,
			"error": "database not initialized",
		})
		return
	}
	if !s.githubConfigured() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":    false,
			"error": "GitHub OAuth is not configured on this operator",
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var body struct {
		UserPubkey string `json:"user_pubkey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid JSON body",
		})
		return
	}
	userPub, err := config.ParseUserPubKey(body.UserPubkey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	canonicalPub := "sc_pub_" + hex.EncodeToString(userPub)

	state, err := randomHexToken(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "failed to generate state",
		})
		return
	}
	pollToken, err := randomHexToken(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "failed to generate poll token",
		})
		return
	}

	now := time.Now().UTC()
	if _, err := s.queries.CreateOAuthSession(r.Context(), db.CreateOAuthSessionParams{
		State:         state,
		UserPubkey:    canonicalPub,
		PollTokenHash: sha256Hex(pollToken),
		Status:        "pending",
		CertToken:     "",
		ErrorMsg:      "",
		ExpiresAt:     now.Add(oauthSessionTTL).Unix(),
		CreatedAt:     now.Unix(),
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "failed to create enrollment session",
		})
		return
	}
	_ = s.queries.DeleteExpiredOAuthSessions(r.Context(), now.Unix())

	authURL := s.externalBaseURL(r) + "/auth/github/start?state=" + url.QueryEscape(state)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"state":      state,
		"poll_token": pollToken,
		"auth_url":   authURL,
	})
}

func (s *ConsoleServer) renderOAuthPage(w http.ResponseWriter, statusCode int, data oauthPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = s.oauthTmpl.Execute(w, data)
}

func (s *ConsoleServer) handleGitHubStart(w http.ResponseWriter, r *http.Request) {
	if s.queries == nil || !s.githubConfigured() {
		s.renderOAuthPage(w, http.StatusServiceUnavailable, oauthPageData{
			Title:   "OAuth Unavailable",
			Heading: "GitHub Enrollment Unavailable",
			Message: "GitHub OAuth is not configured on this operator.",
			IsError: true,
		})
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if state == "" {
		s.renderOAuthPage(w, http.StatusBadRequest, oauthPageData{
			Title:   "Invalid Request",
			Heading: "Missing Enrollment State",
			Message: "No enrollment state parameter was provided.",
			IsError: true,
		})
		return
	}

	sess, err := s.queries.GetOAuthSession(r.Context(), state)
	if err != nil {
		s.renderOAuthPage(w, http.StatusNotFound, oauthPageData{
			Title:   "Unknown Session",
			Heading: "Invalid Enrollment Session",
			Message: "The enrollment session was not found. Please start again from your CLI.",
			IsError: true,
		})
		return
	}
	if time.Now().UTC().Unix() > sess.ExpiresAt {
		s.renderOAuthPage(w, http.StatusGone, oauthPageData{
			Title:   "Session Expired",
			Heading: "Enrollment Session Expired",
			Message: "This enrollment link has expired. Please start again from your CLI.",
			IsError: true,
		})
		return
	}
	if sess.Status != "pending" {
		s.renderOAuthPage(w, http.StatusConflict, oauthPageData{
			Title:   "Session Completed",
			Heading: "Enrollment Session Already Used",
			Message: "This enrollment link has already been processed.",
			IsError: true,
		})
		return
	}

	oauthBase := strings.TrimRight(s.GitHubOAuthBaseURL, "/")
	callbackURL := s.externalBaseURL(r) + "/auth/github/callback"
	q := url.Values{}
	q.Set("client_id", s.cfg.GitHubClientID)
	q.Set("redirect_uri", callbackURL)
	q.Set("state", state)
	q.Set("scope", "read:user")
	http.Redirect(w, r, oauthBase+"/login/oauth/authorize?"+q.Encode(), http.StatusFound)
}

type githubAccessTokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type githubUserProfile struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	CreatedAt string `json:"created_at"`
}

func (s *ConsoleServer) exchangeGitHubCode(ctx context.Context, code, state, redirectURI string) (string, error) {
	oauthBase := strings.TrimRight(s.GitHubOAuthBaseURL, "/")
	form := url.Values{}
	form.Set("client_id", s.cfg.GitHubClientID)
	form.Set("client_secret", s.cfg.GitHubClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("state", state)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthBase+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sshcast-operator")

	resp, err := s.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub token endpoint returned status %d", resp.StatusCode)
	}
	var tok githubAccessTokenResponse
	if err := json.Unmarshal(bodyBytes, &tok); err != nil {
		return "", fmt.Errorf("parse GitHub token response: %w", err)
	}
	if tok.AccessToken == "" {
		msg := tok.ErrorDescription
		if msg == "" {
			msg = tok.Error
		}
		if msg == "" {
			msg = "missing access_token"
		}
		return "", fmt.Errorf("GitHub OAuth error: %s", msg)
	}
	return tok.AccessToken, nil
}

func (s *ConsoleServer) fetchGitHubUser(ctx context.Context, accessToken string) (*githubUserProfile, error) {
	apiBase := strings.TrimRight(s.GitHubAPIBaseURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "sshcast-operator")

	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub user endpoint returned status %d", resp.StatusCode)
	}
	var profile githubUserProfile
	if err := json.Unmarshal(bodyBytes, &profile); err != nil {
		return nil, fmt.Errorf("parse GitHub user response: %w", err)
	}
	if profile.ID <= 0 {
		return nil, errors.New("GitHub user profile missing numeric id")
	}
	return &profile, nil
}

func (s *ConsoleServer) failOAuthSession(ctx context.Context, w http.ResponseWriter, state, sessStatus, heading, message string, httpStatus int) {
	if s.queries != nil && state != "" {
		_, _ = s.queries.UpdateOAuthSession(ctx, db.UpdateOAuthSessionParams{
			Status:    sessStatus,
			CertToken: "",
			ErrorMsg:  message,
			State:     state,
		})
	}
	s.renderOAuthPage(w, httpStatus, oauthPageData{
		Title:   heading,
		Heading: heading,
		Message: message,
		IsError: true,
	})
}

func (s *ConsoleServer) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if s.queries == nil || !s.githubConfigured() {
		s.renderOAuthPage(w, http.StatusServiceUnavailable, oauthPageData{
			Title:   "OAuth Unavailable",
			Heading: "GitHub Enrollment Unavailable",
			Message: "GitHub OAuth is not configured on this operator.",
			IsError: true,
		})
		return
	}

	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if state == "" {
		s.renderOAuthPage(w, http.StatusBadRequest, oauthPageData{
			Title:   "Invalid Callback",
			Heading: "Missing Enrollment State",
			Message: "No enrollment state parameter was provided.",
			IsError: true,
		})
		return
	}

	sess, err := s.queries.GetOAuthSession(ctx, state)
	if err != nil {
		s.renderOAuthPage(w, http.StatusNotFound, oauthPageData{
			Title:   "Unknown Session",
			Heading: "Invalid Enrollment Session",
			Message: "The enrollment session was not found. Please restart enrollment from your CLI.",
			IsError: true,
		})
		return
	}

	now := time.Now().UTC()
	if now.Unix() > sess.ExpiresAt {
		s.renderOAuthPage(w, http.StatusGone, oauthPageData{
			Title:   "Session Expired",
			Heading: "Enrollment Session Expired",
			Message: "This enrollment session has expired. Please restart enrollment from your CLI.",
			IsError: true,
		})
		return
	}

	if sess.Status != "pending" {
		switch sess.Status {
		case "approved":
			s.renderOAuthPage(w, http.StatusOK, oauthPageData{
				Title:   "Enrollment Approved",
				Heading: "Enrollment Approved",
				Message: "Your key has been approved. You may close this tab and return to your terminal.",
				IsOK:    true,
			})
		case "awaiting_approval":
			s.renderOAuthPage(w, http.StatusOK, oauthPageData{
				Title:   "Awaiting Approval",
				Heading: "Awaiting Administrator Approval",
				Message: "Your enrollment is pending administrator approval. Keep your CLI running to receive your certificate automatically.",
			})
		case "banned":
			s.renderOAuthPage(w, http.StatusForbidden, oauthPageData{
				Title:   "Access Denied",
				Heading: "Account Banned",
				Message: "Your account is banned from this operator.",
				IsError: true,
			})
		default:
			s.renderOAuthPage(w, http.StatusBadRequest, oauthPageData{
				Title:   "Enrollment Failed",
				Heading: "Enrollment Failed",
				Message: sess.ErrorMsg,
				IsError: true,
			})
		}
		return
	}

	if ghErr := strings.TrimSpace(r.URL.Query().Get("error")); ghErr != "" {
		desc := strings.TrimSpace(r.URL.Query().Get("error_description"))
		if desc == "" {
			desc = ghErr
		}
		s.failOAuthSession(ctx, w, state, "error", "GitHub Authorization Cancelled", desc, http.StatusBadRequest)
		return
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		s.failOAuthSession(ctx, w, state, "error", "Invalid Callback", "Missing GitHub authorization code.", http.StatusBadRequest)
		return
	}

	callbackURL := s.externalBaseURL(r) + "/auth/github/callback"
	accessToken, err := s.exchangeGitHubCode(ctx, code, state, callbackURL)
	if err != nil {
		s.failOAuthSession(ctx, w, state, "error", "GitHub Token Exchange Failed", err.Error(), http.StatusBadGateway)
		return
	}

	ghUser, err := s.fetchGitHubUser(ctx, accessToken)
	if err != nil {
		s.failOAuthSession(ctx, w, state, "error", "GitHub Profile Lookup Failed", err.Error(), http.StatusBadGateway)
		return
	}

	userPubBytes, err := config.ParseUserPubKey(sess.UserPubkey)
	if err != nil {
		s.failOAuthSession(ctx, w, state, "error", "Invalid Public Key", err.Error(), http.StatusBadRequest)
		return
	}

	existingUser, err := s.queries.GetUserByGitHubID(ctx, sql.NullInt64{Int64: ghUser.ID, Valid: true})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.failOAuthSession(ctx, w, state, "error", "Database Error", "Failed to look up user account.", http.StatusInternalServerError)
		return
	}

	if err == nil {
		if existingUser.Status == "banned" {
			s.failOAuthSession(ctx, w, state, "banned", "Account Banned", "Your GitHub account is banned from this operator.", http.StatusForbidden)
			return
		}

		updatedUser, err := s.queries.UpdateUserPubkeyAndLogin(ctx, db.UpdateUserPubkeyAndLoginParams{
			UserPubkey:  sess.UserPubkey,
			GithubLogin: ghUser.Login,
			UpdatedAt:   now.Unix(),
			ID:          existingUser.ID,
		})
		if err != nil {
			s.failOAuthSession(ctx, w, state, "error", "Public Key Conflict", "Failed to update your registered public key.", http.StatusConflict)
			return
		}

		if updatedUser.Status == "active" {
			_, certToken, err := s.mintUserCert(userPubBytes, updatedUser.UserID, s.cfg.DefaultExpiresDays, now)
			if err != nil {
				s.failOAuthSession(ctx, w, state, "error", "Signing Error", "Failed to sign user certificate.", http.StatusInternalServerError)
				return
			}
			_, _ = s.queries.UpdateOAuthSession(ctx, db.UpdateOAuthSessionParams{
				Status:    "approved",
				CertToken: certToken,
				ErrorMsg:  "",
				State:     state,
			})
			s.renderOAuthPage(w, http.StatusOK, oauthPageData{
				Title:   "Enrollment Approved",
				Heading: "Enrollment Approved",
				Message: fmt.Sprintf("Authenticated as @%s. Your SSHcast certificate has been issued; you may close this window and return to your terminal.", ghUser.Login),
				IsOK:    true,
			})
			return
		}

		_, _ = s.queries.UpdateOAuthSession(ctx, db.UpdateOAuthSessionParams{
			Status:    "awaiting_approval",
			CertToken: "",
			ErrorMsg:  "",
			State:     state,
		})
		s.renderOAuthPage(w, http.StatusOK, oauthPageData{
			Title:   "Awaiting Approval",
			Heading: "Awaiting Administrator Approval",
			Message: fmt.Sprintf("Authenticated as @%s. Your account is pending administrator approval; keep your CLI running to receive your certificate automatically.", ghUser.Login),
		})
		return
	}

	// New GitHub user: defend against banned/conflicting pubkey rows as well.
	if existingByPub, pubErr := s.queries.GetUserByPubkey(ctx, sess.UserPubkey); pubErr == nil {
		if existingByPub.Status == "banned" {
			s.failOAuthSession(ctx, w, state, "banned", "Key Banned", "This public key is banned from this operator.", http.StatusForbidden)
			return
		}
		s.failOAuthSession(ctx, w, state, "error", "Public Key Conflict", "This public key is already registered to another user.", http.StatusConflict)
		return
	} else if !errors.Is(pubErr, sql.ErrNoRows) {
		s.failOAuthSession(ctx, w, state, "error", "Database Error", "Failed to verify public key uniqueness.", http.StatusInternalServerError)
		return
	}

	createdAt, parseErr := time.Parse(time.RFC3339, ghUser.CreatedAt)
	var ghCreatedUnix int64
	if parseErr == nil {
		ghCreatedUnix = createdAt.Unix()
	}

	minAge := time.Duration(s.cfg.MinGitHubAccountAgeDays) * 24 * time.Hour
	mature := parseErr == nil && now.Sub(createdAt) >= minAge
	autoApprove := s.effectiveAutoApprove(ctx)

	userStatus := "pending"
	if autoApprove && mature {
		userStatus = "active"
	}

	userID := "gh:" + ghUser.Login
	if strings.TrimSpace(ghUser.Login) == "" {
		userID = fmt.Sprintf("gh:%d", ghUser.ID)
	}

	inserted, err := s.queries.InsertUser(ctx, db.InsertUserParams{
		UserPubkey:      sess.UserPubkey,
		UserID:          userID,
		GithubID:        sql.NullInt64{Int64: ghUser.ID, Valid: true},
		GithubLogin:     ghUser.Login,
		GithubCreatedAt: ghCreatedUnix,
		Status:          userStatus,
		Note:            "github_oauth",
		CreatedAt:       now.Unix(),
		UpdatedAt:       now.Unix(),
		LastRenewedAt:   0,
	})
	if err != nil {
		s.failOAuthSession(ctx, w, state, "error", "Registration Failed", "Failed to save user registration.", http.StatusInternalServerError)
		return
	}

	if inserted.Status == "active" {
		_, certToken, err := s.mintUserCert(userPubBytes, inserted.UserID, s.cfg.DefaultExpiresDays, now)
		if err != nil {
			s.failOAuthSession(ctx, w, state, "error", "Signing Error", "Failed to sign user certificate.", http.StatusInternalServerError)
			return
		}
		_, _ = s.queries.UpdateOAuthSession(ctx, db.UpdateOAuthSessionParams{
			Status:    "approved",
			CertToken: certToken,
			ErrorMsg:  "",
			State:     state,
		})
		s.renderOAuthPage(w, http.StatusOK, oauthPageData{
			Title:   "Enrollment Approved",
			Heading: "Enrollment Approved",
			Message: fmt.Sprintf("Welcome @%s! Your SSHcast certificate has been issued; you may close this window and return to your terminal.", ghUser.Login),
			IsOK:    true,
		})
		return
	}

	_, _ = s.queries.UpdateOAuthSession(ctx, db.UpdateOAuthSessionParams{
		Status:    "awaiting_approval",
		CertToken: "",
		ErrorMsg:  "",
		State:     state,
	})
	s.renderOAuthPage(w, http.StatusOK, oauthPageData{
		Title:   "Awaiting Approval",
		Heading: "Awaiting Administrator Approval",
		Message: fmt.Sprintf("Authenticated as @%s. Your enrollment requires administrator approval; keep your CLI running to receive your certificate automatically.", ghUser.Login),
	})
}

func extractBearerToken(r *http.Request) string {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authz) < 7 || !strings.EqualFold(authz[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(authz[7:])
}

func (s *ConsoleServer) handleEnrollPoll(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, "GET, POST, OPTIONS")
	if s.queries == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":    false,
			"error": "database not initialized",
		})
		return
	}

	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if state == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "missing state",
		})
		return
	}
	pollToken := extractBearerToken(r)
	if pollToken == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok":    false,
			"error": "missing bearer token",
		})
		return
	}

	ctx := r.Context()
	sess, err := s.queries.GetOAuthSession(ctx, state)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]any{
				"ok":     false,
				"status": "not_found",
				"error":  "enrollment session not found",
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "failed to query enrollment session",
		})
		return
	}

	gotHash := sha256Hex(pollToken)
	if subtle.ConstantTimeCompare([]byte(gotHash), []byte(sess.PollTokenHash)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok":    false,
			"error": "invalid poll token",
		})
		return
	}

	now := time.Now().UTC()
	if now.Unix() > sess.ExpiresAt {
		_ = s.queries.DeleteExpiredOAuthSessions(ctx, now.Unix())
		writeJSON(w, http.StatusGone, map[string]any{
			"ok":     false,
			"status": "expired",
			"error":  "enrollment session expired",
		})
		return
	}

	switch sess.Status {
	case "approved":
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         true,
			"status":     "approved",
			"cert_token": sess.CertToken,
		})
	case "awaiting_approval":
		user, err := s.queries.GetUserByPubkey(ctx, sess.UserPubkey)
		if err == nil {
			switch user.Status {
			case "active":
				userPubBytes, pubErr := config.ParseUserPubKey(user.UserPubkey)
				if pubErr != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]any{
						"ok":    false,
						"error": "stored user pubkey is invalid",
					})
					return
				}
				_, certToken, signErr := s.mintUserCert(userPubBytes, user.UserID, s.cfg.DefaultExpiresDays, now)
				if signErr != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]any{
						"ok":    false,
						"error": "failed to sign user certificate",
					})
					return
				}
				_, _ = s.queries.UpdateOAuthSession(ctx, db.UpdateOAuthSessionParams{
					Status:    "approved",
					CertToken: certToken,
					ErrorMsg:  "",
					State:     state,
				})
				writeJSON(w, http.StatusOK, map[string]any{
					"ok":         true,
					"status":     "approved",
					"cert_token": certToken,
				})
				return
			case "banned":
				_, _ = s.queries.UpdateOAuthSession(ctx, db.UpdateOAuthSessionParams{
					Status:    "banned",
					CertToken: "",
					ErrorMsg:  "user account is banned",
					State:     state,
				})
				writeJSON(w, http.StatusForbidden, map[string]any{
					"ok":     false,
					"status": "banned",
					"error":  "user account is banned",
				})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"status": "awaiting_approval",
		})
	case "banned":
		msg := sess.ErrorMsg
		if msg == "" {
			msg = "user account is banned"
		}
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":     false,
			"status": "banned",
			"error":  msg,
		})
	case "error":
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":     false,
			"status": "error",
			"error":  sess.ErrorMsg,
		})
	default:
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"status": "pending",
		})
	}
}

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sshcast Operator Console — Sign In</title>
  <style>
    :root {
      --bg: #0b0f17;
      --card: #131b2e;
      --border: #23304d;
      --text: #e6edf3;
      --muted: #8b949e;
      --accent: #3b82f6;
      --accent-hover: #2563eb;
      --danger: #ef4444;
      --warn: #f59e0b;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      display: flex;
      min-height: 100vh;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      width: 100%;
      max-width: 420px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 28px;
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45);
    }
    h1 {
      margin: 0 0 6px;
      font-size: 20px;
      font-weight: 600;
    }
    .sub {
      color: var(--muted);
      font-size: 13px;
      margin-bottom: 22px;
    }
    label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      margin-bottom: 6px;
      color: var(--text);
    }
    input {
      width: 100%;
      padding: 10px 12px;
      margin-bottom: 16px;
      background: #0d1322;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-size: 14px;
    }
    input:focus {
      outline: none;
      border-color: var(--accent);
    }
    button {
      width: 100%;
      padding: 10px 14px;
      background: var(--accent);
      color: #fff;
      font-weight: 600;
      font-size: 14px;
      border: none;
      border-radius: 6px;
      cursor: pointer;
    }
    button:hover { background: var(--accent-hover); }
    .alert-err {
      background: rgba(239, 68, 68, 0.14);
      border: 1px solid var(--danger);
      color: #fca5a5;
      padding: 10px 12px;
      border-radius: 6px;
      font-size: 13px;
      margin-bottom: 16px;
    }
    .alert-warn {
      background: rgba(245, 158, 11, 0.14);
      border: 1px solid var(--warn);
      color: #fde68a;
      padding: 10px 12px;
      border-radius: 6px;
      font-size: 12px;
      margin-bottom: 16px;
    }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>Sshcast Operator Console</h1>
    <div class="sub">User Key Signing &amp; Swarm Authority</div>
    {{if .ErrorMsg}}
      <div class="alert-err">{{.ErrorMsg}}</div>
    {{end}}
    {{if .NoUsers}}
      <div class="alert-warn">
        No admin users are configured in <code>/etc/sshcast/operator.toml</code> yet.<br/>
        Run <code>sshcast-operator --hash-password 'yourpass'</code> and add a <code>[[users]]</code> entry.
      </div>
    {{end}}
    <form method="POST" action="{{.BasePath}}/login">
      <label for="username">Username</label>
      <input id="username" name="username" type="text" autocomplete="username" required autofocus />
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required />
      <button type="submit">Sign In</button>
    </form>
  </div>
</body>
</html>
`

const oauthHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sshcast Enrollment — {{.Title}}</title>
  <style>
    :root {
      --bg: #0b0f17;
      --card: #131b2e;
      --border: #23304d;
      --text: #e6edf3;
      --muted: #8b949e;
      --ok: #10b981;
      --danger: #ef4444;
      --warn: #f59e0b;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      display: flex;
      min-height: 100vh;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      width: 100%;
      max-width: 480px;
      background: var(--card);
      border: 1px solid {{if .IsError}}var(--danger){{else if .IsOK}}var(--ok){{else}}var(--warn){{end}};
      border-radius: 12px;
      padding: 28px;
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45);
    }
    h1 {
      margin: 0 0 10px;
      font-size: 20px;
      font-weight: 600;
    }
    p {
      margin: 0;
      color: var(--muted);
      font-size: 14px;
      line-height: 1.55;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>{{.Heading}}</h1>
    <p>{{.Message}}</p>
  </div>
</body>
</html>
`

const portalHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sshcast Operator Console</title>
  <style>
    :root {
      --bg: #0b0f17;
      --card: #131b2e;
      --border: #23304d;
      --text: #e6edf3;
      --muted: #8b949e;
      --accent: #3b82f6;
      --accent-hover: #2563eb;
      --ok: #10b981;
      --warn: #f59e0b;
      --danger: #ef4444;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 24px 16px 60px;
    }
    .container {
      max-width: 980px;
      margin: 0 auto;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    header h1 {
      margin: 0;
      font-size: 20px;
      font-weight: 600;
    }
    .header-right {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 13px;
      color: var(--muted);
    }
    .btn-secondary {
      background: #1e293b;
      color: var(--text);
      border: 1px solid var(--border);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 12px;
      cursor: pointer;
    }
    .btn-secondary:hover { background: #334155; }
    .btn-ok {
      background: rgba(16, 185, 129, 0.16);
      color: #6ee7b7;
      border: 1px solid var(--ok);
      padding: 5px 10px;
      border-radius: 6px;
      font-size: 12px;
      cursor: pointer;
    }
    .btn-ok:hover { background: rgba(16, 185, 129, 0.28); }
    .btn-danger {
      background: rgba(239, 68, 68, 0.16);
      color: #fca5a5;
      border: 1px solid var(--danger);
      padding: 5px 10px;
      border-radius: 6px;
      font-size: 12px;
      cursor: pointer;
    }
    .btn-danger:hover { background: rgba(239, 68, 68, 0.28); }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 22px;
      margin-bottom: 20px;
    }
    .card h2 {
      margin: 0 0 8px;
      font-size: 16px;
      font-weight: 600;
    }
    .card p {
      margin: 0 0 14px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }
    label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      margin-bottom: 6px;
    }
    input[type="text"], input[type="number"] {
      width: 100%;
      padding: 10px 12px;
      margin-bottom: 14px;
      background: #0d1322;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-size: 13px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    input:focus {
      outline: none;
      border-color: var(--accent);
    }
    .row {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 14px;
    }
    .policy-row {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .policy-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      font-size: 13px;
      color: var(--muted);
    }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .badge-active { background: rgba(16, 185, 129, 0.16); color: #6ee7b7; border: 1px solid var(--ok); }
    .badge-pending { background: rgba(245, 158, 11, 0.16); color: #fde68a; border: 1px solid var(--warn); }
    .badge-banned { background: rgba(239, 68, 68, 0.16); color: #fca5a5; border: 1px solid var(--danger); }
    .btn-primary {
      background: var(--accent);
      color: #fff;
      border: none;
      padding: 10px 18px;
      border-radius: 6px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
    }
    .btn-primary:hover { background: var(--accent-hover); }
    .code-box {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 12px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      overflow-x: auto;
      word-break: break-all;
      margin-bottom: 10px;
    }
    .alert-err {
      background: rgba(239, 68, 68, 0.14);
      border: 1px solid var(--danger);
      color: #fca5a5;
      padding: 10px 12px;
      border-radius: 6px;
      font-size: 13px;
      margin-bottom: 16px;
    }
    .card-ok {
      border-color: var(--ok);
    }
    .meta-grid {
      display: grid;
      grid-template-columns: 140px 1fr;
      row-gap: 6px;
      font-size: 13px;
      margin-bottom: 14px;
    }
    .meta-label { color: var(--muted); }
    .meta-val {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      word-break: break-all;
    }
    .table-wrap { overflow-x: auto; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      text-align: left;
      padding: 10px 8px;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }
    th {
      color: var(--muted);
      font-weight: 500;
      font-size: 12px;
    }
    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
    }
    .actions {
      display: flex;
      gap: 6px;
      align-items: center;
    }
    .actions form { margin: 0; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>Sshcast Operator Console</h1>
      </div>
      <div class="header-right">
        <span>Signed in as <strong>{{.Username}}</strong></span>
        <form method="POST" action="{{.BasePath}}/logout" style="margin:0;">
          <button type="submit" class="btn-secondary">Sign Out</button>
        </form>
      </div>
    </header>

    <div class="card">
      <h2>Enrollment Policy</h2>
      <div class="policy-row">
        <div class="policy-meta">
          <span>Auto-Approve:
            {{if .AutoApprove}}
              <span class="badge badge-active">Enabled</span>
            {{else}}
              <span class="badge badge-pending">Disabled</span>
            {{end}}
          </span>
          <span>Min GitHub Age: <strong>{{.MinGitHubAccountAgeDays}}d</strong></span>
          <span>Cert Validity: <strong>{{.DefaultExpiresDays}}d</strong></span>
          <span>GitHub OAuth: <strong>{{if .GitHubConfigured}}Configured{{else}}Not Configured{{end}}</strong></span>
        </div>
        <form method="POST" action="{{.BasePath}}/settings/auto-approve" style="margin:0;">
          <input type="hidden" name="auto_approve" value="{{if .AutoApprove}}false{{else}}true{{end}}" />
          <button type="submit" class="btn-secondary">{{if .AutoApprove}}Disable Auto-Approve{{else}}Enable Auto-Approve{{end}}</button>
        </form>
      </div>
    </div>

    <div class="card">
      <h2>Sign User Key</h2>
      <p>
        Paste a user's Ed25519 root public key (<code>sc_pub_...</code> from <code>sshcast-client keygen</code>)
        to mint an operator-signed <code>UserCert</code> (<code>sc_cert_...</code>) and register the key as active for renewal.
      </p>
      {{if .ErrorMsg}}
        <div class="alert-err">{{.ErrorMsg}}</div>
      {{end}}
      <form method="POST" action="{{.BasePath}}/sign">
        <label for="user_pubkey">User Root Public Key (<code>sc_pub_...</code> or 64-char hex)</label>
        <input id="user_pubkey" name="user_pubkey" type="text" placeholder="sc_pub_..." value="{{.UserPubKeyInput}}" required autofocus />
        <div class="row">
          <div>
            <label for="user_id">User ID / Label (optional — defaults to <code>sc_u_&lt;keyprefix&gt;</code>)</label>
            <input id="user_id" name="user_id" type="text" placeholder="e.g. alice" value="{{.UserIDInput}}" />
          </div>
          <div>
            <label for="expires_days">Validity (Days, 0 = never expires)</label>
            <input id="expires_days" name="expires_days" type="number" min="0" value="{{.ExpiresDaysInput}}" />
          </div>
        </div>
        <button type="submit" class="btn-primary">Sign User Key</button>
      </form>
    </div>

    {{if .Result}}
    <div class="card card-ok">
      <h2>Signed User Certificate (<code>sc_cert_...</code>)</h2>
      <div class="meta-grid">
        <div class="meta-label">User ID:</div>
        <div class="meta-val">{{.Result.UserID}}</div>
        <div class="meta-label">User Public Key:</div>
        <div class="meta-val">{{.Result.UserPubKeyHex}}</div>
        <div class="meta-label">Issued At:</div>
        <div class="meta-val">{{.Result.IssuedAtStr}}</div>
        <div class="meta-label">Expires At:</div>
        <div class="meta-val">{{.Result.ExpiresAtStr}}</div>
      </div>

      <label>Certificate Token</label>
      <div class="code-box">
        <span id="cert-token">{{.Result.CertToken}}</span>
        <button type="button" class="btn-secondary" onclick="copyText('cert-token', this)">Copy</button>
      </div>

      <label>Import on User Workstation (<code>sshcast-client</code>)</label>
      <div class="code-box">
        <span id="cmd-client">sshcast-client import-cert --cert {{.Result.CertToken}}</span>
        <button type="button" class="btn-secondary" onclick="copyText('cmd-client', this)">Copy</button>
      </div>
    </div>
    {{end}}

    <div class="card">
      <h2>Registered Users</h2>
      {{if .Users}}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>User ID</th>
              <th>GitHub</th>
              <th>Public Key</th>
              <th>Status</th>
              <th>Last Renewed</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {{range .Users}}
            <tr>
              <td><strong>{{.UserID}}</strong></td>
              <td>{{.GitHubDisplay}}</td>
              <td class="mono" title="{{.PubKeyFull}}">{{.PubKeyShort}}</td>
              <td><span class="badge badge-{{.Status}}">{{.Status}}</span></td>
              <td>{{.LastRenewed}}</td>
              <td>
                <div class="actions">
                  {{if eq .Status "pending"}}
                    <form method="POST" action="{{$.BasePath}}/users/status">
                      <input type="hidden" name="id" value="{{.ID}}" />
                      <input type="hidden" name="status" value="active" />
                      <button type="submit" class="btn-ok">Approve</button>
                    </form>
                    <form method="POST" action="{{$.BasePath}}/users/status">
                      <input type="hidden" name="id" value="{{.ID}}" />
                      <input type="hidden" name="status" value="banned" />
                      <button type="submit" class="btn-danger">Ban</button>
                    </form>
                  {{else if eq .Status "active"}}
                    <form method="POST" action="{{$.BasePath}}/users/status">
                      <input type="hidden" name="id" value="{{.ID}}" />
                      <input type="hidden" name="status" value="banned" />
                      <button type="submit" class="btn-danger">Ban</button>
                    </form>
                  {{else if eq .Status "banned"}}
                    <form method="POST" action="{{$.BasePath}}/users/status">
                      <input type="hidden" name="id" value="{{.ID}}" />
                      <input type="hidden" name="status" value="active" />
                      <button type="submit" class="btn-ok">Unban</button>
                    </form>
                  {{end}}
                </div>
              </td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </div>
      {{else}}
      <p>No registered users yet.</p>
      {{end}}
    </div>

    <div class="card">
      <h2>Operator Public Key</h2>
      <p>
        Configure this public key in <code>/etc/sshcast/server.toml</code> under <code>trusted_operator_pubkeys</code>
        on each coordinator server in your swarm:
      </p>
      <div class="code-box">
        <span id="op-pubkey">{{.OperatorPubKey}}</span>
        <button type="button" class="btn-secondary" onclick="copyText('op-pubkey', this)">Copy</button>
      </div>
    </div>
  </div>

  <script>
    function copyText(id, btn) {
      const el = document.getElementById(id);
      if (!el) return;
      navigator.clipboard.writeText(el.textContent.trim()).then(() => {
        const prev = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = prev; }, 1400);
      });
    }
  </script>
</body>
</html>
`
