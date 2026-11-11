package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"stingr.net/go/sshcast-operator/internal/config"
	sshcastv1 "stingr.net/go/sshcast-proto/gen/go/sshcast/v1"
	"stingr.net/go/sshcast-proto/pkg/auth"
)

const (
	sessionCookieName = "sshcast_operator_session"
	sessionDuration   = 12 * time.Hour
)

type ConsoleServer struct {
	cfg        *config.Config
	cookieKey  []byte
	loginTmpl  *template.Template
	portalTmpl *template.Template
	mux        *http.ServeMux
}

type SignedCertResult struct {
	CertToken     string
	UserID        string
	UserPubKeyHex string
	OperatorPub   string
	IssuedAtStr   string
	ExpiresAtStr  string
}

type portalPageData struct {
	BasePath           string
	Username           string
	OperatorPubKey     string
	DefaultExpiresDays uint64
	UserPubKeyInput    string
	UserIDInput        string
	ExpiresDaysInput   string
	ErrorMsg           string
	Result             *SignedCertResult
}

type loginPageData struct {
	BasePath string
	ErrorMsg string
	NoUsers  bool
}

func NewConsoleServer(cfg *config.Config) *ConsoleServer {
	salt := make([]byte, 32)
	_, _ = rand.Read(salt)
	mac := hmac.New(sha256.New, salt)
	mac.Write(cfg.OperatorPrivKey)
	cookieKey := mac.Sum(nil)

	s := &ConsoleServer{
		cfg:        cfg,
		cookieKey:  cookieKey,
		loginTmpl:  template.Must(template.New("login").Parse(loginHTML)),
		portalTmpl: template.Must(template.New("portal").Parse(portalHTML)),
		mux:        http.NewServeMux(),
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
	_ = s.portalTmpl.Execute(w, portalPageData{
		BasePath:           s.cfg.BasePath,
		Username:           user,
		OperatorPubKey:     s.cfg.OperatorPubKeyToken(),
		DefaultExpiresDays: s.cfg.DefaultExpiresDays,
		ExpiresDaysInput:   strconv.FormatUint(s.cfg.DefaultExpiresDays, 10),
	})
}

func (s *ConsoleServer) signKeyInternal(rawUserPub, rawUserID, rawExpiresDays string) (*SignedCertResult, error) {
	userPub, err := config.ParseUserPubKey(rawUserPub)
	if err != nil {
		return nil, err
	}
	userID := strings.TrimSpace(rawUserID)
	if userID == "" {
		userID = auth.DeriveUserID(userPub)
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
	nowSec := uint64(now.Unix())
	var expSec uint64
	expStr := "Never (0)"
	if expiresDays > 0 {
		expTime := now.Add(time.Duration(expiresDays) * 24 * time.Hour)
		expSec = uint64(expTime.Unix())
		expStr = fmt.Sprintf("%s (%d days)", expTime.Format("2006-01-02 15:04:05 UTC"), expiresDays)
	}
	cert := &sshcastv1.UserCert{
		UserId:           userID,
		UserPubkey:       userPub,
		IssuedAtUnixSec:  nowSec,
		ExpiresAtUnixSec: expSec,
	}
	if err := auth.SignUserCert(cert, s.cfg.OperatorPrivKey); err != nil {
		return nil, err
	}
	token, err := auth.EncodeUserCertToken(cert)
	if err != nil {
		return nil, err
	}
	return &SignedCertResult{
		CertToken:     token,
		UserID:        userID,
		UserPubKeyHex: "sc_pub_" + hex.EncodeToString(userPub),
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

	res, err := s.signKeyInternal(pubIn, uidIn, daysIn)
	data := portalPageData{
		BasePath:           s.cfg.BasePath,
		Username:           user,
		OperatorPubKey:     s.cfg.OperatorPubKeyToken(),
		DefaultExpiresDays: s.cfg.DefaultExpiresDays,
		UserPubKeyInput:    pubIn,
		UserIDInput:        uidIn,
		ExpiresDaysInput:   daysIn,
		Result:             res,
	}
	if err != nil {
		data.ErrorMsg = err.Error()
		w.WriteHeader(http.StatusBadRequest)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.portalTmpl.Execute(w, data)
}

func (s *ConsoleServer) handleSignAPI(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.verifySessionRequest(r); !ok {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":    false,
			"error": "unauthorized",
		})
		return
	}
	var body struct {
		UserPubkey  string `json:"user_pubkey"`
		UserID      string `json:"user_id"`
		ExpiresDays uint64 `json:"expires_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":    false,
			"error": "invalid JSON body",
		})
		return
	}
	daysStr := ""
	if body.ExpiresDays > 0 {
		daysStr = strconv.FormatUint(body.ExpiresDays, 10)
	}
	res, err := s.signKeyInternal(body.UserPubkey, body.UserID, daysStr)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":              true,
		"cert_token":      res.CertToken,
		"user_id":         res.UserID,
		"user_pubkey":     res.UserPubKeyHex,
		"operator_pubkey": res.OperatorPub,
		"issued_at":       res.IssuedAtStr,
		"expires_at":      res.ExpiresAtStr,
	})
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
      max-width: 840px;
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
      <h2>Sign User Key</h2>
      <p>
        Paste a user's Ed25519 root public key (<code>sc_pub_...</code> from <code>sshcast-client keygen</code>)
        to mint an operator-signed <code>UserCert</code> (<code>sc_cert_...</code>). Any autonomous coordinator
        server trusting this operator key will authorize the user without needing per-user keys in <code>server.toml</code>.
      </p>
      {{if .ErrorMsg}}
        <div class="alert-err">{{.ErrorMsg}}</div>
      {{end}}
      <form method="POST" action="{{.BasePath}}/sign">
        <label for="user_pubkey">User Root Public Key (<code>sc_pub_...</code> or 64-char hex)</label>
        <input id="user_pubkey" name="user_pubkey" type="text" placeholder="sc_pub_..." value="{{.UserPubKeyInput}}" required autofocus />
        <div class="row">
          <div>
            <label for="user_id">User ID / Label (optional — defaults to <code>user_&lt;keyprefix&gt;</code>)</label>
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
