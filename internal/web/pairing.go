package web

import (
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"stingr.net/go/sshcast-operator/internal/config"
	"stingr.net/go/sshcast-operator/internal/db"
	sshcastv1 "stingr.net/go/sshcast-proto/gen/go/sshcast/v1"
	"stingr.net/go/sshcast-proto/pkg/auth"
)

const pairingRequestTTL = 5 * time.Minute

type recoveryVaultParamsJSON struct {
	LogN int `json:"log_n"`
	R    int `json:"r"`
	P    int `json:"p"`
}

type recoveryVaultJSON struct {
	Version       int             `json:"version"`
	KdfAlg        string          `json:"kdf_alg"`
	KdfParams     json.RawMessage `json:"kdf_params"`
	SaltB64       string          `json:"salt_b64"`
	NonceB64      string          `json:"nonce_b64"`
	CiphertextB64 string          `json:"ciphertext_b64"`
}

func recoveryVaultToJSON(v db.RecoveryVault) recoveryVaultJSON {
	params := json.RawMessage(v.KdfParamsJson)
	if !json.Valid(params) {
		params = json.RawMessage("{}")
	}
	return recoveryVaultJSON{
		Version:       int(v.Version),
		KdfAlg:        v.KdfAlg,
		KdfParams:     params,
		SaltB64:       v.SaltB64,
		NonceB64:      v.NonceB64,
		CiphertextB64: v.CiphertextB64,
	}
}

// authenticateNodeRequest verifies a base64-encoded NodeAuth protobuf (stripping UserCert so
// expired certs can still renew) and ensures the owning user is active in SQLite.
func (s *ConsoleServer) authenticateNodeRequest(
	w http.ResponseWriter,
	r *http.Request,
	nodeAuthProtoB64 string,
	requiredRole sshcastv1.NodeRole,
) (db.User, *sshcastv1.NodeGrant, time.Time, bool) {
	if s.queries == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":    false,
			"error": "database not initialized",
		})
		return db.User{}, nil, time.Time{}, false
	}

	rawAuth, err := decodeBase64Flexible(nodeAuthProtoB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return db.User{}, nil, time.Time{}, false
	}
	nodeAuth := &sshcastv1.NodeAuth{}
	if err := proto.Unmarshal(rawAuth, nodeAuth); err != nil || nodeAuth.GetGrant() == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid NodeAuth protobuf",
		})
		return db.User{}, nil, time.Time{}, false
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
		return db.User{}, nil, time.Time{}, false
	}

	grant := clonedAuth.GetGrant()
	if requiredRole != sshcastv1.NodeRole_NODE_ROLE_UNSPECIFIED && grant.GetRole() != requiredRole {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": fmt.Sprintf("node role %v is not authorized for this endpoint", grant.GetRole()),
		})
		return db.User{}, nil, time.Time{}, false
	}

	userPubHex := "sc_pub_" + hex.EncodeToString(grant.GetUserPubkey())
	user, err := s.queries.GetUserByPubkey(r.Context(), userPubHex)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"ok":     false,
				"status": "unregistered",
				"error":  "user public key is not registered",
			})
			return db.User{}, nil, time.Time{}, false
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "failed to query user",
		})
		return db.User{}, nil, time.Time{}, false
	}

	if user.Status != "active" {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":     false,
			"status": user.Status,
			"error":  fmt.Sprintf("user status is %s", user.Status),
		})
		return db.User{}, nil, time.Time{}, false
	}

	return user, grant, now, true
}

func validateRecoveryVaultJSON(v *recoveryVaultJSON) (string, error) {
	if v.Version != 1 {
		return "", fmt.Errorf("unsupported vault version %d", v.Version)
	}
	if strings.TrimSpace(v.KdfAlg) != "scrypt" {
		return "", fmt.Errorf("unsupported kdf_alg %q", v.KdfAlg)
	}
	var params recoveryVaultParamsJSON
	if len(v.KdfParams) == 0 || json.Unmarshal(v.KdfParams, &params) != nil {
		return "", errors.New("invalid kdf_params JSON")
	}
	if params.LogN < 1 || params.LogN > 20 || params.R < 1 || params.R > 32 || params.P < 1 || params.P > 16 {
		return "", errors.New("kdf_params out of allowed bounds")
	}
	canonParams, err := json.Marshal(params)
	if err != nil {
		return "", err
	}

	salt, err := decodeBase64Flexible(v.SaltB64)
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return "", errors.New("invalid salt_b64 (expected 16..64 bytes)")
	}
	nonce, err := decodeBase64Flexible(v.NonceB64)
	if err != nil || len(nonce) < 12 || len(nonce) > 32 {
		return "", errors.New("invalid nonce_b64 (expected 12..32 bytes)")
	}
	ct, err := decodeBase64Flexible(v.CiphertextB64)
	if err != nil || len(ct) < 16 || len(ct) > 4096 {
		return "", errors.New("invalid ciphertext_b64 (expected 16..4096 bytes)")
	}

	return string(canonParams), nil
}

func (s *ConsoleServer) handleRecoveryVaultUpsert(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, "POST, OPTIONS")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var body struct {
		NodeAuthProtoB64 string            `json:"node_auth_proto_b64"`
		Vault            recoveryVaultJSON `json:"vault"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid JSON body",
		})
		return
	}

	user, _, now, ok := s.authenticateNodeRequest(w, r, body.NodeAuthProtoB64, sshcastv1.NodeRole_NODE_ROLE_CLIENT)
	if !ok {
		return
	}

	canonParams, err := validateRecoveryVaultJSON(&body.Vault)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}

	saved, err := s.queries.UpsertRecoveryVault(r.Context(), db.UpsertRecoveryVaultParams{
		UserID:        user.ID,
		UserPubkey:    user.UserPubkey,
		Version:       int64(body.Vault.Version),
		KdfAlg:        "scrypt",
		KdfParamsJson: canonParams,
		SaltB64:       strings.TrimSpace(body.Vault.SaltB64),
		NonceB64:      strings.TrimSpace(body.Vault.NonceB64),
		CiphertextB64: strings.TrimSpace(body.Vault.CiphertextB64),
		UpdatedAt:     now.Unix(),
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "failed to store recovery vault",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"updated_at": saved.UpdatedAt,
	})
}

func (s *ConsoleServer) handleRecoveryVaultStatus(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, "POST, OPTIONS")
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

	user, _, _, ok := s.authenticateNodeRequest(w, r, body.NodeAuthProtoB64, sshcastv1.NodeRole_NODE_ROLE_CLIENT)
	if !ok {
		return
	}

	vault, err := s.queries.GetRecoveryVaultByUserID(r.Context(), user.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":         true,
				"configured": false,
				"updated_at": 0,
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "failed to query recovery vault",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"configured": true,
		"updated_at": vault.UpdatedAt,
	})
}

func (s *ConsoleServer) handleRecoveryVaultDelete(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, "POST, OPTIONS")
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

	user, _, _, ok := s.authenticateNodeRequest(w, r, body.NodeAuthProtoB64, sshcastv1.NodeRole_NODE_ROLE_CLIENT)
	if !ok {
		return
	}

	if err := s.queries.DeleteRecoveryVaultByUserID(r.Context(), user.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "failed to delete recovery vault",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"deleted": true,
	})
}

func (s *ConsoleServer) subscribePairingWaiter(pubkey string) (chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	s.pairingMu.Lock()
	if s.pairingWaiters == nil {
		s.pairingWaiters = make(map[string]map[chan struct{}]struct{})
	}
	set := s.pairingWaiters[pubkey]
	if set == nil {
		set = make(map[chan struct{}]struct{})
		s.pairingWaiters[pubkey] = set
	}
	set[ch] = struct{}{}
	s.pairingMu.Unlock()

	cleanup := func() {
		s.pairingMu.Lock()
		if set := s.pairingWaiters[pubkey]; set != nil {
			delete(set, ch)
			if len(set) == 0 {
				delete(s.pairingWaiters, pubkey)
			}
		}
		s.pairingMu.Unlock()
	}
	return ch, cleanup
}

func (s *ConsoleServer) notifyPairingWaiters(pubkey string) {
	s.pairingMu.Lock()
	defer s.pairingMu.Unlock()
	for ch := range s.pairingWaiters[pubkey] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func serializePairingRequests(reqs []db.PairingRequest) []map[string]any {
	items := make([]map[string]any, 0, len(reqs))
	for _, req := range reqs {
		items = append(items, map[string]any{
			"pairing_id":       req.ID,
			"node_name":        req.NodeName,
			"os_name":          req.OsName,
			"github_login":     req.GithubLogin,
			"node_pubkey_b64":  req.NodePubkeyB64,
			"eph_x25519_pub_b64": req.EphX25519PubB64,
			"expires_at":       req.ExpiresAt,
			"created_at":       req.CreatedAt,
		})
	}
	return items
}

func (s *ConsoleServer) handlePairingPoll(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, "POST, OPTIONS")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var body struct {
		NodeAuthProtoB64 string `json:"node_auth_proto_b64"`
		TimeoutSecs      int    `json:"timeout_secs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid JSON body",
		})
		return
	}

	user, _, now, ok := s.authenticateNodeRequest(w, r, body.NodeAuthProtoB64, sshcastv1.NodeRole_NODE_ROLE_CLIENT)
	if !ok {
		return
	}

	timeoutSecs := body.TimeoutSecs
	if timeoutSecs < 0 {
		timeoutSecs = 0
	} else if timeoutSecs > 25 {
		timeoutSecs = 25
	}

	waitCh, cleanup := s.subscribePairingWaiter(user.UserPubkey)
	defer cleanup()

	reqs, err := s.queries.ListPendingPairingRequestsByPubkey(r.Context(), db.ListPendingPairingRequestsByPubkeyParams{
		TargetUserPubkey: user.UserPubkey,
		ExpiresAt:        now.Unix(),
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "failed to query pending pairing requests",
		})
		return
	}

	if len(reqs) == 0 && timeoutSecs > 0 {
		timer := time.NewTimer(time.Duration(timeoutSecs) * time.Second)
		defer timer.Stop()

		select {
		case <-waitCh:
		case <-timer.C:
		case <-r.Context().Done():
			return
		}

		reqs, err = s.queries.ListPendingPairingRequestsByPubkey(r.Context(), db.ListPendingPairingRequestsByPubkeyParams{
			TargetUserPubkey: user.UserPubkey,
			ExpiresAt:        time.Now().UTC().Unix(),
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":    false,
				"error": "failed to query pending pairing requests",
			})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"requests": serializePairingRequests(reqs),
	})
}

func (s *ConsoleServer) handlePairingRespond(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, "POST, OPTIONS")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var body struct {
		NodeAuthProtoB64       string `json:"node_auth_proto_b64"`
		PairingID              string `json:"pairing_id"`
		Approved               bool   `json:"approved"`
		ApproverEphX25519PubB64 string `json:"approver_eph_x25519_pub_b64"`
		ApproverSignatureB64   string `json:"approver_signature_b64"`
		HandoffNonceB64        string `json:"handoff_nonce_b64"`
		EncryptedHandoffB64    string `json:"encrypted_handoff_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid JSON body",
		})
		return
	}

	user, grant, now, ok := s.authenticateNodeRequest(w, r, body.NodeAuthProtoB64, sshcastv1.NodeRole_NODE_ROLE_CLIENT)
	if !ok {
		return
	}

	pairingID := strings.TrimSpace(body.PairingID)
	if pairingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "missing pairing_id",
		})
		return
	}

	ctx := r.Context()
	req, err := s.queries.GetPairingRequestByID(ctx, pairingID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]any{
				"ok":    false,
				"error": "pairing request not found",
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "failed to query pairing request",
		})
		return
	}

	if req.TargetUserPubkey != user.UserPubkey {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": "pairing request belongs to a different user",
		})
		return
	}
	if req.Status != "awaiting_peer" {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":     false,
			"status": req.Status,
			"error":  fmt.Sprintf("pairing request is already %s", req.Status),
		})
		return
	}
	if now.Unix() > req.ExpiresAt {
		writeJSON(w, http.StatusGone, map[string]any{
			"ok":    false,
			"error": "pairing request expired",
		})
		return
	}

	if body.Approved {
		ephPub, err := decodeBase64Flexible(body.ApproverEphX25519PubB64)
		if err != nil || len(ephPub) != 32 {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": "invalid approver_eph_x25519_pub_b64 (expected 32 bytes)",
			})
			return
		}
		sig, err := decodeBase64Flexible(body.ApproverSignatureB64)
		if err != nil || len(sig) != 64 {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": "invalid approver_signature_b64 (expected 64 bytes)",
			})
			return
		}
		nonce, err := decodeBase64Flexible(body.HandoffNonceB64)
		if err != nil || len(nonce) != 12 {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": "invalid handoff_nonce_b64 (expected 12 bytes)",
			})
			return
		}
		ct, err := decodeBase64Flexible(body.EncryptedHandoffB64)
		if err != nil || len(ct) < 16 || len(ct) > 32768 {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": "invalid encrypted_handoff_b64 (expected 16..32768 bytes)",
			})
			return
		}

		if _, err := s.queries.ApprovePairingRequest(ctx, db.ApprovePairingRequestParams{
			ApproverNodeID:          grant.GetNodeId(),
			ApproverEphX25519PubB64: base64.StdEncoding.EncodeToString(ephPub),
			ApproverSignatureB64:    base64.StdEncoding.EncodeToString(sig),
			HandoffNonceB64:         base64.StdEncoding.EncodeToString(nonce),
			EncryptedHandoffB64:     base64.StdEncoding.EncodeToString(ct),
			ID:                      pairingID,
			TargetUserPubkey:        user.UserPubkey,
		}); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeJSON(w, http.StatusConflict, map[string]any{
					"ok":    false,
					"error": "pairing request was already handled",
				})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":    false,
				"error": "failed to store pairing approval",
			})
			return
		}
	} else {
		if _, err := s.queries.SetPairingRequestTerminalStatus(ctx, db.SetPairingRequestTerminalStatusParams{
			Status:   "denied",
			ErrorMsg: "denied by workstation",
			ID:       pairingID,
		}); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeJSON(w, http.StatusConflict, map[string]any{
					"ok":    false,
					"error": "pairing request was already handled",
				})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":    false,
				"error": "failed to store pairing denial",
			})
			return
		}
	}

	s.notifyPairingWaiters(user.UserPubkey)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
	})
}

func (s *ConsoleServer) authenticateOAuthPollSession(
	w http.ResponseWriter,
	r *http.Request,
	state string,
) (db.OauthSession, time.Time, bool) {
	if s.queries == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":    false,
			"error": "database not initialized",
		})
		return db.OauthSession{}, time.Time{}, false
	}

	state = strings.TrimSpace(state)
	if state == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "missing state",
		})
		return db.OauthSession{}, time.Time{}, false
	}
	pollToken := extractBearerToken(r)
	if pollToken == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok":    false,
			"error": "missing bearer token",
		})
		return db.OauthSession{}, time.Time{}, false
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
			return db.OauthSession{}, time.Time{}, false
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "failed to query enrollment session",
		})
		return db.OauthSession{}, time.Time{}, false
	}

	gotHash := sha256Hex(pollToken)
	if subtle.ConstantTimeCompare([]byte(gotHash), []byte(sess.PollTokenHash)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok":    false,
			"error": "invalid poll token",
		})
		return db.OauthSession{}, time.Time{}, false
	}

	now := time.Now().UTC()
	if now.Unix() > sess.ExpiresAt {
		_ = s.queries.DeleteExpiredOAuthSessions(ctx, now.Unix())
		writeJSON(w, http.StatusGone, map[string]any{
			"ok":     false,
			"status": "expired",
			"error":  "enrollment session expired",
		})
		return db.OauthSession{}, time.Time{}, false
	}

	return sess, now, true
}

func (s *ConsoleServer) handleEnrollCancel(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, "GET, POST, OPTIONS")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var body struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid JSON body",
		})
		return
	}

	sess, _, ok := s.authenticateOAuthPollSession(w, r, body.State)
	if !ok {
		return
	}

	ctx := r.Context()
	if pr, err := s.queries.GetPairingRequestByState(ctx, sess.State); err == nil && pr.Status == "awaiting_peer" {
		_, _ = s.queries.SetPairingRequestTerminalStatus(ctx, db.SetPairingRequestTerminalStatusParams{
			Status:   "canceled",
			ErrorMsg: "canceled by requester",
			ID:       pr.ID,
		})
		if pr.TargetUserPubkey != "" {
			s.notifyPairingWaiters(pr.TargetUserPubkey)
		}
	}

	if sess.Status == "pending" || sess.Status == "pairing_required" {
		_, _ = s.queries.UpdateOAuthSession(ctx, db.UpdateOAuthSessionParams{
			Status:    "canceled",
			CertToken: "",
			ErrorMsg:  "canceled by requester",
			State:     sess.State,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"status": "canceled",
	})
}

func (s *ConsoleServer) handleEnrollReplace(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, "GET, POST, OPTIONS")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var body struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid JSON body",
		})
		return
	}

	sess, now, ok := s.authenticateOAuthPollSession(w, r, body.State)
	if !ok {
		return
	}

	if sess.Status != "pairing_required" {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":     false,
			"status": sess.Status,
			"error":  "enrollment session is not awaiting device pairing",
		})
		return
	}

	ctx := r.Context()
	pr, err := s.queries.GetPairingRequestByState(ctx, sess.State)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"ok":    false,
			"error": "pairing request not found",
		})
		return
	}
	if !pr.UserID.Valid || pr.Status != "awaiting_peer" {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":     false,
			"status": pr.Status,
			"error":  "pairing request is no longer awaiting peer approval",
		})
		return
	}

	user, err := s.queries.GetUserByID(ctx, pr.UserID.Int64)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"ok":    false,
			"error": "user account not found",
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

	newPubBytes, err := config.ParseUserPubKey(sess.UserPubkey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}

	if _, err := s.queries.UpdateUserPubkeyAndLogin(ctx, db.UpdateUserPubkeyAndLoginParams{
		UserPubkey:  sess.UserPubkey,
		GithubLogin: pr.GithubLogin,
		UpdatedAt:   now.Unix(),
		ID:          user.ID,
	}); err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":    false,
			"error": "failed to replace user public key",
		})
		return
	}

	_ = s.queries.DeleteRecoveryVaultByUserID(ctx, user.ID)

	_, certToken, err := s.mintUserCert(newPubBytes, user.UserID, s.cfg.DefaultExpiresDays, now)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "failed to sign replacement user certificate",
		})
		return
	}

	_, _ = s.queries.UpdateOAuthSession(ctx, db.UpdateOAuthSessionParams{
		Status:    "approved",
		CertToken: certToken,
		ErrorMsg:  "",
		State:     sess.State,
	})
	_, _ = s.queries.SetPairingRequestTerminalStatus(ctx, db.SetPairingRequestTerminalStatusParams{
		Status:   "replaced_key",
		ErrorMsg: "user root key replaced",
		ID:       pr.ID,
	})

	if pr.TargetUserPubkey != "" {
		s.notifyPairingWaiters(pr.TargetUserPubkey)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"status":     "approved",
		"cert_token": certToken,
	})
}
