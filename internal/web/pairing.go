package web

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"stingr.net/go/sshcast-operator/internal/db"
	sshcastv1 "stingr.net/go/sshcast-proto/gen/go/sshcast/v1"
	"stingr.net/go/sshcast-proto/pkg/auth"
)

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
