package db

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenIdempotentAndQueries(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "nested", "state", "operator.db")

	sqlDB, q, err := Open(dbPath)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	info, err := os.Stat(filepath.Dir(dbPath))
	if err != nil {
		t.Fatalf("stat parent dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0750 {
		t.Fatalf("expected parent dir mode 0750, got %#o", perm)
	}

	ctx := context.Background()
	now := int64(1700000000)

	// Insert GitHub user and verify lookup by pubkey and github_id.
	inserted, err := q.InsertUser(ctx, InsertUserParams{
		UserPubkey:      "sc_pub_01020304",
		UserID:          "gh:alice",
		GithubID:        sql.NullInt64{Int64: 12345, Valid: true},
		GithubLogin:     "alice",
		GithubCreatedAt: now - 86400*60,
		Status:          "pending",
		Note:            "oauth",
		CreatedAt:       now,
		UpdatedAt:       now,
		LastRenewedAt:   0,
	})
	if err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if inserted.Status != "pending" || !inserted.GithubID.Valid || inserted.GithubID.Int64 != 12345 {
		t.Fatalf("unexpected inserted user: %+v", inserted)
	}

	byPub, err := q.GetUserByPubkey(ctx, "sc_pub_01020304")
	if err != nil || byPub.ID != inserted.ID {
		t.Fatalf("GetUserByPubkey: user=%+v err=%v", byPub, err)
	}

	byGH, err := q.GetUserByGitHubID(ctx, sql.NullInt64{Int64: 12345, Valid: true})
	if err != nil || byGH.ID != inserted.ID {
		t.Fatalf("GetUserByGitHubID: user=%+v err=%v", byGH, err)
	}

	// Update pubkey/login, status, and renewal timestamp.
	updated, err := q.UpdateUserPubkeyAndLogin(ctx, UpdateUserPubkeyAndLoginParams{
		UserPubkey:  "sc_pub_aabbccdd",
		GithubLogin: "alice-new",
		UpdatedAt:   now + 10,
		ID:          inserted.ID,
	})
	if err != nil || updated.UserPubkey != "sc_pub_aabbccdd" || updated.GithubLogin != "alice-new" {
		t.Fatalf("UpdateUserPubkeyAndLogin: user=%+v err=%v", updated, err)
	}

	activated, err := q.SetUserStatus(ctx, SetUserStatusParams{
		Status:    "active",
		UpdatedAt: now + 20,
		ID:        inserted.ID,
	})
	if err != nil || activated.Status != "active" {
		t.Fatalf("SetUserStatus: user=%+v err=%v", activated, err)
	}

	if err := q.TouchUserRenewed(ctx, TouchUserRenewedParams{
		LastRenewedAt: now + 30,
		UpdatedAt:     now + 30,
		ID:            inserted.ID,
	}); err != nil {
		t.Fatalf("TouchUserRenewed: %v", err)
	}

	// Upsert multiple manual users (NULL github_id must not violate UNIQUE).
	if _, err := q.UpsertManualUser(ctx, UpsertManualUserParams{
		UserPubkey: "sc_pub_manual_1",
		UserID:     "manual1",
		Note:       "manual",
		CreatedAt:  now + 40,
		UpdatedAt:  now + 40,
	}); err != nil {
		t.Fatalf("UpsertManualUser 1: %v", err)
	}
	if _, err := q.UpsertManualUser(ctx, UpsertManualUserParams{
		UserPubkey: "sc_pub_manual_2",
		UserID:     "manual2",
		Note:       "manual",
		CreatedAt:  now + 50,
		UpdatedAt:  now + 50,
	}); err != nil {
		t.Fatalf("UpsertManualUser 2: %v", err)
	}

	users, err := q.ListUsers(ctx)
	if err != nil || len(users) != 3 {
		t.Fatalf("ListUsers: len=%d err=%v", len(users), err)
	}

	// OAuth session lifecycle and expiration cleanup.
	if _, err := q.CreateOAuthSession(ctx, CreateOAuthSessionParams{
		State:         "state_live",
		UserPubkey:    "sc_pub_aabbccdd",
		PollTokenHash: "hash1",
		Status:        "pending",
		ExpiresAt:     now + 900,
		CreatedAt:     now,
	}); err != nil {
		t.Fatalf("CreateOAuthSession live: %v", err)
	}
	if _, err := q.CreateOAuthSession(ctx, CreateOAuthSessionParams{
		State:         "state_expired",
		UserPubkey:    "sc_pub_deadbeef",
		PollTokenHash: "hash2",
		Status:        "pending",
		ExpiresAt:     now - 1,
		CreatedAt:     now - 100,
	}); err != nil {
		t.Fatalf("CreateOAuthSession expired: %v", err)
	}

	if _, err := q.UpdateOAuthSession(ctx, UpdateOAuthSessionParams{
		Status:    "approved",
		CertToken: "sc_cert_tok",
		ErrorMsg:  "",
		State:     "state_live",
	}); err != nil {
		t.Fatalf("UpdateOAuthSession: %v", err)
	}

	if err := q.DeleteExpiredOAuthSessions(ctx, now); err != nil {
		t.Fatalf("DeleteExpiredOAuthSessions: %v", err)
	}
	if _, err := q.GetOAuthSession(ctx, "state_expired"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected expired session deleted, got err=%v", err)
	}
	liveSess, err := q.GetOAuthSession(ctx, "state_live")
	if err != nil || liveSess.Status != "approved" || liveSess.CertToken != "sc_cert_tok" {
		t.Fatalf("GetOAuthSession live: sess=%+v err=%v", liveSess, err)
	}

	// Settings upsert and read.
	if _, err := q.UpsertSetting(ctx, UpsertSettingParams{
		Key:       "auto_approve",
		Value:     "false",
		UpdatedAt: now + 60,
	}); err != nil {
		t.Fatalf("UpsertSetting: %v", err)
	}
	setting, err := q.GetSetting(ctx, "auto_approve")
	if err != nil || setting.Value != "false" {
		t.Fatalf("GetSetting: setting=%+v err=%v", setting, err)
	}

	_ = sqlDB.Close()

	// Re-open existing DB idempotently and confirm data survived.
	sqlDB2, q2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("second Open (idempotency): %v", err)
	}
	defer sqlDB2.Close()

	users2, err := q2.ListUsers(ctx)
	if err != nil || len(users2) != 3 {
		t.Fatalf("ListUsers after reopen: len=%d err=%v", len(users2), err)
	}

	// Recovery vault upsert, fetch, update, and delete.
	byID, err := q2.GetUserByID(ctx, inserted.ID)
	if err != nil || byID.UserPubkey != "sc_pub_aabbccdd" {
		t.Fatalf("GetUserByID: user=%+v err=%v", byID, err)
	}
	vault1, err := q2.UpsertRecoveryVault(ctx, UpsertRecoveryVaultParams{
		UserID:        inserted.ID,
		UserPubkey:    byID.UserPubkey,
		Version:       1,
		KdfAlg:        "scrypt",
		KdfParamsJson: `{"log_n":15,"r":8,"p":1}`,
		SaltB64:       "c2FsdA==",
		NonceB64:      "bm9uY2U=",
		CiphertextB64: "Y2lwaGVy",
		UpdatedAt:     now + 70,
	})
	if err != nil || vault1.KdfAlg != "scrypt" {
		t.Fatalf("UpsertRecoveryVault 1: vault=%+v err=%v", vault1, err)
	}
	vault2, err := q2.UpsertRecoveryVault(ctx, UpsertRecoveryVaultParams{
		UserID:        inserted.ID,
		UserPubkey:    byID.UserPubkey,
		Version:       1,
		KdfAlg:        "scrypt",
		KdfParamsJson: `{"log_n":16,"r":8,"p":1}`,
		SaltB64:       "c2FsdDI=",
		NonceB64:      "bm9uY2Uy",
		CiphertextB64: "Y2lwaGVyMg==",
		UpdatedAt:     now + 80,
	})
	if err != nil || vault2.CiphertextB64 != "Y2lwaGVyMg==" {
		t.Fatalf("UpsertRecoveryVault 2: vault=%+v err=%v", vault2, err)
	}
	gotVault, err := q2.GetRecoveryVaultByUserID(ctx, inserted.ID)
	if err != nil || gotVault.UpdatedAt != now+80 {
		t.Fatalf("GetRecoveryVaultByUserID: vault=%+v err=%v", gotVault, err)
	}
	if err := q2.DeleteRecoveryVaultByUserID(ctx, inserted.ID); err != nil {
		t.Fatalf("DeleteRecoveryVaultByUserID: %v", err)
	}
	if _, err := q2.GetRecoveryVaultByUserID(ctx, inserted.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected deleted vault, got err=%v", err)
	}

	// Pairing request create, bind, list, approve, deny, and expiration cleanup.
	prLive, err := q2.CreatePairingRequest(ctx, CreatePairingRequestParams{
		ID:              "pair-live",
		OauthState:      "state-pair-live",
		NodeName:        "workstation-b",
		OsName:          "macos",
		NodePubkeyB64:   "bm9kZS1wdWI=",
		EphX25519PubB64: "ZXBoLXB1Yg==",
		Status:          "pending_oauth",
		ExpiresAt:       now + 900,
		CreatedAt:       now,
	})
	if err != nil || prLive.UserID.Valid {
		t.Fatalf("CreatePairingRequest live: pr=%+v err=%v", prLive, err)
	}
	prBound, err := q2.BindPairingRequestToUser(ctx, BindPairingRequestToUserParams{
		UserID:           sql.NullInt64{Int64: inserted.ID, Valid: true},
		TargetUserPubkey: byID.UserPubkey,
		GithubLogin:      "alice-new",
		ExpiresAt:        now + 300,
		OauthState:       "state-pair-live",
	})
	if err != nil || prBound.Status != "awaiting_peer" {
		t.Fatalf("BindPairingRequestToUser: pr=%+v err=%v", prBound, err)
	}
	pendingList, err := q2.ListPendingPairingRequestsByPubkey(ctx, ListPendingPairingRequestsByPubkeyParams{
		TargetUserPubkey: byID.UserPubkey,
		ExpiresAt:        now,
	})
	if err != nil || len(pendingList) != 1 || pendingList[0].ID != "pair-live" {
		t.Fatalf("ListPendingPairingRequestsByPubkey: list=%+v err=%v", pendingList, err)
	}
	approvedPR, err := q2.ApprovePairingRequest(ctx, ApprovePairingRequestParams{
		ApproverNodeID:          "workstation-a",
		ApproverEphX25519PubB64: "YXBwLWVwaA==",
		ApproverSignatureB64:    "c2ln",
		HandoffNonceB64:         "bm9uY2U=",
		EncryptedHandoffB64:     "aGFuZG9mZg==",
		ID:                      "pair-live",
		TargetUserPubkey:        byID.UserPubkey,
	})
	if err != nil || approvedPR.Status != "approved" || approvedPR.ApproverNodeID != "workstation-a" {
		t.Fatalf("ApprovePairingRequest: pr=%+v err=%v", approvedPR, err)
	}

	if _, err := q2.CreatePairingRequest(ctx, CreatePairingRequestParams{
		ID:              "pair-deny",
		OauthState:      "state-pair-deny",
		NodeName:        "workstation-c",
		OsName:          "windows",
		NodePubkeyB64:   "bm9kZTI=",
		EphX25519PubB64: "ZXBoMg==",
		Status:          "pending_oauth",
		ExpiresAt:       now + 900,
		CreatedAt:       now,
	}); err != nil {
		t.Fatalf("CreatePairingRequest deny: %v", err)
	}
	if _, err := q2.BindPairingRequestToUser(ctx, BindPairingRequestToUserParams{
		UserID:           sql.NullInt64{Int64: inserted.ID, Valid: true},
		TargetUserPubkey: byID.UserPubkey,
		GithubLogin:      "alice-new",
		ExpiresAt:        now + 300,
		OauthState:       "state-pair-deny",
	}); err != nil {
		t.Fatalf("BindPairingRequestToUser deny: %v", err)
	}
	deniedPR, err := q2.SetPairingRequestTerminalStatus(ctx, SetPairingRequestTerminalStatusParams{
		Status:   "denied",
		ErrorMsg: "denied by workstation",
		ID:       "pair-deny",
	})
	if err != nil || deniedPR.Status != "denied" {
		t.Fatalf("SetPairingRequestTerminalStatus: pr=%+v err=%v", deniedPR, err)
	}

	if _, err := q2.CreatePairingRequest(ctx, CreatePairingRequestParams{
		ID:              "pair-expired",
		OauthState:      "state-pair-expired",
		NodeName:        "old",
		OsName:          "linux",
		NodePubkeyB64:   "b2xk",
		EphX25519PubB64: "b2xk",
		Status:          "pending_oauth",
		ExpiresAt:       now - 5,
		CreatedAt:       now - 100,
	}); err != nil {
		t.Fatalf("CreatePairingRequest expired: %v", err)
	}
	if err := q2.DeleteExpiredPairingRequests(ctx, now); err != nil {
		t.Fatalf("DeleteExpiredPairingRequests: %v", err)
	}
	if _, err := q2.GetPairingRequestByID(ctx, "pair-expired"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected expired pairing deleted, got err=%v", err)
	}
	gotByState, err := q2.GetPairingRequestByState(ctx, "state-pair-live")
	if err != nil || gotByState.ID != "pair-live" {
		t.Fatalf("GetPairingRequestByState: pr=%+v err=%v", gotByState, err)
	}
}
