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
}
