package db

import (
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed schema.sql
var schemaSQL string

// Open initializes the SQLite database at dbPath, creates parent directories
// with 0750 permissions if needed, enforces single-writer connection pooling,
// and idempotently applies the embedded schema.
func Open(dbPath string) (*sql.DB, *Queries, error) {
	trimmed := strings.TrimSpace(dbPath)
	if trimmed == "" {
		return nil, nil, errors.New("database path must not be empty")
	}

	if trimmed != ":memory:" && !strings.HasPrefix(trimmed, "file::memory:") {
		dir := filepath.Dir(trimmed)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0750); err != nil {
				return nil, nil, fmt.Errorf("create database directory %q: %w", dir, err)
			}
		}
	}

	dsn := trimmed
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	dsn += sep + "_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on"

	sqlDB, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("open sqlite database %q: %w", trimmed, err)
	}
	sqlDB.SetMaxOpenConns(1)

	if _, err := sqlDB.Exec(schemaSQL); err != nil {
		_ = sqlDB.Close()
		return nil, nil, fmt.Errorf("apply sqlite schema: %w", err)
	}

	return sqlDB, New(sqlDB), nil
}
