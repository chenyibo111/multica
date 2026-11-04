package handler

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

func TestFeishuUserSchemaAllowsIndependentSameEmailAccounts(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	email := "same-feishu-schema@example.test"
	if _, err := tx.Exec(ctx, `INSERT INTO "user" (name, email) VALUES ('Local', $1)`, email); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO "user" (name, email, auth_source, oidc_issuer, oidc_subject) VALUES ('Feishu', $1, 'feishu', 'http://localhost:4444/', 'fs_member_a')`, email); err != nil {
		t.Fatalf("same-email Feishu account rejected: %v", err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM "user" WHERE email = $1`, email).Scan(&count); err != nil || count != 2 {
		t.Fatalf("same-email accounts count=%d err=%v", count, err)
	}
}

func TestFeishuUserSchemaIdentityAndEmailIsolation(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil { t.Fatal(err) }
	defer tx.Rollback(ctx)
	queries := db.New(tx)
	for _, subject := range []string{"member-1", "member-2"} {
		_, err := tx.Exec(ctx, `INSERT INTO "user" (name, email, auth_source, oidc_issuer, oidc_subject) VALUES ('Feishu', '', 'feishu', 'https://issuer.example/', $1)`, subject)
		if err != nil { t.Fatalf("empty email for %s: %v", subject, err) }
	}
	_, err = queries.GetUserByEmail(ctx, "")
	if !errors.Is(err, pgx.ErrNoRows) { t.Fatalf("local lookup reached Feishu account: %v", err) }
	_, err = tx.Exec(ctx, `INSERT INTO "user" (name, email, auth_source, oidc_issuer, oidc_subject) VALUES ('Feishu', 'other@example.test', 'feishu', 'https://issuer.example/', 'member-1')`)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" { t.Fatalf("duplicate OIDC identity accepted: %v", err) }
}

func TestFeishuUserSchemaLocalEmailUnique(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil { t.Fatal(err) }
	defer tx.Rollback(ctx)
	for i := 0; i < 2; i++ {
		_, err := tx.Exec(ctx, `INSERT INTO "user" (name, email) VALUES ('Local', 'local-unique@example.test')`)
		if i == 0 && err != nil { t.Fatal(err) }
		if i == 1 {
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23505" { t.Fatalf("duplicate local email accepted: %v", err) }
		}
	}
}
