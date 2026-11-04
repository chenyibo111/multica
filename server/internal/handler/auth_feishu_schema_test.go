package handler

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
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
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	queries := db.New(tx)
	for _, subject := range []string{"member-1", "member-2"} {
		_, err := tx.Exec(ctx, `INSERT INTO "user" (name, email, auth_source, oidc_issuer, oidc_subject) VALUES ('Feishu', '', 'feishu', 'https://issuer.example/', $1)`, subject)
		if err != nil {
			t.Fatalf("empty email for %s: %v", subject, err)
		}
	}
	_, err = queries.GetUserByEmail(ctx, "")
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("local lookup reached Feishu account: %v", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO "user" (name, email, auth_source, oidc_issuer, oidc_subject) VALUES ('Feishu', 'other@example.test', 'feishu', 'https://issuer.example/', 'member-1')`)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("duplicate OIDC identity accepted: %v", err)
	}
}

func TestFeishuUserSchemaLocalEmailUnique(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for i := 0; i < 2; i++ {
		_, err := tx.Exec(ctx, `INSERT INTO "user" (name, email) VALUES ('Local', 'local-unique@example.test')`)
		if i == 0 && err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
				t.Fatalf("duplicate local email accepted: %v", err)
			}
		}
	}
}

func TestFeishuAccountUpsertKeepsIdentityWhenEmailChanges(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	q := db.New(tx)
	identity := db.CreateFeishuUserParams{Name: "Alice", Email: "first@example.test", OidcIssuer: pgtype.Text{String: "https://issuer.example/", Valid: true}, OidcSubject: pgtype.Text{String: "fs_email_change", Valid: true}}
	first, err := q.CreateFeishuUser(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	identity.Email = "second@example.test"
	second, err := q.CreateFeishuUser(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || second.Email != "second@example.test" {
		t.Fatal("email change created a new account")
	}
	if _, _, err := (&Handler{Queries: q, cfg: Config{AllowSignup: true}}).findOrCreateUser(ctx, second.Email); !errors.Is(err, ErrFeishuLoginRequired) {
		t.Fatalf("email login allowed Feishu-only email: %v", err)
	}
}

func TestConcurrentFirstFeishuLoginUsesOneAccount(t *testing.T) {
	ctx := context.Background()
	subject := "fs_" + uuid.NewString()
	defer testPool.Exec(ctx, `DELETE FROM "user" WHERE oidc_issuer='https://issuer.example/' AND oidc_subject=$1`, subject)
	params := db.CreateFeishuUserParams{Name:"Alice", Email:"", OidcIssuer:pgtype.Text{String:"https://issuer.example/",Valid:true}, OidcSubject:pgtype.Text{String:subject,Valid:true}}
	var wg sync.WaitGroup
	ids := make([]pgtype.UUID,2)
	errs := make([]error,2)
	for i := range ids {
		wg.Add(1)
		go func(i int) { defer wg.Done(); user, err := db.New(testPool).CreateFeishuUser(ctx,params); errs[i]=err; ids[i]=user.ID }(i)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || ids[0] != ids[1] { t.Fatalf("concurrent account IDs differ: %v %v",errs[0],errs[1]) }
}
