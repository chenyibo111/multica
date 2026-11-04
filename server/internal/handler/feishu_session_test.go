package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/middleware"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

func TestFeishuSessionPropagatesToCLIAndPAT(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	q := db.New(tx)
	user, err := q.CreateFeishuUser(ctx, db.CreateFeishuUserParams{Name: "Feishu", Email: "same@example.test", OidcIssuer: pgtype.Text{String: "https://issuer.example/", Valid: true}, OidcSubject: pgtype.Text{String: "fs_session_test", Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Queries: q}
	jwtToken, err := h.issueJWTWithSSO(user, "sid-session-test")
	if err != nil {
		t.Fatal(err)
	}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer provider.Close()
	t.Setenv("FEISHU_SSO_STATUS_URL", provider.URL)
	t.Setenv("SSO_SERVICE_KEY", "01234567890123456789012345678901")
	request := func(path, body string, next http.HandlerFunc) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()
		middleware.Auth(q, nil, nil, nil)(next).ServeHTTP(w, r)
		return w
	}
	cli := request("/api/cli-token", "", h.IssueCliToken)
	if cli.Code != http.StatusOK {
		t.Fatalf("CLI token: %d %s", cli.Code, cli.Body)
	}
	var cliBody struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(cli.Body.Bytes(), &cliBody); err != nil {
		t.Fatal(err)
	}
	claims, err := auth.ParseSessionToken(cliBody.Token)
	if err != nil || claims["sso_sid"] != "sid-session-test" {
		t.Fatalf("CLI lost SSO session: %v", err)
	}
	pat := request("/api/tokens", `{"name":"Feishu CLI"}`, h.CreatePersonalAccessToken)
	if pat.Code != http.StatusCreated {
		t.Fatalf("PAT: %d %s", pat.Code, pat.Body)
	}
	var patBody CreatePATResponse
	if err := json.Unmarshal(pat.Body.Bytes(), &patBody); err != nil {
		t.Fatal(err)
	}
	stored, err := q.GetPersonalAccessTokenByHash(ctx, auth.HashToken(patBody.Token))
	if err != nil || stored.SsoSid.String != "sid-session-test" {
		t.Fatalf("PAT lost SSO session: %v", err)
	}
}
