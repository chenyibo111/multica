package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/multica-ai/multica/server/internal/auth"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

func TestFeishuLoginCallbackCreatesAndReusesAccount(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-SSO-Service-Key") != "01234567890123456789012345678901" {
			t.Error("missing SSO service key")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer status.Close()
	t.Setenv("FEISHU_SSO_STATUS_URL", status.URL)
	t.Setenv("SSO_SERVICE_KEY", "01234567890123456789012345678901")

	var identityEmail, nonce string
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if r.PostFormValue("code_verifier") == "" || r.PostFormValue("client_id") != "multica-web" {
				t.Error("token exchange lost PKCE or client ID")
			}
			claims := jwt.MapClaims{"iss": provider.URL + "/", "aud": "multica-web", "sub": "fs_callback_member", "sid": "sid-callback", "nonce": nonce, "feishu_tenant_key": "tenant-a", "feishu_app_id": "app-a", "feishu_open_id": "ou_callback", "feishu_user_id": "u_callback", "name": "Callback member", "email": identityEmail, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "callback-key"
			signed, signErr := token.SignedString(key)
			if signErr != nil {
				t.Error(signErr)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": signed})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "callback-key", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	h := &Handler{Queries: db.New(tx), FeishuOIDC: &auth.FeishuOIDC{Config: auth.FeishuOIDCConfig{Issuer: provider.URL + "/", AuthorizationURL: provider.URL + "/auth", TokenURL: provider.URL + "/token", JWKSURL: provider.URL + "/jwks", ClientID: "multica-web", RedirectURL: "http://localhost:8080/auth/feishu/callback", TenantKey: "tenant-a", AppID: "app-a", AppURL: "http://localhost:3000"}}}

	login := func(email string) {
		t.Helper()
		identityEmail = email
		start := httptest.NewRecorder()
		h.FeishuLoginStart(start, httptest.NewRequest(http.MethodGet, "/auth/feishu/start?next=%2Finvitations", nil))
		if start.Code != http.StatusFound || len(start.Result().Cookies()) == 0 {
			t.Fatalf("login start failed: %d", start.Code)
		}
		authorization, err := url.Parse(start.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		nonce = authorization.Query().Get("nonce")
		callback := httptest.NewRequest(http.MethodGet, "/auth/feishu/callback?code=test-code&state="+url.QueryEscape(authorization.Query().Get("state")), nil)
		callback.AddCookie(start.Result().Cookies()[0])
		response := httptest.NewRecorder()
		h.FeishuLoginCallback(response, callback)
		if response.Code != http.StatusFound || response.Header().Get("Location") != "http://localhost:3000/login?next=%2Finvitations" {
			t.Fatalf("callback failed: %d %s", response.Code, response.Body.String())
		}
		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == feishuIDTokenCookie && cookie.MaxAge != 8*60*60 {
				t.Fatalf("ID token cookie age = %d", cookie.MaxAge)
			}
		}
	}
	login("first@example.test")
	login("changed@example.test")
	var count int
	var email, source string
	if err := tx.QueryRow(ctx, `SELECT count(*), max(email), max(auth_source) FROM "user" WHERE oidc_issuer = $1 AND oidc_subject = 'fs_callback_member'`, provider.URL+"/").Scan(&count, &email, &source); err != nil || count != 1 || email != "changed@example.test" || source != "feishu" {
		t.Fatalf("Feishu account was not reused: count=%d email=%q source=%q err=%v", count, email, source, err)
	}
}

func TestFeishuCallbackRejectsMissingState(t *testing.T) {
	h := &Handler{FeishuOIDC: &auth.FeishuOIDC{Config: auth.FeishuOIDCConfig{}}}
	w := httptest.NewRecorder()
	h.FeishuLoginCallback(w, httptest.NewRequest(http.MethodGet, "/auth/feishu/callback?code=bad&state=bad", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("callback without state cookie: %d", w.Code)
	}
}

func TestFeishuSilentStartRequestsPromptNone(t *testing.T) {
	h := &Handler{FeishuOIDC: &auth.FeishuOIDC{Config: auth.FeishuOIDCConfig{AuthorizationURL: "http://localhost:4444/oauth2/auth", ClientID: "multica-web", RedirectURL: "http://localhost:8080/auth/feishu/callback"}}}
	w := httptest.NewRecorder()
	h.FeishuLoginStart(w, httptest.NewRequest(http.MethodGet, "/auth/feishu/start?silent=1&next=%2Finvitations", nil))
	redirect, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != http.StatusFound || redirect.Query().Get("prompt") != "none" || redirect.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("silent authorization malformed: status=%d url=%s err=%v", w.Code, redirect, err)
	}
}

func TestFeishuSilentLoginRequiredReturnsToLoginWithoutRetry(t *testing.T) {
	h := &Handler{FeishuOIDC: &auth.FeishuOIDC{Config: auth.FeishuOIDCConfig{AuthorizationURL: "http://localhost:4444/oauth2/auth", ClientID: "multica-web", RedirectURL: "http://localhost:8080/auth/feishu/callback", AppURL: "http://localhost:3000"}}}
	start := httptest.NewRecorder()
	h.FeishuLoginStart(start, httptest.NewRequest(http.MethodGet, "/auth/feishu/start?silent=1&next=%2Finvitations", nil))
	redirect, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	callback := httptest.NewRequest(http.MethodGet, "/auth/feishu/callback?error=login_required&state="+url.QueryEscape(redirect.Query().Get("state")), nil)
	callback.AddCookie(start.Result().Cookies()[0])
	w := httptest.NewRecorder()
	h.FeishuLoginCallback(w, callback)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "http://localhost:3000/login?next=%2Finvitations&sso_attempted=1" {
		t.Fatalf("silent login_required failed: status=%d location=%q body=%s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
}

func TestFeishuSilentConsentRequiredRetriesWithoutPrompt(t *testing.T) {
	h := &Handler{FeishuOIDC: &auth.FeishuOIDC{Config: auth.FeishuOIDCConfig{AuthorizationURL: "http://localhost:4444/oauth2/auth", ClientID: "multica-web", RedirectURL: "http://localhost:8080/auth/feishu/callback", AppURL: "http://localhost:3000"}}}
	start := httptest.NewRecorder()
	h.FeishuLoginStart(start, httptest.NewRequest(http.MethodGet, "/auth/feishu/start?silent=1&next=%2Finvitations", nil))
	redirect, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	callback := httptest.NewRequest(http.MethodGet, "/auth/feishu/callback?error=consent_required&state="+url.QueryEscape(redirect.Query().Get("state")), nil)
	callback.AddCookie(start.Result().Cookies()[0])
	w := httptest.NewRecorder()
	h.FeishuLoginCallback(w, callback)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/auth/feishu/start?next=%2Finvitations" {
		t.Fatalf("consent retry failed: status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}

func TestFeishuLogoutUsesRegisteredSameOriginReturn(t *testing.T) {
	h := &Handler{FeishuOIDC: &auth.FeishuOIDC{Config: auth.FeishuOIDCConfig{Issuer: "http://localhost:4444/", RedirectURL: "http://localhost:8080/auth/feishu/callback", AppURL: "http://localhost:3000"}}}
	r := httptest.NewRequest(http.MethodGet, "/auth/feishu/logout", nil)
	r.AddCookie(&http.Cookie{Name: feishuIDTokenCookie, Value: "id.token"})
	w := httptest.NewRecorder()
	h.FeishuLogout(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("logout code: %d", w.Code)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || u.Host != "localhost:4444" || u.Query().Get("id_token_hint") != "id.token" || u.Query().Get("post_logout_redirect_uri") != "http://localhost:8080/auth/feishu/logged-out" {
		t.Fatalf("logout target invalid: %v", err)
	}
}

func TestSafeCliCallbackForFeishu(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:1234/callback", "http://localhost:1234/callback", "http://192.168.1.3:1234/callback"} {
		if !safeCliCallback(raw) {
			t.Fatalf("rejected %s", raw)
		}
	}
	for _, raw := range []string{"https://evil.example/callback", "http://10.evil.example/callback", "javascript:alert(1)", "http://8.8.8.8/callback"} {
		if safeCliCallback(raw) {
			t.Fatalf("accepted %s", raw)
		}
	}
}
