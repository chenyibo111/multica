package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/multica-ai/multica/server/internal/auth"
)

func TestFeishuCallbackRejectsMissingState(t *testing.T) {
	h := &Handler{FeishuOIDC: &auth.FeishuOIDC{Config: auth.FeishuOIDCConfig{}}}
	w := httptest.NewRecorder()
	h.FeishuLoginCallback(w, httptest.NewRequest(http.MethodGet, "/auth/feishu/callback?code=bad&state=bad", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("callback without state cookie: %d", w.Code)
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
