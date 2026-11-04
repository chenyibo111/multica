package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestFeishuOIDCExchangeVerifiesIdentity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	claims := jwt.MapClaims{"aud": "multica-web", "sub": "fs_alice", "sid": "sid-a", "nonce": "nonce-a", "feishu_tenant_key": "tenant-a", "feishu_app_id": "app-a", "feishu_open_id": "ou_a", "feishu_user_id": "u_a", "email": "same@example.test", "name": "Alice", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if r.PostFormValue("code_verifier") != "verifier-a" {
				t.Error("PKCE verifier missing")
			}
			if claims["iss"] == nil {
				claims["iss"] = server.URL + "/"
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "key-a"
			signed, signErr := token.SignedString(key)
			if signErr != nil {
				t.Error(signErr)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": signed})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "key-a", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := FeishuOIDC{Config: FeishuOIDCConfig{Issuer: server.URL + "/", ClientID: "multica-web", RedirectURL: "http://localhost:8080/auth/feishu/callback", TokenURL: server.URL + "/token", JWKSURL: server.URL + "/jwks", TenantKey: "tenant-a", AppID: "app-a"}}
	identity, err := client.Exchange(context.Background(), "code-a", "verifier-a", "nonce-a")
	if err != nil || identity.Subject != "fs_alice" || identity.SID != "sid-a" || identity.Email != "same@example.test" {
		t.Fatalf("identity=%+v err=%v", identity, err)
	}
	claims["feishu_tenant_key"] = "tenant-b"
	if _, err := client.Exchange(context.Background(), "code-a", "verifier-a", "nonce-a"); err == nil {
		t.Fatal("accepted different Feishu tenant")
	}
	claims["feishu_tenant_key"] = "tenant-a"
	claims["nonce"] = "wrong"
	if _, err := client.Exchange(context.Background(), "code-a", "verifier-a", "nonce-a"); err == nil {
		t.Fatal("accepted wrong nonce")
	}
	claims["nonce"] = "nonce-a"
	for _, changed := range []struct {
		name  string
		value any
	}{
		{"aud", "other-client"}, {"feishu_app_id", "other-app"}, {"sid", ""}, {"iss", "https://wrong-issuer.example/"},
	} {
		original := claims[changed.name]
		claims[changed.name] = changed.value
		if _, err := client.Exchange(context.Background(), "code-a", "verifier-a", "nonce-a"); err == nil {
			t.Fatalf("accepted wrong %s", changed.name)
		}
		claims[changed.name] = original
	}
}

func TestLoadFeishuOIDCConfigRequiresCompleteValues(t *testing.T) {
	t.Setenv("FEISHU_OIDC_CLIENT_ID", "")
	if cfg, err := LoadFeishuOIDCConfig(); err != nil || cfg != nil {
		t.Fatalf("disabled config: %v %v", cfg, err)
	}
	t.Setenv("FEISHU_OIDC_CLIENT_ID", "multica-web")
	if _, err := LoadFeishuOIDCConfig(); err == nil {
		t.Fatal("partial config accepted")
	}
	for name, value := range map[string]string{
		"FEISHU_OIDC_ISSUER": "http://localhost:4444/", "FEISHU_OIDC_AUTH_URL": "http://localhost:4444/oauth2/auth", "FEISHU_OIDC_TOKEN_URL": "http://hydra:4444/oauth2/token", "FEISHU_OIDC_JWKS_URL": "http://hydra:4444/.well-known/jwks.json", "FEISHU_OIDC_REDIRECT_URL": "http://localhost:8080/auth/feishu/callback", "FEISHU_TENANT_KEY": "tenant-a", "FEISHU_APP_ID": "app-a", "FEISHU_SSO_STATUS_URL": "http://sso:9000/internal/session-status", "SSO_SERVICE_KEY": "01234567890123456789012345678901", "MULTICA_APP_URL": "http://localhost:3000",
	} {
		t.Setenv(name, value)
	}
	cfg, err := LoadFeishuOIDCConfig()
	if err != nil || cfg == nil || cfg.Issuer == cfg.TokenURL {
		t.Fatalf("public/internal endpoints lost: %v %v", cfg, err)
	}
}
