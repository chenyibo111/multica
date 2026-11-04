package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type FeishuOIDCConfig struct {
	Issuer, AuthorizationURL, TokenURL, JWKSURL string
	ClientID, RedirectURL, TenantKey, AppID     string
	StatusURL, ServiceKey, AppURL               string
}

// LoadFeishuOIDCConfig returns nil when the integration is disabled. A partial
// configuration is an error so it cannot accidentally admit an unverified user.
func LoadFeishuOIDCConfig() (*FeishuOIDCConfig, error) {
	clientID := strings.TrimSpace(os.Getenv("FEISHU_OIDC_CLIENT_ID"))
	if clientID == "" {
		return nil, nil
	}
	cfg := &FeishuOIDCConfig{
		Issuer:           os.Getenv("FEISHU_OIDC_ISSUER"),
		AuthorizationURL: os.Getenv("FEISHU_OIDC_AUTH_URL"),
		TokenURL:         os.Getenv("FEISHU_OIDC_TOKEN_URL"),
		JWKSURL:          os.Getenv("FEISHU_OIDC_JWKS_URL"),
		ClientID:         clientID,
		RedirectURL:      os.Getenv("FEISHU_OIDC_REDIRECT_URL"),
		TenantKey:        os.Getenv("FEISHU_TENANT_KEY"),
		AppID:            os.Getenv("FEISHU_APP_ID"),
		StatusURL:        os.Getenv("FEISHU_SSO_STATUS_URL"),
		ServiceKey:       os.Getenv("SSO_SERVICE_KEY"),
		AppURL:           strings.TrimRight(os.Getenv("MULTICA_APP_URL"), "/"),
	}
	if cfg.AppURL == "" {
		cfg.AppURL = strings.TrimRight(os.Getenv("FRONTEND_ORIGIN"), "/")
	}
	if cfg.Issuer == "" || cfg.AuthorizationURL == "" || cfg.TokenURL == "" || cfg.JWKSURL == "" || cfg.RedirectURL == "" || cfg.TenantKey == "" || cfg.AppID == "" || cfg.StatusURL == "" || len(cfg.ServiceKey) < 32 || cfg.AppURL == "" {
		return nil, errors.New("incomplete Feishu OIDC configuration")
	}
	for _, raw := range []string{cfg.Issuer, cfg.AuthorizationURL, cfg.TokenURL, cfg.JWKSURL, cfg.RedirectURL, cfg.StatusURL, cfg.AppURL} {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
			return nil, errors.New("invalid Feishu OIDC URL")
		}
	}
	return cfg, nil
}

type FeishuIdentity struct {
	Issuer, Subject, SID, Name, Email, TenantKey, AppID string
	IDToken                                             string
}

type FeishuOIDC struct {
	Config     FeishuOIDCConfig
	HTTPClient *http.Client
}

func (c FeishuOIDC) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 5 * time.Second}
}

func RandomOIDCValue() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func PKCEChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (c FeishuOIDC) AuthorizationURL(state, nonce, challenge string) (string, error) {
	u, err := url.Parse(c.Config.AuthorizationURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", c.Config.ClientID)
	q.Set("redirect_uri", c.Config.RedirectURL)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email feishu_identity")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c FeishuOIDC) Exchange(ctx context.Context, code, verifier, nonce string) (FeishuIdentity, error) {
	if code == "" || verifier == "" || nonce == "" {
		return FeishuIdentity{}, errors.New("missing OIDC callback value")
	}
	values := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {c.Config.ClientID}, "redirect_uri": {c.Config.RedirectURL}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Config.TokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return FeishuIdentity{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return FeishuIdentity{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return FeishuIdentity{}, fmt.Errorf("OIDC token exchange returned %d", resp.StatusCode)
	}
	var payload struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&payload); err != nil || payload.IDToken == "" {
		return FeishuIdentity{}, errors.New("OIDC token response has no ID token")
	}
	return c.verifyIDToken(ctx, payload.IDToken, nonce)
}

func (c FeishuOIDC) verifyIDToken(ctx context.Context, raw, nonce string) (FeishuIdentity, error) {
	keys, err := c.loadJWKS(ctx)
	if err != nil {
		return FeishuIdentity{}, err
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		key, ok := keys[kid]
		if !ok || kid == "" {
			return nil, errors.New("unknown OIDC signing key")
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(c.Config.Issuer), jwt.WithAudience(c.Config.ClientID), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(30*time.Second))
	if err != nil || !token.Valid {
		return FeishuIdentity{}, errors.New("invalid OIDC ID token")
	}
	stringClaim := func(name string) string { value, _ := claims[name].(string); return strings.TrimSpace(value) }
	if stringClaim("nonce") != nonce || !strings.HasPrefix(stringClaim("sub"), "fs_") || stringClaim("sid") == "" || stringClaim("feishu_tenant_key") != c.Config.TenantKey || stringClaim("feishu_app_id") != c.Config.AppID || stringClaim("feishu_open_id") == "" || stringClaim("feishu_user_id") == "" {
		return FeishuIdentity{}, errors.New("invalid Feishu identity claims")
	}
	return FeishuIdentity{Issuer: stringClaim("iss"), Subject: stringClaim("sub"), SID: stringClaim("sid"), Name: stringClaim("name"), Email: strings.ToLower(stringClaim("email")), TenantKey: stringClaim("feishu_tenant_key"), AppID: stringClaim("feishu_app_id"), IDToken: raw}, nil
}

func (c FeishuOIDC) loadJWKS(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Config.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS returned %d", resp.StatusCode)
	}
	var jwks struct {
		Keys []struct{ Kty, Kid, Alg, N, E string } `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&jwks); err != nil {
		return nil, err
	}
	out := map[string]*rsa.PublicKey{}
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Kid == "" || (key.Alg != "" && key.Alg != "RS256") {
			continue
		}
		nBytes, nErr := base64.RawURLEncoding.DecodeString(key.N)
		eBytes, eErr := base64.RawURLEncoding.DecodeString(key.E)
		if nErr != nil || eErr != nil || len(nBytes) < 256 || len(eBytes) == 0 || len(eBytes) > 4 {
			continue
		}
		exponent := new(big.Int).SetBytes(eBytes)
		if !exponent.IsInt64() || exponent.Int64() < 3 || exponent.Int64() > 1<<31-1 {
			continue
		}
		out[key.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(exponent.Int64())}
	}
	if len(out) == 0 {
		return nil, errors.New("OIDC JWKS has no usable RSA key")
	}
	return out, nil
}
