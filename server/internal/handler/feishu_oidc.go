package handler

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/auth"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

const feishuStateCookie = "multica_feishu_oidc"
const feishuIDTokenCookie = "multica_feishu_id_token"

func feishuSafeNext(raw string) string {
	if raw == "" || len(raw) > 2048 || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n") {
		return ""
	}
	return raw
}

func (h *Handler) FeishuLoginStart(w http.ResponseWriter, r *http.Request) {
	if h.FeishuOIDC == nil {
		http.NotFound(w, r)
		return
	}
	state, err := auth.RandomOIDCValue()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start Feishu login")
		return
	}
	nonce, err := auth.RandomOIDCValue()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start Feishu login")
		return
	}
	verifier, err := auth.RandomOIDCValue()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start Feishu login")
		return
	}
	params := url.Values{}
	if next := feishuSafeNext(r.URL.Query().Get("next")); next != "" {
		params.Set("next", next)
	}
	if platform := r.URL.Query().Get("platform"); platform == "desktop" {
		params.Set("platform", platform)
	}
	// The web login page validates the CLI callback before handing out a token.
	// Bound the value and only permit loopback/private HTTP targets here too.
	if cb := r.URL.Query().Get("cli_callback"); len(cb) <= 512 && safeCliCallback(cb) {
		params.Set("cli_callback", cb)
	}
	if cliState := r.URL.Query().Get("cli_state"); cliState != "" && len(cliState) <= 512 && params.Has("cli_callback") {
		params.Set("cli_state", cliState)
	}
	silent := r.URL.Query().Get("silent") == "1"
	claims := jwt.MapClaims{"state": state, "nonce": nonce, "verifier": verifier, "next": params.Encode(), "silent": silent, "exp": time.Now().Add(10 * time.Minute).Unix()}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(auth.JWTSecret())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start Feishu login")
		return
	}
	redirect, err := h.FeishuOIDC.AuthorizationURL(state, nonce, auth.PKCEChallenge(verifier), silent)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start Feishu login")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: feishuStateCookie, Value: signed, Path: "/auth/feishu", MaxAge: 600, HttpOnly: true, Secure: strings.HasPrefix(h.FeishuOIDC.Config.RedirectURL, "https://"), SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, redirect, http.StatusFound)
}

func safeCliCallback(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Hostname() == "" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Is4() && (ip.IsPrivate() || ip.IsLoopback())
}

func (h *Handler) FeishuLoginCallback(w http.ResponseWriter, r *http.Request) {
	if h.FeishuOIDC == nil {
		http.NotFound(w, r)
		return
	}
	cookie, err := r.Cookie(feishuStateCookie)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Feishu login state missing")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: feishuStateCookie, Path: "/auth/feishu", MaxAge: -1, HttpOnly: true, Secure: strings.HasPrefix(h.FeishuOIDC.Config.RedirectURL, "https://"), SameSite: http.SameSiteLaxMode})
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (any, error) { return auth.JWTSecret(), nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	if err != nil || !token.Valid || r.URL.Query().Get("state") == "" || r.URL.Query().Get("state") != claims["state"] {
		writeError(w, http.StatusBadRequest, "invalid Feishu login state")
		return
	}
	if oidcError := r.URL.Query().Get("error"); oidcError != "" {
		silent, _ := claims["silent"].(bool)
		if silent && oidcError == "consent_required" {
			params, _ := claims["next"].(string)
			target := "/auth/feishu/start"
			if params != "" {
				target += "?" + params
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		if silent && (oidcError == "login_required" || oidcError == "interaction_required" || oidcError == "account_selection_required") {
			params, _ := claims["next"].(string)
			if params != "" {
				params += "&"
			}
			params += "sso_attempted=1"
			http.Redirect(w, r, h.FeishuOIDC.Config.AppURL+"/login?"+params, http.StatusFound)
			return
		}
		writeError(w, http.StatusUnauthorized, "Feishu login failed")
		return
	}
	nonce, _ := claims["nonce"].(string)
	verifier, _ := claims["verifier"].(string)
	identity, err := h.FeishuOIDC.Exchange(r.Context(), r.URL.Query().Get("code"), verifier, nonce)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Feishu identity verification failed")
		return
	}
	if err := auth.CheckSSOSession(r.Context(), identity.SID); err != nil {
		if errors.Is(err, auth.ErrSSORevoked) {
			writeError(w, http.StatusUnauthorized, "SSO session revoked")
		} else {
			writeError(w, http.StatusServiceUnavailable, "SSO session unavailable")
		}
		return
	}
	name := identity.Name
	if name == "" {
		name = "Feishu member"
	}
	user, err := h.Queries.CreateFeishuUser(r.Context(), db.CreateFeishuUserParams{Name: name, Email: identity.Email, OidcIssuer: pgtype.Text{String: identity.Issuer, Valid: true}, OidcSubject: pgtype.Text{String: identity.Subject, Valid: true}})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create Feishu account")
		return
	}
	jwtToken, err := h.issueJWTWithSSO(user, identity.SID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create Feishu session")
		return
	}
	if err := auth.SetAuthCookies(w, jwtToken); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create Feishu session")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: feishuIDTokenCookie, Value: identity.IDToken, Path: "/auth", MaxAge: int((30 * 24 * time.Hour).Seconds()), HttpOnly: true, Secure: strings.HasPrefix(h.FeishuOIDC.Config.RedirectURL, "https://"), SameSite: http.SameSiteLaxMode})
	next, _ := claims["next"].(string)
	target := h.FeishuOIDC.Config.AppURL + "/login"
	if next != "" {
		target += "?" + next
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (h *Handler) FeishuLoggedOut(w http.ResponseWriter, r *http.Request) {
	auth.ClearAuthCookies(w)
	h.clearFeishuIDTokenCookie(w)
	if h.FeishuOIDC == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	http.Redirect(w, r, h.FeishuOIDC.Config.AppURL+"/login?signed_out=1", http.StatusFound)
}

func (h *Handler) clearFeishuIDTokenCookie(w http.ResponseWriter) {
	secure := h.FeishuOIDC != nil && strings.HasPrefix(h.FeishuOIDC.Config.RedirectURL, "https://")
	http.SetCookie(w, &http.Cookie{Name: feishuIDTokenCookie, Path: "/auth", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
}

func (h *Handler) FeishuLogout(w http.ResponseWriter, r *http.Request) {
	if h.FeishuOIDC == nil {
		http.NotFound(w, r)
		return
	}
	cookie, err := r.Cookie(feishuIDTokenCookie)
	if err != nil || cookie.Value == "" {
		h.FeishuLoggedOut(w, r)
		return
	}
	redirect, err := url.Parse(h.FeishuOIDC.Config.RedirectURL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "logout unavailable")
		return
	}
	redirect.Path = "/auth/feishu/logged-out"
	redirect.RawQuery = ""
	issuer, err := url.Parse(h.FeishuOIDC.Config.Issuer)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "logout unavailable")
		return
	}
	issuer.Path = "/oauth2/sessions/logout"
	issuer.RawQuery = url.Values{"id_token_hint": {cookie.Value}, "post_logout_redirect_uri": {redirect.String()}}.Encode()
	h.clearFeishuIDTokenCookie(w)
	auth.ClearAuthCookies(w)
	http.Redirect(w, r, issuer.String(), http.StatusFound)
}
