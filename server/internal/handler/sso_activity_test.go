package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/multica-ai/multica/server/internal/auth"
)

func TestRecordSSOActivityRequiresSignedSession(t *testing.T) {
	calls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer provider.Close()
	t.Setenv("FEISHU_SSO_STATUS_URL", provider.URL)
	t.Setenv("SSO_SERVICE_KEY", strings.Repeat("k", 32))
	h := &Handler{}
	request := func(ssoSID string, cookie bool) int {
		claims := jwt.MapClaims{"sub": "user-1", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
		if ssoSID != "" {
			claims["sso_sid"] = ssoSID
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(auth.JWTSecret())
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/api/auth/activity", nil)
		r.Header.Set("X-User-ID", "user-1")
		if cookie {
			r.AddCookie(&http.Cookie{Name: auth.AuthCookieName, Value: token})
		} else {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.RecordSSOActivity(w, r)
		return w.Code
	}
	if got := request("sid-1", false); got != http.StatusNoContent || calls != 1 {
		t.Fatalf("bearer activity: %d calls=%d", got, calls)
	}
	if got := request("", true); got != http.StatusNoContent || calls != 1 {
		t.Fatalf("non-SSO activity: %d calls=%d", got, calls)
	}
	if got := request("sid-1", true); got != http.StatusNoContent || calls != 2 {
		t.Fatalf("SSO activity: %d calls=%d", got, calls)
	}
}
