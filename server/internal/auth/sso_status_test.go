package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckSSOSessionRevocationAndOutage(t *testing.T) {
	status := http.StatusNoContent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-SSO-Service-Key") != "01234567890123456789012345678901" {
			t.Error("missing service key")
		}
		w.WriteHeader(status)
	}))
	defer server.Close()
	t.Setenv("FEISHU_SSO_STATUS_URL", server.URL)
	t.Setenv("SSO_SERVICE_KEY", "01234567890123456789012345678901")
	if err := CheckSSOSession(context.Background(), "sid-a"); err != nil {
		t.Fatal(err)
	}
	status = http.StatusUnauthorized
	if err := CheckSSOSession(context.Background(), "sid-a"); !errors.Is(err, ErrSSORevoked) {
		t.Fatalf("revocation: %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := CheckSSOSession(context.Background(), "sid-a"); !errors.Is(err, ErrSSOUnavailable) {
		t.Fatalf("outage: %v", err)
	}
}
