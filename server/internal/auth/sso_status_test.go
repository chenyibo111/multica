package auth

import (
	"context"
	"encoding/json"
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
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["sid"] != "sid-a" || body["activity"] != nil {
			t.Errorf("status check added activity: %v %v", body, err)
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

func TestRecordSSOActivitySendsExplicitActivityFlag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			SID      string `json:"sid"`
			Activity bool   `json:"activity"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.SID != "sid-a" || !body.Activity {
			t.Errorf("activity payload: %+v %v", body, err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	t.Setenv("FEISHU_SSO_STATUS_URL", server.URL)
	t.Setenv("SSO_SERVICE_KEY", "01234567890123456789012345678901")
	if err := RecordSSOActivity(context.Background(), "sid-a"); err != nil {
		t.Fatal(err)
	}
}
