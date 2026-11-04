package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"
)

var ErrSSORevoked = errors.New("SSO session revoked")
var ErrSSOUnavailable = errors.New("SSO session status unavailable")

// CheckSSOSession checks every SSO credential request against the provider's
// revocation store. The short timeout bounds the cost of an SSO outage.
func CheckSSOSession(ctx context.Context, sid string) error {
	statusURL, key := os.Getenv("FEISHU_SSO_STATUS_URL"), os.Getenv("SSO_SERVICE_KEY")
	if sid == "" {
		return ErrSSORevoked
	}
	if statusURL == "" || len(key) < 32 {
		return ErrSSOUnavailable
	}
	body, _ := json.Marshal(map[string]string{"sid": sid})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, statusURL, bytes.NewReader(body))
	if err != nil {
		return ErrSSOUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SSO-Service-Key", key)
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return ErrSSOUnavailable
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusUnauthorized:
		return ErrSSORevoked
	default:
		return ErrSSOUnavailable
	}
}
