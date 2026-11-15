package garmin

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Exercise the public client with an entirely synthetic SSO/OAuth service.
// Unexpected requests fail instead of reaching Garmin or the network.
func TestClientLoginWithMFA(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mode        string
		wantError   string
		wantPrompts int
	}{
		{name: "MFA success", wantPrompts: 1},
		{name: "non-MFA success", mode: "no-mfa"},
		{name: "retry rotates CSRF", mode: "retry", wantPrompts: 2},
		{name: "cancel", mode: "cancel", wantError: "cancelled", wantPrompts: 1},
		{name: "empty code", mode: "empty", wantError: "code is empty", wantPrompts: 1},
		{name: "no provider", mode: "nil", wantError: "code provider"},
		{name: "missing CSRF", mode: "no-csrf", wantError: "CSRF token"},
		{name: "retries bounded", mode: "rejected", wantError: "after 3 attempts", wantPrompts: 3},
		{name: "HTTP error", mode: "http-error", wantError: "HTTP 429", wantPrompts: 1},
		{name: "malformed response", mode: "malformed", wantError: "no title", wantPrompts: 1},
		{name: "session expired", mode: "expired", wantError: "session expired", wantPrompts: 1},
		{name: "missing ticket", mode: "no-ticket", wantError: "ticket not found", wantPrompts: 1},
		{name: "bad credentials", mode: "bad-password", wantError: "check credentials"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prompts, verifications, exchanges, preauthorized := 0, 0, 0, 0
			var signinQuery url.Values
			var lastSSOURL string
			originalTransport := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = originalTransport })
			http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				status, body := http.StatusOK, ""
				headers := make(http.Header)
				check := func(got, want, field string) {
					t.Helper()
					if got != want {
						t.Errorf("%s = %q; want %q", field, got, want)
					}
				}
				if r.URL.Host == "sso.garmin.com" {
					check(r.Header.Get("User-Agent"), ssoUserAgent, "user agent")
					if lastSSOURL != "" {
						check(r.Header.Get("Referer"), lastSSOURL, "referer")
						cookie, err := r.Cookie("session")
						if err != nil || cookie.Value != "test-session" {
							t.Fatal("SSO session cookie lost")
						}
					}
					lastSSOURL = r.URL.String()
				}
				switch r.URL.Host + r.URL.Path {
				case "thegarth.s3.amazonaws.com/oauth_consumer.json":
					body = `{"consumer_key":"test-key","consumer_secret":"test-secret"}`
				case "sso.garmin.com/sso/embed":
					headers.Add("Set-Cookie", "session=test-session; Path=/; Secure")
				case "sso.garmin.com/sso/signin":
					if r.Method == http.MethodGet {
						body = `<input name="_csrf" value="signin-csrf">`
						break
					}
					signinQuery = r.URL.Query()
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					check(r.PostForm.Get("username"), "test@example.com", "username")
					check(r.PostForm.Get("password"), "test-password", "password")
					check(r.PostForm.Get("_csrf"), "signin-csrf", "signin CSRF")
					body = `<title>Garmin Connect - MFA</title><input name="_csrf" value="challenge-0&amp;token">`
					if tc.mode == "no-mfa" {
						body = `<title>Success</title><a href="embed?ticket=test-ticket">`
					}
					if tc.mode == "no-csrf" {
						body = `<title>MFA</title>`
					}
					if tc.mode == "bad-password" {
						body = `<title>Sign In</title>`
					}
				case "sso.garmin.com/sso/verifyMFA/loginEnterMfaCode":
					check(r.Method, http.MethodPost, "MFA method")
					check(r.URL.Query().Encode(), signinQuery.Encode(), "MFA query")
					check(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded", "MFA content type")
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					check(r.PostForm.Get("_csrf"), fmt.Sprintf("challenge-%d&token", verifications), "challenge CSRF")
					check(r.PostForm.Get("mfa-code"), "012345", "code (leading zero preserved)")
					check(r.PostForm.Get("embed"), "true", "embed")
					check(r.PostForm.Get("fromPage"), "setupEnterMfaCode", "fromPage")
					if r.PostForm.Has("password") {
						t.Error("password resubmitted with MFA")
					}
					verifications++
					body = `<title>Success</title><a href="embed?ticket=test-ticket">`
					if tc.mode == "rejected" || tc.mode == "retry" && verifications == 1 {
						body = fmt.Sprintf(`<title>MFA</title><input name="_csrf" value="challenge-%d&amp;token">`, verifications)
					}
					switch tc.mode {
					case "http-error":
						status, body = 429, "secret-response 012345"
					case "malformed":
						body = "secret-response 012345"
					case "expired":
						body = "<title>Sign In</title>"
					case "no-ticket":
						body = "<title>Success</title>"
					}
				case "connectapi.garmin.com/oauth-service/oauth/preauthorized":
					preauthorized++
					check(r.URL.Query().Get("ticket"), "test-ticket", "ticket")
					check(r.URL.Query().Get("accepts-mfa-tokens"), "true", "accept MFA tokens")
					if !strings.HasPrefix(r.Header.Get("Authorization"), "OAuth ") {
						t.Error("missing OAuth signature")
					}
					body = "oauth_token=test-oauth1&oauth_token_secret=test-secret&mfa_token=test-mfa&mfa_expiration_timestamp=123"
				case "connectapi.garmin.com/oauth-service/oauth/exchange/user/2.0":
					exchanges++
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					check(r.PostForm.Get("mfa_token"), "test-mfa", "MFA token exchange")
					body = `{"access_token":"test-access","refresh_token":"test-refresh","expires_in":3600}`
				default:
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
				}
				return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			var provider MFACodeProvider = func(message string) (string, error) {
				prompts++
				if prompts > 1 && !strings.Contains(message, "did not accept") {
					t.Error("retry prompt does not explain rejection")
				}
				if tc.mode == "cancel" {
					return "", ErrMFACancelled
				}
				if tc.mode == "empty" {
					return " \t\n", nil
				}
				return " 012345\n", nil
			}
			if tc.mode == "nil" {
				provider = nil
			}
			dir := t.TempDir()
			client := NewClient(dir)
			err := client.LoginWithMFA("test@example.com", "test-password", provider)
			if prompts != tc.wantPrompts {
				t.Errorf("prompts = %d; want %d", prompts, tc.wantPrompts)
			}
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("error = %v; want %q", err, tc.wantError)
				}
				if strings.Contains(err.Error(), "012345") || strings.Contains(err.Error(), "secret-response") {
					t.Error("response leaked into error")
				}
				if tc.mode == "cancel" && !errors.Is(err, ErrMFACancelled) {
					t.Error("lost cancellation error")
				}
				if exchanges != 0 || preauthorized != 0 || client.OAuth1 != nil || client.OAuth2 != nil {
					t.Error("failed login continued into OAuth")
				}
				files, readErr := os.ReadDir(dir)
				if readErr != nil || len(files) != 0 {
					t.Error("failed login cached credentials")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if exchanges != 1 || client.OAuth2.AccessToken != "test-access" {
				t.Fatal("OAuth exchange not completed")
			}
			oauth1, _, err := LoadTokens(dir)
			if err != nil || oauth1.MFAToken != "test-mfa" {
				t.Fatal("MFA token not cached")
			}
			resumed := NewClient(dir)
			if err := resumed.Resume(); err != nil {
				t.Fatalf("resume: %v", err)
			}
			if exchanges != 1 {
				t.Error("valid cached session performed another exchange")
			}
			// Refresh must continue to send the stored MFA token without prompting.
			resumed.OAuth2.ExpiresAt = 1
			if err := SaveTokens(dir, nil, resumed.OAuth2); err != nil {
				t.Fatal(err)
			}
			if err := NewClient(dir).Resume(); err != nil {
				t.Fatalf("refresh: %v", err)
			}
			if exchanges != 2 || prompts != tc.wantPrompts {
				t.Error("refresh did not reuse cached MFA token")
			}
		})
	}
}
