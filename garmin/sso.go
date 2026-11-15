package garmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/dghubble/oauth1"
)

const (
	oauthConsumerURL = "https://thegarth.s3.amazonaws.com/oauth_consumer.json"
	ssoUserAgent     = "com.garmin.android.apps.connectmobile"
)

var (
	csrfRe   = regexp.MustCompile(`name="_csrf"\s+value="(.+?)"`)
	titleRe  = regexp.MustCompile(`<title>(.+?)</title>`)
	ticketRe = regexp.MustCompile(`embed\?ticket=([^"]+)"`)
)

// ErrMFACancelled indicates that the user cancelled verification.
var ErrMFACancelled = errors.New("Garmin verification cancelled")

// MFACodeProvider requests a code when Garmin requires two-factor authentication.
// It runs on the login caller's goroutine. Return ErrMFACancelled to stop login.
// The message explains whether this is the first prompt or a retry.
type MFACodeProvider func(message string) (string, error)

type oauthConsumer struct {
	ConsumerKey    string `json:"consumer_key"`
	ConsumerSecret string `json:"consumer_secret"`
}

// ssoSession tracks cookies and the last response URL (for Referer headers)
// across the multi-step Garmin SSO flow.
type ssoSession struct {
	client  *http.Client
	lastURL string
}

func newSSOSession() *ssoSession {
	jar, _ := cookiejar.New(nil)
	return &ssoSession{
		client: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
		},
	}
}

func (s *ssoSession) get(reqURL string, useReferer bool) (string, error) {
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", ssoUserAgent)
	if useReferer && s.lastURL != "" {
		req.Header.Set("Referer", s.lastURL)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	s.lastURL = resp.Request.URL.String()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return string(body), nil
}

func (s *ssoSession) post(reqURL string, form url.Values, useReferer bool) (string, error) {
	req, err := http.NewRequest("POST", reqURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", ssoUserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if useReferer && s.lastURL != "" {
		req.Header.Set("Referer", s.lastURL)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	s.lastURL = resp.Request.URL.String()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return string(body), nil
}

// Login performs the full Garmin SSO login flow and returns OAuth tokens.
func Login(email, password, domain string) (*OAuth1Token, *OAuth2Token, error) {
	return LoginWithMFA(email, password, domain, nil)
}

// LoginWithMFA completes SSO, asking for a verification code only if required.
// A nil provider returns an error if the account requires MFA.
func LoginWithMFA(email, password, domain string, provider MFACodeProvider) (*OAuth1Token, *OAuth2Token, error) {
	if domain == "" {
		domain = "garmin.com"
	}

	// 1. Fetch OAuth consumer credentials from Garmin's S3 bucket
	consumer, err := fetchConsumer()
	if err != nil {
		return nil, nil, fmt.Errorf("fetch consumer: %w", err)
	}

	// 2. Start SSO session with cookie jar
	sess := newSSOSession()

	ssoBase := fmt.Sprintf("https://sso.%s", domain)
	ssoEmbed := ssoBase + "/sso/embed"

	embedParams := url.Values{
		"id":          {"gauth-widget"},
		"embedWidget": {"true"},
		"gauthHost":   {ssoBase + "/sso"},
	}
	signinParams := url.Values{
		"id":                              {"gauth-widget"},
		"embedWidget":                     {"true"},
		"gauthHost":                       {ssoEmbed},
		"service":                         {ssoEmbed},
		"source":                          {ssoEmbed},
		"redirectAfterAccountLoginUrl":    {ssoEmbed},
		"redirectAfterAccountCreationUrl": {ssoEmbed},
	}

	// 3. GET /sso/embed — set cookies
	_, err = sess.get(ssoEmbed+"?"+embedParams.Encode(), false)
	if err != nil {
		return nil, nil, fmt.Errorf("sso embed: %w", err)
	}

	// 4. GET /sso/signin — extract CSRF token
	signinURL := ssoBase + "/sso/signin?" + signinParams.Encode()
	body, err := sess.get(signinURL, true)
	if err != nil {
		return nil, nil, fmt.Errorf("sso signin page: %w", err)
	}

	csrf := csrfRe.FindStringSubmatch(body)
	if csrf == nil {
		return nil, nil, fmt.Errorf("CSRF token not found in signin page")
	}

	// 5. POST /sso/signin — submit credentials
	formData := url.Values{
		"username": {email},
		"password": {password},
		"embed":    {"true"},
		"_csrf":    {html.UnescapeString(csrf[1])},
	}

	body, err = sess.post(
		ssoBase+"/sso/signin?"+signinParams.Encode(),
		formData,
		true,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("sso login: %w", err)
	}

	// 6. Check result title
	titleMatch := titleRe.FindStringSubmatch(body)
	if titleMatch == nil {
		return nil, nil, fmt.Errorf("no title in response — login may have failed")
	}

	title := titleMatch[1]
	if strings.Contains(title, "MFA") {
		body, err = sess.verifyMFA(ssoBase, signinParams, body, provider)
		if err != nil {
			return nil, nil, err
		}
		// verifyMFA only returns a page whose title is Success.
		title = "Success"
	}
	if title != "Success" {
		return nil, nil, fmt.Errorf("login failed: %q (check credentials)", title)
	}

	// 7. Parse ticket from response
	ticketMatch := ticketRe.FindStringSubmatch(body)
	if ticketMatch == nil {
		return nil, nil, fmt.Errorf("ticket not found in response")
	}
	ticket := ticketMatch[1]

	// 8. Get OAuth1 token via OAuth1-signed request
	oauth1Token, err := getOAuth1Token(consumer, ticket, domain)
	if err != nil {
		return nil, nil, fmt.Errorf("oauth1 token: %w", err)
	}

	// 9. Exchange OAuth1 for OAuth2 Bearer token
	oauth2Token, err := exchangeOAuth2(consumer, oauth1Token, domain)
	if err != nil {
		return nil, nil, fmt.Errorf("oauth2 exchange: %w", err)
	}

	return oauth1Token, oauth2Token, nil
}

func (s *ssoSession) verifyMFA(ssoBase string, params url.Values, body string, provider MFACodeProvider) (string, error) {
	if provider == nil {
		return "", errors.New("Garmin requires a verification code; use LoginWithMFA with a code provider")
	}
	message := "Enter the verification code from Garmin (check your email or SMS)."
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Garmin may rotate the CSRF token after a rejected code. Always use
		// the latest challenge and the same cookie jar as the password login.
		csrf := csrfRe.FindStringSubmatch(body)
		if csrf == nil {
			return "", errors.New("CSRF token not found in Garmin verification page; try logging in again")
		}
		code, err := provider(message)
		if err != nil {
			return "", fmt.Errorf("MFA code entry: %w", err)
		}
		code = strings.TrimSpace(code)
		if code == "" {
			return "", errors.New("Garmin verification code is empty")
		}
		body, err = s.post(ssoBase+"/sso/verifyMFA/loginEnterMfaCode?"+params.Encode(), url.Values{
			"mfa-code": {code},
			"embed":    {"true"},
			"_csrf":    {html.UnescapeString(csrf[1])},
			"fromPage": {"setupEnterMfaCode"},
		}, true)
		if err != nil {
			return "", fmt.Errorf("Garmin verification failed: %w", err)
		}
		title := titleRe.FindStringSubmatch(body)
		if title == nil {
			return "", errors.New("no title in Garmin verification response; try logging in again")
		}
		if title[1] == "Success" {
			return body, nil
		}
		if !strings.Contains(title[1], "MFA") {
			return "", errors.New("Garmin verification failed or the session expired; try logging in again")
		}
		message = "Garmin did not accept that code. Enter a valid code, or cancel and log in again for a new one."
	}
	return "", errors.New("Garmin did not accept the verification code after 3 attempts; try logging in again")
}

// ExchangeForOAuth2 refreshes the OAuth2 token using an existing OAuth1 token.
func ExchangeForOAuth2(oauth1Token *OAuth1Token) (*OAuth2Token, error) {
	consumer, err := fetchConsumer()
	if err != nil {
		return nil, fmt.Errorf("fetch consumer: %w", err)
	}
	domain := oauth1Token.Domain
	if domain == "" {
		domain = "garmin.com"
	}
	return exchangeOAuth2(consumer, oauth1Token, domain)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func fetchConsumer() (*oauthConsumer, error) {
	resp, err := http.Get(oauthConsumerURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("consumer fetch HTTP %d", resp.StatusCode)
	}
	var c oauthConsumer
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func getOAuth1Token(consumer *oauthConsumer, ticket, domain string) (*OAuth1Token, error) {
	// OAuth1 signed with consumer-only (empty token)
	config := oauth1.NewConfig(consumer.ConsumerKey, consumer.ConsumerSecret)
	token := oauth1.NewToken("", "")
	httpClient := config.Client(context.Background(), token)
	httpClient.Timeout = 30 * time.Second

	apiBase := fmt.Sprintf("https://connectapi.%s", domain)
	loginURL := fmt.Sprintf("https://sso.%s/sso/embed", domain)
	reqURL := fmt.Sprintf(
		"%s/oauth-service/oauth/preauthorized?ticket=%s&login-url=%s&accepts-mfa-tokens=true",
		apiBase, url.QueryEscape(ticket), url.QueryEscape(loginURL),
	)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ssoUserAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("preauthorized HTTP %d: %s", resp.StatusCode,
			string(body[:min(300, len(body))]))
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("parse oauth1 response: %w", err)
	}

	return &OAuth1Token{
		OAuthToken:       values.Get("oauth_token"),
		OAuthTokenSecret: values.Get("oauth_token_secret"),
		MFAToken:         values.Get("mfa_token"),
		MFAExpiration:    values.Get("mfa_expiration_timestamp"),
		Domain:           domain,
	}, nil
}

func exchangeOAuth2(consumer *oauthConsumer, oauth1Token *OAuth1Token, domain string) (*OAuth2Token, error) {
	// OAuth1 signed with consumer + token
	config := oauth1.NewConfig(consumer.ConsumerKey, consumer.ConsumerSecret)
	token := oauth1.NewToken(oauth1Token.OAuthToken, oauth1Token.OAuthTokenSecret)
	httpClient := config.Client(context.Background(), token)
	httpClient.Timeout = 30 * time.Second

	apiBase := fmt.Sprintf("https://connectapi.%s", domain)
	reqURL := fmt.Sprintf("%s/oauth-service/oauth/exchange/user/2.0", apiBase)

	var bodyContent string
	if oauth1Token.MFAToken != "" {
		bodyContent = "mfa_token=" + url.QueryEscape(oauth1Token.MFAToken)
	}

	req, err := http.NewRequest("POST", reqURL, strings.NewReader(bodyContent))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ssoUserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("exchange HTTP %d: %s", resp.StatusCode,
			string(respBody[:min(300, len(respBody))]))
	}

	// Parse the exchange response (contains expires_in but not expires_at)
	var raw struct {
		Scope                 string `json:"scope"`
		Jti                   string `json:"jti"`
		TokenType             string `json:"token_type"`
		AccessToken           string `json:"access_token"`
		RefreshToken          string `json:"refresh_token"`
		ExpiresIn             int64  `json:"expires_in"`
		RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
	}
	if err := json.Unmarshal(respBody, &raw); err != nil {
		return nil, fmt.Errorf("parse oauth2: %w", err)
	}

	now := time.Now().Unix()
	return &OAuth2Token{
		Scope:                 raw.Scope,
		Jti:                   raw.Jti,
		TokenType:             raw.TokenType,
		AccessToken:           raw.AccessToken,
		RefreshToken:          raw.RefreshToken,
		ExpiresIn:             raw.ExpiresIn,
		ExpiresAt:             now + raw.ExpiresIn,
		RefreshTokenExpiresIn: raw.RefreshTokenExpiresIn,
		RefreshTokenExpiresAt: now + raw.RefreshTokenExpiresIn,
	}, nil
}
