package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec-agent-shield/internal/config"
)

// DeviceCodeResponse is returned when initiating device flow login
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// TokenResponse is returned when device code is exchanged for tokens
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	UserEmail    string `json:"email,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	TenantID     string `json:"tenant_id,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	TenantDomain string `json:"tenant_domain,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorDesc    string `json:"error_description,omitempty"`
}

// Client handles AuthSec authentication
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new auth client
func NewClient(cfg *config.Config) *Client {
	return &Client{
		baseURL: cfg.AuthSecBaseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// InitiateDeviceLogin starts the device code flow (RFC 8628).
// No client_id or tenant config required — server resolves tenant from
// the user's browser session when they enter the code.
func (c *Client) InitiateDeviceLogin() (*DeviceCodeResponse, error) {
	payload := map[string]interface{}{
		"scopes": []string{"openid", "email", "profile"},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/authsec/uflow/auth/device/code",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate device login: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device login failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result DeviceCodeResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// PollForToken polls the token endpoint until the user completes authentication
func (c *Client) PollForToken(deviceCode string, interval, expiresIn int) (*TokenResponse, error) {
	if interval < 1 {
		interval = 5
	}

	deadline := time.Now().Add(time.Duration(expiresIn) * time.Second)

	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(interval) * time.Second)

		payload := map[string]string{
			"device_code": deviceCode,
			"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		}

		body, err := json.Marshal(payload)
		if err != nil {
			continue
		}

		resp, err := c.httpClient.Post(
			c.baseURL+"/authsec/uflow/auth/device/token",
			"application/json",
			bytes.NewBuffer(body),
		)
		if err != nil {
			continue
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var result TokenResponse
		if err := json.Unmarshal(respBody, &result); err != nil {
			continue
		}

		// Still waiting
		if result.Error == "authorization_pending" {
			continue
		}

		// Server asking us to back off — increase interval and keep polling
		if result.Error == "slow_down" {
			interval += 5
			continue
		}

		// Expired
		if result.Error == "expired_token" {
			return nil, fmt.Errorf("login expired — user did not authenticate in time")
		}

		// Error
		if result.Error != "" {
			return nil, fmt.Errorf("login failed: %s — %s", result.Error, result.ErrorDesc)
		}

		// Success
		if result.AccessToken != "" {
			return &result, nil
		}
	}

	return nil, fmt.Errorf("login timed out")
}

// Logout clears stored credentials
func Logout(cfg *config.Config) error {
	cfg.AccessToken = ""
	cfg.RefreshToken = ""
	cfg.UserEmail = ""
	cfg.UserID = ""
	return cfg.Save()
}
