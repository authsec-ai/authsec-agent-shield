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

// AuthURLResponse is returned by /oidc/auth-url
type AuthURLResponse struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"state"`
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
	baseURL  string
	clientID string
	httpClient *http.Client
}

// NewClient creates a new auth client
func NewClient(cfg *config.Config) *Client {
	return &Client{
		baseURL:  cfg.AuthSecBaseURL,
		clientID: cfg.ClientID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// InitiateLogin performs step 1+2:
// 1. Get device code (user_code for the user to enter after auth)
// 2. Get auth URL using client_id (OIDC login link)
// Returns both so the shield can show: "Open: [auth_url], Code: [user_code]"
func (c *Client) InitiateLogin() (*DeviceCodeResponse, *AuthURLResponse, error) {
	// Step 1: Get device code
	deviceResp, err := c.requestDeviceCode()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get device code: %w", err)
	}

	// Step 2: Get auth URL
	authResp, err := c.getAuthURL()
	if err != nil {
		return deviceResp, nil, fmt.Errorf("failed to get auth URL: %w", err)
	}

	return deviceResp, authResp, nil
}

// PollForToken polls the device token endpoint until the user completes authentication
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

		if result.Error == "authorization_pending" {
			continue
		}
		if result.Error == "slow_down" {
			interval += 5
			continue
		}
		if result.Error == "expired_token" {
			return nil, fmt.Errorf("login expired — user did not authenticate in time")
		}
		if result.Error != "" {
			return nil, fmt.Errorf("login failed: %s — %s", result.Error, result.ErrorDesc)
		}
		if result.AccessToken != "" {
			return &result, nil
		}
	}

	return nil, fmt.Errorf("login timed out")
}

// requestDeviceCode calls POST /auth/device/code
func (c *Client) requestDeviceCode() (*DeviceCodeResponse, error) {
	payload := map[string]interface{}{
		"scopes": []string{"openid", "email", "profile"},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/authsec/uflow/auth/device/code",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result DeviceCodeResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// getAuthURL calls POST /oidc/auth-url with client_id
func (c *Client) getAuthURL() (*AuthURLResponse, error) {
	payload := map[string]string{
		"client_id": c.clientID,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/authsec/uflow/oidc/auth-url",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result AuthURLResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Logout clears stored credentials
func Logout(cfg *config.Config) error {
	cfg.AccessToken = ""
	cfg.RefreshToken = ""
	cfg.UserEmail = ""
	cfg.UserID = ""
	return cfg.Save()
}
