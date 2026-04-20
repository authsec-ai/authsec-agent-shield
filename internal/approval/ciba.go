package approval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec-agent-shield/internal/config"
	"github.com/authsec-ai/authsec-agent-shield/internal/risk"
)

// Result is the outcome of an approval request
type Result struct {
	Approved bool
	Status   string // auto_approved, approved, denied, expired, timed_out
	Reason   string
}

// Client handles approval requests to the AuthSec Agent Guard API
type Client struct {
	cfg        *config.Config
	httpClient *http.Client
}

// NewClient creates a new approval client
func NewClient(cfg *config.Config) *Client {
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// RequestApproval sends an action to the AuthSec Agent Guard API and waits for human decision
func (c *Client) RequestApproval(eval *risk.Evaluation) (*Result, error) {
	resource := approvalResource(eval)

	// Build request — includes client_id for tenant resolution
	payload := map[string]interface{}{
		"client_id":       c.cfg.ClientID,
		"agent_id":        "authsec-shield",
		"agent_name":      "AuthSec Agent Shield",
		"agent_framework": "shield",
		"action":          eval.Action,
		"resource":        resource,
		"detail":          formatDetail(eval),
		"user_email":      c.cfg.UserEmail,
		"metadata": map[string]interface{}{
			"risk_score":  eval.Score,
			"risk_level":  string(eval.Level),
			"reasons":     eval.Reasons,
			"machine":     getMachineName(),
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Call evaluate endpoint
	req, err := http.NewRequest("POST",
		c.cfg.AuthSecBaseURL+"/authsec/uflow/agent/actions/evaluate",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.AccessToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call Agent Guard API: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Agent Guard response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Agent Guard API error %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var evalResp evaluateResponse
	if err := json.Unmarshal(respBody, &evalResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Auto-approved
	if evalResp.Status == "auto_approved" {
		return &Result{
			Approved: true,
			Status:   "auto_approved",
		}, nil
	}

	// Error
	if evalResp.Error != "" && evalResp.Error != "authorization_pending" {
		return &Result{
			Approved: false,
			Status:   "error",
			Reason:   evalResp.ErrorDescription,
		}, nil
	}

	// Needs human approval — poll
	interval := evalResp.Interval
	if interval < 3 {
		interval = 5
	}
	expiresIn := evalResp.ExpiresIn
	if expiresIn < 30 {
		expiresIn = 300
	}

	return c.pollForDecision(evalResp.ActionReqID, interval, expiresIn)
}

func (c *Client) pollForDecision(actionReqID string, interval, expiresIn int) (*Result, error) {
	deadline := time.Now().Add(time.Duration(expiresIn) * time.Second)

	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(interval) * time.Second)

		req, err := http.NewRequest("GET",
			fmt.Sprintf("%s/authsec/uflow/agent/actions/status?action_req_id=%s",
				c.cfg.AuthSecBaseURL, actionReqID),
			nil,
		)
		if err != nil {
			continue
		}
		if c.cfg.AccessToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.cfg.AccessToken)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			continue
		}

		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			continue
		}

		var status statusResponse
		if err := json.Unmarshal(respBody, &status); err != nil {
			continue
		}

		switch status.Status {
		case "approved", "auto_approved":
			return &Result{
				Approved: true,
				Status:   status.Status,
			}, nil

		case "denied":
			return &Result{
				Approved: false,
				Status:   "denied",
				Reason:   status.ErrorDescription,
			}, nil

		case "expired", "timed_out":
			return &Result{
				Approved: false,
				Status:   status.Status,
				Reason:   "No response from approver",
			}, nil
		}
		// Still pending, continue polling
	}

	return &Result{
		Approved: false,
		Status:   "timed_out",
		Reason:   "Approval request expired",
	}, nil
}

// ========================================
// Internal types
// ========================================

type evaluateResponse struct {
	ActionReqID      string `json:"action_req_id"`
	Status           string `json:"status"`
	RiskScore        int    `json:"risk_score"`
	RiskLevel        string `json:"risk_level"`
	ApprovalType     string `json:"approval_type"`
	ExpiresIn        int    `json:"expires_in"`
	Interval         int    `json:"interval"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type statusResponse struct {
	Status           string `json:"status"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func formatDetail(eval *risk.Evaluation) string {
	if len(eval.Reasons) == 0 {
		return eval.Action
	}
	detail := eval.Action
	for _, r := range eval.Reasons {
		detail += " | " + r
	}
	return detail
}

func approvalResource(eval *risk.Evaluation) string {
	if eval.Target != "" {
		return eval.Target
	}

	parts := strings.Fields(eval.Action)
	if len(parts) == 0 {
		return "unknown"
	}

	return parts[0]
}

func getMachineName() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}
