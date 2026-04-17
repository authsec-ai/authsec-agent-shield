package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Config holds the shield configuration
type Config struct {
	// AuthSec connection
	AuthSecBaseURL string `json:"authsec_base_url"`  // e.g. https://prod.api.authsec.ai
	AuthSecIssuer  string `json:"authsec_issuer"`    // e.g. https://oauth.prod.authsec.ai
	ClientID       string `json:"client_id"`
	TenantID       string `json:"tenant_id"`
	TenantDomain   string `json:"tenant_domain"`

	// User session (populated after login)
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	UserEmail    string `json:"user_email,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	DeviceToken  string `json:"device_token,omitempty"` // Expo push token from mobile

	// Shield behavior
	Enabled          bool     `json:"enabled"`
	RiskThreshold    int      `json:"risk_threshold"`     // score above this triggers approval (default 30)
	ProtectedPaths   []string `json:"protected_paths"`    // directories to watch
	DangerousCommands []string `json:"dangerous_commands"` // commands that always need approval
	AutoApproveRead  bool     `json:"auto_approve_read"`  // skip approval for read-only ops
	PausedUntil      string   `json:"paused_until,omitempty"`

	// MCP proxy
	MCPProxyEnabled bool `json:"mcp_proxy_enabled"`
	MCPProxyPort    int  `json:"mcp_proxy_port"` // default 18900
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		AuthSecBaseURL: "https://prod.api.authsec.ai",
		AuthSecIssuer:  "https://oauth.prod.authsec.ai",
		Enabled:        true,
		RiskThreshold:  30,
		AutoApproveRead: true,
		MCPProxyEnabled: true,
		MCPProxyPort:    18900,
		// Only protect small, critical credential directories.
		// Large dirs like .config, C:\Windows, /var cause icacls/chattr to hang.
		ProtectedPaths: func() []string {
			return []string{
				filepath.Join(home, ".ssh"),
				filepath.Join(home, ".aws"),
				filepath.Join(home, ".kube"),
				filepath.Join(home, ".env"),
			}
		}(),
		// DangerousCommands are PATTERNS that are always high-risk.
		// These are NOT bare command names — "rm" alone is fine (the risk engine
		// scores based on arguments like -rf, sensitive paths, etc.)
		// Only put patterns here that are dangerous regardless of context.
		DangerousCommands: []string{
			// Filesystem — dangerous combos, not bare commands
			"rm -rf /", "rm -rf ~", "rm -rf *",
			"shred", "mkfs", "dd if=",
			// Git — force/destructive only
			"git push --force", "git push -f",
			"git reset --hard", "git clean -fd",
			// Container/infra — destructive subcommands
			"docker system prune", "docker rm -f",
			"kubectl delete namespace", "kubectl delete ns",
			"helm delete", "helm uninstall",
			"terraform destroy",
			// System
			"shutdown", "reboot", "halt", "poweroff",
			// Database — destructive SQL
			"DROP TABLE", "DROP DATABASE", "TRUNCATE TABLE", "DELETE FROM",
			// Cloud — destructive resource operations
			"aws s3 rm --recursive", "aws ec2 terminate",
			"gcloud compute instances delete",
			"az vm delete", "az group delete",
		},
	}
}

// ConfigDir returns the shield config directory
func ConfigDir() string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("LOCALAPPDATA")
		if appData != "" {
			return filepath.Join(appData, "authsec-shield")
		}
		return filepath.Join(home, ".authsec-shield")
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "authsec-shield")
	default:
		xdg := os.Getenv("XDG_CONFIG_HOME")
		if xdg != "" {
			return filepath.Join(xdg, "authsec-shield")
		}
		return filepath.Join(home, ".config", "authsec-shield")
	}
}

// ConfigPath returns the path to the config file
func ConfigPath() string {
	return filepath.Join(ConfigDir(), "config.json")
}

// Load reads config from disk, returns defaults if not found
func Load() (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

// Save writes config to disk
func (c *Config) Save() error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(ConfigPath(), data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// IsLoggedIn checks if we have valid credentials
func (c *Config) IsLoggedIn() bool {
	return c.AccessToken != ""
}
