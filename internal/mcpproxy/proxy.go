package mcpproxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/authsec-ai/authsec-agent-shield/internal/approval"
	"github.com/authsec-ai/authsec-agent-shield/internal/config"
	"github.com/authsec-ai/authsec-agent-shield/internal/risk"
)

// Proxy sits between an MCP client (Claude Desktop, Codex, Cursor) and an MCP server.
// It intercepts tool call requests, evaluates risk, requests approval if needed,
// then forwards or blocks the call.
//
// Usage: authsec-shield mcp-proxy -- <real-mcp-server-command>
//
// In claude_desktop_config.json, replace:
//   "command": "npx mcp-server-filesystem"
// With:
//   "command": "authsec-shield"
//   "args": ["mcp-proxy", "--", "npx", "mcp-server-filesystem"]
type Proxy struct {
	riskEngine     *risk.Engine
	approvalClient *approval.Client
	cfg            *config.Config
}

// NewProxy creates a new MCP proxy
func NewProxy(cfg *config.Config, riskEngine *risk.Engine, approvalClient *approval.Client) *Proxy {
	return &Proxy{
		riskEngine:     riskEngine,
		approvalClient: approvalClient,
		cfg:            cfg,
	}
}

// Run starts the MCP proxy, spawning the real server and piping stdio through
func (p *Proxy) Run(serverCmd []string) error {
	if len(serverCmd) == 0 {
		return fmt.Errorf("no server command provided")
	}

	// Set env var so any child processes (shell commands spawned by MCP tools)
	// are detected as AI-initiated by the shield's detect module
	os.Setenv("AUTHSEC_SHIELD_MCP", "1")

	// Start the real MCP server as a subprocess
	cmd := exec.Command(serverCmd[0], serverCmd[1:]...)
	cmd.Stderr = os.Stderr // Pass through stderr
	cmd.Env = append(os.Environ(), "AUTHSEC_SHIELD_MCP=1")

	serverStdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	serverStdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start MCP server: %w", err)
	}

	var wg sync.WaitGroup

	// Client (Claude/Codex) → us → real server
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.pipeClientToServer(os.Stdin, serverStdin)
		serverStdin.Close()
	}()

	// Real server → us → client
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.pipeServerToClient(serverStdout, os.Stdout)
	}()

	wg.Wait()
	return cmd.Wait()
}

// pipeClientToServer reads JSON-RPC messages from client, intercepts tool calls
func (p *Proxy) pipeClientToServer(client io.Reader, server io.Writer) {
	scanner := bufio.NewScanner(client)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer

	for scanner.Scan() {
		line := scanner.Text()

		// Try to parse as JSON-RPC
		var msg jsonRPCMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			// Not JSON, pass through
			fmt.Fprintln(server, line)
			continue
		}

		// Check if this is a tool call
		if p.isToolCall(&msg) {
			toolName, args := p.extractToolInfo(&msg)

			eval := p.riskEngine.EvaluateToolCall(toolName, args)

			if eval.Level != risk.LevelNone && eval.Score > p.cfg.RiskThreshold {
				fmt.Fprintf(os.Stderr, "[AuthSec Shield] Tool call intercepted: %s (risk: %d/%s)\n",
					toolName, eval.Score, eval.Level)
				fmt.Fprintf(os.Stderr, "[AuthSec Shield] Waiting for approval...\n")

				result, err := p.approvalClient.RequestApproval(eval)
				if err != nil || !result.Approved {
					reason := "approval failed"
					if result != nil {
						reason = result.Status + ": " + result.Reason
					}
					fmt.Fprintf(os.Stderr, "[AuthSec Shield] BLOCKED: %s\n", reason)

					// Send error response back to client
					p.sendErrorResponse(server, msg.ID, "Blocked by AuthSec Agent Shield: "+reason)
					continue
				}

				fmt.Fprintf(os.Stderr, "[AuthSec Shield] APPROVED\n")
			}
		}

		// Forward to real server
		fmt.Fprintln(server, line)
	}
}

// pipeServerToClient passes responses through unmodified
func (p *Proxy) pipeServerToClient(server io.Reader, client io.Writer) {
	scanner := bufio.NewScanner(server)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		fmt.Fprintln(client, scanner.Text())
	}
}

// isToolCall checks if a JSON-RPC message is a tool execution request
func (p *Proxy) isToolCall(msg *jsonRPCMessage) bool {
	if msg.Method == "" {
		return false
	}

	// MCP tool call methods
	toolMethods := []string{
		"tools/call",          // Standard MCP tool call
		"callTool",            // Alternative
		"execute",             // Generic
		"sampling/createMessage", // Sampling with tool use
	}

	for _, m := range toolMethods {
		if strings.EqualFold(msg.Method, m) {
			return true
		}
	}

	return false
}

// extractToolInfo gets the tool name and arguments from the message
func (p *Proxy) extractToolInfo(msg *jsonRPCMessage) (string, map[string]interface{}) {
	params, ok := msg.Params.(map[string]interface{})
	if !ok {
		return "unknown", nil
	}

	// Standard MCP: params.name and params.arguments
	name, _ := params["name"].(string)
	if name == "" {
		name, _ = params["tool"].(string)
	}
	if name == "" {
		name = msg.Method
	}

	args, _ := params["arguments"].(map[string]interface{})
	if args == nil {
		args, _ = params["params"].(map[string]interface{})
	}

	return name, args
}

// sendErrorResponse sends a JSON-RPC error back to the client
func (p *Proxy) sendErrorResponse(writer io.Writer, id interface{}, message string) {
	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    -32000,
			"message": message,
		},
	}
	data, _ := json.Marshal(resp)
	fmt.Fprintln(writer, string(data))
}

// ========================================
// JSON-RPC message structure
// ========================================

type jsonRPCMessage struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Method  string      `json:"method,omitempty"`
	Params  interface{} `json:"params,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

// ========================================
// Config patching helpers
// ========================================

// PatchClaudeDesktopConfig generates the config snippet for Claude Desktop
func PatchClaudeDesktopConfig(serverName string, originalCmd []string) string {
	shieldBin, _ := os.Executable()
	if shieldBin == "" {
		shieldBin = "authsec-shield"
	}

	args := append([]string{"mcp-proxy", "--"}, originalCmd...)
	argsJSON, _ := json.Marshal(args)

	return fmt.Sprintf(`{
  "mcpServers": {
    "%s": {
      "command": "%s",
      "args": %s
    }
  }
}`, serverName, strings.ReplaceAll(shieldBin, "\\", "\\\\"), string(argsJSON))
}
