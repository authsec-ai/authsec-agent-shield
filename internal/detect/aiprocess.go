package detect

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// Known AI tool process names — if any of these are in the parent process chain,
// the command is coming from an AI tool, not a human.
var aiProcessNames = []string{
	// Claude
	"claude", "claude-desktop", "claude-code",
	// OpenAI
	"codex", "chatgpt",
	// Cursor
	"cursor",
	// OpenClaw
	"openclaw",
	// MCP servers (Node.js based)
	"mcp-server",
	// Common agent runtimes
	"langchain", "crewai", "autogpt", "aider",
	// Generic indicators — AI tools often run through these
	// but only when spawned as child of an AI process
}

// IsAIInitiated checks if the current process was spawned by an AI tool
// by walking up the parent process tree.
//
// Returns true if an AI tool is detected in the ancestry.
// Returns false if it looks like a direct human command.
func IsAIInitiated() bool {
	// Check 1: Environment variables set by AI tools
	if isAIEnvironment() {
		return true
	}

	// Check 2: Check if we're in a non-interactive shell (AI tools use non-interactive)
	if isNonInteractiveShell() {
		// Non-interactive doesn't always mean AI — scripts, cron, etc.
		// But combined with parent process check, it's a strong signal.
		if hasAIParentProcess() {
			return true
		}
	}

	// Check 3: Walk parent process tree looking for known AI tool names
	if hasAIParentProcess() {
		return true
	}

	return false
}

// isAIEnvironment checks for environment variables that AI tools set
func isAIEnvironment() bool {
	aiEnvVars := []string{
		// Claude Code sets these
		"CLAUDE_CODE",
		"CLAUDE_SESSION",
		// Codex
		"CODEX_SESSION",
		"OPENAI_AGENT",
		// Cursor
		"CURSOR_SESSION",
		// OpenClaw
		"OPENCLAW_SESSION",
		"OPENCLAW_NODE",
		// MCP
		"MCP_SERVER_NAME",
		// Generic AI agent markers
		"AI_AGENT",
		"AGENT_FRAMEWORK",
		// authsec-shield's own MCP proxy sets this
		"AUTHSEC_SHIELD_MCP",
	}

	for _, env := range aiEnvVars {
		if os.Getenv(env) != "" {
			return true
		}
	}

	return false
}

// isNonInteractiveShell checks if the current shell is non-interactive
func isNonInteractiveShell() bool {
	// On Unix: check if stdin is a terminal
	if runtime.GOOS != "windows" {
		fi, err := os.Stdin.Stat()
		if err != nil {
			return false
		}
		// If stdin is a pipe or not a character device, it's non-interactive
		if fi.Mode()&os.ModeCharDevice == 0 {
			return true
		}
	}

	// Check common non-interactive indicators
	if os.Getenv("TERM") == "dumb" || os.Getenv("TERM") == "" {
		return true
	}

	return false
}

// hasAIParentProcess walks up the process tree looking for known AI tools
func hasAIParentProcess() bool {
	if runtime.GOOS == "windows" {
		return hasAIParentWindows()
	}
	return hasAIParentUnix()
}

// hasAIParentUnix checks parent processes on Linux/macOS via /proc or ps
func hasAIParentUnix() bool {
	pid := os.Getppid()

	// Walk up to 10 levels
	for i := 0; i < 10 && pid > 1; i++ {
		name := getProcessNameUnix(pid)
		if name == "" {
			break
		}

		lower := strings.ToLower(name)
		for _, ai := range aiProcessNames {
			if strings.Contains(lower, ai) {
				return true
			}
		}

		// Get parent of this process
		pid = getParentPIDUnix(pid)
	}

	return false
}

// hasAIParentWindows checks parent processes on Windows via WMI/tasklist
func hasAIParentWindows() bool {
	pid := os.Getppid()

	for i := 0; i < 10 && pid > 0; i++ {
		name := getProcessNameWindows(pid)
		if name == "" {
			break
		}

		lower := strings.ToLower(name)
		for _, ai := range aiProcessNames {
			if strings.Contains(lower, ai) {
				return true
			}
		}

		pid = getParentPIDWindows(pid)
	}

	return false
}

// ========================================
// Unix process helpers (read /proc)
// ========================================

func getProcessNameUnix(pid int) string {
	// Try /proc (Linux)
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err == nil {
		return strings.TrimSpace(string(data))
	}

	// Fallback: /proc/pid/cmdline
	data, err = os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err == nil {
		parts := strings.Split(string(data), "\x00")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	return ""
}

func getParentPIDUnix(pid int) int {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}

	// /proc/pid/stat format: pid (name) state ppid ...
	// Find the closing paren of the name, then parse ppid
	content := string(data)
	closeIdx := strings.LastIndex(content, ")")
	if closeIdx < 0 || closeIdx+2 >= len(content) {
		return 0
	}

	fields := strings.Fields(content[closeIdx+2:])
	if len(fields) < 2 {
		return 0
	}

	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return ppid
}

// ========================================
// Windows process helpers (uses wmic/PowerShell)
// ========================================

func getProcessNameWindows(pid int) string {
	// Use wmic to get process name — works on all Windows versions
	out, err := exec.Command("wmic", "process", "where",
		fmt.Sprintf("ProcessId=%d", pid),
		"get", "Name", "/value").Output()
	if err != nil {
		return getProcessNameWindowsFallback(pid)
	}

	// Parse "Name=process.exe" from output
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Name=") {
			name := strings.TrimPrefix(line, "Name=")
			name = strings.TrimSuffix(name, ".exe")
			name = strings.TrimSuffix(name, ".EXE")
			return strings.TrimSpace(name)
		}
	}

	return ""
}

func getProcessNameWindowsFallback(pid int) string {
	// Fallback: use tasklist
	out, err := exec.Command("tasklist", "/FI",
		fmt.Sprintf("PID eq %d", pid),
		"/FO", "CSV", "/NH").Output()
	if err != nil {
		return ""
	}

	// CSV: "process.exe","1234","Console","1","12,345 K"
	line := strings.TrimSpace(string(out))
	if strings.HasPrefix(line, "\"") {
		end := strings.Index(line[1:], "\"")
		if end > 0 {
			name := line[1 : end+1]
			name = strings.TrimSuffix(name, ".exe")
			return name
		}
	}
	return ""
}

func getParentPIDWindows(pid int) int {
	// Use wmic to get parent process ID
	out, err := exec.Command("wmic", "process", "where",
		fmt.Sprintf("ProcessId=%d", pid),
		"get", "ParentProcessId", "/value").Output()
	if err != nil {
		return 0
	}

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ParentProcessId=") {
			ppidStr := strings.TrimPrefix(line, "ParentProcessId=")
			ppid, err := strconv.Atoi(strings.TrimSpace(ppidStr))
			if err != nil {
				return 0
			}
			return ppid
		}
	}

	return 0
}
