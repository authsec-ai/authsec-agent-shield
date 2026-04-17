package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/authsec-ai/authsec-agent-shield/internal/approval"
	"github.com/authsec-ai/authsec-agent-shield/internal/auth"
	"github.com/authsec-ai/authsec-agent-shield/internal/config"
	"github.com/authsec-ai/authsec-agent-shield/internal/fsprotect"
	"github.com/authsec-ai/authsec-agent-shield/internal/hooks"
	"github.com/authsec-ai/authsec-agent-shield/internal/kernel"
	"github.com/authsec-ai/authsec-agent-shield/internal/mcpproxy"
	"github.com/authsec-ai/authsec-agent-shield/internal/risk"
	"github.com/authsec-ai/authsec-agent-shield/internal/wrappers"
)

func main() {
	// ============================================================
	// SHIM MODE: If invoked as "rm", "git", "kubectl", etc.
	// (the shield binary replaced the real binary on the system)
	// ============================================================
	if isShim, cmdName := wrappers.IsShimInvocation(); isShim {
		runAsShim(cmdName)
		return
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "setup":
		cmdSetup()
	case "login":
		cmdLogin()
	case "logout":
		cmdLogout()
	case "status":
		cmdStatus()
	case "pause":
		cmdPause()
	case "enable":
		cmdEnable()
	case "doctor":
		cmdDoctor()
	case "install":
		cmdInstall()
	case "uninstall":
		cmdUninstall()
	case "check":
		cmdCheck()
	case "run":
		cmdRun()
	case "test":
		cmdTest()
	case "mcp-proxy":
		cmdMCPProxy()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`AuthSec Agent Shield — Protect your machine from risky AI tool actions

USAGE:
  authsec-shield <command> [options]

COMMANDS:
  setup              Configure shield with your tenant's client ID
  login              Authenticate with AuthSec (opens browser)
  logout             Clear stored credentials
  status             Show current shield status
  pause [duration]   Temporarily bypass enforcement, e.g. 15m or 1h
  enable             Re-enable enforcement immediately
  doctor [--fix]     Diagnose and optionally auto-repair protection gaps
  install            Install shell hooks + PATH wrappers + MCP proxy config
  uninstall          Fully remove shield and revert machine changes
  check <command>    Evaluate a command (used by hooks internally)
  run ...            Brokered command execution path used by wrappers
  test <command>     Test risk scoring manually
  mcp-proxy -- <cmd> Run as MCP proxy in front of another MCP server

FLOW:
  1. Run: ./install.sh
  2. Run: authsec-shield login
  3. Done — every risky AI action now needs your mobile approval`)
}

// ========================================
// setup — configure shield with tenant info
// ========================================

func cmdSetup() {
	cfg, err := config.Load()
	if err != nil {
		fatal("Failed to load config: %v", err)
	}

	// Parse flags
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--client-id":
			if i+1 < len(os.Args) {
				cfg.ClientID = os.Args[i+1]
				i++
			}
		case "--base-url":
			if i+1 < len(os.Args) {
				cfg.AuthSecBaseURL = os.Args[i+1]
				i++
			}
		case "--issuer":
			if i+1 < len(os.Args) {
				cfg.AuthSecIssuer = os.Args[i+1]
				i++
			}
		case "--tenant-id":
			if i+1 < len(os.Args) {
				cfg.TenantID = os.Args[i+1]
				i++
			}
		case "--tenant-domain":
			if i+1 < len(os.Args) {
				cfg.TenantDomain = os.Args[i+1]
				i++
			}
		case "--token":
			if i+1 < len(os.Args) {
				cfg.AccessToken = os.Args[i+1]
				i++
			}
		case "--email":
			if i+1 < len(os.Args) {
				cfg.UserEmail = os.Args[i+1]
				i++
			}
		}
	}

	if cfg.ClientID == "" {
		fatal("--client-id is required\nUsage: authsec-shield setup --client-id <id> --tenant-domain <domain> --base-url <url>")
	}

	if err := cfg.Save(); err != nil {
		fatal("Failed to save config: %v", err)
	}

	fmt.Println("Shield configured.")
	fmt.Printf("  Client ID:      %s\n", cfg.ClientID)
	fmt.Printf("  Tenant Domain:  %s\n", cfg.TenantDomain)
	fmt.Printf("  Base URL:       %s\n", cfg.AuthSecBaseURL)
	fmt.Printf("  Config at:      %s\n", config.ConfigPath())
	fmt.Println("\nNext: run 'authsec-shield login' to authenticate.")
}

// ========================================
// login — device code flow authentication
// ========================================

func cmdLogin() {
	cfg, err := config.Load()
	if err != nil {
		fatal("Failed to load config: %v", err)
	}

	if cfg.ClientID == "" {
		fatal("Not configured. Run 'authsec-shield setup --client-id <id> --base-url <url>' first.")
	}

	client := auth.NewClient(cfg)

	// Step 1+2: Get device code + auth URL
	fmt.Println("Initiating login...")
	deviceResp, authResp, err := client.InitiateLogin()
	if err != nil {
		fatal("Login failed: %v", err)
	}

	fmt.Println()
	fmt.Println("===========================================")
	fmt.Printf("  Open this URL to authenticate:\n")
	fmt.Println()
	if authResp != nil {
		fmt.Printf("  %s\n", authResp.AuthURL)
	} else {
		fmt.Printf("  %s\n", deviceResp.VerificationURI)
	}
	fmt.Println()
	fmt.Printf("  Then enter this code:  %s\n", deviceResp.UserCode)
	fmt.Println("===========================================")
	fmt.Println()
	fmt.Println("Waiting for you to authenticate and enter the code...")

	// Step 3: Poll for token (backend releases it after user authenticates + enters code)
	tokenResp, err := client.PollForToken(deviceResp.DeviceCode, deviceResp.Interval, deviceResp.ExpiresIn)
	if err != nil {
		fatal("Login failed: %v", err)
	}

	cfg.AccessToken = tokenResp.AccessToken
	cfg.RefreshToken = tokenResp.RefreshToken
	cfg.UserEmail = tokenResp.UserEmail
	cfg.UserID = tokenResp.UserID
	if tokenResp.TenantID != "" {
		cfg.TenantID = tokenResp.TenantID
	}
	if tokenResp.ClientID != "" {
		cfg.ClientID = tokenResp.ClientID
	}
	if tokenResp.TenantDomain != "" {
		cfg.TenantDomain = tokenResp.TenantDomain
	}

	if err := cfg.Save(); err != nil {
		fatal("Failed to save credentials: %v", err)
	}

	fmt.Printf("\nLogged in as: %s\n", cfg.UserEmail)
	fmt.Print("Activating protections... ")

	// Re-run install now that we have credentials — activates deferred
	// filesystem locks, kernel daemon, and anything else that needed a token.
	self, _ := os.Executable()
	activate := exec.Command("sudo", "-E", self, "install")
	if err := activate.Run(); err != nil {
		fmt.Println("warning")
		fmt.Fprintf(os.Stderr, "Could not activate protections automatically: %v\n", err)
		fmt.Fprintln(os.Stderr, "Run manually: sudo authsec-shield install")
		return
	}
	fmt.Println("done")
	fmt.Println("Shield is active. Every risky AI action now requires your approval.")
}

// ========================================
// logout
// ========================================

func cmdLogout() {
	cfg, err := config.Load()
	if err != nil {
		fatal("Failed to load config: %v", err)
	}

	if err := auth.Logout(cfg); err != nil {
		fatal("Logout failed: %v", err)
	}

	fmt.Println("Logged out. Shield is inactive until you login again.")
}

// ========================================
// status
// ========================================

func cmdStatus() {
	cfg, err := config.Load()
	if err != nil {
		fatal("Failed to load config: %v", err)
	}

	fmt.Println("AuthSec Agent Shield Status")
	fmt.Println("===========================")

	fmt.Printf("  Configured:  Yes (client: %s)\n", cfg.ClientID)

	if cfg.IsLoggedIn() {
		fmt.Printf("  Logged in:   Yes (%s)\n", cfg.UserEmail)
	} else {
		fmt.Println("  Logged in:   No")
		fmt.Println("\n  Run: authsec-shield login")
		return
	}

	fmt.Printf("  Enabled:     %v\n", cfg.Enabled)
	fmt.Printf("  Threshold:   %d (score above this needs approval)\n", cfg.RiskThreshold)
	if pausedUntil, active := pauseStatus(cfg); active {
		fmt.Printf("  Paused:      Yes (until %s)\n", pausedUntil.Local().Format(time.RFC1123))
	} else {
		fmt.Println("  Paused:      No")
	}
	fmt.Printf("  MCP Proxy:   %v\n", cfg.MCPProxyEnabled)
	fmt.Printf("  Config:      %s\n", config.ConfigPath())
}

func cmdPause() {
	cfg, err := config.Load()
	if err != nil {
		fatal("Failed to load config: %v", err)
	}

	duration := 15 * time.Minute
	if len(os.Args) >= 3 {
		duration, err = time.ParseDuration(os.Args[2])
		if err != nil || duration <= 0 {
			fatal("Invalid duration. Example: authsec-shield pause 15m")
		}
	}

	until := time.Now().Add(duration)
	cfg.PausedUntil = until.UTC().Format(time.RFC3339)
	if err := cfg.Save(); err != nil {
		fatal("Failed to save config: %v", err)
	}

	// Unlock filesystem protection during pause
	unlocked, _ := fsprotect.UnprotectPaths(cfg.ProtectedPaths)
	if unlocked > 0 {
		fmt.Printf("Filesystem unlocked: %d paths\n", unlocked)
	}

	fmt.Printf("Shield paused until %s\n", until.Local().Format(time.RFC1123))
	fmt.Println("All protections suspended. Run 'authsec-shield enable' to re-activate.")
}

func cmdEnable() {
	cfg, err := config.Load()
	if err != nil {
		fatal("Failed to load config: %v", err)
	}

	cfg.Enabled = true
	cfg.PausedUntil = ""
	if err := cfg.Save(); err != nil {
		fatal("Failed to save config: %v", err)
	}

	// Re-lock filesystem protection
	locked, _ := fsprotect.ProtectPaths(cfg.ProtectedPaths)
	if locked > 0 {
		fmt.Printf("Filesystem locked: %d paths\n", locked)
	}

	// Restart kernel daemon if available
	km := kernel.New(cfg.ProtectedPaths, cfg.AuthSecBaseURL, cfg.AccessToken)
	if err := km.Start(); err == nil {
		fmt.Println("Kernel daemon started.")
	}

	fmt.Println("Shield enabled. All protections active.")
}

func cmdDoctor() {
	// Check for --fix flag
	fix := false
	for _, arg := range os.Args[2:] {
		if arg == "--fix" {
			fix = true
		}
	}

	cfg, err := config.Load()
	if err != nil {
		fatal("Failed to load config: %v", err)
	}

	issues := 0
	fixed := 0

	label := "AuthSec Agent Shield — Doctor"
	if fix {
		label += " (--fix mode)"
	}
	fmt.Println(label)
	fmt.Println(strings.Repeat("=", len(label)))
	fmt.Println()

	// ── Config ──────────────────────────────────────────────────────────────
	fmt.Println("Config:")
	fmt.Printf("  File:      %s\n", config.ConfigPath())
	fmt.Printf("  Logged in: %v\n", cfg.IsLoggedIn())
	fmt.Printf("  Enabled:   %v\n", cfg.Enabled)
	if pausedUntil, active := pauseStatus(cfg); active {
		fmt.Printf("  Paused:    Yes (until %s)\n", pausedUntil.Local().Format(time.RFC1123))
	} else {
		fmt.Println("  Paused:    No")
	}
	if !cfg.IsLoggedIn() {
		fmt.Println("  ISSUE: Not logged in — run 'authsec-shield login'")
		issues++
	}

	// ── Binary shims ─────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("Binary Shims (OS-level interception):")
	shieldBin, _ := os.Executable()
	shims := wrappers.DiagnoseShims()
	shimOK := 0
	shimMiss := 0
	var brokenShims []string
	for _, s := range shims {
		if s.Installed {
			fmt.Printf("  OK    %-12s → %s\n", s.Command, s.ShimPath)
			shimOK++
		} else if s.Error == "not found on system" {
			// Not installed on this machine — not a problem
		} else {
			fmt.Printf("  MISS  %-12s — %s\n", s.Command, s.Error)
			shimMiss++
			issues++
			brokenShims = append(brokenShims, s.Command)
		}
	}
	fmt.Printf("  Active: %d  Missing: %d\n", shimOK, shimMiss)

	if shimMiss > 0 && fix {
		fmt.Println()
		fmt.Println("  [fix] Re-installing missing shims...")
		results, _ := wrappers.InstallShims(shieldBin)
		for _, r := range results {
			if r.Installed && containsStr(brokenShims, r.Command) {
				fmt.Printf("  FIXED %-12s → %s\n", r.Command, r.ShimPath)
				fixed++
			}
		}
	} else if shimMiss > 0 {
		fmt.Println("  → Fix: authsec-shield doctor --fix  (requires sudo/admin)")
	}

	// ── Orphaned backups (real binary backed up but shim not in place) ────────
	fmt.Println()
	fmt.Println("Orphaned Backups (backup exists but shim missing):")
	orphans := wrappers.FindOrphanedBackups()
	if len(orphans) == 0 {
		fmt.Println("  None")
	}
	for _, o := range orphans {
		fmt.Printf("  ORPHAN  %s  (backup: %s)\n", o.Command, o.BackupPath)
		issues++
		if fix {
			if err := wrappers.RepairOrphan(o, shieldBin); err != nil {
				fmt.Printf("  FAIL    could not repair: %v\n", err)
			} else {
				fmt.Printf("  FIXED   shim placed at %s\n", o.ShimPath)
				fixed++
			}
		}
	}

	// ── Filesystem protection ────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("Filesystem Protection:")
	fsStatus := fsprotect.DiagnoseProtection(cfg.ProtectedPaths)
	fsOK := 0
	fsMiss := 0
	var unprotectedPaths []string
	for _, s := range fsStatus {
		if !s.Exists {
			fmt.Printf("  SKIP  %s  (does not exist)\n", s.Path)
			continue
		}
		if s.Protected {
			fmt.Printf("  LOCKED  %s\n", s.Path)
			fsOK++
		} else {
			fmt.Printf("  OPEN    %s\n", s.Path)
			fsMiss++
			issues++
			unprotectedPaths = append(unprotectedPaths, s.Path)
		}
	}
	fmt.Printf("  Locked: %d  Open: %d\n", fsOK, fsMiss)

	if fsMiss > 0 && fix {
		fmt.Println()
		fmt.Println("  [fix] Re-applying filesystem write protection...")
		for _, p := range unprotectedPaths {
			if err := fsprotect.ProtectPath(p); err != nil {
				fmt.Printf("  FAIL  %s: %v\n", p, err)
			} else {
				fmt.Printf("  FIXED %s\n", p)
				fixed++
			}
		}
	} else if fsMiss > 0 {
		fmt.Println("  → Fix: authsec-shield doctor --fix  (requires admin)")
	}

	// ── Shell hooks ──────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("Shell Hooks:")
	hookStatus := hooks.DiagnoseHooks()
	hooksOK := 0
	hooksMiss := 0
	for shell, installed := range hookStatus {
		if installed {
			fmt.Printf("  OK    %s\n", shell)
			hooksOK++
		} else {
			fmt.Printf("  MISS  %s\n", shell)
			hooksMiss++
			issues++
		}
	}
	fmt.Printf("  Active: %d  Missing: %d\n", hooksOK, hooksMiss)

	if hooksMiss > 0 && fix {
		fmt.Println()
		fmt.Println("  [fix] Re-installing shell hooks...")
		shells, err := hooks.Install()
		if err != nil {
			fmt.Printf("  FAIL  %v\n", err)
		} else {
			for _, s := range shells {
				fmt.Printf("  FIXED %s\n", s)
				fixed++
			}
		}
	} else if hooksMiss > 0 {
		fmt.Println("  → Fix: authsec-shield doctor --fix")
	}

	// ── Kernel daemon ────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("Kernel Protection Daemon:")
	km := kernel.New(cfg.ProtectedPaths, cfg.AuthSecBaseURL, cfg.AccessToken)
	kst := km.GetStatus()
	if !kst.Available {
		fmt.Printf("  NOT INSTALLED  (%s)\n", kst.Method)
		fmt.Println("  Optional but recommended — catches Python/Node/shell-redirect writes")
		if runtime.GOOS == "linux" {
			fmt.Println("  Install: make -C kernel/linux/fanotify install")
		} else if runtime.GOOS == "windows" {
			fmt.Println("  Install: build kernel/windows/minifilter/ with WDK")
		}
	} else if kst.Running {
		fmt.Printf("  RUNNING  %s\n", kst.Message)
	} else {
		fmt.Printf("  STOPPED  %s\n", kst.Message)
		issues++
		if fix {
			fmt.Println("  [fix] Starting kernel daemon...")
			if err := km.Start(); err != nil {
				fmt.Printf("  FAIL  %v\n", err)
			} else {
				fmt.Println("  FIXED kernel daemon started")
				fixed++
			}
		} else {
			fmt.Println("  → Fix: authsec-shield doctor --fix")
		}
	}

	// ── Summary ──────────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println(strings.Repeat("─", 40))
	if fix {
		fmt.Printf("Issues found: %d  Fixed: %d  Remaining: %d\n", issues, fixed, issues-fixed)
		remaining := issues - fixed
		if remaining > 0 {
			fmt.Println()
			fmt.Println("Some issues could not be auto-fixed:")
			if runtime.GOOS == "windows" {
				fmt.Println("  → Re-run in an elevated (Run as Administrator) PowerShell")
			} else {
				fmt.Println("  → Re-run with: sudo authsec-shield doctor --fix")
			}
		} else if issues > 0 {
			fmt.Println("All issues fixed.")
		} else {
			fmt.Println("No issues found.")
		}
	} else {
		if issues == 0 {
			fmt.Println("No issues found. Shield is fully operational.")
		} else {
			fmt.Printf("%d issue(s) found. Run 'authsec-shield doctor --fix' to auto-repair.\n", issues)
		}
	}

	fmt.Println()
	fmt.Println("Tips:")
	fmt.Println("  authsec-shield pause 1h    — bypass for 1 hour (your own work)")
	fmt.Println("  authsec-shield mcp-proxy   — proxy for Claude Desktop/Codex MCP tools")
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// ========================================
// install — hooks + wrappers + MCP config
// ========================================

func cmdInstall() {
	// Set env var so the shield's own hooks don't intercept install operations
	os.Setenv("AUTHSEC_SHIELD_ACTIVE", "1")

	cfg, err := config.Load()
	if err != nil {
		fatal("Failed to load config: %v", err)
	}

	if !cfg.IsLoggedIn() {
		fmt.Println("  NOTE: Not logged in — bootstrap mode.")
		fmt.Println("  Installing shims and hooks only; active filesystem/kernel enforcement starts after login.")
		fmt.Println()
	}

	shieldBin, _ := os.Executable()
	if shieldBin == "" {
		shieldBin = "authsec-shield"
	}

	fmt.Println("AuthSec Agent Shield — Installing")
	fmt.Println("==================================")
	fmt.Println()
	fmt.Println("This will replace system binaries with shield shims.")
	fmt.Println("Requires elevated privileges (sudo / Run as Administrator).")
	fmt.Println()

	// 1. OS-level binary shims (the core protection — un-bypassable)
	fmt.Println("[1/5] Installing OS-level binary shims...")
	results, err := wrappers.InstallShims(shieldBin)
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
	}

	installed := 0
	failed := 0
	skipped := 0
	for _, r := range results {
		if r.Installed {
			fmt.Printf("  OK    %-12s → %s\n", r.Command, r.ShimPath)
			installed++
		} else if r.Error == "not found on system" {
			skipped++
		} else {
			fmt.Printf("  FAIL  %-12s — %s\n", r.Command, r.Error)
			failed++
		}
	}
	fmt.Printf("  Installed: %d  Skipped: %d  Failed: %d\n", installed, skipped, failed)

	if failed > 0 {
		fmt.Println()
		fmt.Println("  Some shims failed. This usually means you need elevated privileges:")
		if runtime.GOOS == "windows" {
			fmt.Println("    → Right-click terminal → Run as Administrator → re-run install")
		} else {
			fmt.Println("    → sudo authsec-shield install")
		}
	}

	// 2. Filesystem write protection (NTFS ACL deny / Unix immutable)
	fmt.Println()
	fmt.Println("[2/5] Locking filesystem write protection on sensitive paths...")
	if cfg.IsLoggedIn() {
		fsCount, fsErrs := fsprotect.ProtectPaths(cfg.ProtectedPaths)
		fmt.Printf("  Protected: %d paths\n", fsCount)
		for _, e := range fsErrs {
			fmt.Printf("  WARN  %v\n", e)
		}
		if fsCount > 0 {
			fmt.Println("  Kernel-enforced: no process can write to these paths without approval.")
			fmt.Println("  Use 'authsec-shield pause 1h' to temporarily unlock for your own work.")
		}
	} else {
		fmt.Println("  skipped (login required before active filesystem locks)")
	}

	// 3. Shell hooks (additional layer — catches things shims might miss)
	fmt.Println()
	fmt.Println("[3/5] Installing shell hooks...")
	shells, err := hooks.Install()
	if err != nil {
		fmt.Printf("  warning: %v\n", err)
	} else if len(shells) > 0 {
		fmt.Printf("  OK    %s\n", strings.Join(shells, ", "))
	} else {
		fmt.Println("  no shells detected")
	}

	// 4. Kernel-level protection daemon (deepest layer — catches MSYS2, Python, Node, etc.)
	fmt.Println()
	fmt.Println("[4/5] Starting kernel protection daemon...")
	if cfg.IsLoggedIn() {
		km := kernel.New(cfg.ProtectedPaths, cfg.AuthSecBaseURL, cfg.AccessToken)
		if err := km.Start(); err != nil {
			fmt.Printf("  WARN  %v\n", err)
			fmt.Println("  Kernel protection is optional — shim layer remains active.")
			fmt.Println("  Install the kernel daemon to protect against Python/Node/redirect writes:")
			if runtime.GOOS == "linux" {
				fmt.Println("    make -C kernel/linux/fanotify install")
			} else if runtime.GOOS == "windows" {
				fmt.Println("    Build kernel/windows/minifilter/ with WDK, then run install.ps1")
			}
		} else {
			kst := km.GetStatus()
			fmt.Printf("  OK    kernel daemon running (%s)\n", kst.Method)
		}
	} else {
		fmt.Println("  skipped (login required before kernel daemon can request approvals)")
	}

	// 5. MCP proxy instructions
	fmt.Println()
	fmt.Println("[5/5] MCP Proxy (for Claude Desktop, Codex, Cursor)")
	fmt.Println()
	fmt.Println("  To protect MCP tool calls, update claude_desktop_config.json:")
	fmt.Printf("    \"command\": \"%s\",\n", strings.ReplaceAll(shieldBin, "\\", "\\\\"))
	fmt.Println(`    "args": ["mcp-proxy", "--", "<original-command>", "<original-args>"]`)

	// Summary
	fmt.Println()
	fmt.Println("==================================")
	if cfg.IsLoggedIn() {
		fmt.Printf("Shield active for: %s\n", cfg.UserEmail)
	} else {
		fmt.Println("Shield bootstrap installed.")
		fmt.Println("  Run: authsec-shield login")
	}
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  authsec-shield pause 1h    — pause for 1 hour (your commands pass through)")
	fmt.Println("  authsec-shield enable      — re-enable immediately")
	fmt.Println("  authsec-shield doctor      — check installation health")
	fmt.Println("  authsec-shield uninstall   — fully remove shield and revert changes")
}

// ========================================
// uninstall
// ========================================

func cmdUninstall() {
	fmt.Println("AuthSec Agent Shield — Uninstalling")
	fmt.Println("====================================")
	fmt.Println()

	// 0. Stop kernel daemon + unlock filesystem protection first.
	cfg, _ := config.Load()
	if cfg != nil {
		km := kernel.New(cfg.ProtectedPaths, cfg.AuthSecBaseURL, cfg.AccessToken)
		if err := km.Stop(); err == nil {
			fmt.Println("Kernel daemon stopped.")
		}

		unlocked, _ := fsprotect.UnprotectPaths(cfg.ProtectedPaths)
		if unlocked > 0 {
			fmt.Printf("Filesystem unlocked: %d paths\n", unlocked)
			fmt.Println()
		}
	}

	// 1. Restore original binaries
	fmt.Println("[1/7] Restoring original binaries...")
	results, err := wrappers.UninstallShims()
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
	}

	restored := 0
	for _, r := range results {
		if r.Error == "" {
			fmt.Printf("  OK    %-12s restored\n", r.Command)
			restored++
		} else if r.Error != "not found" && r.Error != "no backup found (not shimmed?)" {
			fmt.Printf("  FAIL  %-12s — %s\n", r.Command, r.Error)
		}
	}
	fmt.Printf("  Restored: %d binaries\n", restored)

	// 2. Remove shell hooks
	fmt.Println()
	fmt.Println("[2/7] Removing shell hooks...")
	if err := hooks.Uninstall(); err != nil {
		fmt.Printf("  warning: %v\n", err)
	} else {
		fmt.Println("  done")
	}
	for _, home := range targetHomes() {
		if err := hooks.UninstallForHome(home); err != nil {
			fmt.Printf("  warning: %s: %v\n", home, err)
		}
	}

	// 3. Remove PATH wrapper directory
	fmt.Println()
	fmt.Println("[3/7] Removing wrapper directories...")
	if err := wrappers.Uninstall(); err != nil {
		fmt.Printf("  warning: %v\n", err)
	} else {
		fmt.Printf("  removed %s\n", wrappers.WrapperDir())
	}
	for _, home := range targetHomes() {
		dir := wrappers.WrapperDirForHome(home)
		if err := os.RemoveAll(filepath.Dir(dir)); err == nil {
			fmt.Printf("  removed %s\n", filepath.Dir(dir))
		}
	}
	wrappers.CleanupLegacyWrappers()

	// 4. Remove kernel services, daemons, and support files.
	fmt.Println()
	fmt.Println("[4/7] Removing kernel services and support files...")
	if cfg != nil {
		km := kernel.New(cfg.ProtectedPaths, cfg.AuthSecBaseURL, cfg.AccessToken)
		errs := km.CleanupInstalledArtifacts()
		if len(errs) == 0 {
			fmt.Println("  done")
		} else {
			for _, err := range errs {
				fmt.Printf("  warning: %v\n", err)
			}
		}
	} else {
		fmt.Println("  skipped (config unavailable)")
	}

	// 5. Revert MCP proxy entries where we can reconstruct the original command.
	fmt.Println()
	fmt.Println("[5/7] Reverting MCP proxy config entries...")
	reverted, warnings := revertMCPProxyConfigs()
	for _, warning := range warnings {
		fmt.Printf("  warning: %s\n", warning)
	}
	fmt.Printf("  Reverted: %d config file(s)\n", reverted)

	// 6. Remove AuthSec config/state directories.
	fmt.Println()
	fmt.Println("[6/7] Removing AuthSec Shield config/state...")
	removedDirs := removeConfigState()
	for _, dir := range removedDirs {
		fmt.Printf("  removed %s\n", dir)
	}
	if len(removedDirs) == 0 {
		fmt.Println("  nothing found")
	}

	if runtime.GOOS == "windows" {
		fmt.Println()
		fmt.Println("[7/8] Reverting Windows machine PATH...")
		if err := removeWindowsPathEntries(); err != nil {
			fmt.Printf("  warning: %v\n", err)
		} else {
			fmt.Println("  done")
		}
	}

	// Remove installed shield binaries last, after shims have been restored.
	fmt.Println()
	if runtime.GOOS == "windows" {
		fmt.Println("[8/8] Removing installed shield binary...")
	} else {
		fmt.Println("[7/7] Removing installed shield binary...")
	}
	removedBins, binWarnings := removeInstalledBinaries()
	for _, warning := range binWarnings {
		fmt.Printf("  warning: %s\n", warning)
	}
	for _, bin := range removedBins {
		fmt.Printf("  removed %s\n", bin)
	}
	if len(removedBins) == 0 {
		fmt.Println("  nothing found")
	}

	fmt.Println()
	fmt.Println("Shield uninstalled. System binaries, hooks, services, config, and installed files were removed where accessible.")
}

func removeConfigState() []string {
	candidates := []string{
		config.ConfigDir(),
		filepath.Join(homeDir(), ".authsec-shield"),
	}
	for _, home := range targetHomes() {
		candidates = append(candidates,
			filepath.Join(home, ".config", "authsec-shield"),
			filepath.Join(home, ".authsec-shield"),
		)
	}
	if runtime.GOOS == "windows" {
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			candidates = append(candidates, filepath.Join(localAppData, "authsec-shield"))
		}
		if programData := os.Getenv("ProgramData"); programData != "" {
			candidates = append(candidates, filepath.Join(programData, "AuthSec", "Shield"))
		}
	}

	var removed []string
	seen := make(map[string]bool)
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		clean := filepath.Clean(dir)
		if seen[strings.ToLower(clean)] {
			continue
		}
		seen[strings.ToLower(clean)] = true
		if _, err := os.Stat(clean); os.IsNotExist(err) {
			continue
		}
		if err := os.RemoveAll(clean); err == nil {
			removed = append(removed, clean)
		}
	}
	return removed
}

func removeInstalledBinaries() ([]string, []string) {
	candidates := []string{}
	if exe, err := os.Executable(); err == nil && strings.Contains(strings.ToLower(filepath.Base(exe)), "authsec-shield") {
		candidates = append(candidates, exe)
	}

	switch runtime.GOOS {
	case "windows":
		if programFiles := os.Getenv("ProgramFiles"); programFiles != "" {
			candidates = append(candidates,
				filepath.Join(programFiles, "AuthSec", "Shield", "authsec-shield.exe"),
				filepath.Join(programFiles, "AuthSec", "Shield", "AuthSecShieldBridge.exe"),
				filepath.Join(programFiles, "AuthSec", "Shield", "AuthSecShield.sys"),
			)
		}
	default:
		candidates = append(candidates,
			"/usr/local/bin/authsec-shield",
			"/usr/bin/authsec-shield",
			"/opt/authsec-shield/authsec-shield",
		)
	}

	var removed []string
	var warnings []string
	seen := make(map[string]bool)
	for _, path := range candidates {
		if path == "" {
			continue
		}
		clean := filepath.Clean(path)
		key := strings.ToLower(clean)
		if seen[key] {
			continue
		}
		seen[key] = true
		if _, err := os.Stat(clean); os.IsNotExist(err) {
			continue
		}
		if err := os.Remove(clean); err != nil {
			warnings = append(warnings, fmt.Sprintf("remove %s: %v", clean, err))
			continue
		}
		removed = append(removed, clean)
	}

	if runtime.GOOS == "windows" {
		if programFiles := os.Getenv("ProgramFiles"); programFiles != "" {
			shieldDir := filepath.Join(programFiles, "AuthSec", "Shield")
			if err := os.RemoveAll(shieldDir); err == nil {
				removed = append(removed, shieldDir)
			}
			authsecDir := filepath.Join(programFiles, "AuthSec")
			if err := os.Remove(authsecDir); err == nil {
				removed = append(removed, authsecDir)
			}
		}
	}
	return removed, warnings
}

func removeWindowsPathEntries() error {
	if runtime.GOOS != "windows" {
		return nil
	}
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		return nil
	}
	installDir := filepath.Join(programFiles, "AuthSec", "Shield")
	ps := fmt.Sprintf(`$dir = %q; $path = [Environment]::GetEnvironmentVariable("Path", "Machine"); if ($null -ne $path) { $parts = $path -split ';' | Where-Object { $_ -and ($_.TrimEnd('\') -ine $dir.TrimEnd('\')) }; [Environment]::SetEnvironmentVariable("Path", ($parts -join ';'), "Machine") }`, installDir)
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s — %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

func revertMCPProxyConfigs() (int, []string) {
	var reverted int
	var warnings []string
	for _, path := range mcpConfigPaths() {
		changed, err := revertMCPProxyConfig(path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		if changed {
			reverted++
		}
	}
	return reverted, warnings
}

func mcpConfigPaths() []string {
	home := homeDir()
	var paths []string
	switch runtime.GOOS {
	case "darwin":
		paths = append(paths,
			filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, "Library", "Application Support", "Cursor", "User", "mcp.json"),
		)
	case "windows":
		appData := os.Getenv("APPDATA")
		localAppData := os.Getenv("LOCALAPPDATA")
		if appData != "" {
			paths = append(paths, filepath.Join(appData, "Claude", "claude_desktop_config.json"))
		}
		if localAppData != "" {
			paths = append(paths, filepath.Join(localAppData, "Cursor", "User", "mcp.json"))
		}
	default:
		paths = append(paths,
			filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, ".config", "Cursor", "User", "mcp.json"),
			filepath.Join(home, ".cursor", "mcp.json"),
		)
	}
	paths = append(paths,
		filepath.Join(home, ".codex", "mcp.json"),
		filepath.Join(home, ".config", "codex", "mcp.json"),
	)
	for _, targetHome := range targetHomes() {
		if targetHome == home {
			continue
		}
		paths = append(paths,
			filepath.Join(targetHome, ".config", "Claude", "claude_desktop_config.json"),
			filepath.Join(targetHome, ".config", "Cursor", "User", "mcp.json"),
			filepath.Join(targetHome, ".cursor", "mcp.json"),
			filepath.Join(targetHome, ".codex", "mcp.json"),
			filepath.Join(targetHome, ".config", "codex", "mcp.json"),
		)
	}
	return paths
}

func revertMCPProxyConfig(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return false, fmt.Errorf("parse JSON: %w", err)
	}

	servers, ok := root["mcpServers"].(map[string]interface{})
	if !ok {
		return false, nil
	}

	changed := false
	for _, rawServer := range servers {
		server, ok := rawServer.(map[string]interface{})
		if !ok {
			continue
		}
		command, _ := server["command"].(string)
		if commandBaseName(command) != "authsec-shield" {
			continue
		}
		args, ok := server["args"].([]interface{})
		if !ok || len(args) < 3 {
			continue
		}
		if s, _ := args[0].(string); s != "mcp-proxy" {
			continue
		}
		separator := -1
		for i := 1; i < len(args); i++ {
			if s, _ := args[i].(string); s == "--" {
				separator = i
				break
			}
		}
		if separator == -1 || separator+1 >= len(args) {
			continue
		}
		originalCommand, ok := args[separator+1].(string)
		if !ok || originalCommand == "" {
			continue
		}
		server["command"] = originalCommand
		restoredArgs := args[separator+2:]
		if len(restoredArgs) == 0 {
			delete(server, "args")
		} else {
			server["args"] = restoredArgs
		}
		changed = true
	}

	if !changed {
		return false, nil
	}
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return false, err
	}
	out = append(out, '\n')
	return true, os.WriteFile(path, out, 0600)
}

func commandBaseName(command string) string {
	base := strings.ToLower(filepath.Base(strings.Trim(command, `"'`)))
	return strings.TrimSuffix(base, ".exe")
}

func homeDir() string {
	home, err := os.UserHomeDir()
	if err == nil {
		return home
	}
	return os.Getenv("HOME")
}

func targetHomes() []string {
	homes := []string{homeDir()}
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
		homes = append(homes, filepath.Join("/home", sudoUser))
	}
	if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
		homes = append(homes, userProfile)
	}

	var out []string
	seen := make(map[string]bool)
	for _, home := range homes {
		if home == "" {
			continue
		}
		clean := filepath.Clean(home)
		key := strings.ToLower(clean)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, clean)
	}
	return out
}

// ========================================
// check — called by hooks/wrappers to evaluate a command
// ========================================

func cmdCheck() {
	if len(os.Args) < 3 {
		os.Exit(0) // No command to check
	}

	command := strings.Join(os.Args[2:], " ")
	if command == "" {
		os.Exit(0)
	}

	// Skip if shield itself is running install/uninstall
	if os.Getenv("AUTHSEC_SHIELD_ACTIVE") == "1" {
		os.Exit(0)
	}

	cfg, err := config.Load()
	if err != nil || !cfg.IsLoggedIn() || !cfg.Enabled {
		os.Exit(0) // Not configured, pass through
	}

	if pausedUntil, active := pauseStatus(cfg); active {
		fmt.Fprintf(os.Stderr, "[AuthSec Shield] Enforcement paused until %s\n", pausedUntil.Local().Format(time.RFC1123))
		os.Exit(0)
	}

	engine := risk.NewEngine(cfg.DangerousCommands, cfg.ProtectedPaths, cfg.AutoApproveRead)
	eval := engine.EvaluateCommand(command)

	// Below threshold — allow silently
	if eval.Score <= cfg.RiskThreshold {
		os.Exit(0)
	}

	// Above threshold — need approval
	fmt.Fprintf(os.Stderr, "[AuthSec Shield] Requesting approval from %s...\n", cfg.UserEmail)

	approvalClient := approval.NewClient(cfg)
	result, err := approvalClient.RequestApproval(eval)

	if err != nil {
		fmt.Fprintf(os.Stderr, "[AuthSec Shield] BLOCKED: approval service error\n")
		os.Exit(1)
	}

	if !result.Approved {
		fmt.Fprintf(os.Stderr, "[AuthSec Shield] DENIED\n")
		os.Exit(1)
	}

	os.Exit(0)
}

func cmdRun() {
	displayCommand, realCommand, err := parseRunArgs(os.Args[2:])
	if err != nil {
		fatal("%v", err)
	}

	if _, err := enforceCommand(displayCommand); err != nil {
		os.Exit(1)
	}

	cmd := exec.Command(realCommand[0], realCommand[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fatal("failed to execute command: %v", err)
	}
}

// ========================================
// test — manually test risk scoring (ignores AI detection)
// ========================================

func cmdTest() {
	if len(os.Args) < 3 {
		fatal("Usage:\n  authsec-shield test \"<command>\"\n  authsec-shield test --file commands.txt")
	}

	cfg, err := config.Load()
	if err != nil || cfg == nil {
		cfg = config.DefaultConfig()
	}

	// --file mode: test every line in a text file
	if os.Args[2] == "--file" {
		if len(os.Args) < 4 {
			fatal("Usage: authsec-shield test --file <path>")
		}
		cmdTestFile(os.Args[3], cfg)
		return
	}

	// Single command mode
	command := strings.Join(os.Args[2:], " ")
	engine := risk.NewEngine(cfg.DangerousCommands, cfg.ProtectedPaths, cfg.AutoApproveRead)
	printTestResult(engine, command, cfg.RiskThreshold)
}

func cmdTestFile(path string, cfg *config.Config) {
	data, err := os.ReadFile(path)
	if err != nil {
		fatal("Cannot read file: %v", err)
	}

	engine := risk.NewEngine(cfg.DangerousCommands, cfg.ProtectedPaths, cfg.AutoApproveRead)
	lines := strings.Split(string(data), "\n")

	var total, blocked, passed int
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		total++
		eval := engine.EvaluateCommand(line)
		wouldBlock := eval.Score > cfg.RiskThreshold

		if wouldBlock {
			blocked++
			fmt.Printf("BLOCK [%3d] %s\n", eval.Score, line)
			for _, r := range eval.Reasons {
				fmt.Printf("            ↳ %s\n", r)
			}
		} else {
			passed++
			fmt.Printf("PASS  [%3d] %s\n", eval.Score, line)
		}
	}

	fmt.Println()
	fmt.Println("─────────────────────────────────────────────")
	fmt.Printf("Total: %d  |  Would block: %d  |  Pass: %d\n", total, blocked, passed)
}

func printTestResult(engine *risk.Engine, command string, threshold int) {
	eval := engine.EvaluateCommand(command)

	fmt.Printf("Command:  %s\n", command)
	fmt.Printf("Score:    %d / 100\n", eval.Score)
	fmt.Printf("Level:    %s\n", eval.Level)
	if eval.Target != "" {
		fmt.Printf("Target:   %s\n", eval.Target)
	}
	if len(eval.Reasons) > 0 {
		fmt.Println("Reasons:")
		for _, r := range eval.Reasons {
			fmt.Printf("  - %s\n", r)
		}
	}
	fmt.Println()

	if eval.Score <= threshold {
		fmt.Printf("Result:   PASS (score %d <= threshold %d)\n", eval.Score, threshold)
	} else {
		fmt.Printf("Result:   WOULD BLOCK (score %d > threshold %d) → needs mobile approval\n", eval.Score, threshold)
	}
}

// ========================================
// mcp-proxy — transparent MCP interception
// ========================================

func cmdMCPProxy() {
	// Find "--" separator
	var serverCmd []string
	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "--" {
			serverCmd = os.Args[i+1:]
			break
		}
	}

	if len(serverCmd) == 0 {
		fatal("Usage: authsec-shield mcp-proxy -- <server-command> [args...]")
	}

	cfg, err := config.Load()
	if err != nil {
		fatal("Failed to load config: %v", err)
	}

	engine := risk.NewEngine(cfg.DangerousCommands, cfg.ProtectedPaths, cfg.AutoApproveRead)
	approvalClient := approval.NewClient(cfg)
	proxy := mcpproxy.NewProxy(cfg, engine, approvalClient)

	if err := proxy.Run(serverCmd); err != nil {
		fatal("MCP proxy error: %v", err)
	}
}

// ========================================
// ========================================
// runAsShim — invoked when shield binary IS the command (e.g., /usr/bin/rm → shield)
// ========================================

func runAsShim(cmdName string) {
	// Find the real binary (backed up as .rm.shield-real)
	realBin := wrappers.GetBackupPath(cmdName)
	if realBin == "" {
		fmt.Fprintf(os.Stderr, "[AuthSec Shield] ERROR: Cannot find original '%s' binary. Run 'authsec-shield doctor --fix' to repair.\n", cmdName)
		os.Exit(127)
	}

	// Reconstruct the full command for display
	displayCmd := cmdName
	if len(os.Args) > 1 {
		displayCmd = cmdName + " " + strings.Join(os.Args[1:], " ")
	}

	// Run risk check — returns evaluation so we know the target path
	eval, err := enforceCommand(displayCmd)
	if err != nil {
		os.Exit(1)
	}

	// If the target is a protected path, temporarily unprotect it for the approved action.
	// Re-protect when done (even if the target no longer exists after deletion).
	if eval != nil && eval.Target != "" {
		cfg, _ := config.Load()
		if cfg != nil && isProtectedTarget(eval.Target, cfg.ProtectedPaths) {
			if uerr := fsprotect.ForceUnprotectPath(eval.Target); uerr != nil {
				fmt.Fprintf(os.Stderr, "[AuthSec Shield] WARNING: Could not temporarily unprotect %s: %v\n", eval.Target, uerr)
			} else {
				defer func() {
					// Re-protect after execution (ignore error if path was deleted)
					fsprotect.ProtectPath(eval.Target) //nolint:errcheck
				}()
			}
		}
	}

	// Exec the real binary with original args
	cmd := exec.Command(realBin, os.Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

// isProtectedTarget checks if a target path falls under any of the protected paths
func isProtectedTarget(target string, protectedPaths []string) bool {
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	for _, p := range protectedPaths {
		pAbs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		// Check if target is inside this protected path
		if strings.HasPrefix(targetAbs, pAbs+string(filepath.Separator)) || strings.EqualFold(targetAbs, pAbs) {
			return true
		}
	}
	return false
}

// ========================================
// helpers
// ========================================

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func pauseStatus(cfg *config.Config) (time.Time, bool) {
	if strings.TrimSpace(cfg.PausedUntil) == "" {
		return time.Time{}, false
	}

	pausedUntil, err := time.Parse(time.RFC3339, cfg.PausedUntil)
	if err != nil {
		return time.Time{}, false
	}

	if time.Now().Before(pausedUntil) {
		return pausedUntil, true
	}

	return pausedUntil, false
}

func expectedProfilePaths() []string {
	home := os.Getenv("USERPROFILE")
	if home == "" {
		home = os.Getenv("HOME")
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}

	return []string{
		filepath.Join(home, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
		filepath.Join(home, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
	}
}

func parseRunArgs(args []string) (string, []string, error) {
	if len(args) == 0 {
		return "", nil, fmt.Errorf("usage: authsec-shield run --display <command> -- <real-command> [args...]")
	}

	display := ""
	separator := -1
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--display":
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("missing value for --display")
			}
			display = args[i+1]
			i++
		case "--":
			separator = i
			i = len(args)
		}
	}

	if separator == -1 || separator+1 >= len(args) {
		return "", nil, fmt.Errorf("usage: authsec-shield run --display <command> -- <real-command> [args...]")
	}

	realCommand := args[separator+1:]
	if display == "" {
		display = strings.Join(realCommand, " ")
	}

	return display, realCommand, nil
}

func enforceCommand(command string) (*risk.Evaluation, error) {
	// Skip if shield itself is running (install/uninstall operations)
	if os.Getenv("AUTHSEC_SHIELD_ACTIVE") == "1" {
		return nil, nil
	}

	cfg, err := config.Load()
	if err != nil || !cfg.IsLoggedIn() || !cfg.Enabled {
		return nil, nil
	}

	if pausedUntil, active := pauseStatus(cfg); active {
		fmt.Fprintf(os.Stderr, "[AuthSec Shield] Enforcement paused until %s\n", pausedUntil.Local().Format(time.RFC1123))
		return nil, nil
	}

	engine := risk.NewEngine(cfg.DangerousCommands, cfg.ProtectedPaths, cfg.AutoApproveRead)
	eval := engine.EvaluateCommand(command)
	if eval.Score <= cfg.RiskThreshold {
		return eval, nil
	}

	fmt.Fprintf(os.Stderr, "[AuthSec Shield] Requesting approval from %s...\n", cfg.UserEmail)

	approvalClient := approval.NewClient(cfg)
	result, err := approvalClient.RequestApproval(eval)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AuthSec Shield] BLOCKED: approval service error\n")
		return eval, err
	}
	if !result.Approved {
		fmt.Fprintf(os.Stderr, "[AuthSec Shield] DENIED\n")
		return eval, fmt.Errorf("approval denied")
	}

	return eval, nil
}
