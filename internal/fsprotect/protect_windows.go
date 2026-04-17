//go:build windows

// Package fsprotect implements filesystem write protection using NTFS ACLs.
//
// When enabled, the shield sets DENY write/delete ACLs on protected paths
// for the current user. This is kernel-enforced — no process running as
// that user can bypass it, regardless of shell redirects, scripting
// runtimes, or any other method.
//
// The shield service (running elevated) can temporarily remove the DENY ACL
// when the user approves an action, then re-apply it.
//
// Human workflow:
//   authsec-shield pause 1h   → removes DENY ACLs, human can write freely
//   authsec-shield enable     → re-applies DENY ACLs
package fsprotect

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ProtectPath sets a DENY write/delete ACL on the given path for the current user.
// Requires elevated privileges.
func ProtectPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	if _, err := os.Stat(abs); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", abs)
	}

	username, err := getCurrentUsername()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	// icacls: deny write, delete with Object Inherit + Container Inherit
	// (OI) = Object Inherit — applies to files in this folder
	// (CI) = Container Inherit — applies to subfolders
	// (WD) = Write Data / Add File
	// (AD) = Append Data / Add Subdirectory
	// (WA) = Write Attributes
	// (WEA) = Write Extended Attributes
	// (DC) = Delete Child
	// (DE) = Delete
	//
	// We deny BOTH the user account AND BUILTIN\Administrators because:
	// - Admin users run with an elevated token that includes the Administrators SID
	// - Even with an explicit DENY on the user account, the Administrators SID's
	//   inherited ALLOW (Full Control) can win when the process token is elevated
	// - Denying Administrators closes this gap for cmd.exe, PowerShell, and most shells
	//
	// NOTE: MSYS2/Git Bash uses a POSIX compatibility layer that by default mounts
	// with "noacl" — bypassing Windows ACL checks entirely for POSIX file ops.
	// The binary shim layer (Layer 1) handles Git Bash interception instead.

	denyFlags := "(OI)(CI)(WD,AD,WA,WEA,DC,DE)"

	// Deny for the specific user account
	cmd1 := exec.Command("icacls", abs,
		"/deny", fmt.Sprintf("%s:%s", username, denyFlags),
		"/T", "/C", "/Q",
	)
	if output, err := cmd1.CombinedOutput(); err != nil {
		return fmt.Errorf("icacls deny user failed: %s — %w", strings.TrimSpace(string(output)), err)
	}

	// Deny for BUILTIN\Administrators to block elevated token bypass
	cmd2 := exec.Command("icacls", abs,
		"/deny", fmt.Sprintf("BUILTIN\\Administrators:%s", denyFlags),
		"/T", "/C", "/Q",
	)
	if output, err := cmd2.CombinedOutput(); err != nil {
		return fmt.Errorf("icacls deny admins failed: %s — %w", strings.TrimSpace(string(output)), err)
	}

	return nil
}

// UnprotectPath removes the DENY write ACL from the given path.
// Requires elevated privileges.
func UnprotectPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	username, err := getCurrentUsername()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	// Remove deny ACEs for both user and Administrators group
	cmd1 := exec.Command("icacls", abs,
		"/remove:d", username,
		"/T", "/C", "/Q",
	)
	if output, err := cmd1.CombinedOutput(); err != nil {
		return fmt.Errorf("icacls remove deny user failed: %s — %w", strings.TrimSpace(string(output)), err)
	}

	cmd2 := exec.Command("icacls", abs,
		"/remove:d", "BUILTIN\\Administrators",
		"/T", "/C", "/Q",
	)
	if output, err := cmd2.CombinedOutput(); err != nil {
		return fmt.Errorf("icacls remove deny admins failed: %s — %w", strings.TrimSpace(string(output)), err)
	}

	return nil
}

// ForceUnprotectPath removes ALL deny ACEs on a path, including for Administrators.
// Use this when the shield needs to temporarily unlock a path for an approved action.
// Must be called from a SYSTEM-level process or with SeRestorePrivilege.
//
// Strategy: use `icacls /remove:d` for each known deny principal, then
// rely on re-protection after the approved action completes.
func ForceUnprotectPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	username, err := getCurrentUsername()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	// Remove all deny ACEs — order matters: remove user first, then admins
	for _, principal := range []string{username, "BUILTIN\\Administrators", "Everyone"} {
		cmd := exec.Command("icacls", abs,
			"/remove:d", principal,
			"/T", "/C", "/Q",
		)
		// Ignore errors — principal may not have a deny ACE
		cmd.Run() //nolint:errcheck
	}

	return nil
}

// ProtectPaths applies DENY write ACLs to multiple paths
func ProtectPaths(paths []string) (int, []error) {
	protected := 0
	var errs []error

	for _, path := range paths {
		if err := ProtectPath(path); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
		} else {
			protected++
		}
	}

	return protected, errs
}

// UnprotectPaths removes DENY write ACLs from multiple paths
func UnprotectPaths(paths []string) (int, []error) {
	unprotected := 0
	var errs []error

	for _, path := range paths {
		if err := UnprotectPath(path); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
		} else {
			unprotected++
		}
	}

	return unprotected, errs
}

// IsProtected checks if a path has a DENY write ACL for the current user
func IsProtected(path string) bool {
	abs, _ := filepath.Abs(path)

	username, err := getCurrentUsername()
	if err != nil {
		return false
	}

	cmd := exec.Command("icacls", abs)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}

	// Look for deny entries for user or Administrators group
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "(DENY)") {
			if strings.Contains(line, username) || strings.Contains(line, "Administrators") {
				return true
			}
		}
	}

	return false
}

// DiagnoseProtection checks all given paths and returns their protection status
func DiagnoseProtection(paths []string) []PathStatus {
	var results []PathStatus

	for _, path := range paths {
		status := PathStatus{
			Path:   path,
			Exists: true,
		}

		abs, _ := filepath.Abs(path)
		if _, err := os.Stat(abs); os.IsNotExist(err) {
			status.Exists = false
			results = append(results, status)
			continue
		}

		status.Protected = IsProtected(abs)
		results = append(results, status)
	}

	return results
}

// PathStatus describes the protection state of a single path
type PathStatus struct {
	Path      string
	Exists    bool
	Protected bool
}

func getCurrentUsername() (string, error) {
	// Try USERNAME env var first (most reliable on Windows)
	username := os.Getenv("USERNAME")
	if username != "" {
		domain := os.Getenv("USERDOMAIN")
		if domain != "" {
			return domain + "\\" + username, nil
		}
		return username, nil
	}

	// Fallback: whoami
	out, err := exec.Command("whoami").Output()
	if err != nil {
		return "", fmt.Errorf("whoami failed: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}
