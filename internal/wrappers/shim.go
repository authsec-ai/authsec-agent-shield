// Package wrappers implements OS-level binary replacement.
//
// Instead of PATH tricks, the shield REPLACES real binaries with itself:
//
//	/usr/bin/rm              → shield binary (symlink or copy)
//	/usr/bin/.rm.shield-real → original rm (moved here)
//
// When invoked as "rm", the shield detects argv[0], runs the risk check,
// and if approved, exec's the real binary from .rm.shield-real.
//
// This is un-bypassable — any process that calls "rm" by path hits the shield.
// Pause/enable controls whether the check actually runs or just passes through.
package wrappers

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const backupSuffix = ".shield-real"

// ShimmedCommands lists all commands we replace at the OS level
var ShimmedCommands = []string{
	// Filesystem destruction
	"rm", "rmdir", "shred", "unlink",
	// Permissions
	"chmod", "chown",
	// Low-level disk
	"mkfs", "dd",
	// Container/orchestration
	"docker", "kubectl", "helm", "terraform",
	// Cloud CLIs
	"aws", "gcloud", "az",
	// NOTE: git is NOT shimmed — it self-calls internally hundreds of times
	// causing fork bombs. Git is protected via shell hooks + PATH wrappers instead.
	// Database CLIs
	"mysql", "psql", "mongosh", "sqlcmd", "redis-cli", "sqlite3",
}

// ShimStatus describes the state of a single command shim
type ShimStatus struct {
	Command    string
	RealPath   string // where the original binary lives now
	ShimPath   string // where the shim is (same as original location)
	BackupPath string // where the backup is
	Installed  bool
	Error      string
}

// InstallShims replaces real binaries with shield shims.
// It shims ALL occurrences of each command found in PATH so that stray copies
// earlier in PATH (e.g. ~/kubectl.exe) cannot bypass the shield.
// Requires elevated privileges (sudo/admin).
func InstallShims(shieldBin string) ([]ShimStatus, error) {
	if shieldBin == "" {
		var err error
		shieldBin, err = os.Executable()
		if err != nil {
			return nil, fmt.Errorf("cannot find shield binary: %w", err)
		}
	}
	shieldBin, _ = filepath.Abs(shieldBin)

	var results []ShimStatus

	for _, cmd := range ShimmedCommands {
		// Find ALL occurrences of this binary in PATH so every copy gets shimmed.
		// A stray binary earlier in PATH (e.g. C:\Users\foo\kubectl.exe) would
		// otherwise bypass the shield installed at the canonical system location.
		allPaths := findAllSystemBinaries(cmd)
		if len(allPaths) == 0 {
			results = append(results, ShimStatus{Command: cmd, Error: "not found on system"})
			continue
		}

		for _, realPath := range allPaths {
			status := ShimStatus{Command: cmd, RealPath: realPath, ShimPath: realPath}

			dir := filepath.Dir(realPath)
			base := filepath.Base(realPath)
			backupName := "." + stripExtension(base) + backupSuffix
			if ext := filepath.Ext(base); ext != "" {
				backupName += ext
			}
			status.BackupPath = filepath.Join(dir, backupName)

			if isShimmed(realPath, shieldBin) {
				status.Installed = true
				results = append(results, status)
				continue
			}

			if _, err := os.Stat(status.BackupPath); err == nil {
				if err := placeShim(shieldBin, realPath); err != nil {
					status.Error = fmt.Sprintf("failed to place shim: %v", err)
				} else {
					status.Installed = true
				}
				results = append(results, status)
				continue
			}

			if runtime.GOOS == "windows" {
				takeOwnership(realPath)
				takeOwnership(filepath.Dir(realPath))
			}

			if err := os.Rename(realPath, status.BackupPath); err != nil {
				// On macOS, SIP-protected directories (/bin, /usr/bin, etc.) reject renames
				// even with sudo. Fall back to placing a shim in /usr/local/bin instead,
				// which has PATH priority on macOS and is writable.
				if isSIPProtectedPath(realPath) {
					shimPath, sipErr := installSIPShim(shieldBin, realPath)
					if sipErr == nil {
						status.ShimPath = shimPath
						status.BackupPath = filepath.Join(filepath.Dir(shimPath), "."+stripExtension(filepath.Base(realPath))+backupSuffix)
						status.Installed = true
						results = append(results, status)
						continue
					}
				}
				status.Error = fmt.Sprintf("failed to backup original (need sudo/admin?): %v", err)
				results = append(results, status)
				continue
			}

			if err := placeShim(shieldBin, realPath); err != nil {
				os.Rename(status.BackupPath, realPath)
				status.Error = fmt.Sprintf("failed to place shim: %v", err)
				results = append(results, status)
				continue
			}

			status.Installed = true
			results = append(results, status)
		}
	}

	return results, nil
}

// UninstallShims restores original binaries from backups
func UninstallShims() ([]ShimStatus, error) {
	var results []ShimStatus

	for _, cmd := range ShimmedCommands {
		status := ShimStatus{Command: cmd}

		realPath := findSystemBinary(cmd)
		if realPath == "" {
			// Try to find the backup directly
			realPath = findBackupBinary(cmd)
			if realPath == "" {
				status.Error = "not found"
				results = append(results, status)
				continue
			}
		}

		dir := filepath.Dir(realPath)
		base := filepath.Base(realPath)
		backupName := "." + stripExtension(base) + backupSuffix
		if ext := filepath.Ext(base); ext != "" {
			backupName += ext
		}
		backupPath := filepath.Join(dir, backupName)

		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			status.Error = "no backup found (not shimmed?)"
			results = append(results, status)
			continue
		}

		// SIP shim detection: backup is a symlink (points at the SIP-protected original).
		// In this case just remove both files — nothing was moved from the protected dir.
		if backupInfo, lErr := os.Lstat(backupPath); lErr == nil && backupInfo.Mode()&os.ModeSymlink != 0 {
			os.Remove(realPath)
			os.Remove(backupPath)
			status.Installed = false
			results = append(results, status)
			continue
		}

		// Remove shim
		os.Remove(realPath)

		// Restore original
		if err := os.Rename(backupPath, realPath); err != nil {
			status.Error = fmt.Sprintf("failed to restore: %v", err)
		} else {
			status.Installed = false
		}
		results = append(results, status)
	}

	return results, nil
}

// GetBackupPath returns the path to the real binary for a given command name.
// This is called by the shield when it's invoked as a shim (argv[0] = "rm").
func GetBackupPath(commandName string) string {
	base := stripExtension(commandName)

	// Strategy 1: Look next to argv[0] (the shim's location, before symlink resolution)
	// This is the directory where the real binary was — e.g., /usr/bin/ or C:\Program Files\Docker\...
	argv0, _ := filepath.Abs(os.Args[0])
	if argv0 != "" {
		dir := filepath.Dir(argv0)
		if found := findBackupIn(dir, base); found != "" {
			return found
		}
	}

	// Strategy 2: Search known system paths for the backup
	var searchPaths []string
	if runtime.GOOS == "windows" {
		searchPaths = strings.Split(os.Getenv("PATH"), ";")
	} else {
		searchPaths = []string{"/usr/bin", "/usr/local/bin", "/bin", "/sbin", "/usr/sbin"}
		searchPaths = append(searchPaths, strings.Split(os.Getenv("PATH"), ":")...)
	}

	for _, dir := range searchPaths {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		if found := findBackupIn(dir, base); found != "" {
			return found
		}
	}

	return ""
}

func findBackupIn(dir, base string) string {
	var candidates []string
	if runtime.GOOS == "windows" {
		candidates = []string{
			filepath.Join(dir, "."+base+backupSuffix+".exe"),
			filepath.Join(dir, "."+base+backupSuffix+".cmd"),
			filepath.Join(dir, "."+base+backupSuffix),
		}
	} else {
		candidates = []string{
			filepath.Join(dir, "."+base+backupSuffix),
		}
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// IsShimInvocation checks if the current process was invoked as a shim
// (i.e., argv[0] is "rm", "git", etc., not "authsec-shield")
func IsShimInvocation() (bool, string) {
	argv0 := filepath.Base(os.Args[0])
	argv0 = stripExtension(argv0)

	// If invoked as "authsec-shield", not a shim
	if strings.EqualFold(argv0, "authsec-shield") {
		return false, ""
	}

	// Check if this command is in our shim list
	for _, cmd := range ShimmedCommands {
		if strings.EqualFold(argv0, cmd) {
			return true, cmd
		}
	}

	return false, ""
}

// DiagnoseShims reports the status of all shims, checking every occurrence of
// each command in PATH so stray unshimmed copies are surfaced as issues.
func DiagnoseShims() []ShimStatus {
	var results []ShimStatus

	shieldBin, _ := os.Executable()

	for _, cmd := range ShimmedCommands {
		allPaths := findAllSystemBinaries(cmd)
		if len(allPaths) == 0 {
			results = append(results, ShimStatus{Command: cmd, Error: "not found on system"})
			continue
		}

		for _, realPath := range allPaths {
			status := ShimStatus{Command: cmd, RealPath: realPath, ShimPath: realPath}

			dir := filepath.Dir(realPath)
			base := filepath.Base(realPath)
			backupName := "." + stripExtension(base) + backupSuffix
			if ext := filepath.Ext(base); ext != "" {
				backupName += ext
			}
			status.BackupPath = filepath.Join(dir, backupName)

			if _, err := os.Stat(status.BackupPath); err == nil {
				if isShimmed(realPath, shieldBin) {
					status.Installed = true
				} else {
					status.Error = "backup exists but shim not in place"
				}
			} else if isShimmed(realPath, shieldBin) {
				status.Installed = true
				status.Error = "shim in place but backup missing"
			} else {
				status.Error = "not shimmed"
			}

			results = append(results, status)
		}
	}

	return results
}

// OrphanedBackup describes a backup binary whose shim is missing
type OrphanedBackup struct {
	Command    string
	BackupPath string // where the backup .shield-real lives
	ShimPath   string // where the shim should be (but isn't)
}

// FindOrphanedBackups looks for .shield-real backups where the shim is missing or broken.
// This happens when shield was uninstalled partially, or the shim binary was deleted.
func FindOrphanedBackups() []OrphanedBackup {
	var orphans []OrphanedBackup

	shieldBin, _ := os.Executable()

	var searchPaths []string
	if runtime.GOOS == "windows" {
		searchPaths = strings.Split(os.Getenv("PATH"), ";")
	} else {
		searchPaths = []string{"/usr/bin", "/usr/local/bin", "/bin", "/sbin", "/usr/sbin"}
		searchPaths = append(searchPaths, strings.Split(os.Getenv("PATH"), ":")...)
	}

	seen := make(map[string]bool)
	for _, dir := range searchPaths {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.Contains(name, backupSuffix) {
				continue
			}
			backupPath := filepath.Join(dir, name)
			if seen[backupPath] {
				continue
			}
			seen[backupPath] = true

			// Derive the original command name from backup filename
			// .rm.shield-real → rm
			cmdName := name
			cmdName = strings.TrimPrefix(cmdName, ".")
			cmdName = strings.Replace(cmdName, backupSuffix, "", 1)
			cmdName = stripExtension(cmdName)

			// Check if only one of the known shimmed commands
			known := false
			for _, c := range ShimmedCommands {
				if strings.EqualFold(c, cmdName) {
					known = true
					break
				}
			}
			if !known {
				continue
			}

			// Expected shim location = same dir, without the backup prefix
			var shimPath string
			if runtime.GOOS == "windows" {
				shimPath = filepath.Join(dir, cmdName+".exe")
			} else {
				shimPath = filepath.Join(dir, cmdName)
			}

			// Orphan if shim doesn't exist OR exists but isn't our shield binary
			if !isShimmed(shimPath, shieldBin) {
				orphans = append(orphans, OrphanedBackup{
					Command:    cmdName,
					BackupPath: backupPath,
					ShimPath:   shimPath,
				})
			}
		}
	}

	return orphans
}

// RepairOrphan places the shield shim back at the expected location for an orphaned backup.
func RepairOrphan(o OrphanedBackup, shieldBin string) error {
	if shieldBin == "" {
		var err error
		shieldBin, err = os.Executable()
		if err != nil {
			return fmt.Errorf("cannot find shield binary: %w", err)
		}
	}

	// Remove whatever is at shimPath (could be broken/stale)
	os.Remove(o.ShimPath) //nolint:errcheck

	return placeShim(shieldBin, o.ShimPath)
}

// ========================================
// Internal helpers
// ========================================

// placeShim puts a symlink or copy of the shield binary at the target path
func placeShim(shieldBin, targetPath string) error {
	// Try symlink first (cheapest, preserves identity)
	if err := os.Symlink(shieldBin, targetPath); err == nil {
		return nil
	}

	// Fallback: hard copy the shield binary
	src, err := os.ReadFile(shieldBin)
	if err != nil {
		return fmt.Errorf("failed to read shield binary: %w", err)
	}

	perm := os.FileMode(0755)
	if err := os.WriteFile(targetPath, src, perm); err != nil {
		// On Windows, Program Files may need takeown + icacls grant first
		if runtime.GOOS == "windows" {
			if takeErr := takeOwnership(targetPath); takeErr == nil {
				if err2 := os.WriteFile(targetPath, src, perm); err2 == nil {
					return nil
				}
			}
		}
		return fmt.Errorf("failed to write shim: %w", err)
	}

	return nil
}

// takeOwnership takes ownership of a file/path and grants full control.
// Needed on Windows to write to Program Files.
// Uses cmd.exe /C to avoid MSYS2/Git Bash path mangling.
func takeOwnership(path string) error {
	// Ensure we have a clean Windows path (not a MSYS2 converted one)
	absPath, _ := filepath.Abs(path)

	// takeown /f <path>
	cmd1 := exec.Command("cmd.exe", "/C", "takeown", "/f", absPath)
	cmd1.Env = append(os.Environ(), "MSYS_NO_PATHCONV=1")
	if _, err := cmd1.CombinedOutput(); err != nil {
		return err
	}

	// icacls <path> /grant Administrators:F
	cmd2 := exec.Command("cmd.exe", "/C", "icacls", absPath, "/grant", "Administrators:F")
	cmd2.Env = append(os.Environ(), "MSYS_NO_PATHCONV=1")
	if _, err := cmd2.CombinedOutput(); err != nil {
		return err
	}

	return nil
}

// isShimmed checks if the binary at path is our shield (by checking symlink target or file size)
func isShimmed(path, shieldBin string) bool {
	// Check symlink
	target, err := os.Readlink(path)
	if err == nil {
		targetAbs, _ := filepath.Abs(target)
		shieldAbs, _ := filepath.Abs(shieldBin)
		return strings.EqualFold(targetAbs, shieldAbs)
	}

	// Check file size match (crude but effective for copies)
	pathInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	shieldInfo, err := os.Stat(shieldBin)
	if err != nil {
		return false
	}

	return pathInfo.Size() == shieldInfo.Size()
}

// findAllSystemBinaries returns every occurrence of cmd found in PATH,
// skipping the wrapper dir. This lets InstallShims shim all copies so a stray
// binary earlier in PATH cannot bypass the shield.
func findAllSystemBinaries(cmd string) []string {
	wrapperDir := WrapperDir()

	var searchPaths []string
	if runtime.GOOS == "windows" {
		searchPaths = strings.Split(os.Getenv("PATH"), ";")
	} else {
		searchPaths = []string{"/usr/bin", "/usr/local/bin", "/bin", "/sbin", "/usr/sbin"}
		searchPaths = append(searchPaths, strings.Split(os.Getenv("PATH"), ":")...)
	}

	var results []string
	seen := make(map[string]bool)

	for _, dir := range searchPaths {
		dir = strings.TrimSpace(dir)
		if dir == "" || samePath(dir, wrapperDir) {
			continue
		}

		var candidates []string
		if runtime.GOOS == "windows" {
			candidates = []string{
				filepath.Join(dir, cmd+".exe"),
				filepath.Join(dir, cmd+".cmd"),
				filepath.Join(dir, cmd+".bat"),
			}
		} else {
			candidates = []string{filepath.Join(dir, cmd)}
		}

		for _, c := range candidates {
			absC := strings.ToLower(filepath.Clean(c))
			if seen[absC] {
				continue
			}
			if info, err := os.Stat(c); err == nil && !info.IsDir() {
				results = append(results, c)
				seen[absC] = true
				break
			}
		}
	}
	return results
}

// findSystemBinary finds a binary in standard system paths (not our wrapper dir)
func findSystemBinary(cmd string) string {
	wrapperDir := WrapperDir()

	var searchPaths []string
	if runtime.GOOS == "windows" {
		searchPaths = strings.Split(os.Getenv("PATH"), ";")
	} else {
		// Search standard system paths first, then PATH
		searchPaths = []string{"/usr/bin", "/usr/local/bin", "/bin", "/sbin", "/usr/sbin"}
		searchPaths = append(searchPaths, strings.Split(os.Getenv("PATH"), ":")...)
	}

	for _, dir := range searchPaths {
		dir = strings.TrimSpace(dir)
		if dir == "" || samePath(dir, wrapperDir) {
			continue
		}

		var candidates []string
		if runtime.GOOS == "windows" {
			candidates = []string{
				filepath.Join(dir, cmd+".exe"),
				filepath.Join(dir, cmd+".cmd"),
				filepath.Join(dir, cmd+".bat"),
			}
		} else {
			candidates = []string{filepath.Join(dir, cmd)}
		}

		for _, c := range candidates {
			if info, err := os.Stat(c); err == nil && !info.IsDir() {
				return c
			}
		}
	}

	return ""
}

// findBackupBinary looks for a .shield-real backup in standard paths
func findBackupBinary(cmd string) string {
	var searchPaths []string
	if runtime.GOOS == "windows" {
		searchPaths = strings.Split(os.Getenv("PATH"), ";")
	} else {
		searchPaths = []string{"/usr/bin", "/usr/local/bin", "/bin", "/sbin"}
	}

	for _, dir := range searchPaths {
		backupName := "." + cmd + backupSuffix
		if runtime.GOOS == "windows" {
			backupName += ".exe"
		}
		candidate := filepath.Join(dir, backupName)
		if _, err := os.Stat(candidate); err == nil {
			return filepath.Join(dir, cmd)
		}
	}

	return ""
}

func stripExtension(name string) string {
	ext := filepath.Ext(name)
	if ext == ".exe" || ext == ".cmd" || ext == ".bat" {
		return strings.TrimSuffix(name, ext)
	}
	return name
}

// isSIPProtectedPath returns true if the path lives inside a macOS SIP-protected
// directory. These directories reject writes even under sudo.
func isSIPProtectedPath(path string) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	sipDirs := []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/System"}
	clean := filepath.Clean(path)
	for _, d := range sipDirs {
		if strings.HasPrefix(clean, d+string(filepath.Separator)) || clean == d {
			return true
		}
	}
	return false
}

// installSIPShim handles macOS SIP-protected binaries by placing both the shim
// and a backup symlink in /usr/local/bin, which is writable and has PATH priority.
// The backup symlink points at the original SIP-protected binary so the shim can
// exec it without a file copy.
func installSIPShim(shieldBin, realPath string) (string, error) {
	const localBin = "/usr/local/bin"

	base := filepath.Base(realPath)
	shimPath := filepath.Join(localBin, base)
	backupPath := filepath.Join(localBin, "."+stripExtension(base)+backupSuffix)

	// Remove any stale shim/backup from a previous install attempt
	os.Remove(shimPath)
	os.Remove(backupPath)

	// Create a symlink-backup that points at the SIP-protected original
	if err := os.Symlink(realPath, backupPath); err != nil {
		return "", fmt.Errorf("failed to create SIP backup symlink %s → %s: %w", backupPath, realPath, err)
	}

	// Place the shield shim
	if err := placeShim(shieldBin, shimPath); err != nil {
		os.Remove(backupPath)
		return "", fmt.Errorf("failed to place SIP shim at %s: %w", shimPath, err)
	}

	return shimPath, nil
}

// WrapperDir is defined in pathwrap.go (kept for backward compatibility)
