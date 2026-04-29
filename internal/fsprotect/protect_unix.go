//go:build !windows

package fsprotect

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ProtectPath sets the immutable attribute on Unix-like systems.
func ProtectPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	if _, err := os.Stat(abs); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", abs)
	}

	if runtime.GOOS == "darwin" {
		// macOS: chflags schg (system immutable, requires root) is stronger than uchg
		if err := exec.Command("chflags", "schg", abs).Run(); err == nil {
			return nil
		}
		// Fallback: user immutable (no root needed, but user can undo without root)
		if err := exec.Command("chflags", "uchg", abs).Run(); err == nil {
			return nil
		}
		return fmt.Errorf("chflags schg/uchg failed for %s; refusing chmod fallback because it cannot be perfectly reverted without a permission snapshot", abs)
	}

	// Linux: chattr +i (immutable flag — needs root)
	if err := exec.Command("chattr", "+i", abs).Run(); err == nil {
		return nil
	}

	return fmt.Errorf("chattr +i failed for %s; refusing chmod fallback because it cannot be perfectly reverted without a permission snapshot", abs)
}

// UnprotectPath removes the immutable attribute.
func UnprotectPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	if runtime.GOOS == "darwin" {
		// Try removing system immutable first, then user immutable
		if err := exec.Command("chflags", "noschg", abs).Run(); err == nil {
			return nil
		}
		output, err := exec.Command("chflags", "nouchg", abs).CombinedOutput()
		if err != nil {
			return fmt.Errorf("chflags noschg/nouchg failed: %s — %w", strings.TrimSpace(string(output)), err)
		}
		return nil
	}

	output, err := exec.Command("chattr", "-i", abs).CombinedOutput()
	if err != nil {
		return fmt.Errorf("chattr -i failed: %s — %w", strings.TrimSpace(string(output)), err)
	}

	return nil
}

// ProtectPaths applies protection to multiple paths
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

// UnprotectPaths removes protection from multiple paths
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

// ForceUnprotectPath removes all write protection from a path.
// Used when an action is approved to temporarily allow the approved operation.
// The caller is responsible for re-calling ProtectPath after execution.
func ForceUnprotectPath(path string) error {
	return UnprotectPath(path)
}

// IsProtected checks if a path is write-protected
func IsProtected(path string) bool {
	abs, _ := filepath.Abs(path)

	if runtime.GOOS == "darwin" {
		// ls -lO shows BSD flags; look for schg (system immutable) or uchg (user immutable)
		out, err := exec.Command("ls", "-lO", abs).Output()
		if err == nil {
			fields := strings.Fields(string(out))
			for _, f := range fields {
				if f == "schg" || f == "uchg" {
					return true
				}
			}
		}
	} else {
		// Linux: check immutable flag via lsattr
		out, err := exec.Command("lsattr", abs).Output()
		if err == nil && strings.Contains(string(out), "i") {
			return true
		}
	}

	// Fallback: check write permission bits
	info, err := os.Stat(abs)
	if err != nil {
		return false
	}

	return info.Mode().Perm()&0222 == 0
}

// DiagnoseProtection checks all given paths
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
