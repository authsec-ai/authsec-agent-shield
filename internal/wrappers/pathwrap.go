package wrappers

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
)

// WrappedCommands lists the commands we create wrappers for
var WrappedCommands = []string{
	"rm", "rmdir", "shred",
	"chmod", "chown",
	"mkfs", "dd",
	"docker", "kubectl", "helm", "terraform",
	"aws", "gcloud", "az",
}

// WrapperDir returns the directory where wrapper scripts are placed
func WrapperDir() string {
	home, _ := os.UserHomeDir()
	return WrapperDirForHome(home)
}

// ResolveRealBinary returns the underlying executable path for a wrapped
// command, skipping the wrapper directory itself.
func ResolveRealBinary(cmd string) string {
	return resolveRealBinary(cmd, WrapperDir())
}

// WrapperDirForHome returns the wrapper directory for a specific user's home.
func WrapperDirForHome(home string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(home, ".authsec-shield", "bin")
	}
	return filepath.Join(home, ".authsec-shield", "bin")
}

// Install creates wrapper scripts and prints PATH instructions
func Install() (int, error) {
	dir := WrapperDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return 0, fmt.Errorf("failed to create wrapper dir: %w", err)
	}

	count := 0
	for _, cmd := range WrappedCommands {
		if err := createWrapper(dir, cmd); err != nil {
			continue
		}
		count++
	}

	return count, nil
}

// Uninstall removes the wrapper directory
func Uninstall() error {
	return os.RemoveAll(WrapperDir())
}

// CleanupLegacyWrappers removes the old PATH-based wrapper directory
func CleanupLegacyWrappers() {
	os.RemoveAll(WrapperDir())
}

// PathInstruction returns the shell line to add wrapper dir to PATH
func PathInstruction() string {
	dir := WrapperDir()
	switch runtime.GOOS {
	case "windows":
		return fmt.Sprintf(`$env:PATH = "%s;$env:PATH"`, dir)
	default:
		return fmt.Sprintf(`export PATH="%s:$PATH"`, dir)
	}
}

func createWrapper(dir, cmd string) error {
	shieldBin, _ := os.Executable()
	if shieldBin == "" {
		if runtime.GOOS == "windows" {
			shieldBin = "authsec-shield.exe"
		} else {
			shieldBin = "authsec-shield"
		}
	}

	realBin := resolveRealBinary(cmd, dir)
	if realBin == "" {
		return fmt.Errorf("real binary not found for: %s", cmd)
	}

	if runtime.GOOS == "windows" {
		// On Windows, create BOTH .cmd (for PowerShell/cmd) AND
		// Unix-style (for Git Bash/WSL/MSYS2 which Claude Code uses)
		err := createWindowsWrapper(dir, cmd, shieldBin, realBin)
		if err != nil {
			return err
		}
		return createUnixWrapper(dir, cmd, shieldBin, realBin)
	}
	return createUnixWrapper(dir, cmd, shieldBin, realBin)
}

const unixWrapperTmpl = `#!/bin/sh
# AuthSec Agent Shield wrapper for {{.Command}}
# Executes through the shield broker

SHIELD="{{.ShieldBin}}"
REAL="{{.RealBin}}"
CMD="{{.Command}} $*"

exec "$SHIELD" run --display "$CMD" -- "$REAL" "$@"
`

const windowsWrapperTmpl = `@echo off
REM AuthSec Agent Shield wrapper for {{.Command}}
set "SHIELD={{.ShieldBin}}"
set "REAL={{.RealBin}}"
"%SHIELD%" run --display "{{.Command}} %*" -- "%REAL%" %*
`

type wrapperData struct {
	Command   string
	ShieldBin string
	RealBin   string
}

func createUnixWrapper(dir, cmd, shieldBin, realBin string) error {
	tmpl, err := template.New("wrapper").Parse(unixWrapperTmpl)
	if err != nil {
		return err
	}

	path := filepath.Join(dir, cmd)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, wrapperData{
		Command:   cmd,
		ShieldBin: shieldBin,
		RealBin:   realBin,
	})
}

func resolveRealBinary(cmd, skipDir string) string {
	realBin := findRealBinary(cmd, skipDir)
	if realBin == "" {
		return ""
	}

	shieldBin, _ := os.Executable()
	if shieldBin == "" || !isShimmed(realBin, shieldBin) {
		return realBin
	}

	// If the found binary is our own shim, use the backed-up original instead.
	// This avoids double-enforcement when both a shim and a wrapper exist.
	base := filepath.Base(realBin)
	backupName := "." + stripExtension(base) + backupSuffix
	if ext := filepath.Ext(base); ext != "" {
		backupName += ext
	}
	backupPath := filepath.Join(filepath.Dir(realBin), backupName)
	if _, err := os.Stat(backupPath); err == nil {
		return backupPath
	}

	return realBin
}

func createWindowsWrapper(dir, cmd, shieldBin, realBin string) error {
	tmpl, err := template.New("wrapper").Parse(windowsWrapperTmpl)
	if err != nil {
		return err
	}

	path := filepath.Join(dir, cmd+".cmd")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, wrapperData{
		Command:   cmd,
		ShieldBin: shieldBin,
		RealBin:   realBin,
	})
}

func findRealBinary(cmd, skipDir string) string {
	pathEnv := os.Getenv("PATH")
	var sep string
	if runtime.GOOS == "windows" {
		sep = ";"
	} else {
		sep = ":"
	}

	skipAbs, _ := filepath.Abs(skipDir)
	for _, dir := range strings.Split(pathEnv, sep) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		dirAbs, _ := filepath.Abs(dir)
		if samePath(dir, skipDir) || samePath(dirAbs, skipAbs) {
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

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// AddToWindowsSystemPath adds dir to the front of the Windows system (Machine)
// PATH. If that fails (insufficient UAC elevation), it falls back to the user
// PATH which still helps when the stray binary is in a user-level PATH entry.
// No-op on non-Windows.
func AddToWindowsSystemPath(dir string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	dir = filepath.Clean(dir)
	escaped := strings.ReplaceAll(dir, "'", "''")

	sysScript := fmt.Sprintf(
		`$d = '%s'; `+
			`$sys = [Environment]::GetEnvironmentVariable('Path','Machine'); `+
			`$parts = $sys -split ';' | Where-Object { $_ -ne '' }; `+
			`if ($parts -notcontains $d) { `+
			`[Environment]::SetEnvironmentVariable('Path', ($d+';'+$sys), 'Machine') }`,
		escaped,
	)
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", sysScript).CombinedOutput()
	if err == nil {
		return nil
	}
	// Machine PATH requires a fully-elevated token; fall back to user PATH.
	_ = out
	userScript := fmt.Sprintf(
		`$d = '%s'; `+
			`$cur = [Environment]::GetEnvironmentVariable('Path','User'); `+
			`$parts = $cur -split ';' | Where-Object { $_ -ne '' }; `+
			`if ($parts -notcontains $d) { `+
			`[Environment]::SetEnvironmentVariable('Path', ($d+';'+$cur), 'User') }`,
		escaped,
	)
	out2, err2 := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", userScript).CombinedOutput()
	if err2 != nil {
		return fmt.Errorf("failed to update PATH (system and user): %w: %s", err2, strings.TrimSpace(string(out2)))
	}
	return fmt.Errorf("system PATH requires full UAC elevation — added to user PATH instead (re-run from an elevated prompt to fix)")
}

// AddToWindowsUserPath adds dir to the Windows user-level PATH.
// Kept for backward compatibility; prefer AddToWindowsSystemPath during admin installs.
func AddToWindowsUserPath(dir string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	dir = filepath.Clean(dir)
	script := fmt.Sprintf(
		`$d = '%s'; $cur = [Environment]::GetEnvironmentVariable('Path','User'); `+
			`$parts = $cur -split ';' | Where-Object { $_ -ne '' }; `+
			`if ($parts -notcontains $d) { `+
			`[Environment]::SetEnvironmentVariable('Path', ($d + ';' + $cur), 'User') }`,
		strings.ReplaceAll(dir, "'", "''"),
	)
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update Windows user PATH: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
