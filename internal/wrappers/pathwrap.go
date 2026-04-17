package wrappers

import (
	"fmt"
	"os"
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

	// Find the real binary location (skip our wrapper dir)
	realBin := findRealBinary(cmd, dir)
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
