package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/authsec-ai/authsec-agent-shield/internal/wrappers"
)

// Install installs shell hooks for all detected shells
func Install() ([]string, error) {
	var installed []string
	var errs []string

	switch runtime.GOOS {
	case "windows":
		if err := installPowerShell(); err == nil {
			installed = append(installed, "PowerShell")
		} else {
			errs = append(errs, "PowerShell: "+err.Error())
		}
		// Also install bash hooks on Windows — Claude Code, Codex, and other
		// AI tools use Git Bash/MSYS2, not PowerShell
		if err := installBash(); err == nil {
			installed = append(installed, "Git Bash")
		} else {
			errs = append(errs, "Git Bash: "+err.Error())
		}
		if err := installCMD(); err == nil {
			installed = append(installed, "CMD")
		} else {
			errs = append(errs, "CMD: "+err.Error())
		}
	default:
		if err := installBash(); err == nil {
			installed = append(installed, "Bash")
		} else {
			errs = append(errs, "Bash: "+err.Error())
		}
		if err := installZsh(); err == nil {
			installed = append(installed, "Zsh")
		} else {
			errs = append(errs, "Zsh: "+err.Error())
		}
	}

	if len(errs) > 0 {
		return installed, fmt.Errorf(strings.Join(errs, "; "))
	}

	return installed, nil
}

// Uninstall removes shell hooks
func Uninstall() error {
	home, _ := os.UserHomeDir()
	return UninstallForHome(home)
}

// UninstallForHome removes shell hooks from profile files under a specific home
// directory. This lets sudo uninstall clean up the invoking user's profiles.
func UninstallForHome(home string) error {
	if home == "" {
		return nil
	}
	switch runtime.GOOS {
	case "windows":
		removeHookFromFile(filepath.Join(home, ".bashrc")) // Git Bash cleanup
		uninstallCMD()
		var firstErr error
		for _, path := range powerShellProfilePathsForHome(home) {
			if err := removeHookFromFile(path); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	default:
		removeHookFromFile(filepath.Join(home, ".bashrc"))
		removeHookFromFile(filepath.Join(home, ".zshrc"))
		return nil
	}
}

const hookMarkerStart = "# >>> authsec-shield >>>"
const hookMarkerEnd = "# <<< authsec-shield <<<"

// The hook script: before each command, call `authsec-shield check "command"`
// If it exits non-zero, the command is blocked.
func bashHookScript() string {
	shieldBin := shieldBinaryPath()
	return fmt.Sprintf(`%s
# AuthSec Agent Shield - intercepts risky commands for approval
authsec_shield_preexec() {
    local cmd="$1"
    if [ -z "$cmd" ]; then return; fi
    "%s" check "$cmd"
    if [ $? -ne 0 ]; then
        return 1
    fi
}

# Install preexec if bash-preexec is loaded, otherwise use DEBUG trap
if declare -F preexec > /dev/null 2>&1; then
    preexec_functions+=(authsec_shield_preexec)
else
    __authsec_shield_trap() {
        [ -n "$COMP_LINE" ] && return
        [ "$BASH_COMMAND" = "$PROMPT_COMMAND" ] && return
        authsec_shield_preexec "$BASH_COMMAND" || kill -SIGINT $$
    }
    trap '__authsec_shield_trap' DEBUG
fi
%s`, hookMarkerStart, shieldBin, hookMarkerEnd)
}

func zshHookScript() string {
	shieldBin := shieldBinaryPath()
	return fmt.Sprintf(`%s
# AuthSec Agent Shield - intercepts risky commands for approval
authsec_shield_preexec() {
    local cmd="$1"
    if [ -z "$cmd" ]; then return; fi
    "%s" check "$cmd"
    if [ $? -ne 0 ]; then
        kill -INT $$
    fi
}
autoload -Uz add-zsh-hook
add-zsh-hook preexec authsec_shield_preexec
%s`, hookMarkerStart, shieldBin, hookMarkerEnd)
}

func powershellHookScript() string {
	shieldBin := strings.ReplaceAll(shieldBinaryPath(), "\\", "\\\\")
	wrapperDir := strings.ReplaceAll(wrapperDirPath(), "\\", "\\\\")
	return fmt.Sprintf(`%s
# AuthSec Agent Shield - intercepts risky commands for approval
$env:PATH = "%s;$env:PATH"
$Global:AuthSecShieldValidation = {
    param([string]$CommandLine)
    if ($env:AUTHSEC_SHIELD_ACTIVE -eq "1") { return }
    $result = & "%s" check $CommandLine 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Blocked by AuthSec Agent Shield"
    }
}
Set-PSReadLineOption -CommandValidationHandler $Global:AuthSecShieldValidation

function global:Invoke-AuthSecShieldCheck {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return }
    if ($env:AUTHSEC_SHIELD_ACTIVE -eq "1") { return }
    $null = & "%s" check $CommandLine
    if ($LASTEXITCODE -ne 0) {
        throw "Blocked by AuthSec Agent Shield"
    }
}

function global:Format-AuthSecArgument {
    param($Value)
    if ($null -eq $Value) { return "" }
    $text = [string]$Value
    if ($text -match '\s' -or $text -match '["'']') {
        return '"' + ($text -replace '"', '\"') + '"'
    }
    return $text
}

function global:Invoke-AuthSecWrappedCmdlet {
    param(
        [string]$CmdletName,
        [hashtable]$BoundParameters,
        [Object[]]$RemainingArgs
    )

    $segments = @($CmdletName)
    foreach ($key in $BoundParameters.Keys) {
        $segments += ('-' + $key)
        $value = $BoundParameters[$key]
        if ($value -isnot [System.Management.Automation.SwitchParameter]) {
            $segments += (Format-AuthSecArgument $value)
        }
    }
    foreach ($arg in $RemainingArgs) {
        $segments += (Format-AuthSecArgument $arg)
    }

    Invoke-AuthSecShieldCheck ($segments -join ' ')
}

function global:Remove-Item {
    [CmdletBinding(DefaultParameterSetName='Path', SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(ParameterSetName='Path', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]$Path,
        [Parameter(ParameterSetName='LiteralPath', ValueFromPipelineByPropertyName=$true)]
        [string[]]$LiteralPath,
        [switch]$Recurse,
        [switch]$Force
    )

    Invoke-AuthSecWrappedCmdlet 'Remove-Item' $PSBoundParameters $args
    Microsoft.PowerShell.Management\Remove-Item @PSBoundParameters @args
}

function global:Clear-Content {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]$Path,
        [string[]]$LiteralPath,
        [switch]$Force
    )

    Invoke-AuthSecWrappedCmdlet 'Clear-Content' $PSBoundParameters $args
    Microsoft.PowerShell.Management\Clear-Content @PSBoundParameters @args
}

function global:Set-Content {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]$Path,
        [Parameter(Position=1)]
        $Value,
        [switch]$Force
    )

    Invoke-AuthSecWrappedCmdlet 'Set-Content' $PSBoundParameters $args
    Microsoft.PowerShell.Management\Set-Content @PSBoundParameters @args
}

function global:Move-Item {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]$Path,
        [Parameter(Position=1)]
        [string]$Destination,
        [switch]$Force
    )

    Invoke-AuthSecWrappedCmdlet 'Move-Item' $PSBoundParameters $args
    Microsoft.PowerShell.Management\Move-Item @PSBoundParameters @args
}

function global:Copy-Item {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]$Path,
        [Parameter(Position=1)]
        [string]$Destination,
        [switch]$Recurse,
        [switch]$Force
    )

    Invoke-AuthSecWrappedCmdlet 'Copy-Item' $PSBoundParameters $args
    Microsoft.PowerShell.Management\Copy-Item @PSBoundParameters @args
}

function global:Rename-Item {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Path,
        [Parameter(Position=1)]
        [string]$NewName,
        [switch]$Force
    )

    Invoke-AuthSecWrappedCmdlet 'Rename-Item' $PSBoundParameters $args
    Microsoft.PowerShell.Management\Rename-Item @PSBoundParameters @args
}
%s`,
		strings.ReplaceAll(hookMarkerStart, "#", "#"),
		wrapperDir,
		shieldBin,
		shieldBin,
		strings.ReplaceAll(hookMarkerEnd, "#", "#"))
}

func installBash() error {
	home, _ := os.UserHomeDir()
	return appendHookToFile(filepath.Join(home, ".bashrc"), bashHookScript())
}

func installZsh() error {
	home, _ := os.UserHomeDir()
	return appendHookToFile(filepath.Join(home, ".zshrc"), zshHookScript())
}

func installPowerShell() error {
	var firstErr error
	for _, path := range powerShellProfilePaths() {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := appendHookToFile(path, powershellHookScript()); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func uninstallBash() error {
	home, _ := os.UserHomeDir()
	return removeHookFromFile(filepath.Join(home, ".bashrc"))
}

func uninstallZsh() error {
	home, _ := os.UserHomeDir()
	return removeHookFromFile(filepath.Join(home, ".zshrc"))
}

func uninstallPowerShell() error {
	var firstErr error
	for _, path := range powerShellProfilePaths() {
		if err := removeHookFromFile(path); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func powerShellProfilePaths() []string {
	home := os.Getenv("USERPROFILE")
	if home == "" {
		home = os.Getenv("HOME")
	}
	if home == "" {
		userHome, _ := os.UserHomeDir()
		home = userHome
	}

	return powerShellProfilePathsForHome(home)
}

func powerShellProfilePathsForHome(home string) []string {
	return []string{
		filepath.Join(home, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
		filepath.Join(home, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
	}
}

func appendHookToFile(path, hookScript string) error {
	// Remove existing hook first
	removeHookFromFile(path)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	_, err = f.WriteString("\n" + hookScript + "\n")
	return err
}

func removeHookFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // File doesn't exist, nothing to remove
	}

	content := string(data)
	startIdx := strings.Index(content, hookMarkerStart)
	endIdx := strings.Index(content, hookMarkerEnd)

	if startIdx == -1 || endIdx == -1 {
		return nil // Hook not found
	}

	// Remove everything between markers (inclusive)
	cleaned := content[:startIdx] + content[endIdx+len(hookMarkerEnd):]
	cleaned = strings.TrimRight(cleaned, "\n") + "\n"

	return os.WriteFile(path, []byte(cleaned), 0644)
}

// DiagnoseHooks checks which shell profiles have the hook installed.
// Returns map of shell name → installed.
func DiagnoseHooks() map[string]bool {
	result := make(map[string]bool)
	home, _ := os.UserHomeDir()

	// Bash
	bashrc := filepath.Join(home, ".bashrc")
	result["bash"] = fileContainsHook(bashrc)

	// Zsh
	if runtime.GOOS != "windows" {
		zshrc := filepath.Join(home, ".zshrc")
		result["zsh"] = fileContainsHook(zshrc)
	}

	// PowerShell (Windows + cross-platform)
	for _, path := range powerShellProfilePaths() {
		if fileContainsHook(path) {
			result["powershell"] = true
			break
		}
	}
	if _, ok := result["powershell"]; !ok {
		result["powershell"] = false
	}

	// CMD (Windows only — AutoRun registry key)
	if runtime.GOOS == "windows" {
		script := `(Get-ItemProperty -Path "HKCU:\Software\Microsoft\Command Processor" ` +
			`-Name AutoRun -ErrorAction SilentlyContinue).AutoRun`
		out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive",
			"-Command", script).Output()
		result["cmd"] = err == nil && strings.Contains(string(out), "cmd-hook.bat")
	}

	return result
}

func fileContainsHook(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), hookMarkerStart)
}

// InstallWSL installs a bash hook inside the default WSL distribution.
// It converts the Windows shield.exe path to a WSL mount path and appends
// the hook to ~/.bashrc in WSL. No-op on non-Windows or when WSL is absent.
func InstallWSL(shieldExePath string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("WSL install only supported on Windows")
	}
	if _, err := exec.LookPath("wsl.exe"); err != nil {
		return fmt.Errorf("wsl.exe not found — WSL not installed")
	}

	// Verify at least one distro is present
	out, err := exec.Command("wsl.exe", "--list", "--quiet").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return fmt.Errorf("no WSL distribution found")
	}

	wslPath := windowsToWSLPath(shieldExePath)
	hook := wslBashHookScript(wslPath)

	// Write hook to a temp file then append it via wsl bash
	tmp, err := os.CreateTemp("", "authsec-shield-wsl-*.sh")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(hook); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	wslTmp := windowsToWSLPath(tmp.Name())
	// Remove any existing hook block then append the new one
	bashCmd := fmt.Sprintf(
		`sed -i '/# >>> authsec-shield >>>/,/# <<< authsec-shield <<</d' ~/.bashrc 2>/dev/null; `+
			`printf '\n' >> ~/.bashrc; cat '%s' >> ~/.bashrc`,
		wslTmp,
	)
	if out, err := exec.Command("wsl.exe", "bash", "-c", bashCmd).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to install WSL hook: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func wslBashHookScript(wslShieldPath string) string {
	return fmt.Sprintf(`%s
# AuthSec Agent Shield - intercepts risky commands for approval (WSL)
authsec_shield_preexec() {
    local cmd="$1"
    if [ -z "$cmd" ]; then return; fi
    "%s" check "$cmd"
    if [ $? -ne 0 ]; then
        kill -INT $$
    fi
}

if declare -F preexec > /dev/null 2>&1; then
    preexec_functions+=(authsec_shield_preexec)
else
    __authsec_shield_trap() {
        [ -n "$COMP_LINE" ] && return
        [ "$BASH_COMMAND" = "$PROMPT_COMMAND" ] && return
        authsec_shield_preexec "$BASH_COMMAND" || kill -SIGINT $$
    }
    trap '__authsec_shield_trap' DEBUG
fi
%s`, hookMarkerStart, wslShieldPath, hookMarkerEnd)
}

// windowsToWSLPath converts a Windows path to a WSL mount path.
// e.g. D:\foo\bar.exe → /mnt/d/foo/bar.exe
func windowsToWSLPath(winPath string) string {
	if len(winPath) >= 2 && winPath[1] == ':' {
		drive := strings.ToLower(string(winPath[0]))
		rest := strings.ReplaceAll(winPath[2:], "\\", "/")
		return "/mnt/" + drive + rest
	}
	return strings.ReplaceAll(winPath, "\\", "/")
}

func cmdAutoRunScript() string {
	wrapperDir := wrapperDirPath()
	shieldBin := shieldBinaryPath()
	var lines []string
	lines = append(lines, "@echo off")
	lines = append(lines, "REM "+hookMarkerStart)
	lines = append(lines, fmt.Sprintf(`set "PATH=%s;%%PATH%%"`, wrapperDir))
	for _, cmd := range wrappers.WrappedCommands {
		realBin := wrappers.ResolveRealBinary(cmd)
		if realBin == "" {
			realBin = cmd + ".exe"
		}
		lines = append(lines,
			fmt.Sprintf(`doskey %s="%s" run --display "%s $*" -- "%s" $*`,
				cmd, shieldBin, cmd, realBin))
	}
	lines = append(lines, "REM "+hookMarkerEnd)
	return strings.Join(lines, "\r\n") + "\r\n"
}

func installCMD() error {
	home, _ := os.UserHomeDir()
	batPath := filepath.Join(home, ".authsec-shield", "cmd-hook.bat")
	if err := os.MkdirAll(filepath.Dir(batPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(batPath, []byte(cmdAutoRunScript()), 0644); err != nil {
		return err
	}
	script := fmt.Sprintf(
		`New-Item -Path "HKCU:\Software\Microsoft\Command Processor" -Force | Out-Null; `+
			`Set-ItemProperty -Path "HKCU:\Software\Microsoft\Command Processor" `+
			`-Name AutoRun -Value '"%s"' -Type String -Force`,
		strings.ReplaceAll(batPath, "'", "''"),
	)
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive",
		"-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set CMD AutoRun: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func uninstallCMD() {
	home, _ := os.UserHomeDir()
	batPath := filepath.Join(home, ".authsec-shield", "cmd-hook.bat")
	os.Remove(batPath)

	script := `Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Command Processor" ` +
		`-Name AutoRun -ErrorAction SilentlyContinue`
	exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Run() //nolint:errcheck
}

func shieldBinaryPath() string {
	// Try to find ourselves
	exe, err := os.Executable()
	if err != nil {
		if runtime.GOOS == "windows" {
			return "authsec-shield.exe"
		}
		return "authsec-shield"
	}
	return exe
}

func wrapperDirPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".authsec-shield", "bin")
}
