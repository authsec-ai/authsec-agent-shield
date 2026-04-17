package hooks

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Install installs shell hooks for all detected shells
func Install() ([]string, error) {
	var installed []string

	switch runtime.GOOS {
	case "windows":
		if err := installPowerShell(); err == nil {
			installed = append(installed, "PowerShell")
		}
		// Also install bash hooks on Windows — Claude Code, Codex, and other
		// AI tools use Git Bash/MSYS2, not PowerShell
		if err := installBash(); err == nil {
			installed = append(installed, "Git Bash")
		}
	default:
		if err := installBash(); err == nil {
			installed = append(installed, "Bash")
		}
		if err := installZsh(); err == nil {
			installed = append(installed, "Zsh")
		}
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
        authsec_shield_preexec "$BASH_COMMAND"
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
    & "%s" check $CommandLine 2>&1 | Out-Null
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

	return result
}

func fileContainsHook(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), hookMarkerStart)
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
