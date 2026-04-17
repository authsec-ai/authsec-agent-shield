# AuthSec Agent Shield

AuthSec Agent Shield is a local command-approval guard for AI agents and interactive shells.

It evaluates risky commands and tool calls, sends approval requests to AuthSec, and blocks execution unless the action is approved or the shield is temporarily paused.

This repository is currently a strong prototype, not a fully hardened endpoint security product.

## What It Does

- Intercepts risky shell commands
- Intercepts risky PowerShell cmdlets
- Intercepts MCP tool calls through `mcp-proxy`
- Sends approval requests to AuthSec
- Blocks risky actions by default
- Allows a human to temporarily pause enforcement

## Current Model

The project currently uses three enforcement layers:

1. Shell hooks
2. Command wrappers
3. MCP proxy

This works well for many common workflows, but it is not yet a full brokered execution architecture. A determined local process can still bypass it if it avoids these paths.

## Supported Platforms

### Windows

Current support is best on Windows PowerShell / PowerShell.

Covered today:

- PowerShell profile hooks
- Wrapped binaries such as `kubectl`, `docker`, `gcloud`, `az`
- PowerShell cmdlets such as `Remove-Item`

Requirements:

- PowerShell profile must load successfully
- Execution policy must permit profile loading
- Wrapper directory must be first in `PATH`

### macOS / Linux

The repo contains bash/zsh hooks and Unix wrappers.

Expected flow:

- install shell hooks
- ensure wrapper dir is first in `PATH`
- route MCP tools through `authsec-shield mcp-proxy`

These paths are supported in code, but should still be validated on real machines with `doctor`.

## Build

From the repo root:

```powershell
go build -buildvcs=false -o authsec-shield.exe ./cmd/shield
```

On macOS / Linux:

```bash
go build -buildvcs=false -o authsec-shield ./cmd/shield
```

## Initial Setup

### 1. Configure tenant details

```powershell
.\authsec-shield.exe setup --client-id <client-id> --tenant-domain <domain> --base-url <url>
```

### 2. Login

```powershell
.\authsec-shield.exe login
```

### 3. Install hooks and wrappers

```powershell
.\authsec-shield.exe install
```

### 4. On Windows, allow PowerShell profiles to load

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### 5. Open a brand-new shell

This is required so the profile and wrapper PATH changes take effect.

## Daily Commands

### Show state

```powershell
.\authsec-shield.exe status
```

### Diagnose local issues

```powershell
.\authsec-shield.exe doctor
```

### Pause enforcement temporarily

```powershell
.\authsec-shield.exe pause 15m
```

### Re-enable immediately

```powershell
.\authsec-shield.exe enable
```

### Score a command without executing it

```powershell
.\authsec-shield.exe test "git reset --hard"
```

## End-to-End Testing

## Windows PowerShell

Open a fresh PowerShell window and run:

```powershell
.\authsec-shield.exe doctor
Get-Command Remove-Item
Get-Command kubectl -All
```

Expected:

- `Remove-Item` resolves as a `Function`
- wrapped tools appear from `C:\Users\<you>\.authsec-shield\bin`
- `doctor` should not say `PATH order: MISS`

Then test a local file delete:

```powershell
Set-Content demo-risky-delete.txt "test"
Remove-Item -LiteralPath demo-risky-delete.txt
```

Then test an external tool:

```powershell
kubectl delete namespace demo-test
```

## macOS / Linux

Open a fresh shell and run:

```bash
./authsec-shield doctor
which rm
which kubectl
```

Then test:

```bash
./authsec-shield test "rm -rf /tmp/demo"
./authsec-shield test "kubectl delete namespace demo-test"
```

## Claude / MCP Tools

Route the MCP server through the shield:

```json
{
  "command": "authsec-shield",
  "args": ["mcp-proxy", "--", "npx", "mcp-server-filesystem", "/path"]
}
```

On Windows, use the full path to `authsec-shield.exe`.

## What `doctor` Checks

- config file present
- logged in state
- enabled / paused state
- expected shell profile files
- wrapper directory
- wrapper presence for common tools
- whether wrapper dir appears in `PATH`

## Known Limitations

The current project is not fully bypass-proof.

It can still be bypassed if a process:

- does not use the protected shell
- does not load the profile
- executes binaries directly outside wrapper resolution
- uses a different execution runtime
- directly edits files or config with the same user privileges

This is why the next architectural step is a broker model, where all risky execution must pass through a single local execution service.

## Why Codex Could Still Edit Files During Development

This is the honest answer:

- My edits in this repo were often made through the development environment's file-editing tool, not through your PowerShell hook or wrapped binaries.
- Your shield currently protects shell commands, PowerShell cmdlets, wrappers, and MCP proxy traffic.
- It does not yet broker every possible write path from every local tool.

So when I edited files directly through the coding environment, those changes did not automatically flow through the same interception layer that catches `Remove-Item`, `kubectl`, or `git reset --hard`.

That is exactly why a future broker architecture is needed.

## Product Direction

To become broadly reliable across devices and operating systems, the project should evolve toward:

1. A local execution broker
2. MCP-first integration
3. Shell hooks and wrappers as defense-in-depth
4. Doctor/self-healing install checks
5. Optional OS-level hardening

## Quick Troubleshooting

### `doctor` says `PATH order: MISS`

Your current shell is not using the wrapper directory.

Temporary fix:

```powershell
$env:PATH = "C:\Users\<you>\.authsec-shield\bin;$env:PATH"
```

Then open a fresh shell and test again.

### PowerShell profile is not loading

Set execution policy:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then restart PowerShell.

### `kubectl` still bypasses

Run:

```powershell
Get-Command kubectl -All
```

The first result must be the wrapper in `.authsec-shield\bin`.

## Current Status

Good for:

- demos
- development environments
- approval workflow validation
- shell and MCP guarding

Not yet complete for:

- full endpoint enforcement
- guaranteed cross-device hardening
- unbypassable local control
