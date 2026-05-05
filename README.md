# AuthSec Agent Shield

**System-level protection against risky AI tool actions. One install. Every AI tool governed.**

When Claude Code, Codex, OpenClaw, Cursor, or any AI tool tries to run a dangerous command on your machine — `rm -rf`, `git push --force`, `kubectl delete namespace`, `DROP TABLE` — your phone buzzes first. You approve or deny. Then it executes.

Safe commands (`git status`, `docker ps`, `ls`, `cat`) pass through instantly with zero latency.

---

## Quick Start (Windows)

### Prerequisites

- Windows 10/11
- Go 1.22+ (to build from source)
- An AuthSec account (your admin gives you a client ID)

### 1. Build

```powershell
cd authsec-agent-shield
go build -o shield.exe ./cmd/shield/
```

### 2. Setup

```powershell
.\shield.exe setup --client-id <YOUR_CLIENT_ID> --base-url https://prod.api.authsec.ai
```

### 3. Login

```powershell
.\shield.exe login
```

Opens browser for AuthSec SSO. After authenticating, enter the code shown in your terminal on the activation page. The shield receives your credentials automatically.

### 4. Install (as Administrator)

Open **Administrator PowerShell** and run:

```powershell
# Step 1: Install hooks and wrappers
cd C:\path\to\authsec-agent-shield
.\shield.exe install

# Step 2: Install binary shims for Program Files (needs admin + takeown)
.\install-shims.ps1
```

Or in one command from a normal terminal:

```powershell
Start-Process powershell -Verb RunAs -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", "& {Set-Location 'C:\path\to\authsec-agent-shield'; .\install-shims.ps1}"
```

### 5. Verify

```powershell
.\shield.exe doctor
```

### 6. Done

Every risky AI action now requires your mobile approval.

---

## Quick Start (macOS / Linux)

### 1. Build

```bash
cd authsec-agent-shield
go build -o authsec-shield ./cmd/shield/
```

### 2. Setup + Login

```bash
./authsec-shield setup --client-id <YOUR_CLIENT_ID> --base-url https://prod.api.authsec.ai
./authsec-shield login
```

### 3. Install

```bash
sudo ./authsec-shield install
```

### 4. Verify

```bash
./authsec-shield doctor
```

---

## What Gets Protected

### Binary Shims (system-level, un-bypassable)

| Command | What it catches |
|---------|----------------|
| `rm`, `rmdir`, `shred`, `unlink` | File/directory deletion |
| `chmod`, `chown` | Permission changes |
| `mkfs`, `dd` | Disk operations |
| `git` | push --force, reset --hard, clean |
| `docker` | rm, rmi, system prune |
| `kubectl` | delete namespace/pod/deployment |
| `helm` | delete, uninstall |
| `terraform` | destroy |
| `aws`, `gcloud`, `az` | Cloud resource deletion |
| `mysql`, `psql` | DROP, DELETE, TRUNCATE |

### Shell Hooks (additional layer)

- **PowerShell**: CommandValidationHandler + wrapped cmdlets (Remove-Item, Set-Content, Move-Item, etc.)
- **Bash**: preexec via DEBUG trap
- **Zsh**: native preexec hook

### MCP Proxy (for Claude Desktop, Codex, Cursor)

Intercepts structured tool calls (`write_file`, `delete_file`, `execute_command`) at the JSON-RPC level.

### Filesystem Protection (NTFS ACL / chattr)

DENY write ACLs on sensitive directories: `.ssh`, `.aws`, `.kube`, `.env`

---

## Risk Scoring

Every command is scored locally (no network call). Only scores above the threshold (default: 30) trigger a network call for mobile approval.

| Command | Score | Result |
|---------|-------|--------|
| `ls -la` | 0 | Pass |
| `cat README.md` | 0 | Pass |
| `git status` | 0 | Pass |
| `docker ps` | 0 | Pass |
| `git push` | 30 | Pass (at threshold) |
| `rm file.txt` | 40 | Blocked |
| `git push --force` | 100 | Blocked |
| `rm -rf /` | 100 | Blocked |
| `kubectl delete namespace production` | 100 | Blocked |
| `DROP TABLE users` | 100 | Blocked |
| `mysql -e "DELETE FROM users"` | 100 | Blocked |

### What adds to the score

| Factor | Points |
|--------|--------|
| Destructive verb (rm, drop, delete) | +40 |
| Dangerous command pattern match | +60 |
| Force/hard flags (--force, -rf) | +20 |
| Recursive operation | +15 |
| Sensitive file path (.env, .ssh) | +25 |
| System path (/etc, C:\Windows) | +30 |
| Elevated privileges (sudo) | +15 |
| SQL destructive (DROP, TRUNCATE) | +60 |
| Pipe to destructive command | +30 |

---

## Commands

```
shield setup --client-id <id> --base-url <url>   Configure
shield login                                      Authenticate via AuthSec SSO
shield logout                                     Clear credentials
shield status                                     Show protection status
shield doctor                                     Diagnose installation health
shield install                                    Install all protection layers
shield uninstall                                  Remove all protection, restore originals
shield pause 1h                                   Pause protection for 1 hour
shield enable                                     Re-enable protection immediately
shield test "rm -rf /"                            Test a command's risk score
shield check "command"                            Evaluate command (used by hooks internally)
shield mcp-proxy -- <cmd> [args]                  Run as MCP proxy for Claude Desktop/Codex
```

---

## Architecture

```
┌──────────────────────────────────────────────┐
│              Your Machine                     │
│                                               │
│  Claude Code  Codex  OpenClaw  Cursor  ...    │
│       │         │       │        │            │
│  ┌────▼─────────▼───────▼────────▼─────────┐  │
│  │        AuthSec Agent Shield              │  │
│  │                                          │  │
│  │  Layer 1: Binary Shims                   │  │
│  │    rm, git, docker, kubectl, mysql, psql │  │
│  │    replaced at system level              │  │
│  │                                          │  │
│  │  Layer 2: Filesystem Protection          │  │
│  │    NTFS DENY ACL on .ssh, .aws, .kube    │  │
│  │                                          │  │
│  │  Layer 3: Shell Hooks                    │  │
│  │    PowerShell, Bash, Zsh preexec         │  │
│  │                                          │  │
│  │  Layer 4: MCP Proxy                      │  │
│  │    JSON-RPC interception for AI tools    │  │
│  │                                          │  │
│  │  Local Risk Engine (no network call)     │  │
│  │    score <= 30: pass instantly            │  │
│  │    score > 30: push to phone             │  │
│  └──────────────────────────────────────────┘  │
│                                               │
│  AuthSec API → CIBA Push → Mobile App         │
└──────────────────────────────────────────────┘
```

---

## Pause / Resume

When YOU need to work freely:

```bash
shield pause 1h      # Pause all protection for 1 hour
shield pause 30m     # Pause for 30 minutes
shield enable        # Re-enable immediately
```

During pause, all commands pass through unchecked.

---

## Uninstall

From admin PowerShell:

```powershell
.\shield.exe uninstall
```

This restores all original binaries, removes shell hooks, removes filesystem DENY ACLs, and cleans up wrappers.

---

## Tested Interceptions

All blocked during live testing with Claude Code (Anthropic):

| Command | Score | Status |
|---------|-------|--------|
| `rm -rf /tmp/shield-test/important.txt` | 55 | BLOCKED |
| `rm -rf /` | 100 | BLOCKED |
| `unlink file` | 40 | BLOCKED |
| `git push --force origin main` | 100 | BLOCKED |
| `git reset --hard HEAD~5` | 100 | BLOCKED |
| `docker rm -f container` | 50 | BLOCKED |
| `kubectl delete namespace production` | 100 | BLOCKED |
| `mysql -e "DROP TABLE users"` | 100 | BLOCKED |
| `git status` | 0 | PASSED |
| `docker ps` | 0 | PASSED |
| `ls -la` | 0 | PASSED |

---

## Standards

AuthSec Agent Shield implements the **Agent Action Approval Protocol (AAAP)** — an open standard for human-in-the-loop governance of AI agent actions.


## License

Apache-2.0

## Links

- Website: [authsec.ai](https://authsec.ai)
- GitHub: [github.com/authsec-ai](https://github.com/authsec-ai)
