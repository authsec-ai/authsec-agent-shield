package risk

import (
	"path/filepath"
	"strings"
)

// Level represents risk severity
type Level string

const (
	LevelNone     Level = "none"
	LevelLow      Level = "low"
	LevelMedium   Level = "medium"
	LevelHigh     Level = "high"
	LevelCritical Level = "critical"
)

// Evaluation is the result of scoring a command/action
type Evaluation struct {
	Score   int      `json:"score"` // 0-100
	Level   Level    `json:"level"`
	Reasons []string `json:"reasons"` // human-readable explanation
	Action  string   `json:"action"`  // what was detected
	Target  string   `json:"target"`  // what it targets
}

// Engine scores commands and actions locally — no API call needed
type Engine struct {
	dangerousCommands []string
	protectedPaths    []string
	autoApproveRead   bool
}

// NewEngine creates a risk engine with the given config
func NewEngine(dangerousCommands, protectedPaths []string, autoApproveRead bool) *Engine {
	return &Engine{
		dangerousCommands: dangerousCommands,
		protectedPaths:    protectedPaths,
		autoApproveRead:   autoApproveRead,
	}
}

// EvaluateCommand scores a shell command
func (e *Engine) EvaluateCommand(command string) *Evaluation {
	eval := &Evaluation{
		Action: command,
	}

	cmd := strings.TrimSpace(command)
	upper := strings.ToUpper(cmd)
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return eval
	}

	parts, wrapperReasons := normalizeWrappedCommand(parts)
	for _, reason := range wrapperReasons {
		eval.Score += 20
		eval.Reasons = append(eval.Reasons, reason)
	}
	if len(parts) == 0 {
		eval.Level = scoreToLevel(eval.Score)
		return eval
	}

	base := commandBase(parts[0])
	lowerCmd := strings.ToLower(cmd)

	// Check against dangerous commands list
	for _, dangerous := range e.dangerousCommands {
		normalizedDangerous := normalizeCommandString(dangerous)
		normalizedCmd := normalizeCommandString(strings.Join(parts, " "))
		if strings.EqualFold(base, normalizedDangerous) || strings.HasPrefix(normalizedCmd, normalizedDangerous) || strings.HasPrefix(upper, strings.ToUpper(dangerous)) {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "Matches dangerous command: "+dangerous)
			break
		}
	}

	if isShieldRealPath(parts[0]) {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "Direct execution of shield backup binary")
	}

	// Destructive verbs
	if isDestructiveVerb(base) {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "Destructive operation: "+base)
	}

	// Force flags
	if containsFlag(parts, "--force", "-f", "--hard", "--no-verify") {
		eval.Score += 20
		eval.Reasons = append(eval.Reasons, "Uses force/dangerous flag")
	}

	// Recursive flags
	if containsFlag(parts, "-r", "-rf", "-R", "--recursive") {
		eval.Score += 15
		eval.Reasons = append(eval.Reasons, "Recursive operation")
	}

	// Targets sensitive paths (only check args that look like file paths)
	for _, arg := range parts[1:] {
		if looksLikePath(arg) && e.isSensitivePath(arg) {
			eval.Score += 25
			eval.Target = arg
			eval.Reasons = append(eval.Reasons, "Targets sensitive path: "+arg)
			break
		}
	}

	// Root/system paths
	for _, arg := range parts[1:] {
		if looksLikePath(arg) && isSystemPath(arg) {
			eval.Score += 30
			eval.Reasons = append(eval.Reasons, "Targets system path: "+arg)
			break
		}
	}

	// Pipe to dangerous commands / shell
	if strings.Contains(cmd, "| rm") || strings.Contains(cmd, "| xargs rm") ||
		strings.Contains(cmd, "| dd") {
		eval.Score += 30
		eval.Reasons = append(eval.Reasons, "Pipes to destructive command")
	}
	// Redirect to block device (disk overwrite): cat /dev/zero > /dev/sda
	if strings.Contains(cmd, "> /dev/sd") || strings.Contains(cmd, "> /dev/nvme") ||
		strings.Contains(cmd, "> /dev/hd") || strings.Contains(cmd, "> /dev/vd") {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "Redirects to block device (disk overwrite)")
	}
	// Remote code execution: curl/wget piped to shell
	if (strings.Contains(lowerCmd, "curl ") || strings.Contains(lowerCmd, "wget ")) &&
		(strings.Contains(lowerCmd, "| bash") || strings.Contains(lowerCmd, "| sh") ||
			strings.Contains(lowerCmd, "| sudo") || strings.Contains(lowerCmd, "| python") ||
			strings.Contains(lowerCmd, "| zsh") || strings.Contains(lowerCmd, "|bash") ||
			strings.Contains(lowerCmd, "|sh") || strings.Contains(lowerCmd, "|sudo")) {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "Remote code execution: download piped to shell")
	}

	// Sudo / elevated
	if base == "sudo" || base == "runas" || base == "doas" {
		eval.Score += 15
		eval.Reasons = append(eval.Reasons, "Elevated privileges")
	}

	if isInterpreter(base) && hasInlineCodeFlag(parts) {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "Inline code execution via interpreter")
	}

	// find -delete / find -exec rm — indirect deletion
	if base == "find" {
		if containsFlag(parts, "-delete") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "find -delete: recursive file deletion")
		}
		if containsFlag(parts, "-exec") || containsFlag(parts, "-execdir") {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "find -exec: executes command on matched files")
		}
	}

	// rsync --delete — can wipe destination
	if base == "rsync" && (containsFlag(parts, "--delete", "--delete-before",
		"--delete-after", "--delete-during", "--delete-excluded") ||
		containsFlag(parts, "--remove-source-files")) {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "rsync --delete: removes destination files not in source")
	}

	// AWS CLI destructive subcommands
	if base == "aws" && len(parts) > 2 {
		svc := strings.ToLower(parts[1])
		sub := strings.ToLower(parts[2])
		awsDestructive := sub == "rm" || sub == "delete" || sub == "terminate" ||
			sub == "destroy" || sub == "remove" || sub == "deregister" ||
			sub == "delete-stack" || sub == "delete-cluster"
		if awsDestructive {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "AWS destructive: aws "+svc+" "+sub)
		}
		if containsFlag(parts, "--recursive") {
			eval.Score += 15
			eval.Reasons = append(eval.Reasons, "AWS recursive operation")
		}
	}

	// gcloud destructive subcommands
	if base == "gcloud" && len(parts) > 1 {
		gcCmd := strings.ToLower(strings.Join(parts[1:], " "))
		if strings.Contains(gcCmd, "delete") || strings.Contains(gcCmd, "remove") ||
			strings.Contains(gcCmd, "destroy") || strings.Contains(gcCmd, "cancel") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "gcloud destructive operation")
		}
	}

	// Unknown binary with destructive flags — renamed binary bypass attempt
	// e.g. rm.bak -rf /, ./mydelete -rf /, xrm -rf /
	if !isKnownCommand(base) && !isInterpreter(base) {
		// Combined flag -rf/-fr counts as both recursive+force
		hasCombined := containsFlag(parts, "-rf", "-fr", "-Rf", "-fR")
		hasRecursive := hasCombined || containsFlag(parts, "-r", "-R", "--recursive")
		hasForce := hasCombined || containsFlag(parts, "-f", "--force")
		hasPathArg := false
		for _, arg := range parts[1:] {
			if looksLikePath(arg) {
				hasPathArg = true
				break
			}
		}
		if hasRecursive && hasForce && hasPathArg {
			eval.Score += 55
			eval.Reasons = append(eval.Reasons, "Unknown binary with recursive+force flags targeting path (possible renamed rm)")
		} else if hasRecursive && hasForce {
			eval.Score += 35
			eval.Reasons = append(eval.Reasons, "Unknown binary with recursive+force flags")
		} else if hasCombined && hasPathArg {
			eval.Score += 45
			eval.Reasons = append(eval.Reasons, "Unknown binary with -rf flag targeting path")
		}
	}

	if base == "curl" || base == "wget" || base == "http" {
		if containsFlag(parts, "-X", "--request") && containsAnyFold(parts, "DELETE", "POST", "PUT", "PATCH") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "Mutating HTTP request")
		}
		if strings.Contains(lowerCmd, "kubernetes") || strings.Contains(lowerCmd, "/api/v1/") ||
			strings.Contains(lowerCmd, "docker.sock") || strings.Contains(lowerCmd, "containerd.sock") {
			eval.Score += 30
			eval.Reasons = append(eval.Reasons, "Targets infrastructure API endpoint")
		}
	}

	// SQL danger
	if strings.Contains(upper, "DROP ") || strings.Contains(upper, "DELETE FROM") ||
		strings.Contains(upper, "TRUNCATE ") || strings.Contains(upper, "ALTER TABLE") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "SQL destructive operation")
	}

	// Git push (especially force)
	if base == "git" && len(parts) > 1 {
		sub := findSubcommand(parts[1:], gitGlobalOptions)
		switch sub {
		case "push":
			eval.Score += 30
			eval.Reasons = append(eval.Reasons, "Git push")
			if containsFlag(parts, "--force", "-f", "--force-with-lease") {
				eval.Score += 30
				eval.Reasons = append(eval.Reasons, "Force push")
			}
		case "reset":
			if containsFlag(parts, "--hard") {
				eval.Score += 50
				eval.Reasons = append(eval.Reasons, "Git reset --hard")
			}
		case "clean":
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "Git clean (removes untracked files)")
		}
	}

	// Docker/k8s destructive
	if base == "docker" || base == "kubectl" || base == "helm" {
		sub := findSubcommand(parts[1:], cliGlobalOptions(base))
		dockerSystemPrune := isDockerSystemPrune(base, sub, parts[1:])
		if isDestructiveSubcommand(sub) || dockerSystemPrune {
			eval.Score += 50
			reason := base + " " + sub
			if dockerSystemPrune {
				reason = "docker system prune"
			}
			eval.Reasons = append(eval.Reasons, "Container/orchestration destructive: "+reason)
		}
	}

	if base == "terraform" {
		sub := findSubcommand(parts[1:], terraformGlobalOptions)
		if isDestructiveSubcommand(sub) {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "Terraform destructive operation: "+sub)
		}
	}

	// ── Fork bomb ───────────────────────────────────────────────────────────────
	if strings.Contains(cmd, ":(){ :|:& }") || strings.Contains(cmd, ":(){:|:&}") ||
		strings.Contains(cmd, ":(){ :|: & }") {
		eval.Score += 100
		eval.Reasons = append(eval.Reasons, "Fork bomb: crashes system by exhausting processes")
	}

	// ── System-wide permission destruction ───────────────────────────────────────
	if (base == "chmod" || base == "chown") && containsFlag(parts, "-R", "-r", "--recursive") {
		for _, arg := range parts[1:] {
			if arg == "/" || arg == "/*" || arg == "/." || strings.HasPrefix(arg, "/etc") ||
				strings.HasPrefix(arg, "/usr") || strings.HasPrefix(arg, "/bin") {
				eval.Score += 70
				eval.Reasons = append(eval.Reasons, base+" -R on system root (destroys all permissions)")
				break
			}
		}
	}

	// ── chmod world-writable / setuid ────────────────────────────────────────────
	if base == "chmod" {
		chmodFull := strings.ToLower(strings.Join(parts, " "))
		isRecursive := containsFlag(parts, "-R", "-r", "--recursive")

		// Detect world-writable modes: 777, 666, a+w, o+w, ugo+w
		isWorldWritable := strings.Contains(chmodFull, "777") ||
			strings.Contains(chmodFull, "666") ||
			strings.Contains(chmodFull, "a+w") ||
			strings.Contains(chmodFull, "o+w") ||
			strings.Contains(chmodFull, "ugo+w")

		// Detect setuid/setgid: +s, u+s, g+s, 4000, 2000, 4755, 6755
		isSetuid := strings.Contains(chmodFull, "+s") ||
			strings.Contains(chmodFull, "4000") || strings.Contains(chmodFull, "2000") ||
			strings.Contains(chmodFull, "4755") || strings.Contains(chmodFull, "6755") ||
			strings.Contains(chmodFull, "4777") || strings.Contains(chmodFull, "6777")

		if isSetuid {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "chmod +s: sets setuid/setgid bit (privilege escalation vector)")
		}
		if isWorldWritable && isRecursive {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "chmod -R world-writable: makes directory tree writable by all users")
		} else if isWorldWritable {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "chmod world-writable (777/666/a+w): any user can modify this file")
		}
	}

	// ── Firewall / security teardown ─────────────────────────────────────────────
	if base == "iptables" || base == "ip6tables" {
		if containsFlag(parts, "-F") || containsFlag(parts, "--flush") ||
			containsFlag(parts, "-X") || containsFlag(parts, "--delete-chain") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "iptables flush: removes all firewall rules")
		}
		// iptables -P INPUT/OUTPUT/FORWARD DROP — blocks all traffic
		if containsFlag(parts, "-P") {
			policy := strings.ToUpper(strings.Join(parts, " "))
			if strings.Contains(policy, " DROP") || strings.Contains(policy, " REJECT") {
				eval.Score += 50
				eval.Reasons = append(eval.Reasons, "iptables default-deny policy: may lock out all connections")
			}
		}
	}
	if base == "ufw" && len(parts) > 1 {
		sub := strings.ToLower(parts[1])
		if sub == "disable" || sub == "reset" {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "ufw "+sub+": disables firewall")
		}
	}
	if base == "netsh" && strings.Contains(lowerCmd, "advfirewall") &&
		(strings.Contains(lowerCmd, "state off") || strings.Contains(lowerCmd, "reset")) {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "Windows firewall disabled")
	}
	if base == "set-mppreference" && strings.Contains(lowerCmd, "disablerealtimemonitoring") {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "Disables Windows Defender real-time monitoring")
	}
	if base == "stop-service" && strings.Contains(lowerCmd, "windefend") {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "Stops Windows Defender service")
	}

	// ── User / privilege manipulation ────────────────────────────────────────────
	if base == "passwd" {
		target := ""
		if len(parts) > 1 {
			target = parts[1]
		}
		eval.Score += 50
		if target == "root" || target == "administrator" || target == "" {
			eval.Score += 20
			eval.Reasons = append(eval.Reasons, "Changing root/system account password")
		} else {
			eval.Reasons = append(eval.Reasons, "Changing user password: "+target)
		}
	}
	if base == "usermod" && containsAnyFold(parts, "sudo", "wheel", "admin", "root") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "Adding user to privileged group (sudo/wheel)")
	}
	if base == "userdel" && containsFlag(parts, "-r", "--remove") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "userdel -r: deletes user and home directory")
	}
	if base == "crontab" && containsFlag(parts, "-r") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "crontab -r: removes all scheduled jobs")
	}
	// Windows user backdoor
	if base == "net" && len(parts) > 1 {
		netSub := strings.ToLower(parts[1])
		if netSub == "user" && containsAnyFold(parts, "/add") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "Creates new Windows user account")
		}
		if netSub == "localgroup" && containsAnyFold(parts, "administrators", "admin") &&
			containsAnyFold(parts, "/add") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "Adds user to local Administrators group")
		}
		if netSub == "user" && containsAnyFold(parts, "/active:yes") &&
			containsAnyFold(parts, "administrator") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "Enables built-in Administrator account")
		}
	}

	// ── Evidence / log destruction ───────────────────────────────────────────────
	if base == "history" && (containsFlag(parts, "-c") || containsFlag(parts, "-w")) {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "Shell history cleared (evidence destruction)")
	}
	if (base == "ln" || base == "echo") && strings.Contains(lowerCmd, ".bash_history") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "Modifying bash history (evidence tampering)")
	}
	if base == "wevtutil" && len(parts) > 1 && strings.ToLower(parts[1]) == "cl" {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "wevtutil cl: clears Windows event log (evidence destruction)")
	}
	if base == "vssadmin" && strings.Contains(lowerCmd, "delete shadows") {
		eval.Score += 90
		eval.Reasons = append(eval.Reasons, "vssadmin delete shadows: destroys backup copies (ransomware indicator)")
	}
	if base == "wmic" && strings.Contains(lowerCmd, "shadowcopy") && strings.Contains(lowerCmd, "delete") {
		eval.Score += 90
		eval.Reasons = append(eval.Reasons, "wmic shadowcopy delete: destroys backup copies (ransomware indicator)")
	}

	// ── Windows registry destruction ─────────────────────────────────────────────
	if base == "reg" && len(parts) > 1 && strings.ToLower(parts[1]) == "delete" {
		regTarget := strings.ToLower(strings.Join(parts[2:], " "))
		if strings.Contains(regTarget, "hklm\\system") || strings.Contains(regTarget, "hklm\\software") ||
			strings.Contains(regTarget, "hklm\\sam") || strings.Contains(regTarget, "hklm\\security") {
			eval.Score += 90
			eval.Reasons = append(eval.Reasons, "Deletes critical Windows registry hive")
		} else {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "Deletes registry key")
		}
	}

	// ── Boot / system destruction ────────────────────────────────────────────────
	if base == "bcdedit" && (strings.Contains(lowerCmd, "/delete") || strings.Contains(lowerCmd, "/deletevalue")) {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "bcdedit /delete: modifies boot configuration")
	}
	// sysctl kernel.sysrq — enables magic syskey (crash, reboot, kill all)
	if base == "sysctl" && strings.Contains(lowerCmd, "kernel.sysrq") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "sysctl kernel.sysrq: enables system crash/reboot key")
	}
	// mount --bind / — bind-mounts root filesystem (container escape / bypass)
	if base == "mount" && containsFlag(parts, "--bind") {
		for _, arg := range parts[1:] {
			if arg == "/" || arg == "/." {
				eval.Score += 70
				eval.Reasons = append(eval.Reasons, "mount --bind /: mounts root filesystem (bypass/escape vector)")
				break
			}
		}
	}
	// Windows scheduled tasks deletion
	if base == "schtasks" && containsFlag(parts, "/delete") {
		eval.Score += 50
		if containsAnyFold(parts, "*") {
			eval.Score += 20
			eval.Reasons = append(eval.Reasons, "schtasks /delete *: removes ALL scheduled tasks")
		} else {
			eval.Reasons = append(eval.Reasons, "schtasks /delete: removes scheduled task")
		}
	}
	// Windows service deletion/stop
	if base == "sc" && len(parts) > 1 {
		scSub := strings.ToLower(parts[1])
		if scSub == "delete" {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "sc delete: removes Windows service")
		}
		if scSub == "stop" {
			eval.Score += 35
			eval.Reasons = append(eval.Reasons, "sc stop: stops Windows service")
		}
	}
	// Windows startup registry persistence
	if base == "reg" && len(parts) > 1 && strings.ToLower(parts[1]) == "add" {
		regPath := strings.ToLower(strings.Join(parts[2:], " "))
		if strings.Contains(regPath, "currentversion\\run") || strings.Contains(regPath, "currentversion/run") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "reg add to Run key: adds program to startup (persistence)")
		}
	}
	// groupdel
	if base == "groupdel" {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "groupdel: deletes system group")
	}
	// Windows cipher /w (secure wipe free space)
	if base == "cipher" && containsFlag(parts, "/w") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "cipher /w: securely wipes free disk space")
	}
	// git branch -D (force local branch delete), git tag -d (delete tag)
	if base == "git" && len(parts) > 1 {
		sub := findSubcommand(parts[1:], gitGlobalOptions)
		if sub == "branch" && containsFlag(parts, "-D") {
			eval.Score += 35
			eval.Reasons = append(eval.Reasons, "git branch -D: force-deletes local branch")
		}
		if sub == "tag" && containsFlag(parts, "-d") {
			eval.Score += 35
			eval.Reasons = append(eval.Reasons, "git tag -d: deletes local tag")
		}
		if sub == "rebase" && containsFlag(parts, "-i") {
			eval.Score += 35
			eval.Reasons = append(eval.Reasons, "git rebase -i: rewrites commit history")
		}
	}
	// kubectl rollout undo to revision 0 (unpredictable state)
	if base == "kubectl" && strings.Contains(lowerCmd, "rollout undo") &&
		strings.Contains(lowerCmd, "--to-revision=0") {
		eval.Score += 35
		eval.Reasons = append(eval.Reasons, "kubectl rollout undo --to-revision=0: reverts to unknown state")
	}
	// docker exec shell
	if base == "docker" && len(parts) > 1 && strings.ToLower(parts[1]) == "exec" {
		execCmd := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(execCmd, " sh") || strings.Contains(execCmd, " bash") ||
			strings.Contains(execCmd, " /bin/") {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "docker exec: spawns shell inside container")
		}
	}
	// AWS public bucket ACL / bucket policy deletion
	if base == "aws" && len(parts) > 1 && strings.ToLower(parts[1]) == "s3api" {
		s3apiCmd := strings.ToLower(strings.Join(parts[2:], " "))
		if strings.Contains(s3apiCmd, "put-bucket-acl") && strings.Contains(s3apiCmd, "public") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "AWS S3: makes bucket publicly accessible")
		}
		if strings.Contains(s3apiCmd, "delete-bucket-policy") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "AWS S3: deletes bucket policy (may open access)")
		}
	}
	// aws ec2 stop-instances (takes instances offline)
	if base == "aws" && len(parts) > 2 &&
		strings.ToLower(parts[1]) == "ec2" && strings.ToLower(parts[2]) == "stop-instances" {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "AWS EC2: stops running instances")
	}
	// gcloud iam service-accounts keys create (creates credential key)
	if base == "gcloud" && strings.Contains(lowerCmd, "service-accounts keys create") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "gcloud: creates new service account key (credential exfiltration risk)")
	}
	// Network tools: arpspoof, nmap aggressive scan
	if base == "arpspoof" {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "arpspoof: ARP spoofing / MITM attack")
	}
	if base == "nmap" && (containsFlag(parts, "-sS", "-sU", "-O", "--script") ||
		strings.Contains(lowerCmd, "-p-")) {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "nmap aggressive/stealth scan")
	}
	// tcpdump writing to file (packet capture exfiltration)
	if base == "tcpdump" && containsFlag(parts, "-w") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "tcpdump -w: captures network traffic to file")
	}
	// SSH reverse tunnel (can expose internal services)
	if base == "ssh" && containsFlag(parts, "-R") {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "ssh -R: creates reverse tunnel (exposes local service remotely)")
	}
	// sudo su / sudo -i — full root shell
	// After normalizeWrappedCommand strips "sudo", base becomes "su"
	if base == "su" {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "su: drops into root/other user shell")
	}
	// Also catch if "sudo su" appears in original cmd (before normalization strips it)
	if strings.Contains(lowerCmd, "sudo su") || strings.Contains(lowerCmd, "sudo -i") ||
		strings.Contains(lowerCmd, "sudo bash") || strings.Contains(lowerCmd, "sudo sh") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "sudo su / sudo -i: drops into interactive root shell")
	}
	// env/printenv piped to grep for secrets — check on original lowerCmd
	// (after normalization, base may become "|" when piped)
	if strings.Contains(lowerCmd, "env") && strings.Contains(lowerCmd, "grep") {
		if strings.Contains(lowerCmd, "secret") || strings.Contains(lowerCmd, "password") ||
			strings.Contains(lowerCmd, "token") || strings.Contains(lowerCmd, "passwd") ||
			strings.Contains(lowerCmd, "cred") || strings.Contains(lowerCmd, "_key") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "env | grep: searching environment for secrets")
		}
	}
	// echo/write to /proc/sys kernel tunables
	if strings.Contains(lowerCmd, "> /proc/sys/kernel/sysrq") ||
		strings.Contains(lowerCmd, ">/proc/sys/kernel/sysrq") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "Writes to /proc/sys/kernel/sysrq (enables crash/reboot key)")
	}
	// Windows cipher /w: (secure wipe — flag uses colon syntax)
	if base == "cipher" {
		for _, arg := range parts[1:] {
			if strings.HasPrefix(strings.ToLower(arg), "/w:") || strings.ToLower(arg) == "/w" {
				eval.Score += 50
				eval.Reasons = append(eval.Reasons, "cipher /w: securely wipes free disk space (irreversible)")
				break
			}
		}
	}
	// aws ecr delete-repository
	if base == "aws" && len(parts) > 2 &&
		strings.ToLower(parts[1]) == "ecr" && strings.ToLower(parts[2]) == "delete-repository" {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "AWS ECR: deletes container image repository")
	}
	// aws ec2 modify-instance-attribute --no-disable-api-termination (enables termination)
	if base == "aws" && strings.Contains(lowerCmd, "no-disable-api-termination") {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "AWS EC2: enables API termination on instance")
	}

	// ── Windows rd/rmdir C:\ ─────────────────────────────────────────────────────
	if (base == "rd" || base == "rmdir") && containsFlag(parts, "/s") {
		for _, arg := range parts[1:] {
			if strings.HasPrefix(strings.ToUpper(arg), "C:\\") || arg == "C:\\" || arg == "C:" {
				eval.Score += 90
				eval.Reasons = append(eval.Reasons, "rd /s on C:\\ — deletes entire Windows drive")
				break
			}
		}
	}

	// ── Windows ACL grant Everyone full control ──────────────────────────────────
	if base == "icacls" && strings.Contains(lowerCmd, "everyone") && strings.Contains(lowerCmd, ":f") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "icacls grants Everyone full control")
	}

	// ── PowerShell RCE / policy bypass ──────────────────────────────────────────
	if base == "powershell" || base == "pwsh" {
		if containsAnyFold(parts, "-ExecutionPolicy", "-ep") &&
			containsAnyFold(parts, "Bypass", "Unrestricted") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "PowerShell execution policy bypassed")
		}
	}
	if base == "set-executionpolicy" && containsAnyFold(parts, "Unrestricted", "Bypass") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "Sets PowerShell execution policy to Unrestricted/Bypass")
	}
	// PowerShell Invoke-Expression / IEX remote download
	if (base == "invoke-expression" || strings.Contains(lowerCmd, "invoke-expression") ||
		strings.Contains(lowerCmd, "iex ")) &&
		(strings.Contains(lowerCmd, "invoke-webrequest") || strings.Contains(lowerCmd, "webclient") ||
			strings.Contains(lowerCmd, "http://") || strings.Contains(lowerCmd, "https://")) {
		eval.Score += 90
		eval.Reasons = append(eval.Reasons, "PowerShell remote code execution (Invoke-Expression + download)")
	}

	// ── Docker dangerous operations ──────────────────────────────────────────────
	// docker run --privileged -v /:/host (container escape)
	if base == "docker" && len(parts) > 1 && strings.ToLower(parts[1]) == "run" {
		if containsFlag(parts, "--privileged") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "docker run --privileged: full host access")
		}
		for _, arg := range parts {
			if strings.HasPrefix(arg, "-v") || arg == "--volume" {
				if strings.Contains(arg, "/:/") || strings.Contains(arg, "/:/host") {
					eval.Score += 70
					eval.Reasons = append(eval.Reasons, "docker run mounts host root filesystem")
					break
				}
			}
		}
	}
	// docker volume rm all / docker kill all / docker network rm all
	if base == "docker" && len(parts) > 1 {
		sub2 := strings.ToLower(parts[1])
		if (sub2 == "volume" || sub2 == "network") && len(parts) > 2 &&
			strings.ToLower(parts[2]) == "rm" {
			if strings.Contains(cmd, "$(") || strings.Contains(cmd, "`") {
				eval.Score += 60
				eval.Reasons = append(eval.Reasons, "docker "+sub2+" rm all (command substitution)")
			}
		}
		if sub2 == "kill" && (strings.Contains(cmd, "$(") || strings.Contains(cmd, "`")) {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "Kills all running Docker containers")
		}
	}

	// ── Network disruption ───────────────────────────────────────────────────────
	if (base == "ip" || base == "ifconfig") && strings.Contains(lowerCmd, " down") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "Takes network interface down")
		// Bringing down loopback too = full network kill
		if strings.Contains(lowerCmd, "lo down") {
			eval.Score += 30
			eval.Reasons = append(eval.Reasons, "Brings down loopback — kills all local networking")
		}
	}
	if (base == "route" || base == "ip") && strings.Contains(lowerCmd, "del default") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "Deletes default network route (loses connectivity)")
	}

	// ── Reverse shells ───────────────────────────────────────────────────────────
	if (base == "nc" || base == "netcat" || base == "ncat") && containsFlag(parts, "-e", "--exec") {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "netcat reverse shell (-e flag)")
	}
	if base == "nc" && containsFlag(parts, "-l", "-lvnp", "-lvp", "-lnvp") &&
		containsFlag(parts, "-e") {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "netcat bind shell")
	}

	// ── MongoDB / Redis destructive ──────────────────────────────────────────────
	if (base == "mongo" || base == "mongosh") && strings.Contains(lowerCmd, "dropdatabase") {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "MongoDB: drops entire database")
	}
	if (base == "mongo" || base == "mongosh") && strings.Contains(lowerCmd, ".drop()") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "MongoDB: drops collection")
	}
	if base == "redis-cli" {
		sub2 := strings.ToUpper(strings.Join(parts[1:], " "))
		if strings.HasPrefix(sub2, "FLUSHALL") || strings.HasPrefix(sub2, "FLUSHDB") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "Redis: flushes all data")
		}
		if strings.Contains(sub2, "CONFIG SET REQUIREPASS \"\"") ||
			strings.Contains(sub2, "CONFIG SET REQUIREPASS ''") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "Redis: removes authentication password")
		}
	}

	// ── AWS IAM privilege escalation / backdoor ──────────────────────────────────
	if base == "aws" && len(parts) > 1 && strings.ToLower(parts[1]) == "iam" {
		awsIAMCmd := strings.ToLower(strings.Join(parts[2:], " "))
		if strings.Contains(awsIAMCmd, "attach") && strings.Contains(awsIAMCmd, "administratoraccess") {
			eval.Score += 90
			eval.Reasons = append(eval.Reasons, "AWS IAM: attaches AdministratorAccess policy (privilege escalation)")
		}
		if strings.Contains(awsIAMCmd, "create-user") && strings.Contains(awsIAMCmd, "backdoor") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "AWS IAM: creates suspicious backdoor user")
		}
		if strings.Contains(awsIAMCmd, "delete-user") || strings.Contains(awsIAMCmd, "delete-role") ||
			strings.Contains(awsIAMCmd, "delete-policy") || strings.Contains(awsIAMCmd, "delete-group") ||
			strings.Contains(awsIAMCmd, "delete-access-key") || strings.Contains(awsIAMCmd, "delete-instance-profile") ||
			strings.Contains(awsIAMCmd, "delete-virtual-mfa-device") ||
			strings.Contains(awsIAMCmd, "detach") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "AWS IAM: destructive identity operation")
		}
		if strings.Contains(awsIAMCmd, "create-login-profile") || strings.Contains(awsIAMCmd, "update-login-profile") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "AWS IAM: creating/changing console login credentials")
		}
	}
	// AWS S3 force-remove bucket
	if base == "aws" && len(parts) > 2 &&
		strings.ToLower(parts[1]) == "s3" && strings.ToLower(parts[2]) == "rb" &&
		containsFlag(parts, "--force") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "AWS S3: force-removes bucket and all contents")
	}
	// AWS delete of other resources not caught above
	if base == "aws" && len(parts) > 2 {
		awsSub := strings.ToLower(parts[2])
		if awsSub == "delete-db-instance" || awsSub == "delete-db-cluster" ||
			awsSub == "delete-function" || awsSub == "delete-security-group" ||
			awsSub == "delete-vpc" || awsSub == "delete-hosted-zone" {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "AWS destructive: "+strings.ToLower(parts[1])+" "+awsSub)
		}
	}

	// ── Azure destructive (not already caught) ────────────────────────────────────
	if base == "az" && len(parts) > 1 {
		azCmd := strings.ToLower(strings.Join(parts[1:], " "))
		if strings.Contains(azCmd, " delete") || strings.Contains(azCmd, " remove") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "Azure: destructive operation")
		}
		if strings.Contains(azCmd, "role assignment create") && strings.Contains(azCmd, "owner") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "Azure: assigns Owner role (privilege escalation)")
		}
		if strings.Contains(azCmd, "sp create") && strings.Contains(azCmd, "owner") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "Azure: creates service principal with Owner role")
		}
	}

	// ── Terraform/Pulumi apply/destroy ───────────────────────────────────────────
	if base == "terraform" {
		sub := findSubcommand(parts[1:], terraformGlobalOptions)
		if sub == "apply" {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "terraform apply: modifies/creates infrastructure")
		}
		if sub == "state" && len(parts) > 2 && strings.ToLower(parts[2]) == "rm" {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "terraform state rm: removes resource from state (dangerous drift)")
		}
	}
	if base == "pulumi" && len(parts) > 1 {
		pulSub := strings.ToLower(parts[1])
		if pulSub == "destroy" {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "pulumi destroy: tears down all stack resources")
		}
		if pulSub == "stack" && len(parts) > 2 && strings.ToLower(parts[2]) == "rm" {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "pulumi stack rm: permanently deletes stack")
		}
	}

	// ── Ansible shell module running destructive commands ────────────────────────
	if (base == "ansible") && containsAnyFold(parts, "-m") {
		for i, p := range parts {
			if strings.ToLower(p) == "-a" && i+1 < len(parts) {
				innerCmd := parts[i+1]
				innerEval := NewEngine(e.dangerousCommands, e.protectedPaths, e.autoApproveRead).EvaluateCommand(innerCmd)
				if innerEval.Score > 30 {
					eval.Score += innerEval.Score / 2
					eval.Reasons = append(eval.Reasons, "ansible -m shell running: "+innerCmd)
				}
				break
			}
		}
	}
	// ansible-playbook with destroy.yml or --limit all
	if base == "ansible-playbook" {
		for _, arg := range parts[1:] {
			if strings.Contains(strings.ToLower(arg), "destroy") {
				eval.Score += 60
				eval.Reasons = append(eval.Reasons, "ansible-playbook targeting destroy playbook")
				break
			}
		}
	}

	// ── Git remote branch deletion / history rewrite ─────────────────────────────
	if base == "git" && len(parts) > 1 {
		sub := findSubcommand(parts[1:], gitGlobalOptions)
		if sub == "push" && (strings.Contains(lowerCmd, "--delete") || strings.Contains(lowerCmd, " :refs/")) {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "git push --delete: deletes remote branch or tag")
		}
		if sub == "checkout" && containsFlag(parts, "--", ".") {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "git checkout -- .: discards all working tree changes")
		}
		if sub == "filter-branch" {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "git filter-branch: rewrites repository history")
		}
		if sub == "stash" && len(parts) > 2 {
			stashSub := strings.ToLower(parts[2])
			if stashSub == "drop" || stashSub == "clear" {
				eval.Score += 35
				eval.Reasons = append(eval.Reasons, "git stash "+stashSub+": discards stashed changes")
			}
		}
	}

	// ── Credential / secret exfiltration ────────────────────────────────────────
	if (base == "cat" || base == "less" || base == "more" || base == "head" || base == "tail") &&
		isCredentialPath(strings.Join(parts[1:], " ")) {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "Reading credential/private key file")
	}
	if base == "printenv" || base == "env" {
		envArgs := strings.ToUpper(strings.Join(parts[1:], " "))
		if strings.Contains(envArgs, "SECRET") || strings.Contains(envArgs, "PASSWORD") ||
			strings.Contains(envArgs, "TOKEN") || strings.Contains(envArgs, "KEY") ||
			strings.Contains(envArgs, "CREDENTIAL") {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "Reads secret/credential from environment")
		}
	}

	// ── Kubernetes exec / scale-to-zero ─────────────────────────────────────────
	if base == "kubectl" && len(parts) > 1 {
		sub := findSubcommand(parts[1:], kubectlGlobalOptions)
		if sub == "exec" {
			execCmd := strings.Join(parts, " ")
			if strings.Contains(execCmd, "rm -rf") || strings.Contains(execCmd, "sh") ||
				strings.Contains(execCmd, "bash") {
				eval.Score += 40
				eval.Reasons = append(eval.Reasons, "kubectl exec into container with shell/destructive cmd")
			}
		}
		if sub == "scale" && strings.Contains(lowerCmd, "replicas=0") {
			eval.Score += 35
			eval.Reasons = append(eval.Reasons, "kubectl scale to 0 replicas: takes service offline")
		}
		if sub == "apply" && (strings.Contains(lowerCmd, "http://") || strings.Contains(lowerCmd, "https://")) {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "kubectl apply from remote URL")
		}
	}

	// ── gcloud storage rm (missed by generic gcloud check) ───────────────────────
	if base == "gcloud" && len(parts) > 1 && strings.ToLower(parts[1]) == "storage" {
		storageCmd := strings.ToLower(strings.Join(parts[2:], " "))
		if strings.HasPrefix(storageCmd, "rm") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "gcloud storage rm: deletes cloud storage objects")
		}
	}

	// ── SQL UPDATE/GRANT without WHERE (affects all rows) ────────────────────────
	if strings.HasPrefix(upper, "UPDATE ") && !strings.Contains(upper, " WHERE ") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "SQL UPDATE without WHERE: modifies all rows")
	}
	if strings.HasPrefix(upper, "GRANT ") && strings.Contains(upper, "*.*") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "SQL GRANT ALL on *.* (grants global permissions)")
	}

	// ── Disk / block device tools ─────────────────────────────────────────────────
	if base == "wipefs" {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "wipefs: erases filesystem signatures from block device")
	}
	if base == "hdparm" && (strings.Contains(lowerCmd, "security-erase") || strings.Contains(lowerCmd, "--yes-i-know")) {
		eval.Score += 90
		eval.Reasons = append(eval.Reasons, "hdparm security-erase: permanent secure disk wipe")
	}
	if base == "parted" && containsAnyFold(parts, "rm", "mklabel", "mkpart") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "parted: modifies disk partition table")
	}
	if base == "badblocks" && containsFlag(parts, "-w") {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "badblocks -w: destructive write test (overwrites disk)")
	}
	if base == "resize2fs" || base == "tune2fs" {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, base+": modifies filesystem geometry/metadata")
	}
	if base == "diskpart" {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "diskpart: interactive disk partitioning (can wipe drives)")
	}
	if base == "fsutil" && strings.Contains(lowerCmd, "deletejournal") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "fsutil deletejournal: deletes USN change journal (anti-forensic)")
	}

	// ── Unmount / swap disable ────────────────────────────────────────────────────
	if base == "umount" && (containsFlag(parts, "-l", "--lazy") || containsAnyFold(parts, "/")) {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "umount: forcefully unmounts filesystem")
	}
	if base == "swapoff" && containsFlag(parts, "-a") {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "swapoff -a: disables all swap (memory pressure risk)")
	}

	// ── systemctl stop/disable/mask critical services ─────────────────────────────
	if base == "systemctl" && len(parts) > 1 {
		sctl := strings.ToLower(strings.Join(parts[1:], " "))
		sctlSub := strings.ToLower(parts[1])
		critServices := []string{"ssh", "sshd", "networking", "network", "networkd",
			"systemd-networkd", "firewalld", "ufw", "iptables", "apparmor", "selinux",
			"auditd", "rsyslog", "syslog", "cron", "crond", "docker", "containerd"}
		if sctlSub == "stop" || sctlSub == "disable" || sctlSub == "mask" {
			for _, svc := range critServices {
				if strings.Contains(sctl, svc) {
					eval.Score += 60
					eval.Reasons = append(eval.Reasons, "systemctl "+sctlSub+" critical service: "+svc)
					break
				}
			}
		}
	}

	// ── Security framework bypass ─────────────────────────────────────────────────
	if base == "setenforce" && containsAnyFold(parts, "0", "permissive") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "setenforce 0: disables SELinux enforcement")
	}
	if base == "aa-teardown" || base == "aa-disable" {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, base+": disables AppArmor security profiles")
	}
	// chmod 000 on security binaries
	if base == "chmod" && (strings.Contains(lowerCmd, "/usr/bin/sudo") ||
		strings.Contains(lowerCmd, "/bin/su") || strings.Contains(lowerCmd, "/usr/bin/ssh")) {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "chmod on security binary: disables sudo/su/ssh")
	}

	// ── Log/evidence wiping ──────────────────────────────────────────────────────
	if base == "journalctl" && (strings.Contains(lowerCmd, "--vacuum") ||
		strings.Contains(lowerCmd, "--rotate")) {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "journalctl vacuum/rotate: destroys system logs")
	}
	if base == "dmesg" && containsFlag(parts, "-c", "--clear") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "dmesg -c: clears kernel ring buffer")
	}
	if (base == "unset" && strings.Contains(lowerCmd, "histfile")) ||
		(base == "export" && (strings.Contains(lowerCmd, "histfilesize=0") ||
			strings.Contains(lowerCmd, "histsize=0"))) {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "Disables shell history logging (evidence destruction)")
	}

	// ── Windows: net stop critical services ──────────────────────────────────────
	if base == "net" && len(parts) > 1 && strings.ToLower(parts[1]) == "stop" {
		svcName := strings.ToLower(strings.Join(parts[2:], " "))
		critWinSvc := []string{"defender", "firewall", "eventlog", "wuauserv", "windefend",
			"mpssvc", "securityhealthservice", "wscsvc"}
		for _, svc := range critWinSvc {
			if strings.Contains(svcName, svc) {
				eval.Score += 70
				eval.Reasons = append(eval.Reasons, "net stop: disables critical Windows security service")
				break
			}
		}
	}
	// taskkill /f /im — force-kills processes
	if base == "taskkill" && containsFlag(parts, "/f", "/F") {
		eval.Score += 50
		svcKill := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(svcKill, "svchost") || strings.Contains(svcKill, "explorer") ||
			strings.Contains(svcKill, "lsass") || strings.Contains(svcKill, "winlogon") {
			eval.Score += 30
			eval.Reasons = append(eval.Reasons, "taskkill /f: force-kills critical Windows process")
		} else {
			eval.Reasons = append(eval.Reasons, "taskkill /f: force-kills process")
		}
	}
	// wmic uninstall antivirus / delete processes
	if base == "wmic" {
		wmicCmd := strings.ToLower(strings.Join(parts[1:], " "))
		if strings.Contains(wmicCmd, "uninstall") && strings.Contains(wmicCmd, "antivirus") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "wmic: uninstalls antivirus software")
		}
		if strings.Contains(wmicCmd, "process") && strings.Contains(wmicCmd, "delete") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "wmic process delete: terminates processes")
		}
	}
	// Windows: netsh disable interface / delete wlan profiles
	if base == "netsh" && strings.Contains(lowerCmd, "interface") && strings.Contains(lowerCmd, "disabled") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "netsh: disables network interface")
	}
	if base == "netsh" && strings.Contains(lowerCmd, "wlan") &&
		(strings.Contains(lowerCmd, "delete profile") || strings.Contains(lowerCmd, "disconnect")) {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "netsh wlan: removes WiFi profiles or disconnects")
	}
	// Windows: reg add for RDP enable / AutoAdminLogon (stores plaintext password)
	if base == "reg" && len(parts) > 1 && strings.ToLower(parts[1]) == "add" {
		regVal := strings.ToLower(strings.Join(parts[2:], " "))
		if strings.Contains(regVal, "fdenytsconnections") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "reg: enables Remote Desktop (RDP)")
		}
		if strings.Contains(regVal, "autoadminlogon") || strings.Contains(regVal, "defaultpassword") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "reg: stores plaintext password in registry (AutoAdminLogon)")
		}
	}
	// Windows: net accounts (weaken password policy)
	if base == "net" && len(parts) > 1 && strings.ToLower(parts[1]) == "accounts" {
		acctCmd := strings.ToLower(strings.Join(parts[2:], " "))
		if strings.Contains(acctCmd, "/maxpwage:unlimited") || strings.Contains(acctCmd, "/minpwlen:0") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "net accounts: weakens password policy")
		}
	}

	// ── PHP / other interpreters with inline code ─────────────────────────────────
	if (base == "php" || base == "lua" || base == "tclsh" || base == "wish") &&
		hasInlineCodeFlag(parts) {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "Inline code execution via interpreter")
	}
	// php -r (uses -r not -c/-e)
	if base == "php" && containsFlag(parts, "-r") {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "php -r: inline PHP code execution")
	}

	// ── Package manager destructive operations ────────────────────────────────────
	if (base == "apt-get" || base == "apt") && len(parts) > 1 {
		aptSub := strings.ToLower(parts[1])
		if aptSub == "purge" || aptSub == "remove" {
			pkgArgs := strings.ToLower(strings.Join(parts[2:], " "))
			critPkgs := []string{"sudo", "ssh", "openssl", "libc", "glibc", "kernel", "systemd", "*"}
			for _, pkg := range critPkgs {
				if strings.Contains(pkgArgs, pkg) {
					eval.Score += 70
					eval.Reasons = append(eval.Reasons, "apt "+aptSub+" critical package: "+pkg)
					break
				}
			}
		}
	}
	if base == "yum" || base == "dnf" {
		pkgCmd := strings.ToLower(strings.Join(parts[1:], " "))
		if strings.HasPrefix(pkgCmd, "remove") || strings.HasPrefix(pkgCmd, "erase") {
			critPkgs := []string{"sudo", "ssh", "kernel", "glibc", "openssl", "systemd"}
			for _, pkg := range critPkgs {
				if strings.Contains(pkgCmd, pkg) {
					eval.Score += 70
					eval.Reasons = append(eval.Reasons, base+" remove critical package: "+pkg)
					break
				}
			}
		}
	}
	if base == "dpkg" && strings.Contains(lowerCmd, "--remove") && strings.Contains(lowerCmd, "--force") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "dpkg --remove --force: force-removes package ignoring dependencies")
	}

	// ── kubectl dangerous read / proxy exposure ───────────────────────────────────
	if base == "kubectl" {
		kubectlFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(kubectlFull, "get secret") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "kubectl get secret: reads Kubernetes secrets")
		}
		if strings.Contains(kubectlFull, "proxy") && strings.Contains(kubectlFull, "accept-hosts") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "kubectl proxy with open accept-hosts: exposes API server publicly")
		}
	}

	// ── Docker swarm destructive ──────────────────────────────────────────────────
	if base == "docker" && strings.Contains(lowerCmd, "swarm") {
		if strings.Contains(lowerCmd, "leave") && containsFlag(parts, "--force") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "docker swarm leave --force: removes node from swarm")
		}
	}

	// ── AWS: secrets/keys/KMS/STS ────────────────────────────────────────────────
	if base == "aws" && len(parts) > 2 {
		awsSvc := strings.ToLower(parts[1])
		awsOp := strings.ToLower(strings.Join(parts[2:], " "))
		if awsSvc == "secretsmanager" && strings.Contains(awsOp, "delete-secret") {
			eval.Score += 70
			if strings.Contains(awsOp, "force-delete") {
				eval.Score += 20
			}
			eval.Reasons = append(eval.Reasons, "AWS: deletes secret (irreversible with --force-delete)")
		}
		if awsSvc == "kms" && (strings.Contains(awsOp, "disable-key") || strings.Contains(awsOp, "schedule-key-deletion")) {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "AWS KMS: disables/schedules deletion of encryption key")
		}
		if awsSvc == "sts" && strings.Contains(awsOp, "assume-role") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "AWS STS: assumes IAM role (privilege escalation potential)")
		}
		if awsSvc == "ssm" && strings.Contains(awsOp, "delete-parameter") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "AWS SSM: deletes parameter store entry")
		}
		if (awsSvc == "sns" || awsSvc == "sqs") && strings.Contains(awsOp, "delete") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "AWS "+strings.ToUpper(awsSvc)+": deletes messaging resource")
		}
		if awsSvc == "logs" && strings.Contains(awsOp, "delete-log-group") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "AWS CloudWatch Logs: deletes log group (evidence destruction)")
		}
		if awsSvc == "cloudwatch" && strings.Contains(awsOp, "delete-alarms") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "AWS CloudWatch: deletes monitoring alarms")
		}
		if awsSvc == "autoscaling" && strings.Contains(awsOp, "delete-auto-scaling-group") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "AWS: deletes auto-scaling group")
		}
		if awsSvc == "s3api" && strings.Contains(awsOp, "delete-public-access-block") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "AWS S3: removes public access block (may expose bucket)")
		}
		if awsSvc == "s3api" && strings.Contains(awsOp, "put-bucket-versioning") &&
			strings.Contains(awsOp, "suspended") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "AWS S3: suspends versioning (disables object recovery)")
		}
		if awsSvc == "elbv2" && strings.Contains(awsOp, "delete-load-balancer") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "AWS: deletes load balancer (takes service offline)")
		}
		if awsSvc == "elasticache" && strings.Contains(awsOp, "delete") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "AWS ElastiCache: deletes cache cluster")
		}
	}

	// ── Azure: keyvault purge / privileged ops ────────────────────────────────────
	if base == "az" {
		azFull := strings.ToLower(strings.Join(parts[1:], " "))
		if strings.Contains(azFull, "keyvault purge") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "az keyvault purge: permanently destroys key vault (unrecoverable)")
		}
	}

	// ── Terraform dangerous state operations ──────────────────────────────────────
	if base == "terraform" {
		tfFull := strings.ToLower(strings.Join(parts[1:], " "))
		if strings.HasPrefix(tfFull, "state push") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "terraform state push: overwrites remote state (can corrupt infra)")
		}
		if strings.HasPrefix(tfFull, "workspace delete") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "terraform workspace delete: removes environment workspace")
		}
		if strings.Contains(tfFull, "force-unlock") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "terraform force-unlock: removes state lock (concurrent apply risk)")
		}
	}
	// terraform/terragrunt destroy via chained commands
	if strings.Contains(lowerCmd, "terraform destroy") || strings.Contains(lowerCmd, "terragrunt destroy") {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "terraform/terragrunt destroy: tears down all infrastructure")
	}
	if base == "terragrunt" && strings.Contains(lowerCmd, "destroy") {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "terragrunt destroy: tears down all infrastructure")
	}
	if base == "cdktf" && containsAnyFold(parts, "destroy") {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "cdktf destroy: tears down CDK-defined infrastructure")
	}
	if base == "crossplane" && strings.Contains(lowerCmd, "delete") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "crossplane delete: removes cloud resources")
	}

	// ── Database: drop/shutdown/privilege removal ─────────────────────────────────
	if base == "dropdb" || base == "dropuser" || base == "pg_dropcluster" {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, base+": permanently drops PostgreSQL database/user/cluster")
	}
	if base == "psql" || base == "mysql" || base == "sqlcmd" {
		dbCmd := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(dbCmd, "pg_terminate_backend") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "Terminates active database connections")
		}
		if strings.Contains(dbCmd, "max_connections = 0") || strings.Contains(dbCmd, "max_connections=0") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "Sets max_connections=0: prevents all DB connections")
		}
	}
	if (base == "mongo" || base == "mongosh") && strings.Contains(lowerCmd, "admincommand") {
		mongoCmd := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(mongoCmd, "shutdown") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "MongoDB: shutdown command")
		}
		if strings.Contains(mongoCmd, "replsetstepdown") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "MongoDB: forces replica set primary to step down")
		}
		if strings.Contains(mongoCmd, "revokeroles") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "MongoDB: revokes admin roles from user")
		}
	}
	if base == "redis-cli" {
		redisFull := strings.ToUpper(strings.Join(parts[1:], " "))
		if strings.HasPrefix(redisFull, "CLUSTER RESET") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "Redis CLUSTER RESET: resets cluster node (loses all data)")
		}
		if strings.HasPrefix(redisFull, "CLUSTER FLUSHSLOTS") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "Redis CLUSTER FLUSHSLOTS: removes all slot assignments")
		}
		if strings.Contains(redisFull, "CONFIG SET SAVE \"\"") || strings.Contains(redisFull, "CONFIG SET SAVE ''") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "Redis: disables persistence (data lost on restart)")
		}
		if strings.Contains(redisFull, "CONFIG SET APPENDONLY NO") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "Redis: disables AOF persistence")
		}
	}
	// SQL: ALTER USER root with empty password
	if strings.Contains(upper, "ALTER USER") && (strings.Contains(upper, "ROOT") || strings.Contains(upper, "ADMIN")) &&
		(strings.Contains(cmd, "''") || strings.Contains(cmd, `""`)) {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "SQL: removes root/admin account password")
	}
	// SQL: REVOKE ALL
	if strings.HasPrefix(upper, "REVOKE ALL") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "SQL REVOKE ALL: removes all privileges from user")
	}
	// SQL: GRANT ALL with wildcard
	if strings.HasPrefix(upper, "GRANT ALL") && strings.Contains(upper, "*.*") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "SQL GRANT ALL ON *.*: grants global privileges to user")
	}

	// ── Network: nft/tc/nmcli/ethtool disruption ──────────────────────────────────
	if base == "nft" && strings.Contains(lowerCmd, "flush ruleset") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "nft flush ruleset: removes all netfilter rules (kills firewall)")
	}
	if base == "tc" && strings.Contains(lowerCmd, "netem") {
		if strings.Contains(lowerCmd, "loss 100") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "tc netem loss 100%: drops all network packets")
		} else if strings.Contains(lowerCmd, "delay") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "tc netem delay: artificially degrades network performance")
		}
	}
	if base == "nmcli" && strings.Contains(lowerCmd, "networking off") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "nmcli networking off: disables all network connectivity")
	}
	if base == "iptables" && strings.Contains(lowerCmd, "-a output") && strings.Contains(lowerCmd, "-j drop") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "iptables: blocks all outbound traffic")
	}

	// ── Cassandra / NoSQL destructive ────────────────────────────────────────────
	if base == "nodetool" {
		ntCmd := strings.ToLower(strings.Join(parts[1:], " "))
		if strings.HasPrefix(ntCmd, "decommission") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "nodetool decommission: removes Cassandra node from cluster")
		}
		if strings.HasPrefix(ntCmd, "removenode") || strings.HasPrefix(ntCmd, "assassinate") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "nodetool removenode/assassinate: forcefully removes cluster node")
		}
		if strings.HasPrefix(ntCmd, "drain") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "nodetool drain: stops accepting writes, flushes memtables")
		}
	}

	// ── Git config poisoning / remote manipulation ────────────────────────────────
	if base == "git" && strings.Contains(lowerCmd, "config") {
		gitConfigFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(gitConfigFull, "insteadof") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "git config insteadOf: rewrites all URL fetches (supply chain risk)")
		}
		if strings.Contains(gitConfigFull, "sshcommand") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "git config core.sshCommand: hijacks SSH used for git operations")
		}
		if strings.Contains(gitConfigFull, "autoadminlogon") || strings.Contains(gitConfigFull, "defaultpassword") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "git config: suspicious credential manipulation")
		}
	}
	if base == "git" && strings.Contains(lowerCmd, "remote set-url") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "git remote set-url: changes remote repository URL")
		if strings.Contains(lowerCmd, "evil") || !strings.Contains(lowerCmd, "github.com") {
			eval.Score += 20
			eval.Reasons = append(eval.Reasons, "Remote URL changed to suspicious host")
		}
	}
	// git archive + curl exfiltration pattern
	if base == "git" && strings.Contains(lowerCmd, "archive") &&
		(strings.Contains(lowerCmd, "curl") || strings.Contains(lowerCmd, "wget")) {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "git archive piped to curl: exfiltrates repository contents")
	}

	// ── GitHub/GitLab/Jenkins CLI destructive ────────────────────────────────────
	if base == "gh" {
		ghFull := strings.ToLower(strings.Join(parts[1:], " "))
		if strings.HasPrefix(ghFull, "repo delete") {
			eval.Score += 90
			eval.Reasons = append(eval.Reasons, "gh repo delete: permanently deletes GitHub repository")
		}
		if strings.Contains(ghFull, "secret delete") || strings.Contains(ghFull, "release delete") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "gh: deletes repository secret or release")
		}
		if strings.Contains(ghFull, "workflow disable") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "gh workflow disable: disables CI/CD workflow")
		}
	}
	if base == "gitlab-ctl" {
		ctlSub := strings.ToLower(strings.Join(parts[1:], " "))
		if strings.HasPrefix(ctlSub, "stop") || strings.HasPrefix(ctlSub, "uninstall") ||
			strings.HasPrefix(ctlSub, "cleanse") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "gitlab-ctl "+ctlSub+": stops/removes GitLab instance")
		}
	}
	if base == "gitlab-rails" && strings.Contains(lowerCmd, "destroy") {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "gitlab-rails runner destroy: permanently deletes GitLab object")
	}
	if strings.HasPrefix(base, "jenkins") && strings.Contains(lowerCmd, "delete") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "jenkins-cli delete: removes Jenkins job/node/view")
	}

	// ── npm / pip / package manager supply chain / self-destruction ──────────────
	if base == "npm" || base == "npx" || base == "yarn" || base == "pnpm" {
		pkgFull := strings.ToLower(strings.Join(parts, " "))
		if base == "npm" && strings.Contains(pkgFull, "uninstall") && strings.Contains(pkgFull, " npm") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "npm uninstall npm: destroys Node package manager")
		}
		if base == "npm" && strings.Contains(pkgFull, "unpublish") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "npm unpublish: permanently removes package from registry")
		}
		if base == "npm" && strings.Contains(pkgFull, "install -g") {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "npm install -g: installs unverified package globally")
		}
		if base == "npx" && containsFlag(parts, "--yes", "-y") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "npx --yes: auto-installs and runs unverified package")
		}
	}
	if base == "pip" || base == "pip3" {
		pipFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(pipFull, "uninstall") &&
			(strings.Contains(pipFull, " pip") || strings.Contains(pipFull, "setuptools") ||
				strings.Contains(pipFull, "wheel")) {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "pip uninstall: removes critical Python packaging tools")
		}
	}
	if base == "gem" && strings.Contains(lowerCmd, "uninstall") &&
		(containsFlag(parts, "--all") || containsFlag(parts, "--force")) {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "gem uninstall --all/--force: removes Ruby gems")
	}

	// ── Git: reflog/gc/prune wipes recovery history ───────────────────────────────
	if base == "git" {
		gitFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(gitFull, "reflog expire") && strings.Contains(gitFull, "expire=now") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "git reflog expire --expire=now: destroys commit recovery history")
		}
		if strings.Contains(gitFull, "gc") && strings.Contains(gitFull, "prune=now") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "git gc --prune=now: permanently removes unreachable objects")
		}
		if strings.Contains(gitFull, "submodule deinit") {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "git submodule deinit: removes submodule working tree")
		}
		if strings.Contains(gitFull, "remote remove") || strings.Contains(gitFull, "remote rm") {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "git remote remove: removes remote repository reference")
		}
		if strings.Contains(gitFull, "config --global") && strings.Contains(gitFull, "user.email") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "git config --global user.email: changes global commit identity")
		}
		// git bisect reset && git clean -fdx — the clean part is dangerous
		if strings.Contains(gitFull, "clean") && strings.Contains(gitFull, "-fdx") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "git clean -fdx: removes all untracked and ignored files")
		}
	}

	// ── kubectl: configmap dump, node patch, proxy exposure ──────────────────────
	if base == "kubectl" {
		kubeFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(kubeFull, "get configmap") && strings.Contains(kubeFull, "all-namespaces") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "kubectl get configmap --all-namespaces: may expose application secrets")
		}
		if strings.Contains(kubeFull, "patch node") && strings.Contains(kubeFull, "unschedulable") {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "kubectl patch node unschedulable: prevents workload scheduling on node")
		}
		if strings.Contains(kubeFull, "exec") && strings.Contains(kubeFull, "env") {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "kubectl exec env: reads container environment (may contain secrets)")
		}
	}

	// ── Docker: secret/config rm, swarm force-new-cluster, network disconnect ─────
	if base == "docker" {
		dockerFull := strings.ToLower(strings.Join(parts, " "))
		if (strings.Contains(dockerFull, "secret rm") || strings.Contains(dockerFull, "config rm")) &&
			(strings.Contains(dockerFull, "$(") || strings.Contains(dockerFull, "`")) {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "docker secret/config rm all: removes all swarm secrets/configs")
		}
		if strings.Contains(dockerFull, "swarm init") && strings.Contains(dockerFull, "force-new-cluster") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "docker swarm init --force-new-cluster: forcefully recreates swarm")
		}
		if strings.Contains(dockerFull, "network disconnect") {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "docker network disconnect: disconnects container from network")
		}
		if strings.Contains(dockerFull, "pause") && (strings.Contains(dockerFull, "$(") || strings.Contains(dockerFull, "`")) {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "docker pause all: freezes all running containers")
		}
	}

	// ── AWS EC2/IAM/networking destructive (catch-all for missed subcommands) ──────
	if base == "aws" {
		awsFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(awsFull, "ec2 delete-") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "AWS EC2: deletes networking/infrastructure resource")
		}
		if strings.Contains(awsFull, "ec2 revoke-security-group") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "AWS EC2: revokes security group rule (may disrupt access)")
		}
		// iam remove- and update-access-key not covered by the specific IAM block above
		if strings.Contains(awsFull, "iam remove-") || strings.Contains(awsFull, "iam update-access-key") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "AWS IAM: destructive identity/access operation")
		}
	}

	// ── gcloud compute instances stop/reset ──────────────────────────────────────
	if base == "gcloud" {
		gcFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(gcFull, "compute instances stop") || strings.Contains(gcFull, "compute instances reset") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "gcloud: stops/resets compute instance")
		}
	}

	// ── terraform plan -destroy + apply, state mv/import ─────────────────────────
	if base == "terraform" {
		tfFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(tfFull, "plan") && strings.Contains(tfFull, "-destroy") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "terraform plan -destroy: generates destruction plan")
		}
		if strings.HasPrefix(strings.TrimSpace(tfFull), "state mv") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "terraform state mv: renames resource in state (can break tracking)")
		}
	}
	// terraform plan -destroy && terraform apply in same command
	if strings.Contains(lowerCmd, "terraform") && strings.Contains(lowerCmd, "destroy") {
		if eval.Score < 80 {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "terraform destroy in pipeline: destroys infrastructure")
		}
	}

	// ── Pulumi: config set secret to empty, cancel ────────────────────────────────
	if base == "pulumi" {
		pulFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(pulFull, "config set") && strings.Contains(pulFull, "--secret") &&
			(strings.HasSuffix(pulFull, `""`) || strings.HasSuffix(pulFull, "''")) {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "pulumi config set --secret to empty: clears secret value")
		}
		if strings.HasPrefix(strings.TrimSpace(pulFull), "cancel") {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "pulumi cancel: cancels in-progress stack update")
		}
	}

	// ── SQL: UPDATE mysql.user (bypass normal auth), RENAME TABLE, RDS replication ──
	if strings.Contains(upper, "UPDATE MYSQL.USER") || strings.Contains(upper, "UPDATE `MYSQL`.`USER`") {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "SQL: directly modifies MySQL user authentication table")
	}
	if strings.Contains(upper, "CALL MYSQL.RDS_STOP_REPLICATION") ||
		strings.Contains(upper, "CALL MYSQL.RDS_RESET_EXTERNAL_MASTER") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "SQL: stops/resets RDS replication (data sync disruption)")
	}
	if strings.HasPrefix(upper, "RENAME TABLE") {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "SQL RENAME TABLE: renames table (application breakage risk)")
	}
	if strings.Contains(upper, "FLUSH PRIVILEGES") {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "SQL FLUSH PRIVILEGES: reloads grant tables (post privilege change)")
	}

	// ── mongosh revokeRolesFromUser ───────────────────────────────────────────────
	if (base == "mongo" || base == "mongosh") {
		mongoFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(mongoFull, "revokerolesfromuser") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "MongoDB: revokes roles from user (access disruption)")
		}
	}

	// ── Redis: replication change, persistence disable ────────────────────────────
	if base == "redis-cli" {
		rFull := strings.ToUpper(strings.Join(parts[1:], " "))
		if strings.HasPrefix(rFull, "SLAVEOF NO ONE") || strings.HasPrefix(rFull, "REPLICAOF NO ONE") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "Redis SLAVEOF NO ONE: breaks replication chain")
		}
		if strings.Contains(rFull, "MIGRATE") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "Redis MIGRATE: moves key to another Redis instance")
		}
		if strings.HasPrefix(rFull, "DEBUG") {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "Redis DEBUG command: can manipulate internal state")
		}
	}

	// ── Network: null route, tc delete, ethtool degrade, WiFi txpower 0 ──────────
	if base == "ip" && strings.Contains(lowerCmd, "route add") && strings.Contains(lowerCmd, "0.0.0.0") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "ip route add via 0.0.0.0: adds null/blackhole route")
	}
	if base == "tc" && strings.Contains(lowerCmd, "qdisc del") {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "tc qdisc del: removes traffic control rules")
	}
	if base == "ethtool" && strings.Contains(lowerCmd, "speed") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "ethtool: degrades network interface speed")
	}
	if base == "iwconfig" && strings.Contains(lowerCmd, "txpower 0") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "iwconfig txpower 0: disables WiFi transmit power")
	}
	if base == "hostnamectl" && strings.Contains(lowerCmd, "set-hostname") {
		eval.Score += 35
		eval.Reasons = append(eval.Reasons, "hostnamectl set-hostname: changes system hostname")
	}

	// ── fuser -k (kills processes using device) ───────────────────────────────────
	if base == "fuser" && containsFlag(parts, "-k") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "fuser -k: kills all processes using device/file")
	}

	// ── e2fsck -y (auto-repair filesystem — can cause data loss) ─────────────────
	if base == "e2fsck" && containsFlag(parts, "-y") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "e2fsck -y: auto-repairs filesystem (may destroy data)")
	}

	// ── setfattr removing SELinux label ──────────────────────────────────────────
	if base == "setfattr" && strings.Contains(lowerCmd, "security.selinux") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "setfattr: removes SELinux security label from binary")
	}

	// ── Windows: reg add HKLM\SYSTEM terminal server RDP enable ─────────────────
	// (path has space so parts[2] is split — check full joined string)
	if base == "reg" && len(parts) > 1 && strings.ToLower(parts[1]) == "add" {
		regJoined := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(regJoined, "fdenytsconnections") && strings.Contains(regJoined, "/d 0") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "reg: enables Remote Desktop (RDP) access")
		}
	}

	// ── SSH: disable host key checking ───────────────────────────────────────────
	if base == "ssh" && strings.Contains(lowerCmd, "stricthostkeychecking=no") {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "ssh -o StrictHostKeyChecking=no: disables MITM protection")
	}

	// ── Cassandra stress write (can overwhelm cluster) ────────────────────────────
	if base == "cassandra-stress" && containsAnyFold(parts, "write") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "cassandra-stress write: stress-tests Cassandra (production risk)")
	}

	// ── act (GitHub Actions local runner with untrusted event) ───────────────────
	if base == "act" && containsFlag(parts, "-e") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "act -e: runs GitHub Actions locally with custom event (code execution)")
	}

	// ── Jenkins: disconnect/reload ────────────────────────────────────────────────
	if strings.HasPrefix(base, "jenkins") {
		jenFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(jenFull, "disconnect-node") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "jenkins-cli disconnect-node: takes build agent offline")
		}
		if strings.Contains(jenFull, "reload-jcasc") {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "jenkins-cli reload-jcasc: reloads Jenkins configuration from disk")
		}
	}

	// ── GitLab rake cleanup ────────────────────────────────────────────────────────
	if base == "gitlab-rake" && strings.Contains(lowerCmd, "cleanup") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "gitlab-rake cleanup: removes GitLab artifacts/files")
	}

	// ── gh run cancel / workflow disable ─────────────────────────────────────────
	if base == "gh" {
		ghFull2 := strings.ToLower(strings.Join(parts[1:], " "))
		if strings.HasPrefix(ghFull2, "run cancel") {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "gh run cancel: cancels running CI/CD pipeline")
		}
	}

	// ── User/account manipulation ─────────────────────────────────────────────────
	if base == "chage" && containsFlag(parts, "-E") && containsAnyFold(parts, "0") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "chage -E 0: immediately expires user account")
	}
	if base == "usermod" && containsFlag(parts, "-L", "--lock") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "usermod -L: locks user account")
	}
	if base == "delgroup" && containsAnyFold(parts, "sudo", "wheel", "admin") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "delgroup: removes privileged group")
	}

	// ── Sysrq trigger / kernel panic ─────────────────────────────────────────────
	if strings.Contains(lowerCmd, "/proc/sysrq-trigger") || strings.Contains(lowerCmd, "sysrq-trigger") {
		eval.Score += 90
		eval.Reasons = append(eval.Reasons, "Writes to /proc/sysrq-trigger: triggers kernel crash/reboot")
	}
	if base == "sysctl" && strings.Contains(lowerCmd, "kernel.panic") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "sysctl kernel.panic: changes kernel panic behavior")
	}

	// ── cp/echo/redirect nullifying config files ──────────────────────────────────
	if (base == "cp" && strings.Contains(lowerCmd, "/dev/null")) ||
		(strings.Contains(lowerCmd, "> ~/") && strings.Contains(lowerCmd, "rc")) {
		for _, arg := range parts[1:] {
			if strings.Contains(arg, ".bashrc") || strings.Contains(arg, ".zshrc") ||
				strings.Contains(arg, ".profile") || strings.Contains(arg, ".bash_profile") {
				eval.Score += 60
				eval.Reasons = append(eval.Reasons, "Overwrites shell config file with null/empty")
				break
			}
		}
	}

	// ── chmod -R on home directory ────────────────────────────────────────────────
	if base == "chmod" && containsFlag(parts, "-R", "-r", "--recursive") {
		for _, arg := range parts[1:] {
			if arg == "~" || arg == "$HOME" || strings.HasPrefix(arg, "/home") {
				eval.Score += 60
				eval.Reasons = append(eval.Reasons, "chmod -R on home directory: destroys file permissions")
				break
			}
		}
	}

	// ── Dangerous mount operations ────────────────────────────────────────────────
	if base == "mount" {
		mountFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(mountFull, "tmpfs") && (strings.HasSuffix(strings.TrimSpace(mountFull), " /") ||
			strings.Contains(mountFull, "tmpfs /")) {
			eval.Score += 90
			eval.Reasons = append(eval.Reasons, "mount tmpfs over /: hides entire filesystem")
		}
		if strings.Contains(mountFull, "-v /:/") || strings.Contains(mountFull, "-v /:/mnt") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "Mounts host root filesystem into container")
		}
	}

	// ── cryptsetup luksFormat (formats disk with encryption) ─────────────────────
	if base == "cryptsetup" && strings.Contains(lowerCmd, "luksformat") {
		eval.Score += 90
		eval.Reasons = append(eval.Reasons, "cryptsetup luksFormat: encrypts/formats block device (data destruction)")
	}

	// ── ulimit DoS ────────────────────────────────────────────────────────────────
	if base == "ulimit" {
		for _, arg := range parts[1:] {
			if arg == "1" || arg == "0" {
				eval.Score += 60
				eval.Reasons = append(eval.Reasons, "ulimit set to 1/0: can cause system-wide DoS")
				break
			}
		}
	}

	// ── resource exhaustion tools ─────────────────────────────────────────────────
	if base == "stress" || base == "stress-ng" {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, base+": resource exhaustion tool (CPU/memory DoS)")
	}

	// ── PATH poisoning ────────────────────────────────────────────────────────────
	if base == "export" && strings.Contains(lowerCmd, "path=") &&
		(strings.Contains(lowerCmd, "/dev/null") || strings.Contains(lowerCmd, "path=\"\"") ||
			strings.Contains(lowerCmd, "path=''")) {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "export PATH to null/empty: breaks all command execution")
	}
	if base == "export" && strings.Contains(lowerCmd, "path=") &&
		strings.Contains(lowerCmd, "http") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "export PATH with URL: PATH hijacking with remote source")
	}

	// ── SSH authorized_keys backdoor ─────────────────────────────────────────────
	if strings.Contains(lowerCmd, "authorized_keys") &&
		(strings.Contains(cmd, ">>") || strings.Contains(cmd, "echo") || strings.Contains(lowerCmd, "curl") || strings.Contains(lowerCmd, "wget")) {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "Modifies authorized_keys: adds/replaces SSH public keys (backdoor)")
	}
	if base == "chmod" && strings.Contains(lowerCmd, ".ssh") && strings.Contains(lowerCmd, "777") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "chmod 777 on .ssh: makes SSH directory world-writable (credential exposure)")
	}

	// ── docker run -v /:/mnt with chroot (container escape) ──────────────────────
	if base == "docker" && strings.Contains(lowerCmd, "run") &&
		(strings.Contains(lowerCmd, "-v /:/") || strings.Contains(lowerCmd, "--volume /:/")) {
		eval.Score += 80
		eval.Reasons = append(eval.Reasons, "docker run mounts host root filesystem (container escape)")
	}

	// ── AWS: make AMI public, stop CloudTrail logging ─────────────────────────────
	if base == "aws" {
		awsFullLower := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(awsFullLower, "modify-image-attribute") && strings.Contains(awsFullLower, "group=all") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "AWS EC2: makes AMI publicly accessible")
		}
		if strings.Contains(awsFullLower, "cloudtrail") && strings.Contains(awsFullLower, "stop-logging") {
			eval.Score += 90
			eval.Reasons = append(eval.Reasons, "AWS CloudTrail stop-logging: disables audit trail (evidence destruction)")
		}
	}

	// ── gcloud: grant Owner role, disable API service ─────────────────────────────
	if base == "gcloud" {
		gcFullLower := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(gcFullLower, "add-iam-policy-binding") && strings.Contains(gcFullLower, "roles/owner") {
			eval.Score += 80
			eval.Reasons = append(eval.Reasons, "gcloud: grants Owner role on project (full access)")
		}
		if strings.Contains(gcFullLower, "services disable") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "gcloud services disable: disables GCP API service")
		}
	}

	// ── AWS: organizations leave, s3api policy/versioning, metadata, cloudtrail ────
	if base == "aws" {
		awsFullLower := strings.ToLower(strings.Join(parts, " "))
		// aws organizations leave-organization — detaches account from org (no way back)
		if strings.Contains(awsFullLower, "organizations") && strings.Contains(awsFullLower, "leave-organization") {
			eval.Score += 90
			eval.Reasons = append(eval.Reasons, "AWS Organizations: leaves organization (irreversible account detachment)")
		}
		// aws s3api put-bucket-policy (can expose or lock bucket)
		if strings.Contains(awsFullLower, "s3api") && strings.Contains(awsFullLower, "put-bucket-policy") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "AWS S3: modifies bucket policy (may expose or lock bucket)")
		}
		// aws ec2 modify-instance-metadata-options --http-endpoint disabled
		if strings.Contains(awsFullLower, "modify-instance-metadata-options") &&
			strings.Contains(awsFullLower, "disabled") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "AWS EC2: disables instance metadata endpoint (breaks IAM role access)")
		}
	}

	// ── gcloud: logging retention reduction, metadata SSH backdoor ──────────────
	if base == "gcloud" {
		gcFullLower := strings.ToLower(strings.Join(parts, " "))
		// gcloud logging buckets update --retention-days=1
		if strings.Contains(gcFullLower, "logging") && strings.Contains(gcFullLower, "update") &&
			strings.Contains(gcFullLower, "retention-days") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "gcloud: reduces logging retention (audit log destruction risk)")
		}
		// gcloud compute project-info add-metadata google-compute-default-allow-ssh=true
		if strings.Contains(gcFullLower, "add-metadata") && strings.Contains(gcFullLower, "allow-ssh") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "gcloud: enables SSH access via project metadata (backdoors all VMs)")
		}
	}

	// ── kubectl replace --force (delete+recreate: data loss risk) ─────────────────
	if base == "kubectl" && len(parts) > 1 && strings.ToLower(parts[1]) == "replace" &&
		containsFlag(parts, "--force") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "kubectl replace --force: deletes and recreates resource (data loss)")
	}

	// ── git update-ref -d HEAD (deletes branch ref), push --mirror ───────────────
	if base == "git" {
		gitFull2 := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(gitFull2, "update-ref") && containsFlag(parts, "-d") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "git update-ref -d: deletes git ref (destroys branch/tag)")
		}
		if strings.Contains(gitFull2, "push") && containsFlag(parts, "--mirror") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "git push --mirror: overwrites ALL remote refs (destructive rewrite)")
		}
	}

	// ── gh workflow run with suspicious name ──────────────────────────────────────
	if base == "gh" {
		ghFull3 := strings.ToLower(strings.Join(parts[1:], " "))
		if strings.HasPrefix(ghFull3, "workflow run") {
			workflowName := strings.ToLower(ghFull3)
			if strings.Contains(workflowName, "delete") || strings.Contains(workflowName, "destroy") ||
				strings.Contains(workflowName, "wipe") || strings.Contains(workflowName, "nuke") {
				eval.Score += 70
				eval.Reasons = append(eval.Reasons, "gh workflow run: triggers destructive-named workflow")
			}
		}
	}

	// ── SQL: SET GLOBAL read_only, iptables block all input ──────────────────────
	if strings.HasPrefix(upper, "SET GLOBAL") && strings.Contains(upper, "READ_ONLY") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "SQL SET GLOBAL read_only: makes database read-only")
	}
	if base == "iptables" && strings.Contains(lowerCmd, "-a input") && strings.Contains(lowerCmd, "-j drop") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "iptables: drops ALL incoming traffic (lockout risk)")
	}

	// ── auditctl -D (deletes all audit rules) ─────────────────────────────────────
	if base == "auditctl" && containsFlag(parts, "-D") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "auditctl -D: removes all audit rules (disables security monitoring)")
	}

	// ── Malicious package source configuration ────────────────────────────────────
	if base == "pip" || base == "pip3" {
		pipFull2 := strings.ToLower(strings.Join(parts, " "))
		if (strings.Contains(pipFull2, "--index-url") || strings.Contains(pipFull2, "--extra-index-url")) &&
			strings.Contains(pipFull2, "http://") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "pip: installs from non-HTTPS (insecure) package index")
		}
	}
	if base == "npm" && strings.Contains(lowerCmd, "config set registry") && strings.Contains(lowerCmd, "http://") {
		eval.Score += 70
		eval.Reasons = append(eval.Reasons, "npm: sets insecure package registry (supply chain risk)")
	}

	// ── System time manipulation ──────────────────────────────────────────────────
	if base == "date" && containsFlag(parts, "-s", "--set") {
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "date -s: sets system clock (breaks TLS/certs/logs/kerberos)")
	}
	if base == "timedatectl" && strings.Contains(lowerCmd, "set-ntp false") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "timedatectl set-ntp false: disables time synchronization")
	}

	// ── Filesystem exfiltration via tar+curl ──────────────────────────────────────
	if (strings.Contains(lowerCmd, "tar") || strings.Contains(lowerCmd, "zip") || strings.Contains(lowerCmd, "gzip")) &&
		(strings.Contains(lowerCmd, "curl") || strings.Contains(lowerCmd, "wget") || strings.Contains(lowerCmd, "nc ")) &&
		strings.Contains(lowerCmd, "/ ") {
		eval.Score += 90
		eval.Reasons = append(eval.Reasons, "tar/zip root filesystem piped to remote: full system exfiltration")
	}

	// ── mv / (moves root — catastrophic) ─────────────────────────────────────────
	if base == "mv" && len(parts) > 1 && (parts[1] == "/" || parts[1] == "/*") {
		eval.Score += 100
		eval.Reasons = append(eval.Reasons, "mv /: moves root filesystem (catastrophic system destruction)")
	}

	// ── MTU DoS ───────────────────────────────────────────────────────────────────
	if base == "ip" && strings.Contains(lowerCmd, "link set") && strings.Contains(lowerCmd, "mtu") {
		for i, p := range parts {
			if p == "mtu" && i+1 < len(parts) {
				mtu := parts[i+1]
				if mtu == "68" || mtu == "1" || mtu == "0" {
					eval.Score += 60
					eval.Reasons = append(eval.Reasons, "ip link set mtu to minimum: breaks packet routing (DoS)")
					break
				}
			}
		}
	}

	// ── ansible-playbook targeting all production ────────────────────────────────
	if base == "ansible-playbook" {
		ansibleFull := strings.ToLower(strings.Join(parts, " "))
		if (strings.Contains(ansibleFull, "--limit all") || strings.Contains(ansibleFull, "-l all")) &&
			strings.Contains(ansibleFull, "production") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "ansible-playbook: targets ALL production hosts (mass deployment risk)")
		} else if strings.Contains(ansibleFull, "--limit all") || strings.Contains(ansibleFull, "-l all") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "ansible-playbook: targets ALL hosts")
		}
	}

	// ── kubectl patch replicas:0 (takes service down) ────────────────────────────
	if base == "kubectl" && len(parts) > 1 && strings.ToLower(parts[1]) == "patch" {
		patchFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(patchFull, "replicas") && strings.Contains(patchFull, ":0") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "kubectl patch: scales deployment to 0 replicas (service outage)")
		}
	}

	// ── helm rollback to revision 0 (uninstalls release) ────────────────────────
	if base == "helm" && len(parts) > 1 && strings.ToLower(parts[1]) == "rollback" {
		// helm rollback <release> 0 — revision 0 means uninstall
		for _, p := range parts[2:] {
			if p == "0" {
				eval.Score += 70
				eval.Reasons = append(eval.Reasons, "helm rollback to revision 0: uninstalls Helm release")
				break
			}
		}
	}

	// ── git merge --strategy-option=theirs (discards all local changes) ─────────
	if base == "git" {
		if containsFlag(parts, "--strategy-option=theirs", "-Xtheirs") ||
			(containsFlag(parts, "--strategy-option", "-X") &&
				containsAnyFold(parts, "theirs")) {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "git merge -Xtheirs: discards all local changes in conflicts")
		}
	}

	// ── sysctl kernel write ──────────────────────────────────────────────────────
	if base == "sysctl" && containsFlag(parts, "-w", "--write") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "sysctl -w: modifies kernel parameters at runtime")
	}

	// ── snap remove --purge (removes with all data) ──────────────────────────────
	if base == "snap" && len(parts) > 1 && strings.ToLower(parts[1]) == "remove" &&
		containsFlag(parts, "--purge") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "snap remove --purge: removes snap package and all its data")
		if strings.Contains(strings.ToLower(strings.Join(parts, " ")), "core") {
			eval.Score += 20
			eval.Reasons = append(eval.Reasons, "snap: removing core package may break system snapd")
		}
	}

	// ── go env -w GOPATH=/dev/null (corrupts Go toolchain config) ───────────────
	if base == "go" && len(parts) > 1 && strings.ToLower(parts[1]) == "env" &&
		containsFlag(parts, "-w", "--write") {
		goEnvFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(goEnvFull, "/dev/null") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "go env -w: sets Go environment variable to /dev/null (breaks toolchain)")
		}
	}

	// ── pip downgrade to broken version ──────────────────────────────────────────
	if (base == "pip" || base == "pip3") && len(parts) > 1 && strings.ToLower(parts[1]) == "install" {
		pipFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(pipFull, "pip==0.") || strings.Contains(pipFull, "pip==1.") ||
			strings.Contains(pipFull, "setuptools==0.") {
			eval.Score += 60
			eval.Reasons = append(eval.Reasons, "pip install: downgrades pip/setuptools to broken version")
		}
	}

	// ── yarn/composer global remove ──────────────────────────────────────────────
	if (base == "yarn" || base == "composer") &&
		strings.Contains(strings.ToLower(strings.Join(parts, " ")), "global remove") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, base+": removes global package")
	}

	// ── flatpak uninstall --assumeyes (non-interactive mass uninstall) ───────────
	if base == "flatpak" && len(parts) > 1 && strings.ToLower(parts[1]) == "uninstall" &&
		(containsFlag(parts, "--assumeyes", "-y") || containsFlag(parts, "--force")) {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "flatpak uninstall --assumeyes: non-interactive application removal")
	}

	// ── nohup background script (persistence mechanism) ──────────────────────────
	if base == "nohup" {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "nohup: runs process immune to hangup (persistence mechanism)")
	}

	// ── docker checkpoint rm (removes checkpoint) ────────────────────────────────
	if base == "docker" && len(parts) > 2 &&
		strings.ToLower(parts[1]) == "checkpoint" && strings.ToLower(parts[2]) == "rm" {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "docker checkpoint rm: deletes container checkpoint")
	}

	// ── mvn dependency:purge-local-repository (removes all cached deps) ──────────
	if base == "mvn" && strings.Contains(strings.ToLower(strings.Join(parts, " ")), "purge-local-repository") {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "mvn purge-local-repository: removes all cached Maven dependencies")
	}

	// ── compact /u /s:C:\ (decompress whole drive — disruptive) ──────────────────
	if base == "compact" && containsFlag(parts, "/u") && strings.Contains(strings.ToLower(strings.Join(parts, " ")), "c:\\") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "compact /u: decompresses entire C: drive (highly disruptive I/O)")
	}

	// ── pulumi cancel / stack import (deployment interference) ───────────────────
	if base == "pulumi" && len(parts) > 1 {
		if strings.ToLower(parts[1]) == "cancel" {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "pulumi cancel: cancels a running deployment (leaves infra in unknown state)")
		}
		pulumiFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(pulumiFull, "stack import") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "pulumi stack import: overwrites stack state (data loss risk)")
		}
	}

	// ── terraform state mv (moves infra state — misuse breaks tracking) ──────────
	if base == "terraform" && len(parts) > 2 &&
		strings.ToLower(parts[1]) == "state" && strings.ToLower(parts[2]) == "mv" {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "terraform state mv: moves resource in state (can desync infra tracking)")
	}

	// ── ip rule add (modifies policy routing) ────────────────────────────────────
	if base == "ip" && len(parts) > 2 && strings.ToLower(parts[1]) == "rule" && strings.ToLower(parts[2]) == "add" {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "ip rule add: modifies policy routing rules (network disruption risk)")
	}

	// ── brew uninstall --force (removes package without confirmation) ────────────
	if base == "brew" && len(parts) > 1 && strings.ToLower(parts[1]) == "uninstall" &&
		containsFlag(parts, "--force") {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "brew uninstall --force: removes Homebrew package forcefully")
	}

	// ── cargo install --force (installs potentially unverified crate) ─────────────
	if base == "cargo" && len(parts) > 1 && strings.ToLower(parts[1]) == "install" &&
		containsFlag(parts, "--force") {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "cargo install --force: force-installs Rust crate (supply chain risk)")
	}

	// ── visudo -f /dev/null (replaces sudoers with empty file) ───────────────────
	if base == "visudo" {
		visudoFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(visudoFull, "/dev/null") {
			eval.Score += 70
			eval.Reasons = append(eval.Reasons, "visudo -f /dev/null: validates sudoers against /dev/null (privilege backdoor)")
		}
	}

	// ── helm repo remove (removes chart repository) ───────────────────────────────
	if base == "helm" && len(parts) > 2 &&
		strings.ToLower(parts[1]) == "repo" && strings.ToLower(parts[2]) == "remove" {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "helm repo remove: removes Helm chart repository")
	}

	// ── helm upgrade --set service.type=LoadBalancer (exposes service publicly) ──
	if base == "helm" && len(parts) > 1 && strings.ToLower(parts[1]) == "upgrade" &&
		strings.Contains(strings.ToLower(strings.Join(parts, " ")), "service.type=loadbalancer") {
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "helm upgrade: exposes Kubernetes service as LoadBalancer (public ingress)")
	}

	// ── git config --global --unset (removes credential helper etc) ──────────────
	if base == "git" && strings.Contains(lowerCmd, "config") &&
		containsFlag(parts, "--global") && containsFlag(parts, "--unset") {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "git config --global --unset: removes global git configuration")
	}

	// ── watch with very short interval on recursive/expensive command ─────────────
	if base == "watch" {
		watchFull := strings.ToLower(strings.Join(parts, " "))
		// -n 0.x or -n 1 with recursive ls or find = resource exhaustion
		if (strings.Contains(watchFull, "-n 0") || strings.Contains(watchFull, "-n 1 ")) &&
			(strings.Contains(watchFull, "-r ") || strings.Contains(watchFull, "ls -r") ||
				strings.Contains(watchFull, "find ") || strings.Contains(watchFull, "du ")) {
			eval.Score += 40
			eval.Reasons = append(eval.Reasons, "watch: high-frequency recursive command (resource exhaustion / DoS)")
		}
	}

	// ── psql CHECKPOINT + pg_switch_wal (forces WAL segment switch — I/O spike) ──
	if base == "psql" {
		psqlFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(psqlFull, "pg_switch_wal") || strings.Contains(psqlFull, "pg_switch_xlog") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "psql: forces PostgreSQL WAL segment switch (storage/I/O disruption)")
		}
		if strings.Contains(psqlFull, "pg_reload_conf") {
			eval.Score += 35
			eval.Reasons = append(eval.Reasons, "psql: reloads PostgreSQL configuration (may change auth/connections)")
		}
	}

	// ── echo > /proc/sys/ (writes kernel parameters — equivalent to sysctl) ──────
	if base == "echo" && strings.Contains(lowerCmd, "/proc/sys/") {
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "echo: writes to /proc/sys/ kernel parameter (runtime kernel change)")
	}

	// ── jenkins-cli admin operations ─────────────────────────────────────────────
	if base == "jenkins-cli" {
		jenkinsFull := strings.ToLower(strings.Join(parts, " "))
		if strings.Contains(jenkinsFull, "cancel-quiet-down") || strings.Contains(jenkinsFull, "shutdown") ||
			strings.Contains(jenkinsFull, "delete-job") || strings.Contains(jenkinsFull, "reload-configuration") {
			eval.Score += 50
			eval.Reasons = append(eval.Reasons, "jenkins-cli: performs Jenkins admin operation (service disruption risk)")
		}
	}

	// ── Read-only check ──────────────────────────────────────────────────────────
	if eval.Score == 0 && e.autoApproveRead && isReadOnly(base) {
		eval.Level = LevelNone
		return eval
	}

	// Cap and set level
	if eval.Score > 100 {
		eval.Score = 100
	}

	eval.Level = scoreToLevel(eval.Score)
	return eval
}

// EvaluateToolCall scores an MCP tool call
func (e *Engine) EvaluateToolCall(toolName string, args map[string]interface{}) *Evaluation {
	eval := &Evaluation{
		Action: "mcp:" + toolName,
	}

	switch toolName {
	// Filesystem tools
	case "write_file", "create_file", "overwrite_file":
		eval.Score += 30
		eval.Reasons = append(eval.Reasons, "File write operation")
		if path, ok := args["path"].(string); ok {
			eval.Target = path
			if e.isSensitivePath(path) {
				eval.Score += 25
				eval.Reasons = append(eval.Reasons, "Writes to sensitive path")
			}
		}

	case "delete_file", "remove_file":
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "File deletion")
		if path, ok := args["path"].(string); ok {
			eval.Target = path
			if e.isSensitivePath(path) {
				eval.Score += 25
				eval.Reasons = append(eval.Reasons, "Deletes sensitive file")
			}
		}

	case "execute_command", "run_command", "bash", "shell":
		// Delegate to command evaluation
		if cmd, ok := args["command"].(string); ok {
			return e.EvaluateCommand(cmd)
		}
		eval.Score += 50
		eval.Reasons = append(eval.Reasons, "Command execution via tool")

	case "read_file", "list_directory", "search_files", "grep":
		if e.autoApproveRead {
			eval.Level = LevelNone
			return eval
		}
		eval.Score += 5
		eval.Reasons = append(eval.Reasons, "Read operation")

	// Git tools
	case "git_push", "git_commit", "git_reset":
		eval.Score += 40
		eval.Reasons = append(eval.Reasons, "Git operation via tool")

	// Network
	case "http_request", "fetch", "curl":
		eval.Score += 20
		eval.Reasons = append(eval.Reasons, "Network request")

	// K8s / cloud
	case "kubectl", "helm", "terraform_apply", "aws", "gcloud":
		eval.Score += 60
		eval.Reasons = append(eval.Reasons, "Infrastructure operation")

	default:
		eval.Score += 25
		eval.Reasons = append(eval.Reasons, "Unknown tool: "+toolName)
	}

	if eval.Score > 100 {
		eval.Score = 100
	}
	eval.Level = scoreToLevel(eval.Score)
	return eval
}

// ========================================
// Helpers
// ========================================

func scoreToLevel(score int) Level {
	switch {
	case score <= 10:
		return LevelNone
	case score <= 30:
		return LevelLow
	case score <= 60:
		return LevelMedium
	case score <= 80:
		return LevelHigh
	default:
		return LevelCritical
	}
}

func isDestructiveVerb(cmd string) bool {
	destructive := []string{"rm", "rmdir", "del", "unlink", "shred",
		"mkfs", "fdisk", "dd", "format",
		"drop", "truncate", "kill", "killall", "pkill",
		"shutdown", "reboot", "halt", "poweroff",
		"remove-item", "clear-content", "set-content",
		"move-item", "copy-item", "rename-item"}
	lower := strings.ToLower(cmd)
	for _, d := range destructive {
		if lower == d {
			return true
		}
	}
	return false
}

func isDestructiveSubcommand(sub string) bool {
	destructive := []string{"delete", "remove", "rm", "rmi", "prune",
		"destroy", "terminate", "drain", "cordon", "taint"}
	lower := strings.ToLower(sub)
	for _, d := range destructive {
		if lower == d {
			return true
		}
	}
	return false
}

func commandBase(cmd string) string {
	// Strip shell quoting and bypass prefixes:
	//   \rm  →  rm  (backslash bypasses shell functions)
	//   'rm' →  rm  (quoted to bypass aliases)
	//   "rm" →  rm
	base := strings.TrimLeft(cmd, `\"'\`)
	base = filepath.Base(strings.Trim(base, `"'`))
	base = strings.TrimSuffix(base, ".exe")
	if strings.HasPrefix(base, ".") && strings.Contains(base, ".shield-real") {
		base = strings.TrimPrefix(base, ".")
		base = strings.TrimSuffix(base, ".shield-real")
	}
	// Strip embedded shell quoting like r''m → rm
	base = strings.ReplaceAll(base, "''", "")
	base = strings.ReplaceAll(base, `""`, "")
	switch strings.ToLower(base) {
	case "k":
		return "kubectl"
	case "tf":
		return "terraform"
	default:
		return strings.ToLower(base)
	}
}

func normalizeCommandString(cmd string) string {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return ""
	}
	parts[0] = commandBase(parts[0])
	return strings.ToLower(strings.Join(parts, " "))
}

func isShieldRealPath(cmd string) bool {
	return strings.Contains(filepath.Base(cmd), ".shield-real")
}

func normalizeWrappedCommand(parts []string) ([]string, []string) {
	var reasons []string
	for len(parts) > 0 {
		base := commandBase(parts[0])
		switch base {
		case "env":
			next := skipEnvAssignments(parts[1:])
			if len(next) == 0 {
				return parts, reasons
			}
			reasons = append(reasons, "Command wrapped by env")
			parts = next
		case "sudo", "doas", "runas":
			next := skipWrapperOptions(parts[1:])
			if len(next) == 0 {
				return parts, reasons
			}
			reasons = append(reasons, "Elevated wrapper command")
			parts = next
		case "command", "builtin":
			// Shell builtins used to bypass shell function hooks:
			//   command rm -rf /  →  skips shell function, calls /bin/rm directly
			//   builtin rm -rf /  →  same bypass
			if len(parts) > 1 {
				reasons = append(reasons, "Shell builtin wrapper (bypass attempt: "+base+")")
				parts = parts[1:]
				continue
			}
			return parts, reasons
		case "eval":
			// eval 'rm -rf /' — execute arbitrary string
			if len(parts) > 1 {
				reasons = append(reasons, "eval wrapper — executes arbitrary string")
				// Reconstruct the inner string by joining remaining parts and stripping quotes
				inner := strings.Trim(strings.Join(parts[1:], " "), `'"`)
				parts = strings.Fields(inner)
				continue
			}
			return parts, reasons
		case "xargs":
			// xargs rm -rf — feeds piped input to dangerous command
			if len(parts) > 1 {
				reasons = append(reasons, "xargs wrapper")
				parts = parts[1:]
				continue
			}
			return parts, reasons
		case "bash", "sh", "zsh", "dash", "ksh", "fish":
			if inline := shellInlineCommand(parts); inline != "" {
				reasons = append(reasons, "Shell inline command wrapper")
				parts = strings.Fields(inline)
				continue
			}
			return parts, reasons
		default:
			return parts, reasons
		}
	}
	return parts, reasons
}

func skipEnvAssignments(parts []string) []string {
	for len(parts) > 0 {
		p := parts[0]
		if strings.Contains(p, "=") && !strings.HasPrefix(p, "-") {
			parts = parts[1:]
			continue
		}
		if p == "-i" || p == "-0" || strings.HasPrefix(p, "-u") || strings.HasPrefix(p, "-C") {
			parts = parts[1:]
			continue
		}
		break
	}
	return parts
}

func skipWrapperOptions(parts []string) []string {
	for len(parts) > 0 && strings.HasPrefix(parts[0], "-") {
		opt := parts[0]
		parts = parts[1:]
		if optionTakesValue(opt, sudoOptionsWithValue) && len(parts) > 0 {
			parts = parts[1:]
		}
	}
	return parts
}

func shellInlineCommand(parts []string) string {
	for i := 1; i < len(parts); i++ {
		if parts[i] == "-c" && i+1 < len(parts) {
			return strings.Join(parts[i+1:], " ")
		}
	}
	return ""
}

func findSubcommand(parts []string, optionsWithValue map[string]bool) string {
	for i := 0; i < len(parts); i++ {
		p := parts[i]
		if p == "--" {
			if i+1 < len(parts) {
				return strings.ToLower(parts[i+1])
			}
			return ""
		}
		if strings.HasPrefix(p, "-") {
			if optionTakesValue(p, optionsWithValue) && !strings.Contains(p, "=") {
				i++
			}
			continue
		}
		return strings.ToLower(p)
	}
	return ""
}

func isDockerSystemPrune(base, sub string, parts []string) bool {
	if base != "docker" || sub != "system" {
		return false
	}
	foundSystem := false
	for i := 0; i < len(parts); i++ {
		p := strings.ToLower(parts[i])
		if strings.HasPrefix(p, "-") {
			if optionTakesValue(p, dockerGlobalOptions) && !strings.Contains(p, "=") {
				i++
			}
			continue
		}
		if !foundSystem {
			foundSystem = p == "system"
			continue
		}
		return p == "prune"
	}
	return false
}

func optionTakesValue(opt string, optionsWithValue map[string]bool) bool {
	if optionsWithValue[opt] {
		return true
	}
	if idx := strings.Index(opt, "="); idx >= 0 {
		return optionsWithValue[opt[:idx]]
	}
	return false
}

func cliGlobalOptions(base string) map[string]bool {
	switch base {
	case "kubectl":
		return kubectlGlobalOptions
	case "docker":
		return dockerGlobalOptions
	case "helm":
		return helmGlobalOptions
	default:
		return nil
	}
}

var kubectlGlobalOptions = map[string]bool{
	"--context": true, "--namespace": true, "-n": true, "--kubeconfig": true,
	"--server": true, "--user": true, "--cluster": true, "--as": true,
	"--as-group": true, "--token": true, "--request-timeout": true,
}

var dockerGlobalOptions = map[string]bool{
	"--config": true, "-c": true, "--context": true, "--host": true, "-H": true,
	"--log-level": true, "--tls": false, "--tlscacert": true, "--tlscert": true, "--tlskey": true,
}

var helmGlobalOptions = map[string]bool{
	"--kube-context": true, "--namespace": true, "-n": true, "--kubeconfig": true,
	"--repository-config": true, "--repository-cache": true, "--registry-config": true,
}

var gitGlobalOptions = map[string]bool{
	"-C": true, "-c": true, "--git-dir": true, "--work-tree": true,
	"--namespace": true, "--exec-path": true,
}

var terraformGlobalOptions = map[string]bool{
	"-chdir": true,
}

var sudoOptionsWithValue = map[string]bool{
	"-u": true, "--user": true, "-g": true, "--group": true, "-h": true,
	"--host": true, "-p": true, "--prompt": true, "-C": true, "-T": true,
}

func containsFlag(parts []string, flags ...string) bool {
	for _, p := range parts {
		for _, f := range flags {
			if strings.EqualFold(p, f) {
				return true
			}
		}
	}
	return false
}

func containsAnyFold(parts []string, values ...string) bool {
	for _, p := range parts {
		for _, v := range values {
			if strings.EqualFold(p, v) {
				return true
			}
		}
	}
	return false
}

func isKnownCommand(base string) bool {
	known := []string{
		// destructive
		"rm", "rmdir", "del", "unlink", "shred", "mkfs", "fdisk", "dd", "format",
		"drop", "truncate", "kill", "killall", "pkill", "shutdown", "reboot", "halt", "poweroff",
		"remove-item", "clear-content", "set-content", "move-item", "copy-item", "rename-item",
		// vcs/infra
		"git", "kubectl", "k", "helm", "terraform", "tf", "docker", "podman",
		"aws", "az", "gcloud", "heroku", "fly",
		// shells / wrappers
		"bash", "sh", "zsh", "dash", "ksh", "fish", "env", "sudo", "doas", "runas",
		"command", "builtin", "eval", "xargs",
		// network
		"curl", "wget", "http", "nc", "netcat",
		// read-only (safe)
		"cat", "head", "tail", "less", "more", "grep", "find", "ls", "dir",
		"pwd", "whoami", "echo", "type", "wc", "diff", "file", "stat", "which",
		"rsync", "scp", "cp", "mv",
		// interpreters
		"python", "python3", "node", "nodejs", "ruby", "perl", "php",
	}
	lower := strings.ToLower(base)
	for _, k := range known {
		if lower == k {
			return true
		}
	}
	return false
}

func isInterpreter(base string) bool {
	switch base {
	case "python", "python3", "node", "nodejs", "ruby", "perl", "php":
		return true
	default:
		return false
	}
}

func hasInlineCodeFlag(parts []string) bool {
	return containsFlag(parts, "-c", "-e", "--eval", "-Command", "-EncodedCommand")
}

func (e *Engine) isSensitivePath(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	for _, protected := range e.protectedPaths {
		protAbs, _ := filepath.Abs(protected)
		if strings.HasPrefix(abs, protAbs) {
			return true
		}
	}

	// Known sensitive files
	sensitive := []string{".env", ".ssh", ".aws", ".kube", "credentials",
		"id_rsa", "id_ed25519", ".gitconfig", ".npmrc", ".pypirc",
		"authorized_keys", "shadow", "passwd", "sudoers"}
	base := filepath.Base(path)
	for _, s := range sensitive {
		if strings.EqualFold(base, s) {
			return true
		}
	}
	return false
}

func isCredentialPath(args string) bool {
	lower := strings.ToLower(args)
	credPaths := []string{
		".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".ssh/id_dsa",
		".aws/credentials", ".aws/config",
		".kube/config",
		".gnupg/", ".gpg",
		"/.env", "/.envrc",
		"credentials.json", "service_account.json",
		"client_secret", "private_key.pem", "private_key.json",
		"id_rsa", "id_ed25519",
	}
	for _, cp := range credPaths {
		if strings.Contains(lower, cp) {
			return true
		}
	}
	return false
}

func isSystemPath(path string) bool {
	systemPaths := []string{"/etc", "/usr", "/bin", "/sbin", "/boot",
		"/var", "/sys", "/proc", "C:\\Windows", "C:\\Program Files"}
	for _, sp := range systemPaths {
		if strings.HasPrefix(path, sp) {
			return true
		}
	}
	return false
}

func looksLikePath(arg string) bool {
	if strings.HasPrefix(arg, "-") {
		return false // It's a flag
	}
	if strings.Contains(arg, "/") || strings.Contains(arg, "\\") {
		return true // Has path separators
	}
	if strings.HasPrefix(arg, ".") || strings.HasPrefix(arg, "~") {
		return true // Relative or home path
	}
	if strings.Contains(arg, ".") && !strings.Contains(arg, " ") {
		return true // Looks like a filename (has extension)
	}
	return false
}

func isReadOnly(cmd string) bool {
	readCmds := []string{"cat", "head", "tail", "less", "more", "grep",
		"find", "ls", "dir", "pwd", "whoami", "echo", "type",
		"wc", "diff", "file", "stat", "which", "where",
		"Get-Content", "Get-ChildItem", "Get-Location"}
	lower := strings.ToLower(cmd)
	for _, r := range readCmds {
		if strings.EqualFold(lower, r) {
			return true
		}
	}
	return false
}
