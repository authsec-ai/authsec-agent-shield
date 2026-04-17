// AuthSec Agent Shield — persistent background daemon
//
// This binary runs as:
//   Linux:   a systemd service (authsec-shield-daemon.service)
//   Windows: a Windows Service (AuthSecShieldDaemon)
//
// It is the control plane for all shield subsystems:
//   - Starts/stops kernel exec monitor (fanotify + eBPF on Linux, minifilter on Windows)
//   - Starts/stops filesystem write monitor
//   - Provides the Unix socket / named pipe control interface used by
//     'authsec-shield pause', 'authsec-shield enable', 'authsec-shield status'
//   - Enforces that stopping the daemon requires mobile approval
//   - Self-protects: OOM-immune, non-root cannot ptrace or kill it
//
// The daemon also runs a local risk engine and proxies approvals to the
// Agent Guard API, acting as a single gateway for both the kernel monitors
// and the shell-hook / shim layers.
//
// Usage:
//   authsec-shield-daemon [--config /path/to/config.json]
//
// Install:
//   Linux:   sudo make -C kernel/linux/execmon install && sudo systemctl enable --now authsec-shield-daemon
//   Windows: authsec-shield-daemon.exe install  (registers Windows Service)
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/authsec-ai/authsec-agent-shield/internal/config"
	"github.com/authsec-ai/authsec-agent-shield/internal/kernel"
)

const (
	unixSocket    = "/run/authsec-shield.sock"
	windowsPipe   = `\\.\pipe\authsec-shield`
	daemonVersion = "1.0.0"
)

// DaemonState holds runtime state
type DaemonState struct {
	mu          sync.RWMutex
	paused      bool
	pauseUntil  time.Time
	startedAt   time.Time
	kernelMgr   *kernel.Manager
	cfg         *config.Config
}

var state *DaemonState

func main() {
	// Windows Service mode
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			installWindowsService()
			return
		case "uninstall":
			uninstallWindowsService()
			return
		case "run-service":
			// Called by Windows SCM — run as service
			runAsWindowsService()
			return
		}
	}

	// Check root/admin
	if os.Getuid() != 0 && runtime.GOOS != "windows" {
		fmt.Fprintln(os.Stderr, "[daemon] ERROR: Must run as root")
		os.Exit(1)
	}

	run()
}

func run() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[daemon] Failed to load config: %v\n", err)
		os.Exit(1)
	}

	state = &DaemonState{
		startedAt: time.Now(),
		cfg:       cfg,
		kernelMgr: kernel.New(cfg.ProtectedPaths, cfg.AuthSecBaseURL, cfg.AccessToken),
	}

	log("INFO", "AuthSec Shield daemon v%s starting (PID=%d)", daemonVersion, os.Getpid())

	// Apply self-protection (Linux only — Windows handled by SCM + ACLs)
	applySelfProtection()

	// Start kernel monitors
	log("INFO", "Starting kernel monitors...")
	if err := state.kernelMgr.Start(); err != nil {
		log("WARN", "Kernel monitor start partial: %v", err)
	} else {
		st := state.kernelMgr.GetStatus()
		log("INFO", "Kernel monitor: %s — %s", st.Method, st.Message)
	}

	// Start control interface
	go serveControlInterface()

	// Signal handling — SIGTERM requires mobile approval
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	log("INFO", "Daemon running. All process executions and file writes are monitored.")

	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			log("INFO", "SIGHUP — reloading config")
			reloadConfig()

		case syscall.SIGTERM, syscall.SIGINT:
			if cfg.AuthSecBaseURL != "" && cfg.AccessToken != "" {
				log("WARN", "Shutdown requested — requiring mobile approval")
				if !requestShutdownApproval() {
					log("WARN", "Shutdown DENIED by mobile. Continuing.")
					continue
				}
				log("INFO", "Shutdown approved. Stopping.")
			}
			shutdown()
			return
		}
	}
}

// ── Self-protection (Linux) ───────────────────────────────────────────────

func applySelfProtection() {
	if runtime.GOOS != "linux" {
		return
	}

	// Set OOM score to -1000 — kernel will not kill this process
	oomPath := fmt.Sprintf("/proc/%d/oom_score_adj", os.Getpid())
	if f, err := os.OpenFile(oomPath, os.O_WRONLY, 0); err == nil {
		f.WriteString("-1000\n")
		f.Close()
		log("PROTECT", "OOM score set to -1000")
	}

	// Make ourselves a subreaper for orphaned children
	// syscall.Prctl(syscall.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
	// (Go doesn't export prctl directly — use syscall.RawSyscall)
	syscall.RawSyscall(syscall.SYS_PRCTL, 36 /* PR_SET_CHILD_SUBREAPER */, 1, 0)

	// Prevent ptrace from non-root
	syscall.RawSyscall(syscall.SYS_PRCTL, 4 /* PR_SET_DUMPABLE */, 0, 0)

	log("PROTECT", "Self-protection applied")
}

// ── Shutdown ──────────────────────────────────────────────────────────────

func shutdown() {
	log("INFO", "Shutting down daemon...")

	if state.kernelMgr != nil {
		if err := state.kernelMgr.Stop(); err != nil {
			log("WARN", "Kernel monitor stop error: %v", err)
		}
	}

	// Remove control socket
	if runtime.GOOS == "linux" {
		os.Remove(unixSocket)
	}

	log("INFO", "Daemon stopped.")
}

// ── Config reload ─────────────────────────────────────────────────────────

func reloadConfig() {
	cfg, err := config.Load()
	if err != nil {
		log("WARN", "Config reload failed: %v", err)
		return
	}
	state.mu.Lock()
	state.cfg = cfg
	state.kernelMgr = kernel.New(cfg.ProtectedPaths, cfg.AuthSecBaseURL, cfg.AccessToken)
	state.mu.Unlock()

	// Push new paths to kernel daemon
	state.kernelMgr.PushPaths() //nolint:errcheck
	log("INFO", "Config reloaded")
}

// ── Mobile approval for daemon shutdown ───────────────────────────────────

func requestShutdownApproval() bool {
	state.mu.RLock()
	cfg := state.cfg
	state.mu.RUnlock()

	if cfg.AuthSecBaseURL == "" || cfg.AccessToken == "" {
		return true // not configured — allow
	}

	// Use the existing shield binary's API client via subprocess
	// This keeps the daemon lean — approval logic lives in the main shield binary
	shieldBin, _ := os.Executable()
	shieldBin = filepath.Join(filepath.Dir(shieldBin), "authsec-shield")
	if runtime.GOOS == "windows" {
		shieldBin += ".exe"
	}

	if _, err := os.Stat(shieldBin); os.IsNotExist(err) {
		log("WARN", "Shield binary not found for approval call — allowing shutdown")
		return true
	}

	// Run: authsec-shield check "stop-daemon authsec-shield-daemon"
	// The check command calls the risk engine + API if needed
	cmd := exec.Command(shieldBin, "check", "stop-daemon authsec-shield-daemon")
	cmd.Env = os.Environ()
	err := cmd.Run()
	return err == nil // exit 0 = approved, exit 1 = denied
}

// ── Control interface ─────────────────────────────────────────────────────
//
// Commands (newline-terminated):
//   STATUS           → JSON status object
//   PAUSE <seconds>  → pause enforcement for N seconds
//   ENABLE           → re-enable enforcement
//   RELOAD           → reload config from disk
//   STOP             → request shutdown (requires mobile approval)

type ControlResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

type StatusResponse struct {
	OK           bool      `json:"ok"`
	Version      string    `json:"version"`
	Uptime       string    `json:"uptime"`
	Paused       bool      `json:"paused"`
	PauseUntil   string    `json:"pause_until,omitempty"`
	KernelMethod string    `json:"kernel_method"`
	KernelActive bool      `json:"kernel_active"`
	LoggedIn     bool      `json:"logged_in"`
	User         string    `json:"user,omitempty"`
}

func serveControlInterface() {
	var ln net.Listener
	var err error

	if runtime.GOOS == "windows" {
		// Named pipe on Windows — created by the npipe library or net.Listen with a custom dialer
		// For simplicity, use a TCP localhost socket on a fixed port
		ln, err = net.Listen("tcp", "127.0.0.1:37290")
	} else {
		os.Remove(unixSocket)
		ln, err = net.Listen("unix", unixSocket)
		if err == nil {
			os.Chmod(unixSocket, 0600) // root-only access
		}
	}

	if err != nil {
		log("WARN", "Control interface unavailable: %v", err)
		return
	}
	defer ln.Close()

	log("INFO", "Control interface listening on %s", unixSocket)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed") {
				return
			}
			continue
		}
		go handleControl(conn)
	}
}

func handleControl(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	cmd := strings.TrimSpace(string(buf[:n]))

	var resp interface{}

	switch {
	case cmd == "STATUS":
		state.mu.RLock()
		paused := state.paused
		pauseUntil := state.pauseUntil
		cfg := state.cfg
		state.mu.RUnlock()

		kst := state.kernelMgr.GetStatus()
		sr := StatusResponse{
			OK:           true,
			Version:      daemonVersion,
			Uptime:       time.Since(state.startedAt).Round(time.Second).String(),
			Paused:       paused && time.Now().Before(pauseUntil),
			KernelMethod: kst.Method,
			KernelActive: kst.Running,
			LoggedIn:     cfg.IsLoggedIn(),
			User:         cfg.UserEmail,
		}
		if sr.Paused {
			sr.PauseUntil = pauseUntil.Format(time.RFC1123)
		}
		resp = sr

	case strings.HasPrefix(cmd, "PAUSE "):
		parts := strings.SplitN(cmd, " ", 2)
		if len(parts) == 2 {
			var secs int
			fmt.Sscanf(parts[1], "%d", &secs)
			if secs > 0 {
				state.mu.Lock()
				state.paused = true
				state.pauseUntil = time.Now().Add(time.Duration(secs) * time.Second)
				state.mu.Unlock()

				// Signal kernel daemons via control socket
				sendKernelControl(fmt.Sprintf("PAUSE %d", secs))

				resp = ControlResponse{OK: true, Message: fmt.Sprintf("Paused for %ds", secs)}
				log("INFO", "Paused for %d seconds", secs)
			} else {
				resp = ControlResponse{OK: false, Message: "invalid duration"}
			}
		}

	case cmd == "ENABLE":
		state.mu.Lock()
		state.paused = false
		state.pauseUntil = time.Time{}
		state.mu.Unlock()

		sendKernelControl("ENABLE")

		resp = ControlResponse{OK: true, Message: "Enforcement re-enabled"}
		log("INFO", "Enforcement re-enabled")

	case cmd == "RELOAD":
		reloadConfig()
		resp = ControlResponse{OK: true, Message: "Config reloaded"}

	case cmd == "STOP":
		resp = ControlResponse{OK: true, Message: "Requesting shutdown approval via mobile..."}
		data, _ := json.Marshal(resp)
		conn.Write(append(data, '\n')) //nolint:errcheck
		// Trigger shutdown in background
		go func() {
			if requestShutdownApproval() {
				shutdown()
				os.Exit(0)
			} else {
				log("WARN", "Shutdown denied by mobile — continuing")
			}
		}()
		return

	default:
		resp = ControlResponse{OK: false, Message: "unknown command: " + cmd}
	}

	data, _ := json.Marshal(resp)
	conn.Write(append(data, '\n')) //nolint:errcheck
}

// sendKernelControl sends a command to the kernel exec monitor's control socket
func sendKernelControl(cmd string) {
	if runtime.GOOS != "linux" {
		return
	}
	conn, err := net.Dial("unix", "/run/authsec-shield-execmon.sock")
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	conn.Write([]byte(cmd))                            //nolint:errcheck
}

// ── Windows Service support ───────────────────────────────────────────────

func installWindowsService() {
	if runtime.GOOS != "windows" {
		fmt.Println("Windows service install only available on Windows")
		return
	}
	exe, _ := os.Executable()
	// sc create AuthSecShieldDaemon type= own start= auto binPath= "<exe> run-service"
	cmd := exec.Command("sc", "create", "AuthSecShieldDaemon",
		"type=", "own",
		"start=", "auto",
		"displayname=", "AuthSec Agent Shield Daemon",
		"binpath=", fmt.Sprintf(`"%s" run-service`, exe))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "sc create failed: %v\n", err)
		return
	}
	// Set description
	exec.Command("sc", "description", "AuthSecShieldDaemon",
		"AuthSec Agent Shield — monitors all process executions for AI safety").Run() //nolint:errcheck
	// Start the service
	exec.Command("sc", "start", "AuthSecShieldDaemon").Run() //nolint:errcheck
	fmt.Println("Windows service installed and started: AuthSecShieldDaemon")
}

func uninstallWindowsService() {
	if runtime.GOOS != "windows" {
		return
	}
	exec.Command("sc", "stop", "AuthSecShieldDaemon").Run()   //nolint:errcheck
	exec.Command("sc", "delete", "AuthSecShieldDaemon").Run() //nolint:errcheck
	fmt.Println("Windows service removed: AuthSecShieldDaemon")
}

func runAsWindowsService() {
	// On Windows, the SCM starts us with "run-service" argument.
	// We call run() directly — SCM handles service lifecycle.
	// A production implementation would use golang.org/x/sys/windows/svc
	// for proper SCM integration (start/stop/pause events).
	run()
}

// ── Logging ───────────────────────────────────────────────────────────────

func log(level, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[authsec-daemon] [%s] [%s] %s\n",
		time.Now().Format("15:04:05"), level, msg)
}
