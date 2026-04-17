// Package kernel manages the optional kernel-level protection daemons.
//
// On Linux:  manages authsec-shield-fanotify via systemd or direct exec
// On Windows: manages the AuthSecShield minifilter via sc.exe + fltMC +
//
//	the AuthSecShieldBridge.exe IOCTL/pipe bridge
//
// The Go shield binary uses these to:
//   - Start kernel protection on 'install'
//   - Push updated protected paths on config change
//   - Stop kernel protection on 'uninstall' or 'pause'
//   - Check kernel protection status in 'doctor'
package kernel

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Status describes the state of kernel-level protection
type Status struct {
	Available bool   // kernel daemon binary found
	Running   bool   // daemon is active
	Method    string // "fanotify", "minifilter", or "none"
	Message   string
}

// Manager controls kernel-level filesystem protection
type Manager struct {
	protectedPaths []string
	apiURL         string
	accessToken    string
}

// New creates a kernel manager
func New(protectedPaths []string, apiURL, accessToken string) *Manager {
	return &Manager{
		protectedPaths: protectedPaths,
		apiURL:         apiURL,
		accessToken:    accessToken,
	}
}

// Start activates kernel-level protection
func (m *Manager) Start() error {
	switch runtime.GOOS {
	case "linux":
		return m.startLinux()
	case "windows":
		return m.startWindows()
	default:
		return fmt.Errorf("kernel protection not available on %s", runtime.GOOS)
	}
}

// Stop deactivates kernel-level protection
func (m *Manager) Stop() error {
	switch runtime.GOOS {
	case "linux":
		return m.stopLinux()
	case "windows":
		return m.stopWindows()
	default:
		return nil
	}
}

// CleanupInstalledArtifacts removes kernel service registrations, daemon binaries,
// and support files installed by the shield.
func (m *Manager) CleanupInstalledArtifacts() []error {
	switch runtime.GOOS {
	case "linux":
		return m.cleanupLinux()
	case "windows":
		return m.cleanupWindows()
	default:
		return nil
	}
}

// GetStatus returns the current kernel protection state
func (m *Manager) GetStatus() Status {
	switch runtime.GOOS {
	case "linux":
		return m.statusLinux()
	case "windows":
		return m.statusWindows()
	default:
		return Status{Method: "none", Message: fmt.Sprintf("not supported on %s", runtime.GOOS)}
	}
}

// PushPaths sends updated protected paths to the running kernel daemon
func (m *Manager) PushPaths() error {
	switch runtime.GOOS {
	case "linux":
		// Linux: restart daemon to pick up new config (config file is source of truth)
		return m.restartLinux()
	case "windows":
		return m.pushPathsWindows()
	default:
		return nil
	}
}

// ========================================
// Linux — fanotify + execmon daemons via systemd
// ========================================

const (
	linuxFanotifyService = "authsec-shield-fanotify"
	linuxFanotifyBin     = "/usr/local/sbin/authsec-shield-fanotify"
	linuxExecMonService  = "authsec-shield-execmon"
	linuxExecMonBin      = "/usr/local/sbin/authsec-shield-execmon"

	// Legacy alias kept for callers that reference the old constant name
	linuxServiceName = linuxFanotifyService
	linuxDaemonBin   = linuxFanotifyBin
)

func (m *Manager) startLinux() error {
	var firstErr error

	// Start exec monitor (ALL exec interception — primary protection)
	if err := m.startLinuxService(linuxExecMonService, linuxExecMonBin); err != nil {
		firstErr = fmt.Errorf("execmon: %w", err)
	}

	// Start fanotify daemon (filesystem write monitor)
	if err := m.startLinuxService(linuxFanotifyService, linuxFanotifyBin); err != nil {
		if firstErr != nil {
			return fmt.Errorf("%v; fanotify: %w", firstErr, err)
		}
		return fmt.Errorf("fanotify: %w", err)
	}

	return firstErr // nil if execmon started OK, or non-fatal warning if fanotify-only issue
}

func (m *Manager) startLinuxService(svcName, binPath string) error {
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		return fmt.Errorf("daemon not found at %s — run installer first", binPath)
	}

	if isSystemdAvailable() {
		if err := runCmd("systemctl", "enable", "--now", svcName); err == nil {
			return nil
		}
	}

	// Fallback: start directly in background
	cmd := exec.Command(binPath)
	cmd.Env = append(os.Environ(),
		"AUTHSEC_API_URL="+m.apiURL,
		"AUTHSEC_TOKEN="+m.accessToken,
	)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start %s: %w", svcName, err)
	}
	return nil
}

func (m *Manager) stopLinux() error {
	m.stopLinuxService(linuxExecMonService, linuxExecMonBin)   //nolint:errcheck
	m.stopLinuxService(linuxFanotifyService, linuxFanotifyBin) //nolint:errcheck
	return nil
}

func (m *Manager) stopLinuxService(svcName, binPath string) error {
	if isSystemdAvailable() {
		if linuxServiceExists(svcName) {
			runCmdQuiet("systemctl", "stop", svcName)    //nolint:errcheck
			runCmdQuiet("systemctl", "disable", svcName) //nolint:errcheck
		}
		return nil
	}
	runCmdQuiet("pkill", "-f", binPath) //nolint:errcheck
	return nil
}

func (m *Manager) cleanupLinux() []error {
	var errs []error

	m.stopLinux() //nolint:errcheck
	if isSystemdAvailable() {
		for _, svc := range []string{linuxExecMonService, linuxFanotifyService, "authsec-shield-daemon"} {
			if linuxServiceExists(svc) {
				runCmdQuiet("systemctl", "stop", svc)    //nolint:errcheck
				runCmdQuiet("systemctl", "disable", svc) //nolint:errcheck
			}
		}
	}

	for _, bin := range []string{linuxExecMonBin, linuxFanotifyBin} {
		if _, err := os.Stat(bin); err == nil {
			runCmdQuiet("chattr", "-i", bin) //nolint:errcheck
		}
		if err := os.Remove(bin); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove %s: %w", bin, err))
		}
	}

	for _, path := range []string{
		"/usr/local/lib/authsec-shield/authsec_execmon_ebpf.o",
		"/etc/systemd/system/authsec-shield-execmon.service",
		"/etc/systemd/system/authsec-shield-fanotify.service",
		"/etc/systemd/system/authsec-shield-daemon.service",
		"/run/authsec-shield-execmon.sock",
	} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove %s: %w", path, err))
		}
	}

	for _, dir := range []string{"/usr/local/lib/authsec-shield", "/etc/authsec-shield"} {
		if err := os.RemoveAll(dir); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", dir, err))
		}
	}

	if isSystemdAvailable() {
		runCmdQuiet("systemctl", "daemon-reload") //nolint:errcheck
		runCmdQuiet("systemctl", "reset-failed")  //nolint:errcheck
	}
	return errs
}

func (m *Manager) restartLinux() error {
	if isSystemdAvailable() {
		runCmd("systemctl", "restart", linuxExecMonService) //nolint:errcheck
		return runCmd("systemctl", "restart", linuxFanotifyService)
	}
	m.stopLinux() //nolint:errcheck
	time.Sleep(500 * time.Millisecond)
	return m.startLinux()
}

func (m *Manager) statusLinux() Status {
	execMonRunning := m.isLinuxServiceRunning(linuxExecMonService, linuxExecMonBin)
	fanotifyRunning := m.isLinuxServiceRunning(linuxFanotifyService, linuxFanotifyBin)

	_, execMonInstalled := os.Stat(linuxExecMonBin)
	_, fanotifyInstalled := os.Stat(linuxFanotifyBin)

	st := Status{Method: "fanotify+execmon"}
	st.Available = execMonInstalled == nil || fanotifyInstalled == nil

	switch {
	case execMonRunning && fanotifyRunning:
		st.Running = true
		st.Message = "execmon + fanotify running — all exec and writes monitored"
	case execMonRunning:
		st.Running = true
		st.Message = "execmon running (all exec intercepted); fanotify not running"
	case fanotifyRunning:
		st.Running = true
		st.Message = "fanotify running (filesystem writes monitored); execmon not running"
	default:
		st.Message = "kernel daemons not running"
	}
	return st
}

func (m *Manager) isLinuxServiceRunning(svcName, binPath string) bool {
	if isSystemdAvailable() {
		out, err := exec.Command("systemctl", "is-active", svcName).Output()
		if err == nil && strings.TrimSpace(string(out)) == "active" {
			return true
		}
	}
	out, _ := exec.Command("pgrep", "-f", binPath).Output()
	return strings.TrimSpace(string(out)) != ""
}

func isSystemdAvailable() bool {
	_, err := exec.LookPath("systemctl")
	if err != nil {
		return false
	}
	// Check if PID 1 is systemd
	target, _ := os.Readlink("/proc/1/exe")
	return strings.Contains(target, "systemd")
}

func linuxServiceExists(svcName string) bool {
	if _, err := os.Stat(filepath.Join("/etc/systemd/system", svcName+".service")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join("/etc/systemd/system/multi-user.target.wants", svcName+".service")); err == nil {
		return true
	}
	cmd := exec.Command("systemctl", "status", svcName)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

// ========================================
// Windows — minifilter driver via sc + fltMC + bridge
// ========================================

const windowsDriverName = "AuthSecShield"
const windowsBridgeName = "AuthSecShieldBridge.exe"

func (m *Manager) startWindows() error {
	bridgePath, err := findWindowsBridge()
	if err != nil {
		return fmt.Errorf("bridge not found: %w — run installer first", err)
	}

	// Load the minifilter
	if err := runCmd("fltMC", "load", windowsDriverName); err != nil {
		return fmt.Errorf("fltMC load failed (driver installed?): %w", err)
	}

	// Push protected paths to driver via bridge
	if err := m.pushPathsWindowsBridge(bridgePath); err != nil {
		return fmt.Errorf("failed to configure driver paths: %w", err)
	}

	// Enable driver
	if err := runCmd(bridgePath, "enable"); err != nil {
		return fmt.Errorf("failed to enable driver: %w", err)
	}

	// Start the bridge listener in background
	// The bridge handles kernel → API communication
	cmd := exec.Command(bridgePath, "listen", m.apiURL, m.accessToken)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

func (m *Manager) stopWindows() error {
	bridgePath, _ := findWindowsBridge()
	if bridgePath != "" {
		runCmd(bridgePath, "disable") //nolint:errcheck
	}
	runCmd("fltMC", "unload", windowsDriverName) //nolint:errcheck
	return nil
}

func (m *Manager) cleanupWindows() []error {
	m.stopWindows()                                    //nolint:errcheck
	runCmd("sc", "stop", "AuthSecShieldDaemon")        //nolint:errcheck
	runCmd("sc", "delete", "AuthSecShieldDaemon")      //nolint:errcheck
	runCmd("sc", "stop", windowsDriverName)            //nolint:errcheck
	runCmd("sc", "delete", windowsDriverName)          //nolint:errcheck
	runCmd("taskkill", "/IM", windowsBridgeName, "/F") //nolint:errcheck
	return nil
}

func (m *Manager) pushPathsWindows() error {
	bridgePath, err := findWindowsBridge()
	if err != nil {
		return err
	}
	return m.pushPathsWindowsBridge(bridgePath)
}

func (m *Manager) pushPathsWindowsBridge(bridgePath string) error {
	args := append([]string{"set-paths"}, m.protectedPaths...)
	return runCmdArgs(bridgePath, args...)
}

func (m *Manager) statusWindows() Status {
	st := Status{Method: "minifilter"}

	_, err := findWindowsBridge()
	st.Available = err == nil

	// Check if driver is loaded
	out, err := exec.Command("fltMC", "filters").Output()
	if err == nil && strings.Contains(string(out), windowsDriverName) {
		st.Running = true
		st.Message = "minifilter driver loaded"
	} else {
		st.Message = "minifilter driver not loaded"
	}
	return st
}

func findWindowsBridge() (string, error) {
	// Look next to the shield binary
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	candidate := filepath.Join(dir, windowsBridgeName)
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}

	// Check PATH
	path, err := exec.LookPath(windowsBridgeName)
	if err == nil {
		return path, nil
	}

	// Check Program Files
	progFiles := os.Getenv("ProgramFiles")
	if progFiles != "" {
		candidate = filepath.Join(progFiles, "AuthSec", "Shield", windowsBridgeName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("%s not found", windowsBridgeName)
}

// ========================================
// Helpers
// ========================================

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runCmdQuiet(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

func runCmdArgs(name string, args ...string) error {
	return runCmd(name, args...)
}
