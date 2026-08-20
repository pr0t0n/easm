package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const serviceLabel = "com.scriptkiddo.bas-agent"

// runInstall registers the current binary to run persistently (survives
// reboot/logout) instead of only as a manually-launched foreground process.
// macOS uses a real launchd LaunchAgent (verified on this machine); Linux
// generates a real systemd user unit (correct unit content, not live-tested
// here); Windows has no in-process service host in this build (no Windows
// host available to verify one) -- prints the manual sc.exe steps instead.
func runInstall() {
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("bas-agent: could not resolve own executable path: %v\n", err)
		os.Exit(1)
	}

	switch runtime.GOOS {
	case "darwin":
		installLaunchd(exePath)
	case "linux":
		installSystemdUser(exePath)
	case "windows":
		printWindowsServiceInstructions(exePath)
	default:
		fmt.Printf("bas-agent: no service integration for GOOS=%s -- run the binary directly.\n", runtime.GOOS)
	}
}

func runUninstall() {
	switch runtime.GOOS {
	case "darwin":
		uninstallLaunchd()
	case "linux":
		uninstallSystemdUser()
	case "windows":
		fmt.Println("bas-agent: run as Administrator: sc.exe stop BasAgent && sc.exe delete BasAgent")
	default:
		fmt.Printf("bas-agent: no service integration for GOOS=%s -- nothing to uninstall.\n", runtime.GOOS)
	}
}

func launchAgentPlistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return filepath.Join(dir, serviceLabel+".plist"), nil
}

func installLaunchd(exePath string) {
	plistPath, err := launchAgentPlistPath()
	if err != nil {
		fmt.Printf("bas-agent: failed to resolve LaunchAgents directory: %v\n", err)
		os.Exit(1)
	}
	home, _ := os.UserHomeDir()
	logDir := filepath.Join(home, "Library", "Logs", "bas-agent")
	_ = os.MkdirAll(logDir, 0755)

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, serviceLabel, exePath, filepath.Join(logDir, "stdout.log"), filepath.Join(logDir, "stderr.log"))

	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		fmt.Printf("bas-agent: failed to write launchd plist: %v\n", err)
		os.Exit(1)
	}

	uid := os.Getuid()
	target := fmt.Sprintf("gui/%d/%s", uid, serviceLabel)
	_ = exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d", uid), plistPath).Run() // best-effort, ignore "not loaded"
	bootstrap := exec.Command("launchctl", "bootstrap", fmt.Sprintf("gui/%d", uid), plistPath)
	if out, err := bootstrap.CombinedOutput(); err != nil {
		fmt.Printf("bas-agent: launchctl bootstrap failed: %v\n%s\n", err, string(out))
		fmt.Printf("bas-agent: plist written to %s -- load it manually with: launchctl bootstrap gui/%d %s\n", plistPath, uid, plistPath)
		os.Exit(1)
	}
	fmt.Printf("bas-agent: installed as a launchd agent (%s) -- runs at login, restarts if it exits.\n", target)
	fmt.Printf("bas-agent: logs at %s\n", logDir)
}

func uninstallLaunchd() {
	plistPath, err := launchAgentPlistPath()
	if err != nil {
		fmt.Printf("bas-agent: failed to resolve LaunchAgents directory: %v\n", err)
		os.Exit(1)
	}
	uid := os.Getuid()
	out, err := exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d", uid), plistPath).CombinedOutput()
	if err != nil {
		fmt.Printf("bas-agent: launchctl bootout warning: %v\n%s\n", err, string(out))
	}
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		fmt.Printf("bas-agent: failed to remove %s: %v\n", plistPath, err)
		os.Exit(1)
	}
	fmt.Println("bas-agent: launchd agent stopped and removed.")
}

func systemdUserUnitPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "bas-agent.service"), nil
}

func installSystemdUser(exePath string) {
	unitPath, err := systemdUserUnitPath()
	if err != nil {
		fmt.Printf("bas-agent: failed to resolve systemd user unit directory: %v\n", err)
		os.Exit(1)
	}
	unit := fmt.Sprintf(`[Unit]
Description=ScriptKidd.o BAS Agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`, exePath)
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		fmt.Printf("bas-agent: failed to write systemd unit: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("bas-agent: systemd user unit written to %s\n", unitPath)
	fmt.Println("bas-agent: to enable and start it now, run:")
	fmt.Println("  systemctl --user daemon-reload && systemctl --user enable --now bas-agent")
	fmt.Println("  (add: sudo loginctl enable-linger $USER   -- to keep it running after logout)")
}

func uninstallSystemdUser() {
	unitPath, err := systemdUserUnitPath()
	if err != nil {
		fmt.Printf("bas-agent: failed to resolve systemd user unit directory: %v\n", err)
		os.Exit(1)
	}
	out, err := exec.Command("systemctl", "--user", "disable", "--now", "bas-agent").CombinedOutput()
	if err != nil {
		fmt.Printf("bas-agent: systemctl disable warning: %v\n%s\n", err, string(out))
	}
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		fmt.Printf("bas-agent: failed to remove %s: %v\n", unitPath, err)
		os.Exit(1)
	}
	fmt.Println("bas-agent: systemd user unit stopped and removed. Run: systemctl --user daemon-reload")
}

// printWindowsServiceInstructions: no native Windows service host is built
// into this binary -- golang.org/x/sys/windows/svc integration needs a real
// Windows machine to verify (none available in this dev environment), so
// rather than ship unverified service code, this prints the standard
// sc.exe-based manual registration instead.
func printWindowsServiceInstructions(exePath string) {
	fmt.Println("bas-agent: no built-in Windows service host in this build.")
	fmt.Println("bas-agent: to run it as a Windows service, open an Administrator prompt and run:")
	fmt.Printf("  sc.exe create BasAgent binPath= \"%s\" start= auto\n", exePath)
	fmt.Println("  sc.exe start BasAgent")
	fmt.Println("bas-agent: (or use NSSM if you prefer a wrapper with log rotation: nssm install BasAgent \"" + exePath + "\")")
}
