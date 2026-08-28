package main

import (
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
)

type InterfaceCapability struct {
	Name  string   `json:"name"`
	Flags []string `json:"flags"`
	Addrs []string `json:"addrs"`
}

type ToolCapability struct {
	Name      string `json:"name"`
	Found     bool   `json:"found"`
	Path      string `json:"path"`
	ManagedBy string `json:"managed_by"`
}

type CapabilityReport struct {
	OS         string                `json:"os"`
	Arch       string                `json:"arch"`
	Hostname   string                `json:"hostname"`
	User       string                `json:"user"`
	Privileged bool                  `json:"privileged"`
	Interfaces []InterfaceCapability `json:"interfaces"`
	Tools      []ToolCapability      `json:"tools"`
	Proxy      map[string]any        `json:"proxy"`
	EDR        map[string]any        `json:"edr"`
	Version    string                `json:"version"`
}

func collectCapabilities(cfg *Config) CapabilityReport {
	hostname, _ := os.Hostname()
	currentUser, _ := user.Current()
	username := ""
	if currentUser != nil {
		username = currentUser.Username
	}
	return CapabilityReport{
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Hostname:   hostname,
		User:       username,
		Privileged: looksPrivileged(username),
		Interfaces: interfaceCapabilities(),
		Tools:      toolCapabilities([]string{"curl", "nmap", "proxychains", "proxychains4", "crackmapexec", "smbmap", "ldapsearch", "powershell", "pwsh", "bash"}),
		Proxy:      map[string]any{"socks_port": cfg.SocksPort, "relay_port": cfg.RelayPort, "relay_failover": cfg.RelayFailover},
		EDR:        edrSignals(),
		Version:    "bas-agent-go-0.1",
	}
}

func looksPrivileged(username string) bool {
	lower := strings.ToLower(username)
	return strings.Contains(lower, "administrator") || strings.HasSuffix(lower, "\\admin") || lower == "root"
}

func interfaceCapabilities() []InterfaceCapability {
	ifaces, err := net.Interfaces()
	if err != nil {
		return []InterfaceCapability{}
	}
	rows := []InterfaceCapability{}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		values := []string{}
		for _, addr := range addrs {
			values = append(values, addr.String())
		}
		rows = append(rows, InterfaceCapability{Name: iface.Name, Flags: strings.Fields(iface.Flags.String()), Addrs: values})
	}
	return rows
}

func toolCapabilities(names []string) []ToolCapability {
	rows := []ToolCapability{}
	for _, name := range names {
		path, err := exec.LookPath(name)
		rows = append(rows, ToolCapability{Name: name, Found: err == nil, Path: path, ManagedBy: "local_path"})
	}
	return rows
}

func edrSignals() map[string]any {
	processes := runningProcessText()
	vendors := map[string][]string{
		"crowdstrike":   {"falcon", "csfalconservice"},
		"sentinelone":   {"sentinelone", "sentineld"},
		"defender":      {"msmpeng", "windefend", "mdatp"},
		"carbon_black":  {"cbdefense", "carbonblack"},
		"cortex_xdr":    {"cyserver", "traps"},
		"elastic_agent": {"elastic-agent"},
	}
	found := []string{}
	lower := strings.ToLower(processes)
	for vendor, needles := range vendors {
		for _, needle := range needles {
			if strings.Contains(lower, needle) {
				found = append(found, vendor)
				break
			}
		}
	}
	return map[string]any{"present": len(found) > 0, "vendors": found}
}

func runningProcessText() string {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("tasklist").Output()
		if err != nil {
			return ""
		}
		return string(out)
	}
	out, err := exec.Command("ps", "axo", "comm").Output()
	if err != nil {
		return ""
	}
	return string(out)
}
