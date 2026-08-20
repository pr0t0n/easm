package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// Config is persisted locally after a successful enroll so the agent doesn't
// re-prompt / re-enroll on every restart. Contains the mTLS client
// certificate issued by the platform's BAS root CA (see bas_ca.py) -- the
// private key that pairs with it never leaves this file.
type Config struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	MTLSPort      int    `json:"mtls_port"`
	// RelayPort: bas-relay's agent-registration port. This agent dials OUT
	// to it (solves NAT -- works even when this agent is on a real, remote
	// customer network with no inbound path) and stays connected, so
	// kali_runner can reach it without needing this agent's host to be the
	// same machine as the dev stack. See relay.go.
	RelayPort     int    `json:"relay_port"`
	AgentID       int    `json:"agent_id"`
	AgentJWT      string `json:"agent_jwt"`
	ClientCertPEM string `json:"client_cert_pem"`
	ClientKeyPEM  string `json:"client_key_pem"`
	CACertPEM     string `json:"ca_cert_pem"`
	SocksPort     int    `json:"socks_port"`
}

// EnrollInput is what the interactive installer collects -- matches the
// original product requirement: username, password, token, IP, and port,
// all shown on the platform's BAS dashboard.
type EnrollInput struct {
	Username string
	Password string
	Code     string
	Host     string
	Port     int
}

func configPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	full := filepath.Join(dir, "bas-agent")
	_ = os.MkdirAll(full, 0700)
	return filepath.Join(full, "config.json")
}

func loadConfig() (*Config, bool) {
	data, err := os.ReadFile(configPath())
	if err != nil {
		return nil, false
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, false
	}
	if cfg.ClientCertPEM == "" || cfg.AgentJWT == "" {
		return nil, false
	}
	return &cfg, true
}

func saveConfig(cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(), data, 0600)
}

// askPassword masks input when stdin is a real terminal (term.ReadPassword);
// falls back to plain-echo reading when it isn't (piped stdin -- automated
// installs, CI, or this project's own smoke tests), since ReadPassword
// requires an actual TTY file descriptor and would otherwise hang/fail.
func askPassword(reader *bufio.Reader, label string) string {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Print(label + ": ")
		bytePw, err := term.ReadPassword(fd)
		fmt.Println()
		if err == nil {
			return strings.TrimSpace(string(bytePw))
		}
	}
	fmt.Print(label + ": ")
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

// promptSetup collects the interactive installer's credentials from stdin.
func promptSetup() *EnrollInput {
	reader := bufio.NewReader(os.Stdin)
	ask := func(label string) string {
		fmt.Print(label + ": ")
		text, _ := reader.ReadString('\n')
		return strings.TrimSpace(text)
	}
	fmt.Println("=== ScriptKidd.o BAS Agent — instalação ===")
	fmt.Println("(dados mostrados no dashboard BAS da plataforma)")
	username := ask("Usuário")
	password := askPassword(reader, "Senha")
	code := ask("Token / código de enrollment")
	host := ask("IP da plataforma")
	portStr := ask("Porta da plataforma")
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		port = 8001
	}
	return &EnrollInput{Username: username, Password: password, Code: code, Host: host, Port: port}
}
