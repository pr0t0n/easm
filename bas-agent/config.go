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
	Host     string `json:"host"`
	Port     int    `json:"port"`
	MTLSPort int    `json:"mtls_port"`
	// RelayPort: bas-relay's agent-registration port. This agent dials OUT
	// to it (solves NAT -- works even when this agent is on a real, remote
	// customer network with no inbound path) and stays connected, so
	// kali_runner can reach it without needing this agent's host to be the
	// same machine as the dev stack. See relay.go.
	RelayPort                int            `json:"relay_port"`
	AgentID                  int            `json:"agent_id"`
	AgentJWT                 string         `json:"agent_jwt"`
	ClientCertPEM            string         `json:"client_cert_pem"`
	ClientKeyPEM             string         `json:"client_key_pem"`
	CACertPEM                string         `json:"ca_cert_pem"`
	SocksPort                int            `json:"socks_port"`
	ConfigRevision           int            `json:"config_revision"`
	HeartbeatIntervalSeconds int            `json:"heartbeat_interval_seconds"`
	RelayFailover            []string       `json:"relay_failover"`
	LocalPolicy              map[string]any `json:"local_policy"`
	AutoUpdate               map[string]any `json:"auto_update"`
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

type ConfigUpdate struct {
	Host      *string
	Port      *int
	MTLSPort  *int
	RelayPort *int
	SocksPort *int
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

func configForRuntime(current *Config) *Config {
	cfg, ok := loadConfig()
	if !ok {
		return current
	}
	return cfg
}

func heartbeatIntervalSeconds(cfg *Config) int {
	if cfg.HeartbeatIntervalSeconds > 0 {
		return cfg.HeartbeatIntervalSeconds
	}
	return 30
}

func applyRemoteConfig(cfg *Config, remote map[string]any) bool {
	if remote == nil {
		return false
	}
	revision := intFromAny(remote["config_revision"])
	if revision <= cfg.ConfigRevision {
		return false
	}
	if value := intFromAny(remote["heartbeat_interval_seconds"]); value > 0 {
		cfg.HeartbeatIntervalSeconds = value
	}
	if values, ok := stringSliceFromAny(remote["relay_failover"]); ok {
		cfg.RelayFailover = values
	}
	if policy, ok := remote["policy"].(map[string]any); ok {
		cfg.LocalPolicy = policy
	}
	if autoUpdate, ok := remote["auto_update"].(map[string]any); ok {
		cfg.AutoUpdate = autoUpdate
	}
	cfg.ConfigRevision = revision
	return true
}

func intFromAny(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case float64:
		return int(typed)
	case string:
		parsed, _ := strconv.Atoi(strings.TrimSpace(typed))
		return parsed
	default:
		return 0
	}
}

func stringSliceFromAny(value any) ([]string, bool) {
	raw, ok := value.([]any)
	if !ok {
		return nil, false
	}
	values := []string{}
	for _, item := range raw {
		text := strings.TrimSpace(fmt.Sprint(item))
		if text != "" {
			values = append(values, text)
		}
	}
	return values, true
}

func redacted(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 12 {
		return "***"
	}
	return value[:6] + "..." + value[len(value)-6:]
}

func printConfig(cfg *Config) {
	fmt.Printf("config_path: %s\n", configPath())
	fmt.Printf("host: %s\n", cfg.Host)
	fmt.Printf("port: %d\n", cfg.Port)
	fmt.Printf("mtls_port: %d\n", cfg.MTLSPort)
	fmt.Printf("relay_port: %d\n", cfg.RelayPort)
	fmt.Printf("agent_id: %d\n", cfg.AgentID)
	fmt.Printf("agent_jwt: %s\n", redacted(cfg.AgentJWT))
	fmt.Printf("client_cert_pem: %t\n", cfg.ClientCertPEM != "")
	fmt.Printf("client_key_pem: %t\n", cfg.ClientKeyPEM != "")
	fmt.Printf("ca_cert_pem: %t\n", cfg.CACertPEM != "")
	fmt.Printf("socks_port: %d\n", cfg.SocksPort)
	fmt.Printf("config_revision: %d\n", cfg.ConfigRevision)
	fmt.Printf("heartbeat_interval_seconds: %d\n", heartbeatIntervalSeconds(cfg))
	fmt.Printf("relay_failover: %s\n", strings.Join(cfg.RelayFailover, ","))
}

func parsePositiveInt(value string, field string) (int, error) {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s inválido", field)
	}
	return parsed, nil
}

func applyConfigUpdate(cfg *Config, update ConfigUpdate) {
	if update.Host != nil {
		cfg.Host = strings.TrimSpace(*update.Host)
	}
	if update.Port != nil {
		cfg.Port = *update.Port
	}
	if update.MTLSPort != nil {
		cfg.MTLSPort = *update.MTLSPort
	}
	if update.RelayPort != nil {
		cfg.RelayPort = *update.RelayPort
	}
	if update.SocksPort != nil {
		cfg.SocksPort = *update.SocksPort
	}
}

func promptConfigUpdate(cfg *Config) (ConfigUpdate, error) {
	reader := bufio.NewReader(os.Stdin)
	ask := func(label string, current string) string {
		fmt.Printf("%s [%s]: ", label, current)
		text, _ := reader.ReadString('\n')
		return strings.TrimSpace(text)
	}
	update := ConfigUpdate{}
	if value := ask("IP/host da plataforma", cfg.Host); value != "" {
		update.Host = &value
	}
	if value := ask("Porta HTTP da plataforma", strconv.Itoa(cfg.Port)); value != "" {
		port, err := parsePositiveInt(value, "port")
		if err != nil {
			return update, err
		}
		update.Port = &port
	}
	if value := ask("Porta mTLS", strconv.Itoa(cfg.MTLSPort)); value != "" {
		port, err := parsePositiveInt(value, "mtls_port")
		if err != nil {
			return update, err
		}
		update.MTLSPort = &port
	}
	if value := ask("Porta relay", strconv.Itoa(cfg.RelayPort)); value != "" {
		port, err := parsePositiveInt(value, "relay_port")
		if err != nil {
			return update, err
		}
		update.RelayPort = &port
	}
	if value := ask("Porta SOCKS local", strconv.Itoa(cfg.SocksPort)); value != "" {
		port, err := parsePositiveInt(value, "socks_port")
		if err != nil {
			return update, err
		}
		update.SocksPort = &port
	}
	return update, nil
}

func parseConfigSetArgs(args []string) (ConfigUpdate, error) {
	update := ConfigUpdate{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		key := ""
		value := ""
		if strings.HasPrefix(arg, "--") {
			key = strings.TrimPrefix(arg, "--")
			if strings.Contains(key, "=") {
				parts := strings.SplitN(key, "=", 2)
				key, value = parts[0], parts[1]
			} else {
				i++
				if i >= len(args) {
					return update, fmt.Errorf("valor ausente para --%s", key)
				}
				value = args[i]
			}
		} else if strings.Contains(arg, "=") {
			parts := strings.SplitN(arg, "=", 2)
			key, value = parts[0], parts[1]
		} else {
			return update, fmt.Errorf("argumento inválido: %s", arg)
		}
		key = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), "-", "_")
		value = strings.TrimSpace(value)
		switch key {
		case "host":
			update.Host = &value
		case "port":
			port, err := parsePositiveInt(value, "port")
			if err != nil {
				return update, err
			}
			update.Port = &port
		case "mtls_port", "mtls":
			port, err := parsePositiveInt(value, "mtls_port")
			if err != nil {
				return update, err
			}
			update.MTLSPort = &port
		case "relay_port", "relay":
			port, err := parsePositiveInt(value, "relay_port")
			if err != nil {
				return update, err
			}
			update.RelayPort = &port
		case "socks_port", "socks":
			port, err := parsePositiveInt(value, "socks_port")
			if err != nil {
				return update, err
			}
			update.SocksPort = &port
		default:
			return update, fmt.Errorf("campo desconhecido: %s", key)
		}
	}
	return update, nil
}

func runConfigCommand(args []string) {
	action := "show"
	if len(args) > 0 {
		action = args[0]
		args = args[1:]
	}
	if action == "path" {
		fmt.Println(configPath())
		return
	}
	cfg, ok := loadConfig()
	if !ok {
		fmt.Printf("bas-agent: configuração não encontrada ou incompleta em %s\n", configPath())
		os.Exit(1)
	}
	switch action {
	case "show":
		printConfig(cfg)
	case "edit":
		update, err := promptConfigUpdate(cfg)
		if err != nil {
			fmt.Printf("bas-agent: %v\n", err)
			os.Exit(1)
		}
		applyConfigUpdate(cfg, update)
		if err := saveConfig(cfg); err != nil {
			fmt.Printf("bas-agent: falha ao salvar config: %v\n", err)
			os.Exit(1)
		}
		printConfig(cfg)
	case "set":
		update, err := parseConfigSetArgs(args)
		if err != nil {
			fmt.Printf("bas-agent: %v\n", err)
			os.Exit(1)
		}
		applyConfigUpdate(cfg, update)
		if err := saveConfig(cfg); err != nil {
			fmt.Printf("bas-agent: falha ao salvar config: %v\n", err)
			os.Exit(1)
		}
		printConfig(cfg)
	default:
		fmt.Println("Usage: bas-agent config [show|path|edit|set]")
		fmt.Println("       bas-agent config set --host 192.168.1.10 --port 8001 --mtls-port 8444 --relay-port 8446")
		os.Exit(1)
	}
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
