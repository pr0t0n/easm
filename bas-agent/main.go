// Command bas-agent is the real, downloadable Windows/Linux BAS agent
// binary (Phase 1 smoke-test grade, per product decision): its enroll and
// heartbeat protocol, its mTLS client certificate, and its SOCKS5 tunnel
// handshake are all real. Only the tunnel's post-handshake response content
// is simulated (see socks5.go) -- the same honesty boundary bas-agent-stub
// (the existing Python container kept in place to validate Kali<->agent
// communication in dev) already draws, just now compiled to a native
// installable binary for Windows and Linux via cross-compilation
// (see build.sh) rather than running only inside docker-compose.
package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
)

func main() {
	log.SetFlags(log.LstdFlags)

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			fmt.Println("ScriptKidd.o BAS Agent (Go, smoke-test build) — installing as a persistent service")
			runInstall()
			return
		case "uninstall":
			fmt.Println("ScriptKidd.o BAS Agent (Go, smoke-test build) — uninstalling service")
			runUninstall()
			return
		case "config":
			runConfigCommand(os.Args[2:])
			return
		case "-h", "--help", "help":
			fmt.Println("Usage: bas-agent [install|uninstall|config]")
			fmt.Println("  (no args)  run in the foreground -- prompts for enrollment on first run")
			fmt.Println("  install    register this binary to run persistently (launchd/systemd; prints sc.exe steps on Windows)")
			fmt.Println("  uninstall  stop and remove the persistent registration")
			fmt.Println("  config     show or edit the current enrollment/config without reinstalling")
			return
		}
	}

	fmt.Println("ScriptKidd.o BAS Agent (Go, smoke-test build)")

	cfg, ok := loadConfig()
	if !ok {
		input := promptSetup()
		keyPEM, csrPEM, err := generateKeyAndCSR()
		if err != nil {
			log.Fatalf("bas-agent: failed to generate keypair: %v", err)
		}
		hostname, _ := os.Hostname()
		resp, err := enroll(input, hostname, runtime.GOOS, runtime.GOARCH, csrPEM, 1080)
		if err != nil {
			log.Fatalf("bas-agent: enrollment failed: %v", err)
		}
		if resp.ClientCertPEM == "" || resp.CACertPEM == "" {
			log.Fatalf("bas-agent: server did not return an mTLS client certificate -- cannot configure heartbeat")
		}
		cfg = &Config{
			Host: input.Host, Port: input.Port, MTLSPort: resp.MTLSPort, RelayPort: resp.RelayPort,
			AgentID: resp.AgentID, AgentJWT: resp.AgentJWT,
			ClientCertPEM: resp.ClientCertPEM, ClientKeyPEM: keyPEM, CACertPEM: resp.CACertPEM,
			SocksPort: 1080,
		}
		if err := saveConfig(cfg); err != nil {
			log.Printf("bas-agent: warning: failed to persist local config: %v", err)
		}
		log.Printf("bas-agent: enrolled as agent_id=%d, config saved to %s", cfg.AgentID, configPath())
	} else {
		log.Printf("bas-agent: loaded existing enrollment (agent_id=%d) from %s", cfg.AgentID, configPath())
	}

	go heartbeatLoop(cfg)
	go relayLoop(cfg)
	serveSocks5("0.0.0.0", cfg.SocksPort)
}
