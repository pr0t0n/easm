package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

// relayLoop dials OUT to bas-relay (solves NAT/firewall -- outbound is
// always allowed, unlike the reverse: the platform dialing IN to wherever
// this agent happens to be) and keeps that connection open as a yamux
// CLIENT session. Every new stream the relay opens on it (whenever
// kali_runner's proxychains reaches this agent's per-agent forwarding port)
// is handled exactly like a locally-accepted SOCKS5 connection --
// handleSocks5Connection doesn't know or care that its net.Conn is actually
// a yamux Stream multiplexed over one long-lived TCP connection to the
// relay instead of a fresh accept() from a real socket.
func relayLoop(cfg *Config) {
	if cfg.RelayPort == 0 {
		log.Printf("bas-agent: no relay port configured, skipping relay connection (older enrollment?)")
		return
	}
	backoff := time.Second
	for {
		current := configForRuntime(cfg)
		if err := connectAndServeRelay(current); err != nil {
			log.Printf("bas-agent: relay connection lost: %v (retrying in %s)", err, backoff)
		}
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func connectAndServeRelay(cfg *Config) error {
	cert, err := tls.X509KeyPair([]byte(cfg.ClientCertPEM), []byte(cfg.ClientKeyPEM))
	if err != nil {
		return fmt.Errorf("loading client cert/key: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM([]byte(cfg.CACertPEM)) {
		return fmt.Errorf("failed to parse BAS CA certificate")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}

	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.RelayPort))
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("dialing relay at %s: %w", addr, err)
	}
	defer conn.Close()

	session, err := yamux.Client(conn, yamux.DefaultConfig())
	if err != nil {
		return fmt.Errorf("starting yamux client session: %w", err)
	}
	defer session.Close()

	log.Printf("bas-agent: registered with relay at %s -- reachable for real dispatch regardless of network location", addr)

	for {
		stream, err := session.Accept()
		if err != nil {
			return fmt.Errorf("session closed: %w", err)
		}
		go handleSocks5Connection(stream)
	}
}
