package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type heartbeatRequest struct {
	// Recalculated every heartbeat (not just at enroll) so the platform
	// self-corrects if the agent's network changes (DHCP renewal, moved to
	// a different segment, etc.) without needing a re-enroll.
	LocalNetworkCIDR string `json:"local_network_cidr"`
}

// buildMTLSClient configures an http.Client that presents the agent's
// CA-signed client certificate on every connection and validates the
// server's certificate against the same BAS root CA -- genuine mutual TLS,
// not just server-authenticated HTTPS.
func buildMTLSClient(cfg *Config) (*http.Client, error) {
	cert, err := tls.X509KeyPair([]byte(cfg.ClientCertPEM), []byte(cfg.ClientKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("loading client cert/key: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM([]byte(cfg.CACertPEM)) {
		return nil, fmt.Errorf("failed to parse BAS CA certificate")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}, nil
}

// heartbeatLoop runs forever, calling the mTLS-required heartbeat endpoint.
// A cert this CA didn't sign never completes the TLS handshake at all
// (enforced by the server's transport-level ssl_cert_reqs=CERT_REQUIRED),
// so a failure here before any HTTP response is itself meaningful evidence
// of the mTLS gate actually working.
func heartbeatLoop(cfg *Config) {
	for {
		current := configForRuntime(cfg)
		client, err := buildMTLSClient(current)
		if err != nil {
			log.Printf("bas-agent: mTLS client setup failed: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}
		url := fmt.Sprintf("https://%s:%d/api/bas/agents/heartbeat", current.Host, current.MTLSPort)
		body, _ := json.Marshal(heartbeatRequest{LocalNetworkCIDR: localNetworkCIDR()})
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+current.AgentJWT)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("bas-agent: heartbeat failed: %v", err)
		} else {
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				log.Printf("bas-agent: heartbeat non-200: %s", resp.Status)
			}
		}
		time.Sleep(30 * time.Second)
	}
}
