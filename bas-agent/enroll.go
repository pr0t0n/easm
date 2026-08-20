package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type enrollRequest struct {
	Code         string `json:"code"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agent_version"`
	TunnelHost   string `json:"tunnel_host"`
	TunnelPort   int    `json:"tunnel_port"`
	CSRPEM       string `json:"csr_pem"`
}

type enrollResponse struct {
	AgentID       int    `json:"agent_id"`
	AgentJWT      string `json:"agent_jwt"`
	ClientCertPEM string `json:"client_cert_pem"`
	CACertPEM     string `json:"ca_cert_pem"`
	MTLSPort      int    `json:"mtls_port"`
	RelayPort     int    `json:"relay_port"`
}

// enroll runs over the platform's existing PLAIN HTTP port -- this is the
// one-time bootstrap step (no client cert exists yet, so there is nothing
// to present for mTLS). Every call after this (heartbeat) uses the mTLS
// port and the certificate this call returns. See bas_ca.py's module
// docstring for the full rationale.
func enroll(input *EnrollInput, hostname, osName, arch, csrPEM string, socksPort int) (*enrollResponse, error) {
	body := enrollRequest{
		Code: input.Code, Username: input.Username, Password: input.Password,
		Hostname: hostname, OS: osName, OSVersion: "bas-agent-go-0.1", Arch: arch,
		AgentVersion: "bas-agent-go-0.1", TunnelHost: hostname, TunnelPort: socksPort,
		CSRPEM: csrPEM,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("http://%s:%d/api/bas/agents/enroll", input.Host, input.Port)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respData, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enroll failed: %s (%s)", resp.Status, string(respData))
	}
	var out enrollResponse
	if err := json.Unmarshal(respData, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
