package main

import "testing"

func TestParseConfigSetArgsAcceptsFlagsAndPairs(t *testing.T) {
	update, err := parseConfigSetArgs([]string{
		"--host", "10.0.0.20",
		"--port=8001",
		"mtls_port=8444",
		"relay-port=8446",
		"socks=1080",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if update.Host == nil || *update.Host != "10.0.0.20" {
		t.Fatalf("host not parsed: %#v", update.Host)
	}
	if update.Port == nil || *update.Port != 8001 {
		t.Fatalf("port not parsed: %#v", update.Port)
	}
	if update.MTLSPort == nil || *update.MTLSPort != 8444 {
		t.Fatalf("mtls not parsed: %#v", update.MTLSPort)
	}
	if update.RelayPort == nil || *update.RelayPort != 8446 {
		t.Fatalf("relay not parsed: %#v", update.RelayPort)
	}
	if update.SocksPort == nil || *update.SocksPort != 1080 {
		t.Fatalf("socks not parsed: %#v", update.SocksPort)
	}
}

func TestApplyConfigUpdatePreservesEnrollment(t *testing.T) {
	host := "192.168.1.50"
	port := 8002
	cfg := &Config{
		Host: "10.0.0.10", Port: 8001, MTLSPort: 8444, RelayPort: 8446,
		AgentID: 42, AgentJWT: "token", ClientCertPEM: "cert", ClientKeyPEM: "key", CACertPEM: "ca",
		SocksPort: 1080,
	}

	applyConfigUpdate(cfg, ConfigUpdate{Host: &host, Port: &port})

	if cfg.Host != host || cfg.Port != port {
		t.Fatalf("network fields not updated: %#v", cfg)
	}
	if cfg.AgentID != 42 || cfg.AgentJWT != "token" || cfg.ClientCertPEM != "cert" || cfg.ClientKeyPEM != "key" || cfg.CACertPEM != "ca" {
		t.Fatalf("enrollment fields changed: %#v", cfg)
	}
	if cfg.MTLSPort != 8444 || cfg.RelayPort != 8446 || cfg.SocksPort != 1080 {
		t.Fatalf("untouched ports changed: %#v", cfg)
	}
}

func TestParseConfigSetArgsRejectsInvalidPort(t *testing.T) {
	_, err := parseConfigSetArgs([]string{"--port", "0"})
	if err == nil {
		t.Fatal("expected invalid port error")
	}
}

func TestApplyRemoteConfigUpdatesRuntimeFields(t *testing.T) {
	cfg := &Config{ConfigRevision: 1, HeartbeatIntervalSeconds: 30}

	changed := applyRemoteConfig(cfg, map[string]any{
		"config_revision":            float64(2),
		"heartbeat_interval_seconds": float64(15),
		"relay_failover":             []any{"relay-a:8446", " relay-b:8446 "},
		"policy":                     map[string]any{"max_parallel_jobs": float64(2)},
		"auto_update":                map[string]any{"enabled": true},
	})

	if !changed {
		t.Fatal("expected config change")
	}
	if cfg.ConfigRevision != 2 || cfg.HeartbeatIntervalSeconds != 15 {
		t.Fatalf("remote config scalar fields not applied: %#v", cfg)
	}
	if len(cfg.RelayFailover) != 2 || cfg.RelayFailover[1] != "relay-b:8446" {
		t.Fatalf("relay failover not applied: %#v", cfg.RelayFailover)
	}
	if cfg.LocalPolicy["max_parallel_jobs"] != float64(2) {
		t.Fatalf("policy not applied: %#v", cfg.LocalPolicy)
	}
	if cfg.AutoUpdate["enabled"] != true {
		t.Fatalf("auto update not applied: %#v", cfg.AutoUpdate)
	}
}

func TestApplyRemoteConfigIgnoresOldRevision(t *testing.T) {
	cfg := &Config{ConfigRevision: 3, HeartbeatIntervalSeconds: 30}

	changed := applyRemoteConfig(cfg, map[string]any{
		"config_revision":            float64(2),
		"heartbeat_interval_seconds": float64(10),
	})

	if changed {
		t.Fatal("expected old revision to be ignored")
	}
	if cfg.HeartbeatIntervalSeconds != 30 {
		t.Fatalf("old config revision changed interval: %#v", cfg)
	}
}
