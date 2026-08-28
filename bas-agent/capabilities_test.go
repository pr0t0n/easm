package main

import "testing"

func TestCollectCapabilitiesIncludesRuntimeAndProxy(t *testing.T) {
	report := collectCapabilities(&Config{
		SocksPort:     1080,
		RelayPort:     8446,
		RelayFailover: []string{"relay2:8446"},
	})

	if report.OS == "" || report.Arch == "" {
		t.Fatalf("runtime fields missing: %#v", report)
	}
	if report.Proxy["socks_port"] != 1080 {
		t.Fatalf("proxy socks port missing: %#v", report.Proxy)
	}
	if len(report.Tools) == 0 {
		t.Fatalf("expected tool inventory: %#v", report.Tools)
	}
}
