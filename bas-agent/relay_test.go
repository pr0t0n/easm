package main

import "testing"

func TestRelayEndpointsIncludesPrimaryAndFailover(t *testing.T) {
	endpoints := relayEndpoints(&Config{
		Host:          "platform.local",
		RelayPort:     8446,
		RelayFailover: []string{"relay-a:8446", " relay-b:8446 "},
	})

	if len(endpoints) != 3 {
		t.Fatalf("unexpected endpoints: %#v", endpoints)
	}
	if endpoints[0] != "platform.local:8446" || endpoints[2] != "relay-b:8446" {
		t.Fatalf("relay endpoints not normalized: %#v", endpoints)
	}
}
