package main

import "net"

// localNetworkCIDR reads the agent's own network interface configuration --
// never sends a packet to anyone, never scans anything -- and returns the
// first non-loopback, non-link-local IPv4 address in real CIDR form (e.g.
// "10.10.10.5/24"), exactly the mask actually configured on that interface.
// A single IP observed from the server side (e.g. the enroll/heartbeat
// connection's peer address) can never reveal this mask -- only the agent
// itself knows it. Returns "" if no such interface is found (e.g. offline,
// or only loopback available).
func localNetworkCIDR() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			return ipNet.String()
		}
	}
	return ""
}
