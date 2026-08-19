package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

// Real SOCKS5 (RFC 1928) server AND real relay: the greeting/CONNECT
// handshake is genuine (proxychains4 inside kali_runner completes it for
// real over the network), and -- unlike bas-agent-stub's Python stub, which
// always answers with a canned payload -- this agent actually dials the
// requested destination FOR REAL from wherever it's installed, and pipes
// bytes bidirectionally. Real traffic in, real relay, real result: this is
// what makes the agent a genuine tunnel endpoint on whatever network it
// runs on, not just a protocol demonstration.
const (
	socksVersion   = 0x05
	cmdConnect     = 0x01
	atypIPv4       = 0x01
	atypDomain     = 0x03
	atypIPv6       = 0x04
	repSucceeded   = 0x00
	repGeneralErr  = 0x01
	repHostUnreach = 0x04
	repConnRefused = 0x05
	dialTimeout    = 8 * time.Second
)

func serveSocks5(host string, port int) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("bas-agent: SOCKS5 listen failed on %s: %v", addr, err)
	}
	log.Printf("bas-agent: SOCKS5 tunnel listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSocks5Connection(conn)
	}
}

func handleSocks5Connection(conn net.Conn) {
	defer conn.Close()
	peer := conn.RemoteAddr().String()

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != socksVersion {
		log.Printf("bas-agent: rejected non-SOCKS5 client peer=%s version=%d", peer, header[0])
		return
	}
	if nmethods := int(header[1]); nmethods > 0 {
		methods := make([]byte, nmethods)
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
	}
	if _, err := conn.Write([]byte{socksVersion, 0x00}); err != nil {
		return
	}

	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}
	cmd, atyp := reqHeader[1], reqHeader[3]

	var destAddr string
	switch atyp {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		destAddr = net.IP(b).String()
	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return
		}
		b := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		destAddr = string(b)
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		destAddr = net.IP(b).String()
	default:
		conn.Write([]byte{socksVersion, repGeneralErr, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return
	}
	destPort := binary.BigEndian.Uint16(portBytes)

	if cmd != cmdConnect {
		conn.Write([]byte{socksVersion, 0x07, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}) // command not supported
		return
	}

	log.Printf("bas-agent: REAL SOCKS5 CONNECT received peer=%s requested_destination=%s:%d", peer, destAddr, destPort)

	dest := net.JoinHostPort(destAddr, strconv.Itoa(int(destPort)))
	destConn, err := net.DialTimeout("tcp", dest, dialTimeout)
	if err != nil {
		log.Printf("bas-agent: REAL dial to %s failed: %v", dest, err)
		rep := byte(repGeneralErr)
		if _, ok := err.(net.Error); ok {
			rep = repConnRefused
		}
		conn.Write([]byte{socksVersion, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	defer destConn.Close()

	log.Printf("bas-agent: REAL relay established peer=%s <-> %s", peer, dest)
	conn.Write([]byte{socksVersion, repSucceeded, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})

	// Real bidirectional relay -- both directions copy actual bytes between
	// the tool (on the Kali side) and the real destination this agent's
	// host can reach. Closes when either side closes or errors.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(destConn, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, destConn); done <- struct{}{} }()
	<-done
}
