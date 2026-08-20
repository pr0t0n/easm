// Command bas-relay is the reverse-tunnel relay that makes a real BAS agent
// reachable regardless of where it's actually installed -- a genuinely
// remote agent (a real customer network, behind NAT/firewall with no
// inbound port forwarding) can never be dialed INTO directly, which is
// exactly what bas_dispatcher.py's earlier "host.docker.internal" shortcut
// assumed (same host as the dev stack only).
//
// The fix: the agent dials OUT to this relay (solves NAT -- outbound is
// always allowed) and keeps that connection open, multiplexed with yamux.
// Whenever kali_runner's proxychains needs to reach that specific agent, it
// connects to a per-agent LOCAL port on this relay; the relay opens a new
// yamux stream over the agent's already-established connection and pipes
// bytes both ways. The agent treats each new incoming stream exactly like a
// new SOCKS5 connection (see bas-agent/socks5.go's handleSocks5Connection,
// unchanged and reused as-is -- a yamux Stream satisfies net.Conn).
//
// Authentication reuses the BAS CA unchanged: agents present their
// CA-signed mTLS client certificate (see bas_ca.py) to register; this
// relay's own server certificate is the SAME server.crt/server.key
// bas_ca.py already generates for the backend's mTLS listener (same CA,
// same trust anchor, no new cert type needed).
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

var agentCNPattern = regexp.MustCompile(`^bas-agent-(\d+)$`)

type sessionManager struct {
	mu               sync.Mutex
	sessions         map[int]*yamux.Session
	forwardListening map[int]bool
}

func newSessionManager() *sessionManager {
	return &sessionManager{
		sessions:         make(map[int]*yamux.Session),
		forwardListening: make(map[int]bool),
	}
}

func (m *sessionManager) register(agentID int, session *yamux.Session) {
	m.mu.Lock()
	old := m.sessions[agentID]
	m.sessions[agentID] = session
	needsListener := !m.forwardListening[agentID]
	if needsListener {
		m.forwardListening[agentID] = true
	}
	m.mu.Unlock()

	if old != nil {
		old.Close()
	}
	if needsListener {
		go m.serveForwarding(agentID)
	}
}

func (m *sessionManager) currentSession(agentID int) *yamux.Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[agentID]
}

// registeredAgentIDs snapshots which agents currently have a live session --
// used by the periodic revocation checker so a revocation takes effect on an
// ALREADY-connected agent, not just future registration attempts.
func (m *sessionManager) registeredAgentIDs() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]int, 0, len(m.sessions))
	for id, session := range m.sessions {
		if session != nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// revoke force-closes an agent's live session (if any). The next real dial
// attempt through kali_runner will simply fail to open a stream -- no
// silent zombie tunnel outliving a revocation.
func (m *sessionManager) revoke(agentID int) {
	m.mu.Lock()
	session := m.sessions[agentID]
	delete(m.sessions, agentID)
	m.mu.Unlock()
	if session != nil {
		log.Printf("bas-relay: agent %d revoked -- closing its live session", agentID)
		session.Close()
	}
}

// serveForwarding starts (once, ever, per agentID) the local listener
// kali_runner's proxychains connects to for this specific agent. Runs for
// the lifetime of the process; always forwards through whatever session is
// CURRENTLY registered for this agentID, so an agent reconnect is handled
// transparently -- kali_runner's config never needs to change.
func (m *sessionManager) serveForwarding(agentID int) {
	port := 20000 + agentID
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("bas-relay: failed to listen for agent %d forwarding on %s: %v", agentID, addr, err)
		return
	}
	log.Printf("bas-relay: forwarding listener for agent %d on %s", agentID, addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go m.forwardOne(agentID, conn)
	}
}

func (m *sessionManager) forwardOne(agentID int, conn net.Conn) {
	defer conn.Close()
	session := m.currentSession(agentID)
	if session == nil {
		log.Printf("bas-relay: agent %d has no active session, dropping connection", agentID)
		return
	}
	stream, err := session.Open()
	if err != nil {
		log.Printf("bas-relay: failed to open stream to agent %d: %v", agentID, err)
		return
	}
	defer stream.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(stream, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, stream); done <- struct{}{} }()
	<-done
}

func loadServerTLSConfig(caDir string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(caDir+"/server.crt", caDir+"/server.key")
	if err != nil {
		return nil, fmt.Errorf("loading relay server cert: %w", err)
	}
	caPEM, err := os.ReadFile(caDir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("reading CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

var revocationHTTPClient = &http.Client{Timeout: 5 * time.Second}

// checkRevocation asks the backend (real, not assumed) whether this
// agent_id has been revoked. Returns (revoked, certain) -- "certain" is
// false when the backend couldn't be reached / gave a bad response, so
// callers can decide their own fail-open-vs-closed policy for that case
// instead of this function silently picking one for both call sites below.
func checkRevocation(backendURL string, agentID int) (revoked bool, certain bool) {
	url := fmt.Sprintf("%s/api/bas/agents/%d/revocation-status", backendURL, agentID)
	resp, err := revocationHTTPClient.Get(url)
	if err != nil {
		log.Printf("bas-relay: revocation check for agent %d: request failed: %v", agentID, err)
		return false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("bas-relay: revocation check for agent %d: HTTP %d", agentID, resp.StatusCode)
		return false, false
	}
	var body struct {
		Revoked bool `json:"revoked"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		log.Printf("bas-relay: revocation check for agent %d: bad response body: %v", agentID, err)
		return false, false
	}
	return body.Revoked, true
}

// isRevokedAtRegistration gates a NEW session, where fail-closed is cheap
// (a legitimate agent just retries the connection): any uncertainty (backend
// unreachable, bad response) is treated as revoked.
func isRevokedAtRegistration(backendURL string, agentID int) bool {
	revoked, certain := checkRevocation(backendURL, agentID)
	if !certain {
		log.Printf("bas-relay: could not confirm agent %d's revocation status -- failing closed on registration", agentID)
		return true
	}
	return revoked
}

// revocationCheckLoop periodically re-checks every currently-registered
// agent so a revocation takes effect on an agent that's ALREADY connected,
// not just on its next registration attempt. Deliberately asymmetric with
// registration: an already-authenticated, already-working tunnel is only
// torn down on a CONFIRMED "revoked: true" -- a transient backend restart
// (routine in this dev stack) must never kill live agent sessions just
// because the revocation check itself briefly failed.
func revocationCheckLoop(backendURL string, manager *sessionManager, interval time.Duration) {
	for {
		time.Sleep(interval)
		for _, agentID := range manager.registeredAgentIDs() {
			revoked, certain := checkRevocation(backendURL, agentID)
			if certain && revoked {
				manager.revoke(agentID)
			}
		}
	}
}

func agentIDFromConn(conn net.Conn) (int, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return 0, fmt.Errorf("not a TLS connection")
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return 0, fmt.Errorf("no peer certificate presented")
	}
	cn := state.PeerCertificates[0].Subject.CommonName
	matches := agentCNPattern.FindStringSubmatch(cn)
	if matches == nil {
		return 0, fmt.Errorf("unexpected certificate CN: %s", cn)
	}
	return strconv.Atoi(matches[1])
}

func main() {
	log.SetFlags(log.LstdFlags)

	caDir := os.Getenv("BAS_CA_DIR")
	if caDir == "" {
		caDir = "/app/bas_ca"
	}
	registrationPort := os.Getenv("BAS_RELAY_PORT")
	if registrationPort == "" {
		registrationPort = "8446"
	}
	backendURL := os.Getenv("BAS_BACKEND_URL")
	if backendURL == "" {
		backendURL = "http://backend:8000"
	}

	tlsConfig, err := loadServerTLSConfig(caDir)
	if err != nil {
		log.Fatalf("bas-relay: %v", err)
	}

	ln, err := tls.Listen("tcp", "0.0.0.0:"+registrationPort, tlsConfig)
	if err != nil {
		log.Fatalf("bas-relay: failed to listen on :%s: %v", registrationPort, err)
	}
	log.Printf("bas-relay: agent registration listener on :%s (mTLS)", registrationPort)

	manager := newSessionManager()
	go revocationCheckLoop(backendURL, manager, 60*time.Second)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("bas-relay: accept error: %v", err)
			continue
		}
		go handleRegistration(manager, conn, backendURL)
	}
}

func handleRegistration(manager *sessionManager, conn net.Conn, backendURL string) {
	// The TLS handshake completes lazily on first read/write in Go's
	// net/tls -- force it now so ConnectionState() is populated before we
	// try to read the peer certificate.
	tlsConn := conn.(*tls.Conn)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("bas-relay: TLS handshake failed: %v", err)
		conn.Close()
		return
	}

	agentID, err := agentIDFromConn(conn)
	if err != nil {
		log.Printf("bas-relay: rejecting registration: %v", err)
		conn.Close()
		return
	}

	if isRevokedAtRegistration(backendURL, agentID) {
		log.Printf("bas-relay: rejecting registration for agent %d: revoked (or unconfirmed)", agentID)
		conn.Close()
		return
	}

	session, err := yamux.Server(conn, yamux.DefaultConfig())
	if err != nil {
		log.Printf("bas-relay: failed to start yamux session for agent %d: %v", agentID, err)
		conn.Close()
		return
	}

	log.Printf("bas-relay: agent %d registered (real remote tunnel active)", agentID)
	manager.register(agentID, session)
}
