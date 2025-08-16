package tunnel

import (
	"log"
	"net"
	"ssh-ify/internal/ssh"
)

// WebSocketHandler upgrades an incoming session to a WebSocket connection and establishes
// a tunnel using an in-process SSH server. It validates the Upgrade header, initializes
// the SSH configuration if necessary, and sets up a bidirectional proxy between the client
// and the SSH server. Returns true if the upgrade and tunnel setup succeed, or false on failure.
func WebSocketHandler(s *Session, reqLines []string) bool {
	upgradeHeader := HeaderValue(reqLines, "Upgrade")

	if upgradeHeader == "" {
		log.Printf("[session %s] No Upgrade header found. Closing connection.", s.sessionID)
		s.Close()
		return false
	}

	log.Printf("[session %s] WebSocket upgrade: using in-process SSH server.", s.sessionID)
	proxyEnd, sshEnd := net.Pipe()
	if s.sshConfig == nil {
		var err error
		s.sshConfig, err = ssh.NewConfig()
		if err != nil {
			log.Printf("[session %s] Error initializing SSH config: %v", s.sessionID, err)
			return false
		}
	}
	go ssh.HandleSSHConnection(sshEnd, s.sshConfig, func() {
		s.server.Add(s)
	})
	s.target = proxyEnd
	if _, err := s.client.Write([]byte(WebSocketUpgradeResponse)); err != nil {
		log.Printf("[session %s] Failed to write WebSocket upgrade response: %v", s.sessionID, err)
		s.Close()
		return false
	}
	log.Printf("[session %s] Tunnel established.", s.sessionID)
	return true
}
