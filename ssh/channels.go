// Package ssh handles SSH channel management and port forwarding logic for the proxy server.
package ssh

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// DirectTCPIP parses the ExtraData for a direct-tcpip channel.
// It extracts the target host and port from the SSH channel request.
// Returns an error if the request is malformed or incomplete.
func DirectTCPIP(extra []byte) (host string, port uint32, err error) {
	// Parse host length (first 4 bytes, big endian)
	if len(extra) < 4 {
		return "", 0, fmt.Errorf("invalid direct-tcpip request: insufficient data for host length")
	}
	l := int(binary.BigEndian.Uint32(extra[:4]))
	// Ensure enough data for host and port
	if len(extra) < 4+l+4 {
		return "", 0, fmt.Errorf("invalid direct-tcpip request: insufficient data for host and port")
	}
	host = string(extra[4 : 4+l])
	portOffset := 4 + l
	// Parse port (next 4 bytes after host)
	port = binary.BigEndian.Uint32(extra[portOffset : portOffset+4])
	return host, port, nil
}

// ForwardedTCPIP parses the ExtraData for a forwarded-tcpip channel.
// Currently not implemented; returns an error indicating unsupported channel type.
func ForwardedTCPIP(extra []byte) (host string, port uint32, err error) {
	// TODO: Implement parsing for forwarded-tcpip if needed
	return "", 0, fmt.Errorf("forwarded-tcpip not supported")
}

// ForwardData handles bidirectional data transfer between an SSH channel and the target TCP connection.
// It launches goroutines for each direction and ensures proper resource cleanup.
func ForwardData(ch ssh.Channel, targetConn net.Conn, addr string) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(targetConn, ch)
		if err != nil {
			log.Printf("forwardChannel: Error copying SSH->%s: %v", addr, err)
		}
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(ch, targetConn)
		if err != nil {
			log.Printf("forwardChannel: Error copying %s->SSH: %v", addr, err)
		}
	}()
	wg.Wait()
	// Close connections after both directions are done
	targetConn.Close()
	ch.Close()
}

// ServePortForward processes incoming SSH channels for port forwarding.
// Supports direct-tcpip requests and rejects unsupported or malformed channels.
// Each accepted channel is handled in a separate goroutine for concurrency.
func ServePortForward(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		var targetHost string
		var targetPort uint32
		var err error

		// Determine channel type and parse target info.
		switch newChannel.ChannelType() {
		case "direct-tcpip":
			targetHost, targetPort, err = DirectTCPIP(newChannel.ExtraData())
			if err != nil {
				// Malformed request, reject channel.
				log.Printf("HandleChannels: %v", err)
				newChannel.Reject(ssh.Prohibited, err.Error())
				continue
			}
		case "forwarded-tcpip":
			targetHost, targetPort, err = ForwardedTCPIP(newChannel.ExtraData())
			log.Printf("HandleChannels: forwarded-tcpip not supported")
			newChannel.Reject(ssh.Prohibited, "forwarded-tcpip not supported")
			continue
		default:
			// Unknown channel type, reject.
			log.Printf("HandleChannels: Unknown channel type: %s", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "only port forwarding allowed")
			continue
		}

		// Accept the channel for port forwarding.
		ch, reqs, err := newChannel.Accept()
		if err != nil {
			log.Printf("HandleChannels: Error accepting channel: %v", err)
			continue
		}
		// Discard any requests on the channel (not used for forwarding).
		go ssh.DiscardRequests(reqs)

		// Handle forwarding in a separate goroutine for concurrency.
		go func(targetHost string, targetPort uint32, ch ssh.Channel) {
			defer ch.Close()
			addr := fmt.Sprintf("%s:%d", targetHost, targetPort)
			// Connect to the requested target address.
			targetConn, err := net.Dial("tcp", addr)
			if err != nil {
				log.Printf("HandleChannels: Error connecting to target %s: %v", addr, err)
				return
			}
			// Relay data between SSH channel and target connection.
			ForwardData(ch, targetConn, addr)
		}(targetHost, targetPort, ch)
	}
}
