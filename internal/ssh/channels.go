package ssh

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

// ForwardData relays data bidirectionally between an SSH channel and a target TCP connection.
//
// This function launches goroutines for each direction (SSH→target and target→SSH),
// ensuring efficient, concurrent data transfer with reusable buffers. It waits for both
// directions to complete and then closes both connections to free resources.
//
// Parameters:
//   - ch: The SSH channel to relay data from/to.
//   - targetConn: The TCP connection to the target host.
//   - addr: The address of the target host (for logging).
//
// Example:
//
//	ForwardData(sshChannel, tcpConn, "example.com:80")
func ForwardData(ch ssh.Channel, targetConn net.Conn, addr string) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := CopyWithSSHBuffer(targetConn, ch)
		if err != nil && err != io.EOF {
			log.Printf("forwardChannel: Error copying SSH->%s: %v", addr, err)
		}
	}()
	go func() {
		defer wg.Done()
		_, err := CopyWithSSHBuffer(ch, targetConn)
		if err != nil && err != io.EOF {
			log.Printf("forwardChannel: Error copying %s->SSH: %v", addr, err)
		}
	}()
	wg.Wait()
	// Close connections after both directions are done
	targetConn.Close()
	ch.Close()
}

// HandleSSHChannels processes incoming SSH channels for port forwarding (direct-tcpip).
//
// It accepts only "direct-tcpip" channel types, parses the target address and port,
// and establishes a TCP connection to the requested destination. Each accepted channel
// is handled in a separate goroutine for concurrency. Unsupported or malformed channels
// are rejected with appropriate error messages.
//
// Parameters:
//   - chans: Channel of incoming SSH NewChannel requests.
//
// Example:
//
//	HandleSSHChannels(newChannelChan)
func HandleSSHChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		// Step 1: Validate channel type
		if !isDirectTCPIPChannel(newChannel) {
			log.Printf("HandleChannels: Unknown channel type: %s", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "only port forwarding allowed")
			continue
		}

		// Step 2: Parse direct-tcpip extra data
		targetHost, targetPort, err := parseDirectTCPIPExtra(newChannel.ExtraData())
		if err != nil {
			log.Printf("HandleChannels: %v", err)
			newChannel.Reject(ssh.Prohibited, err.Error())
			continue
		}

		// Step 3: Accept the channel
		ch, reqs, err := newChannel.Accept()
		if err != nil {
			log.Printf("HandleChannels: Error accepting channel: %v", err)
			continue
		}
		go ssh.DiscardRequests(reqs)

		// Step 4: Handle forwarding in a goroutine
		go handlePortForwarding(targetHost, targetPort, ch)
	}
}

// isDirectTCPIPChannel reports whether the provided SSH channel is of type "direct-tcpip".
//
// Parameters:
//   - newChannel: The SSH NewChannel to inspect.
//
// Returns:
//   - bool: true if the channel type is "direct-tcpip", false otherwise.
func isDirectTCPIPChannel(newChannel ssh.NewChannel) bool {
	return newChannel.ChannelType() == "direct-tcpip"
}

// parseDirectTCPIPExtra extracts the target host and port from the extra data of a "direct-tcpip" SSH channel request.
//
// Parameters:
//   - extra: The extra data payload from the SSH NewChannel request.
//
// Returns:
//   - string: The target host requested for forwarding.
//   - uint32: The target port requested for forwarding.
//   - error:  An error if the extra data is malformed or incomplete.
func parseDirectTCPIPExtra(extra []byte) (string, uint32, error) {
	if len(extra) < 4 {
		return "", 0, fmt.Errorf("invalid direct-tcpip request: insufficient data for host length")
	}
	l := int(binary.BigEndian.Uint32(extra[:4]))
	if len(extra) < 4+l+4 {
		return "", 0, fmt.Errorf("invalid direct-tcpip request: insufficient data for host and port")
	}
	targetHost := string(extra[4 : 4+l])
	portOffset := 4 + l
	targetPort := binary.BigEndian.Uint32(extra[portOffset : portOffset+4])
	return targetHost, targetPort, nil
}

// handlePortForwarding establishes a TCP connection to the specified target and relays data between the SSH channel and the target connection.
//
// Parameters:
//   - targetHost: The destination host to connect to.
//   - targetPort: The destination port to connect to.
//   - ch:         The SSH channel to relay data from/to.
//
// This function ensures proper cleanup of the SSH channel and logs any connection errors.
func handlePortForwarding(targetHost string, targetPort uint32, ch ssh.Channel) {
	defer ch.Close()
	addr := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))
	targetConn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("HandleChannels: Error connecting to target %s: %v", addr, err)
		return
	}
	ForwardData(ch, targetConn, addr)
}
