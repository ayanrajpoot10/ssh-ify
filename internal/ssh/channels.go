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
// ensuring efficient, concurrent data transfer. It waits for both directions to complete
// and then closes both connections to free resources.
//
// Parameters:
//   - ch: The SSH channel to relay data from/to.
//   - targetConn: The TCP connection to the target host.
//   - addr: The address of the target host (for logging).
func ForwardData(ch ssh.Channel, targetConn net.Conn, addr string) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(targetConn, ch)
		if err != nil && err != io.EOF {
			log.Printf("forwardChannel: Error copying SSH->%s: %v", addr, err)
		}
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(ch, targetConn)
		if err != nil && err != io.EOF {
			log.Printf("forwardChannel: Error copying %s->SSH: %v", addr, err)
		}
	}()
	wg.Wait()
	// Close connections after both directions are done
	targetConn.Close()
	ch.Close()
}

// ServePortForward processes incoming SSH channels for port forwarding (direct-tcpip).
//
// It accepts only "direct-tcpip" channel types, parses the target address and port,
// and establishes a TCP connection to the requested destination. Each accepted channel
// is handled in a separate goroutine for concurrency. Unsupported or malformed channels
// are rejected with appropriate error messages.
//
// Parameters:
//   - chans: Channel of incoming SSH NewChannel requests.
func ServePortForward(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		var targetHost string
		var targetPort uint32
		var err error

		// Determine channel type and parse target info.
		if newChannel.ChannelType() == "direct-tcpip" {
			extra := newChannel.ExtraData()
			// Inline DirectTCPIP logic
			if len(extra) < 4 {
				err = fmt.Errorf("invalid direct-tcpip request: insufficient data for host length")
				log.Printf("HandleChannels: %v", err)
				newChannel.Reject(ssh.Prohibited, err.Error())
				continue
			}
			l := int(binary.BigEndian.Uint32(extra[:4]))
			if len(extra) < 4+l+4 {
				err = fmt.Errorf("invalid direct-tcpip request: insufficient data for host and port")
				log.Printf("HandleChannels: %v", err)
				newChannel.Reject(ssh.Prohibited, err.Error())
				continue
			}
			targetHost = string(extra[4 : 4+l])
			portOffset := 4 + l
			targetPort = binary.BigEndian.Uint32(extra[portOffset : portOffset+4])
		} else {
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
			addr := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))
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
