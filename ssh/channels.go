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

// parseDirectTCPIP parses the ExtraData for a direct-tcpip channel.
func parseDirectTCPIP(extra []byte) (host string, port uint32, err error) {
	if len(extra) < 4 {
		return "", 0, fmt.Errorf("invalid direct-tcpip request: insufficient data for host length")
	}
	l := int(binary.BigEndian.Uint32(extra[:4]))
	if len(extra) < 4+l+4 {
		return "", 0, fmt.Errorf("invalid direct-tcpip request: insufficient data for host and port")
	}
	host = string(extra[4 : 4+l])
	portOffset := 4 + l
	port = binary.BigEndian.Uint32(extra[portOffset : portOffset+4])
	return host, port, nil
}

// parseForwardedTCPIP parses the ExtraData for a forwarded-tcpip channel (stub).
func parseForwardedTCPIP(extra []byte) (host string, port uint32, err error) {
	// TODO: Implement parsing for forwarded-tcpip if needed
	return "", 0, fmt.Errorf("forwarded-tcpip not supported")
}

// forwardChannel handles bidirectional copy between SSH channel and target connection.
func forwardChannel(ch ssh.Channel, targetConn net.Conn, addr string) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(targetConn, ch)
		if err != nil {
			log.Printf("forwardChannel: Error copying SSH->%s: %v", addr, err)
		}
		targetConn.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(ch, targetConn)
		if err != nil {
			log.Printf("forwardChannel: Error copying %s->SSH: %v", addr, err)
		}
		ch.Close()
	}()
	wg.Wait()
}

// HandleChannels processes incoming SSH channels for port forwarding.
func HandleChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		var targetHost string
		var targetPort uint32
		var err error

		switch newChannel.ChannelType() {
		case "direct-tcpip":
			targetHost, targetPort, err = parseDirectTCPIP(newChannel.ExtraData())
			if err != nil {
				log.Printf("HandleChannels: %v", err)
				newChannel.Reject(ssh.Prohibited, err.Error())
				continue
			}
		case "forwarded-tcpip":
			targetHost, targetPort, err = parseForwardedTCPIP(newChannel.ExtraData())
			log.Printf("HandleChannels: forwarded-tcpip not supported")
			newChannel.Reject(ssh.Prohibited, "forwarded-tcpip not supported")
			continue
		default:
			log.Printf("HandleChannels: Unknown channel type: %s", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "only port forwarding allowed")
			continue
		}

		ch, reqs, err := newChannel.Accept()
		if err != nil {
			log.Printf("HandleChannels: Error accepting channel: %v", err)
			continue
		}
		go ssh.DiscardRequests(reqs)

		go func(targetHost string, targetPort uint32, ch ssh.Channel) {
			defer ch.Close()
			addr := fmt.Sprintf("%s:%d", targetHost, targetPort)
			targetConn, err := net.Dial("tcp", addr)
			if err != nil {
				log.Printf("HandleChannels: Error connecting to target %s: %v", addr, err)
				return
			}
			forwardChannel(ch, targetConn, addr)
		}(targetHost, targetPort, ch)
	}
}
