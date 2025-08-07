package tunnel

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	sshserver "ssh-ify/ssh"

	"golang.org/x/crypto/ssh"
)

type ConnectionHandler struct {
	client       net.Conn
	target       net.Conn
	server       *Server
	clientClosed bool
	targetClosed bool
	log          string
	startTime    time.Time
	sshConfig    *ssh.ServerConfig
}

func (c *ConnectionHandler) close() {
	if !c.clientClosed && c.client != nil {
		c.client.Close()
		c.clientClosed = true
	}
	if !c.targetClosed && c.target != nil {
		c.target.Close()
		c.targetClosed = true
	}
}

func (c *ConnectionHandler) handle() {
	c.startTime = time.Now()
	c.server.printLog(c.log + " - Connection opened at " + c.startTime.Format(time.RFC3339))
	defer func() {
		c.close()
		c.server.removeConn(c)
		elapsed := time.Since(c.startTime)
		c.server.printLog(c.log + " - Connection closed. Duration: " + elapsed.String())
	}()

	c.server.printLog(c.log + " - Setting client read deadline: " + TIMEOUT.String())
	c.client.SetReadDeadline(time.Now().Add(TIMEOUT))
	reader := bufio.NewReaderSize(c.client, BUFLEN)
	var bufBuilder strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			c.server.printLog(c.log + " - error reading from client: " + err.Error())
			c.server.printLog(c.log + " - Closing connection due to read error.")
			return
		}
		bufBuilder.WriteString(line)
		if strings.HasSuffix(bufBuilder.String(), "\r\n\r\n") {
			break
		}
		if bufBuilder.Len() > BUFLEN {
			c.server.printLog(c.log + " - error: header too large")
			c.client.Write([]byte("HTTP/1.1 400 HeaderTooLarge\r\n\r\n"))
			return
		}
	}
	buf := bufBuilder.String()

	reqLines := strings.Split(buf, "\r\n")
	if len(reqLines) > 0 {
		c.server.printLog(c.log + " - Request: " + reqLines[0])
	}

	c.client.SetReadDeadline(time.Time{})

	// Detect WebSocket upgrade
	upgrade := findHeader(buf, "Upgrade")
	if upgrade == "websocket" {
		c.server.printLog(c.log + " - WebSocket upgrade: using in-process SSH server.")
		proxyEnd, sshEnd := net.Pipe()
		if c.sshConfig == nil {
			var err error
			c.sshConfig, err = sshserver.InitSSHServerConfig()
			if err != nil {
				c.server.printLog(c.log + " - Error initializing SSH config: " + err.Error())
				return
			}
		}
		go sshserver.HandleSSHConn(sshEnd, c.sshConfig)
		c.target = proxyEnd
		c.targetClosed = false
		c.client.Write([]byte(RESPONSE))
		c.server.printLog(c.log + " - Tunnel established.")
		c.doCONNECT()
		return
	} else if strings.HasPrefix(reqLines[0], "CONNECT ") {
		c.server.printLog(c.log + " - HTTP CONNECT: " + reqLines[0])
		parts := strings.Split(reqLines[0], " ")
		if len(parts) < 2 {
			c.server.printLog(c.log + " - Malformed CONNECT request line.")
			c.client.Write([]byte("HTTP/1.1 400 BadRequest\r\n\r\n"))
			return
		}
		targetAddr := parts[1]
		if err := c.connectTarget(targetAddr); err != nil {
			c.server.printLog(c.log + " - Error connecting to target: " + err.Error())
			c.client.Write([]byte("HTTP/1.1 502 BadGateway\r\n\r\n"))
			return
		}
		c.client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		c.server.printLog(c.log + " - Tunnel established.")
		c.doCONNECT()
		return
	} else if upgrade != "" {
		c.server.printLog(c.log + " - Upgrade header present: " + upgrade)
	}
}

func (c *ConnectionHandler) connectTarget(host string) error {
	var port string
	if i := strings.Index(host, ":"); i != -1 {
		port = host[i+1:]
		host = host[:i]
	} else {
		port = fmt.Sprintf("%d", listeningPort)
	}
	addr := net.JoinHostPort(host, port)
	c.server.printLog(c.log + " - Connecting to target: " + addr)
	target, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		c.server.printLog(c.log + " - Error connecting to target: " + err.Error())
		return err
	}
	c.server.printLog(c.log + " - Connected to target: " + addr)
	c.target = target
	c.targetClosed = false
	return nil
}

func (c *ConnectionHandler) doCONNECT() {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		_, err := io.Copy(c.target, c.client)
		if err != nil {
			c.server.printLog(c.log + " - Error copying client to target: " + err.Error())
		}
		wg.Done()
	}()
	go func() {
		_, err := io.Copy(c.client, c.target)
		if err != nil {
			c.server.printLog(c.log + " - Error copying target to client: " + err.Error())
		}
		wg.Done()
	}()
	wg.Wait()
	c.close()
}
