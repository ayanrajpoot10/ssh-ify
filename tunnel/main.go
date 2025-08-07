package tunnel

// RunProxy starts the proxy server.
func RunProxy() {
	s := &Server{
		host:    listeningAddr,
		port:    listeningPort,
		running: true,
		conns:   make(map[*ConnectionHandler]struct{}),
	}
	s.serve()
}
