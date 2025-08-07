package main

import (
	"os"
	"os/signal"
	"syscall"

	tunnel "ssh-ify/tunnel"
)

func main() {

	go tunnel.RunProxy()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	println("Shutting down...")
}
