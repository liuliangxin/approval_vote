package main

import (
	"awesomeProject/priacy_compute"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		_, err := fmt.Fprintf(os.Stderr, "usage: %s <nodeID>\n", os.Args[0])
		if err != nil {
			return
		}
		os.Exit(2)
	}
	nodeID := os.Args[1]

	server := priacy_compute.NewServer(nodeID)
	server.Start()
}
