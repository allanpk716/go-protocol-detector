//go:build ignore

package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	// Message with hbb_common encoding
	message := []byte{0x10, 0xA2, 0x02, 0x08, 0x00}
	
	fmt.Printf("Connecting to 116.62.8.4:21115...\n")
	
	conn, err := net.DialTimeout("tcp", "116.62.8.4:21115", 5*time.Second)
	if err != nil {
		fmt.Printf("Connection failed: %v\n", err)
		return
	}
	defer conn.Close()
	
	fmt.Printf("Connected!\n")
	fmt.Printf("Sending message: %02X\n", message)
	
	// Send the message
	_, err = conn.Write(message)
	if err != nil {
		fmt.Printf("Send failed: %v\n", err)
		return
	}
	
	fmt.Printf("Message sent, waiting for response...\n")
	
	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	
	// Try to read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("Read error: %v\n", err)
		if n == 0 {
			fmt.Printf("No data received (connection closed by server)\n")
		}
		return
	}
	
	fmt.Printf("Received %d bytes:\n", n)
	for i := 0; i < n; i++ {
		fmt.Printf("%02X ", buf[i])
		if (i+1)%16 == 0 {
			fmt.Println()
		}
	}
	fmt.Println()
}
