//go:build ignore

package main

import (
	"encoding/hex"
	"fmt"
)

func main() {
	// Test the hbb_common variable-length encoding
	
	// Test case 1: 4-byte message (should use 1-byte header)
	length := 4
	var header []byte
	if length <= 0x3F {
		header = []byte{byte(length << 2)}
	} else if length <= 0x3FFF {
		header = []byte{byte((length << 2) | 0x1), byte((length << 2) >> 8)}
	}
	
	fmt.Printf("Length: %d\n", length)
	fmt.Printf("Header: %s\n", hex.EncodeToString(header))
	
	// Full message
	innerMsg := []byte{0x08, 0x00}
	outerMsg := []byte{0xA2, 0x02}
	outerMsg = append(outerMsg, innerMsg...)
	result := append(header, outerMsg...)
	
	fmt.Printf("Full message: %s\n", hex.EncodeToString(result))
	fmt.Printf("Message bytes: ")
	for i, b := range result {
		fmt.Printf("%02X ", b)
		if (i+1)%8 == 0 {
			fmt.Printf("\n               ")
		}
	}
	fmt.Println()
	
	// Decode to verify
	firstByte := result[0]
	headLen := ((firstByte & 0x3) + 1)
	decodedLen := firstByte >> 2
	fmt.Printf("\nDecoding:\n")
	fmt.Printf("  First byte: 0x%02X\n", firstByte)
	fmt.Printf("  Header length: %d bytes\n", headLen)
	fmt.Printf("  Decoded length: %d bytes\n", decodedLen)
}
