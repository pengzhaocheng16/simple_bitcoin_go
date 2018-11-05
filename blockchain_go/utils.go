package core

import (
	"bytes"
	"encoding/binary"
	"log"
	"fmt"
)

// IntToHex converts an int64 to a byte array
func IntToHex(num int64) []byte {
	buff := new(bytes.Buffer)
	err := binary.Write(buff, binary.BigEndian, num)
	if err != nil {
		log.Panic(err)
	}

	return buff.Bytes()
}

func HexToInt(num []byte) int64 {
	var varint = binary.BigEndian.Uint64(num)
	fmt.Println("HexToInt:",varint)
	return int64(varint)
}
// ReverseBytes reverses a byte array
func ReverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}
