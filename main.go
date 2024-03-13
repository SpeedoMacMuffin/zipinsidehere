package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
)

func CE(x error) {
	if x != nil {
		log.Fatal(x)
	}
}

func VerifyZipSig(k string) {
	sig := `\x4b\x03\x04`
	fmt.Printf("[%s]---[%s] Is being checked for a ZIP signature\n", "Debug", sig)
	f, x := os.Open(k)
	CE(x)
	defer f.Close()
	buffer := bufio.NewReader(f)
	stat, _ := f.Stat()

	for l := int64(0); 1 < stat.Size(); l++ {
		b, x := buffer.ReadByte()
		CE(x)
		if b == '\x50' {
			BS := make([]byte, 3)
			BS, x = buffer.Peek(3)
			CE(x)
			if bytes.Equal(BS, []byte{0x4b, 0x03, 0x04}) {
				fmt.Println("File [", k, "] is a ZIP file")
			}
		}

	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ", os.Args[0], " <file>")
	} else {
		for _, k := range os.Args[1:] {
			VerifyZipSig(k)
		}
	}
}
