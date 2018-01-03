package main

import (
	"fmt"
	util "github.com/CSUNetSec/gobgpdump"
	mrt "github.com/CSUNetSec/protoparse/protocol/mrt"
	//rib "github.com/CSUNetSec/protoparse/protocol/rib"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Not enough arguments")
		return
	}

	fd, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error opening file: %s\n", os.Args[1])
		return
	}
	defer fd.Close()
	scanner := util.GetMRTScanner(fd)
	ribBuffer := make([]byte, 2<<32)
	scanner.Buffer(ribBuffer, cap(ribBuffer))

	scanner.Scan()
	buf := scanner.Bytes()

	mrth := mrt.NewMrtHdrBuf(buf)
	index, err := mrth.Parse()
	if err != nil {
		fmt.Printf("MRT parse error: %s\n", err)
		return
	}
	_, err = index.Parse()
	if err != nil {
		fmt.Printf("Index parse error: %s\n", err)
		return
	}

	fmt.Printf("Index:\n%s\n", index)

	ribEnts := 0
	for scanner.Scan() {
		ribEnts++
		mrth = mrt.NewMrtHdrBuf(scanner.Bytes())
		ribH, err := mrth.Parse()
		if err != nil {
			fmt.Printf("Message %d MRT ERROR: %s\n", ribEnts, err)
			break
		}
		_, err = ribH.Parse()
		if err != nil {
			fmt.Printf("Message %d RIB ERROR: %s\n", ribEnts, err)
			break
		}
	}

	fmt.Printf("RIB entries: %d\n", ribEnts)

	if scanner.Err() != nil {
		fmt.Printf("Scanner error: %s\n", scanner.Err())
	}
}
