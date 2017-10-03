// This is the main logic of gobgpdump. Retrieves dump parameters
// from config, launches goroutines to parse and dump files.

package main

import (
	"fmt"
	. "github.com/CSUNetSec/gobgpdump"
	"sync"
	"time"
)

func main() {
	// Get the config for this dump
	dc, err := GetDumpConfig()
	if err != nil {
		fmt.Println(err)
		return
	}

	dumpStart := time.Now()
	wg := &sync.WaitGroup{}
	// Launch worker threads
	for w := 0; w < dc.GetWorkers(); w++ {
		wg.Add(1)
		go DumpWorker(dc, wg)
	}

	wg.Wait()
	dc.SummarizeAndClose(dumpStart)
}
