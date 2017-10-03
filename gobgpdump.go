package gobgpdump

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Simple worker function, launched in a new goroutine.
// Reads from stringsource and launches dumpfile
func DumpWorker(dc *DumpConfig, wg *sync.WaitGroup) {
	defer wg.Done()

	// dc.source must be thread safe
	name, serr := dc.source.Next()

	for serr == nil {
		dumpFile(name, dc)
		name, serr = dc.source.Next()
	}
	// On an unsuccessful dump, other threads should also stop
	// TODO: add context to DumpConfig
	if serr != EOP {
		fmt.Printf("Dump unsucessful: %s\n", serr)
	}
}

// Main compenent of the program. Opens a file, parses messages,
// filters them, formats them, and writes them to the dump file
func dumpFile(name string, dc *DumpConfig) {
	// At this point, we only want to read bzipped files
	if !isBz2(name) && false {
		dc.log.WriteString(fmt.Sprintf("Couldn't open: %s: not a bz2 file\n", name))
		return
	}

	mrtFile, err := os.Open(name)
	if err != nil {
		dc.log.WriteString("Error opening file: " + name + "\n")
		return
	}
	defer mrtFile.Close()

	scanner := getScanner(mrtFile)
	entryCt := 0
	passedCt := 0
	sz := 0
	start := time.Now()

	for scanner.Scan() {
		entryCt++
		data := scanner.Bytes()
		sz += len(data)
		mbs, err := parseHeaders(data)

		if err != nil {
			dc.log.WriteString(fmt.Sprintf("[%d] Error: %s\n", entryCt, err))
			break
		}

		if filterAll(dc.filters, mbs) {
			passedCt++
			output, err := dc.fmtr.format(mbs, NewMBSInfo(data, name, entryCt))
			if err != nil {
				dc.log.WriteString(fmt.Sprintf("%s\n", err))
			} else {
				dc.dump.WriteString(output)
			}
		}

	}

	if err = scanner.Err(); err != nil {
		dc.log.WriteString("Scanner returned an error.\n")
		return
	}

	dt := time.Since(start)
	statstr := fmt.Sprintf("Scanned %s: %d entries, %d passed filters, total size: %d bytes in %v\n", name, entryCt, passedCt, sz, dt)
	dc.stat.WriteString(statstr)

}