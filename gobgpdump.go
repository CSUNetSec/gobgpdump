package gobgpdump

import (
	"fmt"
	pp "github.com/CSUNetSec/protoparse"
	filter "github.com/CSUNetSec/protoparse/filter"
	mrt "github.com/CSUNetSec/protoparse/protocol/mrt"
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

	isRib := false
	var index pp.PbVal
	var mbs *mrt.MrtBufferStack

	for scanner.Scan() {
		entryCt++
		data := scanner.Bytes()
		sz += len(data)

		r, err := mrt.IsRib(data)
		if err != nil {
			dc.log.WriteString(fmt.Sprintf("[%d] Error: %s\n", entryCt, err))
			break
		}

		if r {
			if isRib {
				mbs, err = mrt.ParseRibHeaders(data, index)
			} else {
				mbs, err = mrt.ParseHeaders(data, true)
				index = mbs.Ribbuf
				isRib = true
				// The index message should not pass through any filtering or formatting
				continue
			}
		} else {
			mbs, err = mrt.ParseHeaders(data, false)
		}

		if err != nil {
			dc.log.WriteString(fmt.Sprintf("[%d] Error: %s\n", entryCt, err))
			break
		}

		if filter.FilterAll(dc.filters, mbs) {
			passedCt++
			output, err := dc.fmtr.format(mbs, NewMBSInfo(name, entryCt))
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
