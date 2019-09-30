// This is the main logic of gobgpdump. Retrieves dump parameters
// from config, launches goroutines to parse and dump files.

package main

import (
	"flag"
	"fmt"
	. "github.com/CSUNetSec/gobgpdump"
	"sync"
	"time"
)

var configFile ConfigFile

func init() {
	flag.StringVar(&configFile.Lo, "lo", "stdout", "file to place log output")
	flag.StringVar(&configFile.So, "so", "stdout", "file to place stat output")
	flag.StringVar(&configFile.Do, "o", "stdout", "file to place dump output")
	flag.StringVar(&configFile.Fmtr, "fmtr", "text", "format to output results in.\n"+
		"Available Formats:\n"+
		"pup, pts, day, json, text, ml, prefixlock, id")
	flag.StringVar(&configFile.Srcas, "srcas", "", "list of comma separated AS's (e.g. 1,2,3,4) to filter message source by")
	flag.StringVar(&configFile.Destas, "destas", "", "list of comma separated AS's (e.g. 1,2,3,4) to filter message destination by")
	flag.StringVar(&configFile.PrefList, "prefixes", "", "list of commma separated prefixes. Messages containing any in the list will pass filters")
	flag.StringVar(&configFile.PrefLoc, "prefloc", "", "where to filter for prefixes; one of [any, advertized, withdrawn]")
	flag.BoolVar(&configFile.Conf, "conf", false, "draw configuration from a file")
	flag.BoolVar(&configFile.Debug, "debug", false, "set the debug flag")
	flag.IntVar(&configFile.Wc, "wc", 1, "number of worker threads to use (max 16)")
}

func main() {
	flag.Parse()
	// Get the config for this dump
	dc, err := GetDumpConfig(configFile)
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
