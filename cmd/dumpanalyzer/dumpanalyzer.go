// dump analyzers buckets and prints
// timeseries results produced by gobgpdump
// for visualization with other tools like gnuplot.

package main

import (
	"encoding/gob"
	"flag"
	"fmt"
	"github.com/CSUNetSec/gobgpdump"
	"os"
)

func init() {
	flag.Parse()
}

func main() {
	if len(flag.Args()) != 1 {
		fmt.Println("requires a gob file to decode")
		return
	}
	gfd, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Errorf("error opening file:%s\n", err)
		return
	}
	defer gfd.Close()
	dec := gob.NewDecoder(gfd)
	ph := gobgpdump.PrefixHistory{}
	count := 0
	for {
		decerr := dec.Decode(&ph)
		if decerr != nil {
			fmt.Errorf("decoding error:%s. decoded:%d entries\n", decerr, count)
			return
		}
		count++
		fmt.Printf("[%d]:%+v\n", count, ph)
	}
}
