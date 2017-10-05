// dump analyzers buckets and prints
// timeseries results produced by gobgpdump
// for visualization with other tools like gnuplot.

package main

import (
	"encoding/gob"
	"flag"
	"fmt"
	"github.com/CSUNetSec/gobgpdump"
	"io"
	"os"
	"sort"
	"time"
)

var (
	clusterDurationStart string
	clusterDurationEnd   string
	clusterDurationDelta int
)

const (
	timeFrmt = "200601021504"
)

func init() {
	const (
		defaultDelta = 1440
	)
	flag.IntVar(&clusterDurationDelta, "d", defaultDelta, "clustering duration delta in minutes (default 1440 minutes in a day)")
}

type PrefixDateValues struct {
	date          time.Time          //bucket
	prefAdvCounts map[string]int64   //this will be populated in the end
	prefWdrCounts map[string]int64   //this will be populated in the end
	peerAdv       map[string][]int32 //advertizement events where int32 is the peer ASN
}

func NewPrefixDateValues(date time.Time) PrefixDateValues {
	return PrefixDateValues{
		date,
		make(map[string]int64),
		make(map[string]int64),
		make(map[string][]int32),
	}
}

type PrefixHistoryMgr struct {
	buckets []PrefixDateValues
	delta   time.Duration
}

func NewPrefixHistoryMgr(a time.Duration) *PrefixHistoryMgr {
	return &PrefixHistoryMgr{
		[]PrefixDateValues{},
		a,
	}
}

func (p *PrefixHistoryMgr) Add(a gobgpdump.PrefixHistory) {
	for _, ev := range a.Events {
		bucket_ind := p.GetBucket(ev.Timestamp)
		//fmt.Printf("event with ts:%s will go to bucket with ts:%s from %d buckets\n", ev.Timestamp, p.buckets[bucket_ind].date, len(p.buckets))
		//increase prefix count
		buck := p.buckets[bucket_ind]
		if ev.Advertized {
			if count, ok := buck.prefAdvCounts[a.Pref]; ok {
				buck.prefAdvCounts[a.Pref] = count + 1
			} else {
				buck.prefAdvCounts[a.Pref] = 1
			}
		} else {
			if count, ok := buck.prefWdrCounts[a.Pref]; ok {
				buck.prefWdrCounts[a.Pref] = count + 1
			} else {
				buck.prefWdrCounts[a.Pref] = 1
			}
		}

	}
}

func (p *PrefixHistoryMgr) GetBucket(a time.Time) int {
	if len(p.buckets) == 0 { //create the first bucket
		fmt.Printf("creating first\n")
		p.buckets = append(p.buckets, NewPrefixDateValues(a))
		return 0
	}
	ind1 := sort.Search(len(p.buckets), func(i int) bool { return p.buckets[i].date.After(a) })
	ind2 := sort.Search(len(p.buckets), func(i int) bool { return p.buckets[i].date.Add(p.delta).After(a) })
	if ind1 == ind2 { // need to expand
		// add all the inbetween buckets to keep it sorted
		for cdate := p.buckets[len(p.buckets)-1].date.Add(p.delta); a.After(cdate); cdate = cdate.Add(p.delta) {
			p.buckets = append(p.buckets, NewPrefixDateValues(cdate))
		}
		return len(p.buckets) - 1
	}
	return ind1 - 1
}

func main() {
	flag.Parse()
	if len(flag.Args()) != 1 {
		fmt.Println("requires a gob file to decode")
		return
	}
	// this is ugly to get the type system to work. doesn't happen with const decls cause it gets promoted
	dur := time.Duration(clusterDurationDelta) * time.Minute
	gfd, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Printf("error opening file:%s\n", err)
		return
	}
	defer gfd.Close()
	dec := gob.NewDecoder(gfd)
	count := 0
	phmgr := NewPrefixHistoryMgr(dur)
	for {
		ph := gobgpdump.PrefixHistory{}
		decerr := dec.Decode(&ph)
		if decerr == io.EOF {
			break
		}
		if decerr != nil {
			fmt.Errorf("decoding error:%s. decoded:%d entries\n", decerr, count)
			return
		}
		phmgr.Add(ph)
		count++
	}
}
