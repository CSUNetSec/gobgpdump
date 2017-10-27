// dump analyzers buckets and prints
// timeseries results produced by gobgpdump
// for visualization with other tools like gnuplot.

package main

import (
	"encoding/gob"
	"flag"
	"fmt"
	"github.com/CSUNetSec/gobgpdump"
	rad "github.com/armon/go-radix"
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

/*
type asCount struct {
	as  uint32
	cnt uint64
}

type asCountSlice []asCount

func NewAsCount(as uint32) asCount {
	return asCount{
		as:  as,
		cnt: 1,
	}
}

func (a *asCountSlice) Add(as uint32) {
	for _, asc := range *a {
		if asc.as == as {
			asc.cnt = asc.cnt + 1
			return
		}
	}
	*a = append(*a, NewAsCount(as))
}
*/

type PrefixDateValues struct {
	date time.Time //bucket
	//prefAdvCounts map[string]uint64   //this will be populated in the end
	//prefWdrCounts map[string]uint64   //this will be populated in the end
	//peerAdv       map[string][]uint32 //advertizement events where int32 is the peer ASN
}

func NewPrefixDateValues(date time.Time) PrefixDateValues {
	return PrefixDateValues{
		date,
		//	make(map[string]uint64),
		//	make(map[string]uint64),
		//	make(map[string][]uint32),
	}
}

type asCount struct {
	as  uint32
	cnt uint64
}

type prefEvSums struct {
	prefix   string
	events   uint64
	peerAses []asCount
}

type event struct {
	prefix    string
	withdrawn bool
	time      time.Time
	asp       []uint32
	bucket    int
}

type evlist []event

func (e evlist) PeerAses() (ret []uint32) {
	ret = make([]uint32, 0)
	for _, ev := range e {
		if len(ev.asp) > 2 { //parent AS and us
			pas := ev.asp[len(ev.asp)-2]
			if !uint32InSlice(pas, ret) {
				ret = append(ret, pas)
			}
		}
	}
	return
}

func (e evlist) Prefixes() (ret []string) {
	uniqpref := make(map[string]bool)
	ret = make([]string, 0)
	for _, ev := range e {
		if _, ok := uniqpref[ev.prefix]; !ok {
			ret = append(ret, ev.prefix)
			uniqpref[ev.prefix] = true
		}
	}
	return
}

func (e evlist) FilterBucket(i int) (ret evlist) {
	ret = make([]event, 0)
	for _, ev := range e {
		if ev.bucket == i {
			ret = append(ret, ev)
		}
	}
	return
}

func (e evlist) NumEventsFromPeer(a uint32) int {
	count := 0
	for _, ev := range e {
		if len(ev.asp) > 2 { //parent AS and us
			pas := ev.asp[len(ev.asp)-2]
			if pas == a {
				count++
			}
		}
	}
	return count
}

func (e evlist) NumEventsFromPrefix(a string) int {
	count := 0
	for _, ev := range e {
		if ev.prefix == a {
			count++
		}
	}
	return count
}
func (e evlist) NumWithdrawn() int {
	count := 0
	for _, ev := range e {
		if ev.withdrawn {
			count++
		}
	}
	return count
}

type PrefixHistoryMgr struct {
	buckets    []PrefixDateValues
	delta      time.Duration
	prefSeen   []prefEvSums
	events     evlist
	PrefEvents map[string]*gobgpdump.PrefixHistory
}

func NewPrefixHistoryMgr(a time.Duration) *PrefixHistoryMgr {
	return &PrefixHistoryMgr{
		[]PrefixDateValues{},
		a,
		make([]prefEvSums, 0),
		make([]event, 0),
		make(map[string]*gobgpdump.PrefixHistory),
	}
}

/*
func asToPrefix(a map[string]asCountSlice) (ret map[uint32][]string) {
	ret = make(map[uint32][]string)
outer:
	for k1, v1 := range a {
		//fmt.Printf("i found %s %v\n", k1, v1)
		for _, asc := range v1 {
			if plist, ok := ret[asc.as]; ok {
				for _, p := range plist {
					if p == k1 {
						continue outer
					}
				}
				ret[asc.as] = append(plist, k1)
			} else {
				ret[asc.as] = []string{k1}
			}
		}
	}
	return
}
*/

func uint32InSlice(a uint32, slice []uint32) bool {
	for _, ui := range slice {
		if a == ui {
			return true
		}
	}
	return false
}

//returns the index or -1 on not found
func asIndexInAsCountSlice(a uint32, slice []asCount) int {
	for i, ui := range slice {
		if a == ui.as {
			return i
		}
	}
	return -1
}

func (p *PrefixHistoryMgr) Add(a gobgpdump.PrefixHistory) {
	//update the total events seen for this prefix.
	/*var pes prefEvSums
	pes.events = pes.events + uint64(len(a.Events))
	pes.prefix = a.Pref
	for _, ev := range a.Events {
		bucket_ind := p.GetBucket(ev.Timestamp)
		//fmt.Printf("event with ts:%s will go to bucket with ts:%s from %d buckets\n", ev.Timestamp, p.buckets[bucket_ind].date, len(p.buckets))
		///increase prefix count
		buck := p.buckets[bucket_ind]
		if ev.Advertized {
			if count, ok := buck.prefAdvCounts[a.Pref]; ok {
				buck.prefAdvCounts[a.Pref] = count + 1
			} else {
				buck.prefAdvCounts[a.Pref] = 1
			}
			//get peer from AS path
			if len(ev.ASPath) > 1 { //has at least a peer
				pas := ev.ASPath[len(ev.ASPath)-2]
				if peerAses, ok := buck.peerAdv[a.Pref]; ok {
					if !uint32InSlice(pas, peerAses) {
						peerAses = append(peerAses, pas)
						buck.peerAdv[a.Pref] = peerAses
					}
					//peerAses.Add(pas)
				} else {
					buck.peerAdv[a.Pref] = []uint32{pas}
				}
				if ind := asIndexInAsCountSlice(pas, pes.peerAses); ind != -1 {
					pes.peerAses[ind].cnt = pes.peerAses[ind].cnt + 1
				} else {
					pes.peerAses = append(pes.peerAses, asCount{pas, 1})
				}
			}
		} else {
			if count, ok := buck.prefWdrCounts[a.Pref]; ok {
				buck.prefWdrCounts[a.Pref] = count + 1
			} else {
				buck.prefWdrCounts[a.Pref] = 1
			}
		}
	}
	//update it in the end
	p.prefSeen = append(p.prefSeen, pes)
	*/
	for _, ev := range a.Events {
		bucket_ind := p.GetBucket(ev.Timestamp)
		nev := event{
			prefix:    a.Pref,
			withdrawn: true,
			time:      ev.Timestamp,
			asp:       []uint32{},
			bucket:    bucket_ind,
		}
		if ev.Advertized {
			nev.withdrawn = false
			nev.asp = make([]uint32, len(ev.ASPath))
			copy(nev.asp, ev.ASPath)

		}
		p.events = append(p.events, nev)
	}
}

type asPercentage struct {
	as uint32
	p  float64
}

func (p *PrefixHistoryMgr) Summarize() {
	//for _, b := range p.buckets {
	//countSeen(p.prefSeen, b.prefAdvCounts)
	/*as2p := asToPrefix(b.peerAdv)
	dayAses := []asPercentage{}
	for k, v := range as2p {
		dayAses = append(dayAses, asPercentage{k, float64(len(v)) / float64(len(p.prefSeen))})
	}
	sort.Slice(dayAses, func(i, j int) bool { return dayAses[i].p > dayAses[j].p })
	fmt.Printf("bucket:%v\tNPref:%d\n", b.date, len(p.prefSeen))
	topk := 0
	for _, das := range dayAses {
		fmt.Printf("\tPASN:%d %.3f\n", das.as, das.p)
		if topk > 5 {
			break
		}
		topk++
	}*/
	//}
	//p.TopKPrefixes(10)
	p.PrintSums()
	fmt.Printf("#peerases bucketid peerAsid no.updates ASname")
	distinctAses := make(map[uint32]int)
	resolveAs := func(as uint32, dict map[uint32]int) int {
		if resolved, ok := dict[as]; ok {
			return resolved
		} else {
			dict[as] = len(dict) + 1
			return len(dict)
		}
	}
	//distinctPrefixes := make(map[string]int)
	/*resolvePrefix := func(prefix string, dict map[string]int) int {
		if resolved, ok := dict[prefix]; ok {
			return resolved
		} else {
			dict[prefix] = len(dict) + 1
			return len(dict)
		}

	}*/
	/*
		resolveAses := func(a []uint32, dict map[uint32]int) []int {
			ret := make([]int, 0)
			for _, as := range a {
				asi := resolveAs(as, dict)
				ret = append(ret, asi)
			}
			return ret
		}
	*/

	//fmt.Printf("total events:%d\n", len(p.events))
	//fmt.Printf("all peers:%v\n", resolveAses(p.events.PeerAses(), distinctAses))
	allpeers := p.events.PeerAses()
	allprefs := p.events.Prefixes()
	for bi, _ := range p.buckets {
		subevents := p.events.FilterBucket(bi)
		for _, pas := range allpeers {
			fmt.Printf("%d %d %d %s\n", bi, resolveAs(pas, distinctAses), subevents.NumEventsFromPeer(pas), fmt.Sprintf("as%d", pas))
		}
		fmt.Println("")
	}
	fmt.Printf("#prefixcounts bucketid prefixid no.updates prefixname")
	for bi, _ := range p.buckets {
		subevents := p.events.FilterBucket(bi)
		for pi, pref := range allprefs {
			fmt.Printf("%d %d %d %s\n", bi, pi, subevents.NumEventsFromPrefix(pref), fmt.Sprintf("%s", pref))
		}
		fmt.Println("")
	}
}

/*
func (p *PrefixHistoryMgr) TopKPrefixes(k int) {
	//totPrefCount := make(map[string]countPercentage)
	//count all prefixes
	for _, e := range p.events {
		if foundPrefix, ok := totPrefCount[e.prefix]; ok {
			foundPrefix.count++
			totPrefCount[e.prefix] = foundPrefix
		} else {
			//totPrefCount[e.prefix] = countId{1, float32(0)}
		}
	}
	//record the percentage
	totNumPref := len(totPrefCount)
	for k, v := range totPrefCount {
		v.percentage = float32(v.count) / float32(totNumPref) * float32(100)
		totPrefCount[k] = v
	}
	//sort b
	evacc := uint64(0)
	for _, pref := range p.prefSeen {
		evacc = evacc + pref.events
	}
	fmt.Printf("num prefixes:%d\t total events:%d\n", len(p.prefSeen), evacc)
	sort.Slice(p.prefSeen, func(i, j int) bool { return p.prefSeen[i].events > p.prefSeen[j].events })
	fmt.Printf("top %d prefixes by event count:\n", k)
	for i := 0; i < k; i++ {
		fmt.Printf("\t%s %d %.4f%%\n", p.prefSeen[i].prefix, p.prefSeen[i].events, float32(p.prefSeen[i].events)/float32(evacc)*float32(100))
	}
	sort.Slice(p.prefSeen, func(i, j int) bool { return len(p.prefSeen[i].peerAses) > len(p.prefSeen[j].peerAses) })
	fmt.Printf("top %d prefixes by number of peers advertized\n", k)
	for i := 0; i < k; i++ {
		fmt.Printf("\t%s %d [%v]\n", p.prefSeen[i].prefix, len(p.prefSeen[i].peerAses), p.prefSeen[i].peerAses)
	}
	sort.Slice(p.prefSeen, func(i, j int) bool {
		cnt1, cnt2 := uint64(0), uint64(0)
		for _, pa := range p.prefSeen[i].peerAses {
			cnt1 = cnt1 + pa.cnt
		}
		for _, pa := range p.prefSeen[j].peerAses {
			cnt2 = cnt2 + pa.cnt
		}
		return cnt1 > cnt2
	})
	fmt.Printf("again top %d prefixes by event count:\n", k)
	for i := 0; i < k; i++ {
		fmt.Printf("\t%s %d %v\n", p.prefSeen[i].prefix, p.prefSeen[i].events, p.prefSeen[i].peerAses)
	}

}
*/

func (p *PrefixHistoryMgr) PrintSums() {
	fmt.Printf("#sums date no.updates no.withdraws")
	for bi, b := range p.buckets {
		subevents := p.events.FilterBucket(bi)
		nwdr := subevents.NumWithdrawn()
		fmt.Printf("%s\t%d\t%d\n", b.date.Format(timeFrmt), len(subevents)-nwdr, nwdr)
	}
}

func (p *PrefixHistoryMgr) GetBucket(a time.Time) int {
	if len(p.buckets) == 0 { //create the first bucket
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
	phmgr := NewPrefixHistoryMgr(dur)
	decerr := dec.Decode(&phmgr.PrefEvents)
	if decerr != nil {
		fmt.Errorf("decoding error:%s. decoded:%d entries\n", decerr)
		return
	}
	fmt.Printf("got %d prefixes\n", len(phmgr.PrefEvents))
	fulltree := rad.New()
	for k, v := range phmgr.PrefEvents {
		fmt.Printf("pref:%s events:%+v\n", v.Pref, v.Events)
		fulltree.Insert(k, v)
	}
	getMinMaxdate := func(a *rad.Tree) (time.Time, time.Time) {
		var (
			min, max time.Time
			first    bool
		)
		first = true
		kvdate := func(s string, v interface{}) bool {
			evlist := v.(*gobgpdump.PrefixHistory).Events
			if len(evlist) > 1 {
				if first {
					min, max = evlist[0].Timestamp, evlist[len(evlist)-1].Timestamp
					first = false
				} else {
					if evlist[0].Timestamp.Before(min) {
						min = evlist[0].Timestamp
					}
					if evlist[len(evlist)-1].Timestamp.After(max) {
						max = evlist[len(evlist)-1].Timestamp
					}
				}
			}
			return false
		}
		fulltree.Walk(kvdate)
		return min, max

	}
	dateA, dateB := getMinMaxdate(fulltree)
	fmt.Printf("min date:%s max:%s\n", dateA, dateB)
	/*
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
		phmgr.Summarize()
	*/
}
