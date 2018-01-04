// Defines all formatters available to gobgpdump, and convenience
// functions for formatters.
// Current formatters:
// -TextFormatter
// -JSONFormatter
// -IdentityFormatter - Rename to MRTFormatter?

// These both need new configuration names
// -UniquePrefixList
// -UniquePrefixSeries

package gobgpdump

import (
	//"encoding/gob"
	"encoding/json"
	"fmt"
	mrt "github.com/CSUNetSec/protoparse/protocol/mrt"
	util "github.com/CSUNetSec/protoparse/util"
	//gr "github.com/armon/go-radix"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A Formatter takes the bufferstack and the underlying buffer
// and returns a representation of the data to be written to the
// dump file.
// The underlying buffer is necessary for the ID formatter
type Formatter interface {
	format(*mrt.MrtBufferStack, MBSInfo) (string, error)
	summarize()
	setBucketer(Bucketer)
}

// This contains miscellaneous info for the MBS structure
type MBSInfo struct {
	file   string
	msgNum int
}

func NewMBSInfo(file string, msg int) MBSInfo {
	return MBSInfo{file, msg}
}

// A simple text representation for the dump.
// The only formatter that needs the msgnum
type TextFormatter struct {
	bm     Bucketer
	msgNum int
}

func NewTextFormatter() *TextFormatter {
	return &TextFormatter{
		msgNum: 0,
	}
}

func (t *TextFormatter) setBucketer(a Bucketer) {
	t.bm = a
}

func (t *TextFormatter) format(mbs *mrt.MrtBufferStack, _ MBSInfo) (string, error) {
	b := t.bm.GetBucket(getTimestamp(mbs))
	ret := fmt.Sprintf("[%d][Bucket:%d] MRT Header: %s\n", t.msgNum, b, mbs.MrthBuf)
	ret += fmt.Sprintf("BGP4MP Header: %s\n", mbs.Bgp4mpbuf)
	ret += fmt.Sprintf("BGP Header: %s\n", mbs.Bgphbuf)
	ret += fmt.Sprintf("BGP Update: %s\n\n", mbs.Bgpupbuf)
	t.msgNum++
	return ret, nil
}

// The text formatter doesn't need to summarize
func (t *TextFormatter) summarize() {}

// Formats each update as a JSON message
type JSONFormatter struct {
	bm Bucketer
}

func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

func (j *JSONFormatter) setBucketer(a Bucketer) {
	j.bm = a
}

func (j *JSONFormatter) format(mbs *mrt.MrtBufferStack, _ MBSInfo) (string, error) {
	mbsj, err := json.Marshal(mbs)
	return string(mbsj) + "\n", err
}

// The JSON formatter doesn't need to summarize
func (j *JSONFormatter) summarize() {}

// Applies no formatting to the data
// But data is decompressed, may need to fix that
// However, golang bz2 doesn't have compression features
type IdentityFormatter struct {
	bm Bucketer
}

func NewIdentityFormatter() *IdentityFormatter {
	return &IdentityFormatter{}
}

func (id *IdentityFormatter) setBucketer(a Bucketer) {
	id.bm = a
}

func (id *IdentityFormatter) format(mbs *mrt.MrtBufferStack, _ MBSInfo) (string, error) {
	return string(mbs.GetRawMessage()), nil
}

// No summarization needed
func (id *IdentityFormatter) summarize() {}

type PrefixHistory struct {
	Pref   string
	info   MBSInfo
	Events []PrefixEvent
}

type PrefixHistory1 struct {
	info   MBSInfo
	Events []PrefixEvent1
}

func NewPrefixHistory(pref string, info MBSInfo, firstTime time.Time, advert bool, asp []uint32) *PrefixHistory {
	pe := PrefixEvent{firstTime, advert, asp}
	return &PrefixHistory{pref, info, []PrefixEvent{pe}}
}

func (ph *PrefixHistory) addEvent(timestamp time.Time, advert bool, asp []uint32) {
	ph.Events = append(ph.Events, PrefixEvent{timestamp, advert, asp})
}

func (ph *PrefixHistory1) addEvent(timestamp time.Time, advert bool, asp []uint32, pref string, key string, peer string, col string) {
	ph.Events = append(ph.Events, PrefixEvent1{timestamp, advert, asp, pref, key, peer, col})
}

func (ph *PrefixHistory) String() string {
	str := ph.Pref
	if len(ph.Events) > 0 {
		str += fmt.Sprintf(" %d", ph.Events[0].Timestamp.Unix())
	}
	str += debugSprintf(" %s[%d]", ph.info.file, ph.info.msgNum)
	return str
}

type PrefixEvent struct {
	Timestamp  time.Time
	Advertized bool
	ASPath     []uint32
}

type PrefixEvent1 struct {
	Timestamp  time.Time
	Advertized bool
	ASPath     []uint32
	Prefix     string
	key        string
	Peer       string
	Collector  string
}

// In original gobgpdump, the List and Series are the same struct.
// Consider two separate structs

// UniquePrefixList will look at all incoming messages, and output
// only the top level prefixes seen.
type UniquePrefixList struct {
	bm       Bucketer
	output   io.Writer // This should only be used in summarize
	mux      *sync.Mutex
	prefixes map[string]interface{}
}

func NewUniquePrefixList(fd io.Writer) *UniquePrefixList {
	upl := UniquePrefixList{}
	upl.output = fd
	upl.mux = &sync.Mutex{}
	upl.prefixes = make(map[string]interface{})
	return &upl
}

func (upl *UniquePrefixList) setBucketer(a Bucketer) {
	upl.bm = a
}

func (upl *UniquePrefixList) format(mbs *mrt.MrtBufferStack, inf MBSInfo) (string, error) {

	timestamp := getTimestamp(mbs)
	advRoutes, err := getAdvertizedPrefixes(mbs)
	asp, errasp := getASPath(mbs)
	if errasp != nil || len(asp) == 0 {
		//maybe just a withdrawn message? make it empty.
		asp = []uint32{}
	}
	// Do something with routes only if there is no error.
	// Otherwise, move on to withdrawn routes
	if err == nil {
		upl.addRoutes(advRoutes, inf, timestamp, true, asp)
	}

	wdnRoutes, err := getWithdrawnPrefixes(mbs)
	if err == nil {
		upl.addRoutes(wdnRoutes, inf, timestamp, false, asp)
	}
	return "", nil
}

// If this finds a Route that is not present in the prefixes map,
// adds it in. If it finds one, but these Routes have an earlier
// timestamp, it replaces the old one.
func (upl *UniquePrefixList) addRoutes(rts []Route, info MBSInfo, timestamp time.Time, advert bool, asp []uint32) {
	for _, route := range rts {
		// Ignore this prefix, because it causes a lot of problems
		if route.Mask == 1 {
			continue
		}

		key := util.IpToRadixkey(route.IP, route.Mask)
		upl.mux.Lock()
		if upl.prefixes[key] == nil {
			upl.prefixes[key] = NewPrefixHistory(route.String(), info, timestamp, advert, asp)
		} else {
			oldT := upl.prefixes[key].(*PrefixHistory).Events[0].Timestamp
			if oldT.After(timestamp) {
				upl.prefixes[key] = NewPrefixHistory(route.String(), info, timestamp, advert, asp)
			}
		}
		upl.mux.Unlock()
	}
}

// All output is done in this function
func (upl *UniquePrefixList) summarize() {
	// Whatever is left should be output
	for _, value := range upl.prefixes {
		ph := value.(*PrefixHistory)
		str := ph.String() + "\n"
		upl.output.Write([]byte(str))
	}
}

// UniquePrefixSeries does the same thing as UniquePrefixList, but
// rather than just a list, it will output a gob file containing each
// prefix and every event seen associated with that prefix
type UniquePrefixSeries struct {
	bm               Bucketer
	output           io.Writer
	mux              *sync.Mutex
	prefixes         map[string]*PrefixHistory
	bucketedPrefixes [][]PrefixEvent1
	bucketedPeerAses [][]uint32
	allPeerAses      []uint32
}

func NewUniquePrefixSeries(fd io.Writer) *UniquePrefixSeries {
	ups := UniquePrefixSeries{}
	ups.output = fd
	ups.mux = &sync.Mutex{}
	ups.prefixes = make(map[string]*PrefixHistory, 0)
	ups.bucketedPrefixes = make([][]PrefixEvent1, 0)
	ups.bucketedPeerAses = make([][]uint32, 0)
	ups.allPeerAses = make([]uint32, 0)
	return &ups
}

func uintInSlice(a uint32, slice []uint32) bool {
	for i := range slice {
		if a == slice[i] {
			return true
		}
	}
	return false
}

func (ups *UniquePrefixSeries) setBucketer(a Bucketer) {
	ups.bm = a
}

func (ups *UniquePrefixSeries) format(mbs *mrt.MrtBufferStack, inf MBSInfo) (string, error) {
	timestamp := getTimestamp(mbs)
	bi := ups.bm.GetBucket(timestamp)
	//this will keep bucketedPrefixes and ups.bm.buckets being same sized
	for cbi := len(ups.bucketedPrefixes); cbi <= bi; cbi++ {
		ups.bucketedPrefixes = append(ups.bucketedPrefixes, make([]PrefixEvent1, 0))
		ups.bucketedPeerAses = append(ups.bucketedPeerAses, make([]uint32, 0))
	}

	advRoutes, err := getAdvertizedPrefixes(mbs)
	asp, errasp := getASPath(mbs)
	if errasp != nil || len(asp) == 0 {
		//maybe just a withdrawn message? make it empty.
		asp = []uint32{}
	}
	colstr := getCollector(mbs).String()
	peerstr := getPeer(mbs).String()
	if len(asp) > 2 {
		pas := asp[len(asp)-2]
		if !uintInSlice(pas, ups.allPeerAses) {
			ups.mux.Lock()
			ups.allPeerAses = append(ups.allPeerAses, pas)
			ups.bucketedPeerAses[bi] = append(ups.bucketedPeerAses[bi], pas)
			ups.mux.Unlock()
		}
	}
	if err == nil {
		ups.addRoutes(advRoutes, inf, timestamp, true, asp, bi, peerstr, colstr)
	}

	wdnRoutes, err := getWithdrawnPrefixes(mbs)
	if err == nil {
		ups.addRoutes(wdnRoutes, inf, timestamp, false, nil, bi, peerstr, colstr)
	}
	return "", nil
}

func (ups *UniquePrefixSeries) addRoutes(rts []Route, info MBSInfo, timestamp time.Time, advert bool, asp []uint32, bucketInd int, peerstr string, colstr string) {
	for _, route := range rts {
		//This route causes a lot of trouble
		if route.Mask == 1 {
			continue
		}

		key := util.IpToRadixkey(route.IP, route.Mask)
		ups.mux.Lock()
		//if ups.bucketedPrefixes[bucketInd][key] == nil {
		//	ups.bucketPrefixes[bucketInd][key] = NewPrefixHistory(route.String(), info, timestamp, advert, asp)
		//} else {
		//ups.bucketPrefixes[bucketInd].addEvent(timestamp, advert, asp)
		ups.bucketedPrefixes[bucketInd] = append(ups.bucketedPrefixes[bucketInd], PrefixEvent1{timestamp, advert, asp, route.String(), key, peerstr, colstr})
		//}
		ups.mux.Unlock()
	}
}

func printTreeFun(s string, v interface{}) bool {
	pev := v.(PrefixEvent1)
	ni, _ := numips(pev.Prefix)
	fmt.Printf("Pref:%s\tnumips:%d\ttime:%s\tcollector:%s\tpeer:%s\n", pev.Prefix, ni, pev.Timestamp, pev.Collector, pev.Peer)
	return false
}

type asval struct {
	as  uint32
	val int
}

// All output is done here
func (ups *UniquePrefixSeries) summarize() {
	//var err error
	//allEventsTree := gr.New()
	for _, bp := range ups.bucketedPrefixes {
		sortPrefixEventsByTime(bp)
	}
	prefmap := make(map[string]bool)
	for bi, bp := range ups.bucketedPrefixes {
		nums := make(map[uint32]int)
		for _, ev := range bp {
			if len(ev.ASPath) > 1 {
				as := ev.ASPath[len(ev.ASPath)-1]
				if ev.Advertized {
					if val, ok := nums[as]; ok {
						nums[as] = val + 1
					} else {
						nums[as] = 1
					}
				} else {
					if val, ok := nums[as]; ok {
						nums[as] = val - 1
					} else {
						nums[as] = -1
					}
				}
			}
			if ev.Advertized {
				//_, parentpref, havelp := allEventsTree.LongestPrefix(ev.key)
				//if !havelp {
				//	allEventsTree.Insert(ev.key, ev)
				//	} else {
				//	if ev.Prefix != parentpref.(PrefixEvent1).Prefix {
				//fmt.Printf("not adding %s:%s cause i have %v:%s\n", ev.Prefix, ev.key, parentpref.(PrefixEvent1), parenkey)
				//}
				//}
				prefmap[ev.Prefix] = true //record all the prefixes in a map
			}
		}
		asv := make([]asval, 0)
		for as, vals := range nums {
			asv = append(asv, asval{as: as, val: vals})
		}
		sort.Slice(asv, func(i, j int) bool { return asv[i].as < asv[j].as })
		fmt.Printf("%d\t", bi)
		for i := range asv {
			fmt.Printf("%d\t\t%d\t\n", asv[i].as, asv[i].val)
		}
		fmt.Println("")
	}
	for k, _ := range prefmap {
		fmt.Fprintf(ups.output, "%s\n", k)
	}
	//allEventsTree.Walk(printTreeFun)
	//for i := range ups.bucketedPeerAses {
	//fmt.Fprintf(ups.output, "%d %d %d new peer ases:%v\n", i+1, len(ups.bucketedPeerAses[i]), len(ups.bucketedPrefixes[i]), ups.bucketedPeerAses[i])
	//}
	/*
		totadv, totwdr, totdel, totadd, totupd, buckadv, buckwdr := 0, 0, 0, 0, 0, 0, 0
		totips := int64(0)
		fmt.Printf("bucket\ttotadv\ttotwdr\ttotdel\ttotadd\ttotupd\tbuckadv\tbuckwdr\tprefsKnown\tnumips\n")
		for i, bp := range ups.bucketedPrefixes {
			buckadv, buckwdr = 0, 0
			for _, ev := range bp {
				numips, _ := numips(ev.Prefix)
				if ev.Advertized {
					totadv += 1
					buckadv += 1
					_, updated := allEventsTree.Insert(ev.key, ev.Prefix)
					if !updated {
						totadd += 1
						totips += int64(numips)
					} else {
						totupd += 1
					}
				} else {
					totwdr += 1
					buckwdr += 1
					totdel += allEventsTree.DeletePrefix(ev.key)
					totips -= int64(numips)
				}
			}
			fmt.Printf("%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", i, totadv, totwdr, totdel, totadd, totupd, buckadv, buckwdr, allEventsTree.Len(), totips)
		}*/
	//fmt.Printf("bucketer:%s\n", ups.bm)
	//g := gob.NewEncoder(ups.output)
	//encode the whole map so we don't have to recreate the keys
	//err = g.Encode(ups.prefixes)
	//if err != nil {
	//	fmt.Printf("Error marshalling gob:%s\n", err)
	//}
}

func numips(a string) (int, error) {
	erripstr := fmt.Errorf("malformed str: %s", a)
	parts := strings.Split(a, "/")
	if len(parts) != 2 {
		return 0, erripstr
	}
	mask, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return 0, err
	}
	if strings.Contains(parts[0], ":") { //v6
		//return math.Pow(2, 128-int(mask)) - 2, nil
		return 0, nil //for now
	} else { //v4
		return int(math.Pow(2, float64(32-int(mask))) - 2), nil
	}
}

func sortPrefixEventsByTime(a []PrefixEvent1) {
	sort.Slice(a, func(i, j int) bool {
		if a[i].Timestamp.Before(a[j].Timestamp) {
			return true
		}
		return false
	})
}

/*
func sortPrefixHistoriesByTime(a map[string]*PrefixHistory) {
	for k, v := range a {
		sortPrefixEventsByTime(v.Events)
		a[k] = v
	}
}*/

/*
func PrefixTreeAsSortedSlice(a map[string]*PrefixHistory) (ret []PrefixRadixKeyEvent) {
	for k, v := range a {
		for _, ev := range v {
			ret = append(ret, PrefixRadixKeyEvent{ev, k})
		}
	}
	sortPrefixEventsByTime(ret)
}
*/
type DayFormatter struct {
	bm     Bucketer
	output io.Writer
	hourCt []int
}

func (d *DayFormatter) setBucketer(a Bucketer) {
	d.bm = a
}

func NewDayFormatter(fd io.Writer) *DayFormatter {
	return &DayFormatter{
		output: fd,
		hourCt: make([]int, 24),
	}
}

func (d *DayFormatter) format(mbs *mrt.MrtBufferStack, _ MBSInfo) (string, error) {
	timestamp := getTimestamp(mbs)
	d.hourCt[timestamp.Hour()]++
	return "", nil
}

func (d *DayFormatter) summarize() {
	for i := 0; i < len(d.hourCt); i++ {
		d.output.Write([]byte(fmt.Sprintf("%d %d\n", i, d.hourCt[i])))
	}
}
