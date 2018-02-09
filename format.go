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
	"encoding/gob"
	"encoding/json"
	"fmt"
	mrt "github.com/CSUNetSec/protoparse/protocol/mrt"
	util "github.com/CSUNetSec/protoparse/util"
	radix "github.com/armon/go-radix"
	"io"
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
	msgNum int
}

func NewTextFormatter() *TextFormatter {
	return &TextFormatter{0}
}

func (t *TextFormatter) format(mbs *mrt.MrtBufferStack, _ MBSInfo) (string, error) {
	ret := fmt.Sprintf("[%d] MRT Header: %s\n", t.msgNum, mbs.MrthBuf)
	if mbs.IsRibStack() {
		ret += fmt.Sprintf("RIB Header: %s\n", mbs.Ribbuf)
	} else {
		ret += fmt.Sprintf("BGP4MP Header: %s\n", mbs.Bgp4mpbuf)
		ret += fmt.Sprintf("BGP Header: %s\n", mbs.Bgphbuf)
		ret += fmt.Sprintf("BGP Update: %s\n\n", mbs.Bgpupbuf)
	}
	t.msgNum++
	return ret, nil
}

// The text formatter doesn't need to summarize
func (t *TextFormatter) summarize() {}

// Formats each update as a JSON message
type JSONFormatter struct{}

func NewJSONFormatter() JSONFormatter {
	return JSONFormatter{}
}

func (j JSONFormatter) format(mbs *mrt.MrtBufferStack, _ MBSInfo) (string, error) {
	mbsj, err := json.Marshal(mbs)
	return string(mbsj) + "\n", err
}

// The JSON formatter doesn't need to summarize
func (j JSONFormatter) summarize() {}

// Applies no formatting to the data
// But data is decompressed, may need to fix that
// However, golang bz2 doesn't have compression features
type IdentityFormatter struct{}

func NewIdentityFormatter() IdentityFormatter {
	return IdentityFormatter{}
}

func (id IdentityFormatter) format(mbs *mrt.MrtBufferStack, _ MBSInfo) (string, error) {
	return string(mbs.GetRawMessage()), nil
}

// No summarization needed
func (id IdentityFormatter) summarize() {}

type PrefixHistory struct {
	Pref   string
	info   MBSInfo
	Events []PrefixEvent
}

func NewPrefixHistory(pref string, info MBSInfo, firstTime time.Time, advert bool, asp []uint32) *PrefixHistory {
	pe := PrefixEvent{firstTime, advert, asp}
	return &PrefixHistory{pref, info, []PrefixEvent{pe}}
}

func (ph *PrefixHistory) addEvent(timestamp time.Time, advert bool, asp []uint32) {
	ph.Events = append(ph.Events, PrefixEvent{timestamp, advert, asp})
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

// In original gobgpdump, the List and Series are the same struct.
// Consider two separate structs

// UniquePrefixList will look at all incoming messages, and output
// only the top level prefixes seen.
type UniquePrefixList struct {
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
	deleteChildPrefixes(upl.prefixes)

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
	output   io.Writer
	mux      *sync.Mutex
	prefixes map[string]interface{}
}

func NewUniquePrefixSeries(fd io.Writer) *UniquePrefixSeries {
	ups := UniquePrefixSeries{}
	ups.output = fd
	ups.mux = &sync.Mutex{}
	ups.prefixes = make(map[string]interface{})
	return &ups
}

func (ups *UniquePrefixSeries) format(mbs *mrt.MrtBufferStack, inf MBSInfo) (string, error) {
	timestamp := getTimestamp(mbs)

	advRoutes, err := getAdvertizedPrefixes(mbs)
	asp, errasp := getASPath(mbs)
	if errasp != nil || len(asp) == 0 {
		//maybe just a withdrawn message? make it empty.
		asp = []uint32{}
	}
	if err == nil {
		ups.addRoutes(advRoutes, inf, timestamp, true, asp)
	}

	wdnRoutes, err := getWithdrawnPrefixes(mbs)
	if err == nil {
		ups.addRoutes(wdnRoutes, inf, timestamp, false, asp)
	}
	return "", nil
}

func (ups *UniquePrefixSeries) addRoutes(rts []Route, info MBSInfo, timestamp time.Time, advert bool, asp []uint32) {
	for _, route := range rts {
		//This route causes a lot of trouble
		if route.Mask == 1 {
			continue
		}

		key := util.IpToRadixkey(route.IP, route.Mask)
		ups.mux.Lock()
		if ups.prefixes[key] == nil {
			ups.prefixes[key] = NewPrefixHistory(route.String(), info, timestamp, advert, asp)
		} else {
			ups.prefixes[key].(*PrefixHistory).addEvent(timestamp, advert, asp)
		}
		ups.mux.Unlock()
	}
}

// All output is done here
func (ups *UniquePrefixSeries) summarize() {
	g := gob.NewEncoder(ups.output)
	var err error

	deleteChildPrefixes(ups.prefixes)
	// Whatever is left are top-level prefixes and should be
	// encoded
	for _, value := range ups.prefixes {
		ph := value.(*PrefixHistory)
		err = g.Encode(ph)
		if err != nil {
			fmt.Printf("Error marshalling gob:%s\n", err)
		}
	}
}

type PrefixWalker struct {
	top      bool
	prefixes map[string]interface{}
}

func (p *PrefixWalker) subWalk(s string, v interface{}) bool {
	if p.top {
		p.top = false
	} else {
		delete(p.prefixes, s)
	}
	return false
}

// This function will delete subprefixes from the provided map
func deleteChildPrefixes(pm map[string]interface{}) {
	pw := &PrefixWalker{false, pm}

	rTree := radix.New()
	for key, value := range pm {
		rTree.Insert(key, value)
	}

	rTree.Walk(func(s string, v interface{}) bool {
		pw.top = true
		rTree.WalkPrefix(s, pw.subWalk)
		return false
	})
}

type DayFormatter struct {
	output io.Writer
	hourCt []int
}

func NewDayFormatter(fd io.Writer) *DayFormatter {
	return &DayFormatter{fd, make([]int, 24)}
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
