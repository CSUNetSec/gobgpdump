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
	"io"
	"strings"
	"sync"
	"time"

	mrt "github.com/CSUNetSec/protoparse/protocol/mrt"
	util "github.com/CSUNetSec/protoparse/util"
	radix "github.com/armon/go-radix"
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

// PrefixLock formatter keeps track of a prefix and the AS that advertized it.
// It then "locks" that relation. In case the same prefix (exactly the same for now)
// is advertized by some other AS, it outputs that event.
type PrefixLockFormatter struct {
	plmap map[string]*asLock
	m     *sync.Mutex
}

type asEvent struct {
	as uint32
	t  time.Time
}

type asLock struct {
	owner  asEvent
	others []asEvent
}

func newAsLock(as uint32, t time.Time) *asLock {
	return &asLock{
		owner: asEvent{
			as: as,
			t:  t,
		},
	}
}

func NewPrefixLockFormatter() *PrefixLockFormatter {
	return &PrefixLockFormatter{
		plmap: make(map[string]*asLock),
		m:     &sync.Mutex{},
	}
}

// this function will output a string of an event if the prefix is already registered to another AS.
func (p *PrefixLockFormatter) registerPrefixAS(pref string, as uint32, t time.Time) (string, error) {
	p.m.Lock()
	defer p.m.Unlock()
	al, ok := p.plmap[pref]
	if ok { // it exists already. check if we the event is from an "owner" or a "hijacker"
		if al.owner.as == as { // owner.
			return "", nil
		}
		for _, has := range al.others {
			if has.as == as { // we have seen this "hijacker"
				return "", nil
			}
		}
		// we have a new "hijacker" register him and output it.
		al.others = append(al.others, asEvent{as, t})
		return fmt.Sprintf("Prefix:%s\t\tOwner:%d\t\tHijacker:%d\t\tTime:%s", pref, al.owner.as, as, t), nil
	}
	// register it and don't output anything
	p.plmap[pref] = newAsLock(as, t)
	return "", nil
}

func (p *PrefixLockFormatter) summarize() {}

func (p *PrefixLockFormatter) format(mbs *mrt.MrtBufferStack, _ MBSInfo) (string, error) {
	eventstrs := []string(nil)
	advRoutes, merr := mrt.GetAdvertisedPrefixes(mbs)
	asp, errasp := mrt.GetASPath(mbs)
	if errasp != nil || len(asp) == 0 || merr != nil {
		//maybe just a withdrawn message? don't output anything
		return "", nil
	}
	ts := mrt.GetTimestamp(mbs)
	for _, route := range advRoutes {
		rets, err := p.registerPrefixAS(route.String(), asp[len(asp)-1], ts)
		if rets != "" {
			eventstrs = append(eventstrs, rets)
		}
		if err != nil {
			return "", err
		}
	}
	if len(eventstrs) != 0 {
		return fmt.Sprintf("%s\n", strings.Join(eventstrs, "\n")), nil
	}
	return "", nil
}

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

func NewMlFormatter() mlFormatter {
	return mlFormatter{}
}

type mltext struct {
	Mrt_header struct {
		Timestamp string
	}
	Bgp4mp_header struct {
		Local_AS int
		Peer_AS  int
		Local_IP string
		Peer_IP  string
	}
	Bgp_update struct {
		Advertized_routes []struct {
			Prefix string
			Mask   int
		}
		Attrs struct {
			AS_path []struct {
				AS_seq []int
				AS_set []int
			}
			Next_hop string
		}
		Withdrawn_routes []struct {
			Prefix string
			Mask   int
		}
	}
}

type mlFormatter struct{}

func (m mlFormatter) format(mbs *mrt.MrtBufferStack, _ MBSInfo) (string, error) {
	mbsj, err := json.Marshal(mbs)
	if err != nil {
		return "", err
	}
	mtext := &mltext{}
	err = json.Unmarshal(mbsj, mtext)
	if err != nil {
		return "", err
	}
	tparts := strings.Split(mtext.Mrt_header.Timestamp, "T")
	if len(tparts) != 2 {
		return "", err
	}
	t1parts := strings.Split(tparts[1], "Z")
	retstr := ""
	for _, ar := range mtext.Bgp_update.Advertized_routes {
		aspstr := ""
		for _, asp := range mtext.Bgp_update.Attrs.AS_path {
			for _, setelem := range asp.AS_set {
				if aspstr == "" {
					aspstr += fmt.Sprintf("%d", setelem)
				} else {
					aspstr += fmt.Sprintf("-%d", setelem)
				}
			}
			for _, seqelem := range asp.AS_seq {
				if aspstr == "" {
					aspstr += fmt.Sprintf("%d", seqelem)
				} else {
					aspstr += fmt.Sprintf("-%d", seqelem)
				}
			}
		}
		retstr += fmt.Sprintf("%s,%s,%d,%d,%s,%s,%s,%s,%d,%s,%s\n", tparts[0], t1parts[0], mtext.Bgp4mp_header.Local_AS,
			mtext.Bgp4mp_header.Peer_AS, mtext.Bgp4mp_header.Local_IP, mtext.Bgp4mp_header.Peer_IP,
			"advertized", ar.Prefix, ar.Mask, aspstr,
			mtext.Bgp_update.Attrs.Next_hop)
	}
	for _, wr := range mtext.Bgp_update.Withdrawn_routes {
		retstr += fmt.Sprintf("%s,%s,%d,%d,%s,%s,%s,%s,%d,%s,%s\n", tparts[0], t1parts[0], mtext.Bgp4mp_header.Local_AS,
			mtext.Bgp4mp_header.Peer_AS, mtext.Bgp4mp_header.Local_IP, mtext.Bgp4mp_header.Peer_IP,
			"withdrawn", wr.Prefix, wr.Mask, "",
			"")
	}
	return retstr, nil
}

func (m mlFormatter) summarize() {}

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

	timestamp := mrt.GetTimestamp(mbs)
	advRoutes, err := mrt.GetAdvertisedPrefixes(mbs)
	asp, errasp := mrt.GetASPath(mbs)
	if errasp != nil || len(asp) == 0 {
		//maybe just a withdrawn message? make it empty.
		asp = []uint32{}
	}
	// Do something with routes only if there is no error.
	// Otherwise, move on to withdrawn routes
	if err == nil {
		upl.addRoutes(advRoutes, inf, timestamp, true, asp)
	}

	wdnRoutes, err := mrt.GetWithdrawnPrefixes(mbs)
	if err == nil {
		upl.addRoutes(wdnRoutes, inf, timestamp, false, asp)
	}
	return "", nil
}

// If this finds a Route that is not present in the prefixes map,
// adds it in. If it finds one, but these Routes have an earlier
// timestamp, it replaces the old one.
func (upl *UniquePrefixList) addRoutes(rts []mrt.Route, info MBSInfo, timestamp time.Time, advert bool, asp []uint32) {
	for _, route := range rts {
		// Ignore this prefix, because it causes a lot of problems
		if route.Mask == 1 {
			continue
		}

		key := util.IPToRadixkey(route.IP, route.Mask)
		if key == "" {
			continue
		}
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
	timestamp := mrt.GetTimestamp(mbs)

	advRoutes, err := mrt.GetAdvertisedPrefixes(mbs)
	asp, errasp := mrt.GetASPath(mbs)
	if errasp != nil || len(asp) == 0 {
		//maybe just a withdrawn message? make it empty.
		asp = []uint32{}
	}
	if err == nil {
		ups.addRoutes(advRoutes, inf, timestamp, true, asp)
	}

	wdnRoutes, err := mrt.GetWithdrawnPrefixes(mbs)
	if err == nil {
		ups.addRoutes(wdnRoutes, inf, timestamp, false, asp)
	}
	return "", nil
}

func (ups *UniquePrefixSeries) addRoutes(rts []mrt.Route, info MBSInfo, timestamp time.Time, advert bool, asp []uint32) {
	for _, route := range rts {
		//This route causes a lot of trouble
		if route.Mask == 1 {
			continue
		}

		key := util.IPToRadixkey(route.IP, route.Mask)
		if key == "" {
			continue
		}
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
	timestamp := mrt.GetTimestamp(mbs)
	d.hourCt[timestamp.Hour()]++
	return "", nil
}

func (d *DayFormatter) summarize() {
	for i := 0; i < len(d.hourCt); i++ {
		d.output.Write([]byte(fmt.Sprintf("%d %d\n", i, d.hourCt[i])))
	}
}

type ASNode struct {
	as       uint32
	ct       int
	next     []uint32
	isOrigin bool
}

func (asn *ASNode) HasNext(as uint32) bool {
	for _, next := range asn.next {
		if next == as {
			return true
		}
	}
	return false
}

func (asn *ASNode) AddNext(as uint32) {
	if asn.HasNext(as) {
		return
	}

	asn.next = append(asn.next, as)
}

func (asn *ASNode) GetDotAttributres() string {
	attrTmpl := "[style=\"filled\",fillcolor=\"%s\"]"
	color := ""
	// These colors were chosen to be lightly colored but still
	// noticeable
	if asn.isOrigin && asn.ct == 1 {
		color = "darkorchid1"
	} else if asn.isOrigin {
		color = "cornflowerblue"
	} else if asn.ct == 1 {
		color = "firebrick1"
	} else {
		return ""
	}

	return fmt.Sprintf(attrTmpl, color)
}

type ASMap struct {
	nodes map[uint32]*ASNode
}

func NewASMap() *ASMap {
	return &ASMap{nodes: make(map[uint32]*ASNode)}
}

func (asm *ASMap) AddPath(aspath []uint32) {
	// Add all the links starting from the origin
	for i := len(aspath) - 1; i >= 0; i-- {
		node, ok := asm.nodes[aspath[i]]
		if !ok {
			node = &ASNode{as: aspath[i], ct: 0, next: []uint32{}, isOrigin: false}
		}

		node.ct++
		if i == len(aspath)-1 {
			node.isOrigin = true
		}
		if i != 0 {
			node.AddNext(aspath[i-1])
		}
		asm.nodes[aspath[i]] = node
	}
}

func (asm *ASMap) ToDotFile(w io.Writer) error {
	graphTmpl := "digraph ASMap {\n %s \n\n %s \n}"
	nodeTmpl := "%d %s; // Appeared: %d\n"
	nodes := ""
	edges := ""
	for k, v := range asm.nodes {
		nodes += fmt.Sprintf(nodeTmpl, k, v.GetDotAttributres(), v.ct)

		asList := "{"
		for _, as := range v.next {
			asList = fmt.Sprintf("%s %d", asList, as)
		}
		asList += "}"
		edges += fmt.Sprintf("%d -> %s;\n", k, asList)
	}
	graph := fmt.Sprintf(graphTmpl, nodes, edges)
	_, err := w.Write([]byte(graph))
	return err
}

type ASMapFormatter struct {
	output io.Writer
	asMap  *ASMap
	pathC  chan []uint32
	wg     *sync.WaitGroup
}

func NewASMapFormatter(fd io.Writer) *ASMapFormatter {
	asmf := &ASMapFormatter{output: fd}
	asmf.asMap = NewASMap()
	asmf.pathC = make(chan []uint32, 32)
	asmf.wg = &sync.WaitGroup{}

	asmf.wg.Add(1)
	go asmf.processPaths()
	return asmf
}

func (asmf *ASMapFormatter) format(mbs *mrt.MrtBufferStack, _ MBSInfo) (string, error) {
	asp, err := mrt.GetASPath(mbs)
	if err != nil || len(asp) == 0 {
		return "", nil
	}

	asmf.pathC <- asp
	return "", nil
}

func (asmf *ASMapFormatter) processPaths() {
	defer asmf.wg.Done()

	for path := range asmf.pathC {
		asmf.asMap.AddPath(path)
	}
}

func (asmf *ASMapFormatter) summarize() {
	close(asmf.pathC)
	asmf.wg.Wait()

	asmf.asMap.ToDotFile(asmf.output)
}
