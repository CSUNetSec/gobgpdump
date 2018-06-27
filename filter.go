// This file defines all filters and convenience functions for filters.
// Should be functionally equivalent to stable gobgpdump
// Current Filter options:
// -Source AS number (NewASFilter("1,2,3", true))
// -Destination AS number (NewASFilter("1,2,3", false))

// TODO
// -Maybe a function to return an array of filters based on config
//	options?
// -Time filter
// -Filters based on other attributes (peers, prefixes seen, etc.)
package gobgpdump

import (
	"fmt"
	mrt "github.com/CSUNetSec/protoparse/protocol/mrt"
	pu "github.com/CSUNetSec/protoparse/util"
	"net"
	"strconv"
	"strings"
)

type Filter func(mbs *mrt.MrtBufferStack) bool

type PrefixFilter struct {
	prefixes []string
	pt       pu.PrefixTree
}

func NewPrefixFilter(raw string) Filter {
	pf := PrefixFilter{}
	pf.pt = pu.NewPrefixTree()
	prefstrings := strings.Split(raw, ",")
	for _, p := range prefstrings {
		parts := strings.Split(p, "/")
		if len(parts) != 2 {
			panic("malformed prefix string")
		}
		mask, err := pu.MaskStrToUint8(parts[1])
		if err != nil {
			panic(fmt.Sprintf("error parsing mask:%s err:%s", parts[1], err))
		}
		parsedip := net.ParseIP(parts[0])
		if parsedip == nil {
			panic(fmt.Sprintf("malformed IP address:%s", parts[0]))
		}
		pf.pt.Add(parsedip, mask)
	}
	pf.prefixes = prefstrings
	return pf.filterBySeen
}

func (pf PrefixFilter) filterBySeen(mbs *mrt.MrtBufferStack) bool {
	advPrefs, err := getAdvertizedPrefixes(mbs)
	if err == nil {
		for _, pref := range advPrefs {
			if pf.pt.ContainsIpMask(pref.IP, pref.Mask) {
				return true
			}
		}
	}

	wdnPrefs, err := getWithdrawnPrefixes(mbs)
	if err == nil {
		for _, pref := range wdnPrefs {
			if pf.pt.ContainsIpMask(pref.IP, pref.Mask) {
				return true
			}
		}
	}
	return false
}

type ASFilter struct {
	asList []uint32
}

// Returns an AS filter with the list of AS's in the form "1,2,3,4"
// If src is true, filters messages by source AS number
// otherwise filters by destination AS number
func NewASFilter(list string, src bool) (Filter, error) {
	aslist, err := parseASList(list)
	if err != nil {
		return nil, err
	}

	asf := ASFilter{aslist}
	if src {
		return asf.FilterBySource, nil
	} else {
		return asf.FilterByDest, nil
	}
}

func (asf ASFilter) FilterBySource(mbs *mrt.MrtBufferStack) bool {
	path, err := getASPath(mbs)
	if err != nil || len(path) < 1 {
		return false
	}

	return asf.matchesOne(path[len(path)-1])
}

func (asf ASFilter) FilterByDest(mbs *mrt.MrtBufferStack) bool {
	path, err := getASPath(mbs)
	if err != nil || len(path) < 1 {
		return false
	}

	return asf.matchesOne(path[0])
}

// Convenience function used by both FilterBySrc/Dest
func (asf ASFilter) matchesOne(comp uint32) bool {
	for _, asnum := range asf.asList {
		if asnum == comp {
			return true
		}
	}
	return false
}

func parseASList(str string) ([]uint32, error) {
	list := strings.Split(str, ",")
	aslist := make([]uint32, len(list))

	for i := 0; i < len(aslist); i++ {
		as, err := strconv.ParseUint(list[i], 10, 32)
		if err != nil {
			return nil, err
		}
		aslist[i] = uint32(as)
	}

	return aslist, nil
}

func filterAll(filters []Filter, mbs *mrt.MrtBufferStack) bool {
	for _, fil := range filters {
		if fil != nil && !fil(mbs) {
			return false
		}
	}
	return true
}
