package main

import (
	"bufio"
	"flag"
	"fmt"
	util "github.com/CSUNetSec/protoparse/util"
	rad "github.com/armon/go-radix"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
)

var (
	preffile string
)

func init() {
	flag.StringVar(&preffile, "pf", "", "file name containing the prefixes")
}

type IpMask struct {
	ip   []byte
	mask uint8
}

func (i IpMask) String() string {
	ip := net.IP(i.ip)
	return fmt.Sprintf("%s/%d", ip, i.mask)
}

func str2IpMask(a string) (IpMask, error) {
	ret := IpMask{}
	parts := strings.Split(a, "/")
	if len(parts) != 2 {
		return ret, fmt.Errorf("malformed prefix")
	}
	ret.ip = net.ParseIP(parts[0])
	mask, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return ret, err
	}
	ret.mask = uint8(mask)
	return ret, nil
}

type observectx struct {
	regPrefs    map[string]interface{}
	regPrefTree *rad.Tree
	foundPrefs  map[string]IpMask //here the key is the one of the registered parent prefix to cross ref.
}

func newObserveCtx() *observectx {
	return &observectx{
		regPrefs:    make(map[string]interface{}),
		regPrefTree: nil,
		foundPrefs:  make(map[string]IpMask),
	}
}

func numips(a uint8) int {
	if a > 32 {
		return int(math.Pow(2, float64(128-int(a))) - 2)
	} else {
		return int(math.Pow(2, float64(32-int(a))) - 2)
	}
}

func (o *observectx) parseBgpdumpLine(line string) error {
	seekstr := "PREFIX: "
	if len(line) > 0 && strings.Contains(line, seekstr) {
		pstr := line[len(seekstr):]
		ipm, err := str2IpMask(pstr)
		if err != nil {
			return err
		}
		key := util.IpToRadixkey(ipm.ip, ipm.mask)
		pkey, _, haveparent := o.regPrefTree.LongestPrefix(key)
		if haveparent {
			o.foundPrefs[pkey] = ipm
		}
	}
	return nil
}

func (o *observectx) summarize() {
	totips, seenips := 0, 0
	for _, v := range o.regPrefs {
		p := v.(IpMask)
		totips += numips(p.mask)
	}
	fmt.Printf("prefix\t\tparentprefix\t\tnips\tparentnips\tcov\n")
	for k, v := range o.foundPrefs {
		parent := o.regPrefs[k].(IpMask)
		nipparent := numips(parent.mask)
		nipchild := numips(v.mask)
		seenips += nipchild
		percentage := float64(nipchild) / float64(nipparent)
		fmt.Printf("%s\t%s\t\t%d\t%d\t\t%.2f\n", v, parent, nipchild, nipparent, percentage)
	}
	fmt.Printf("prefixes tracked:%d prefs discovered:%d perc of ips covered:%.5f\n", len(o.regPrefs), len(o.foundPrefs), float64(seenips)/float64(totips))
}

func main() {
	var (
		scanner *bufio.Scanner
	)
	flag.Parse()
	if preffile == "" {
		fmt.Printf("error: prefix file required\n")
		return
	}
	pfd, err := os.Open(preffile)
	if err != nil {
		fmt.Printf("error:%s\n", err)
		return
	}
	scanner = bufio.NewScanner(pfd)
	octx := newObserveCtx()
	for scanner.Scan() {
		ipm, err := str2IpMask(scanner.Text())
		if err != nil {
			fmt.Printf("error:%s\n", err)
			pfd.Close()
			return
		}
		key := util.IpToRadixkey(ipm.ip, ipm.mask)
		if key != "" { //returned error (XXX return actual error)
			octx.regPrefs[key] = ipm
		}
	}
	pfd.Close()
	//create the prefixtree
	octx.regPrefTree = rad.NewFromMap(octx.regPrefs)
	scanner = bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		err := octx.parseBgpdumpLine(scanner.Text())
		if err != nil {
			fmt.Printf("error:%s\n", err)
		}
	}
	octx.summarize()
	return
}
