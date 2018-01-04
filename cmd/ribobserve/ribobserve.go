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
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

var (
	preffile   string
	nworkers   int
	bgpdumpbin string
)

func init() {
	flag.StringVar(&preffile, "pf", "", "file name containing the prefixes")
	flag.IntVar(&nworkers, "nw", 1, "number of workers")
	flag.StringVar(&bgpdumpbin, "bin", "", "path of the bgpdump binary that the workers use to read RIBs")
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
	missPrefs   map[string]IpMask
}

type foundPrefs struct {
	prefs         map[string]interface{}
	foundPrefTree *rad.Tree
	fname         string
}

func newObserveCtx() *observectx {
	return &observectx{
		regPrefs:    make(map[string]interface{}),
		regPrefTree: nil,
		missPrefs:   make(map[string]IpMask),
	}
}

func numips(a uint8) int {
	if a > 32 {
		return int(math.Pow(2, float64(128-int(a))) - 2)
	} else {
		return int(math.Pow(2, float64(32-int(a))) - 2)
	}
}

func (o *observectx) parseBgpdumpLine(line string, found foundPrefs) error {
	seekstr := "PREFIX: "
	if len(line) > 0 && strings.Contains(line, seekstr) {
		pstr := line[len(seekstr):]
		ipm, err := str2IpMask(pstr)
		if err != nil {
			return err
		}
		key := util.IpToRadixkey(ipm.ip, ipm.mask)
		_, _, haveparent := o.regPrefTree.LongestPrefix(key)
		if haveparent {
			_, _, havefoundparent := found.foundPrefTree.LongestPrefix(key)
			if !havefoundparent { // we haven't seen it and we are looking for it
				found.foundPrefTree.Insert(key, ipm)
			}
		}
	}
	return nil
}

func summarize(fp foundPrefs, o *observectx) {
	totips, seenips := 0, 0
	newmissing := make([]IpMask, 0)
	//fp.foundPrefTree = rad.NewFromMap(fp.prefs)
	dp := 0
	fp.foundPrefTree.Walk(func(s string, v interface{}) bool {
		fp.foundPrefTree.WalkPrefix(s, func(schild string, vchild interface{}) bool { //delete the children
			fp.foundPrefTree.WalkPrefix(schild, func(schild1 string, vchild1 interface{}) bool {
				if schild1 != schild {
					fmt.Printf("%s has parent %s. deleting under it:", vchild1.(IpMask), vchild.(IpMask))
					delp := fp.foundPrefTree.DeletePrefix(schild1)
					fmt.Printf("%d prefs\n", delp)
					dp += delp
					return true
				}
				return false
			})
			return true
		})
		return false
	})
	/*
			pk, paren, hasparent := fp.foundPrefTree.LongestPrefix(s)
			fmt.Printf("examining:%s and found that hasparent:%v %s\ns", v.(IpMask), hasparent, paren.(IpMask))
			if hasparent && pk != s {
				fmt.Printf("%s has parent %s. deleting\n", v.(IpMask), paren.(IpMask))
				dp += fp.foundPrefTree.DeletePrefix(s)
			}
			return false
		})
	*/
	fmt.Printf("totally deleted %d from discovered prefixes\n", dp)

	for _, v := range o.regPrefs {
		p := v.(IpMask)
		nummask := numips(p.mask)
		totips += nummask
	}
	pdiscovered := 0
	fp.foundPrefTree.Walk(func(s string, v interface{}) bool {
		seenips += numips(v.(IpMask).mask)
		pdiscovered++
		return false
	})
	/*for _, v := range fp.prefs {
		nipchild := numips(v.(IpMask).mask)
		seenips += nipchild
	}*/

	/*
		for k, v := range o.regPrefs {
			if _, ok := fp.prefs[k]; !ok {
				if _, ok := o.missPrefs[k]; !ok { // add prefix to missing set
					ipm := v.(IpMask)
					o.missPrefs[k] = ipm
					newmissing = append(newmissing, ipm)
				}
				untrackedprefs++
				fmt.Printf("missing:%s key:%s\n", v, k)
			} else {
				delete(o.missPrefs, k) //prefix is no longer missing
			}
		}*/
	fmt.Printf("file:%s prefixes tracked:%d prefs discovered:%d perc of ips covered:%.5f seenips:%d totips:%d \n", fp.fname, len(o.regPrefs), pdiscovered, float64(seenips)/float64(totips)*float64(100), seenips, totips)
	if len(newmissing) != 0 {
		if len(newmissing) != len(o.regPrefs) { //this guy saw nothing. don't print it.
			fmt.Printf("new missing prefixes: ")
			for _, v := range newmissing { //something was added to the missing set so print it.
				fmt.Printf(" %v ", v)
			}
			fmt.Printf("\n")
		}
	}
}

func launchWorker(id int, f <-chan string, bin string, res chan<- foundPrefs, octx *observectx, wg *sync.WaitGroup) {
	if _, err := os.Stat(bin); err != nil {
		fmt.Printf("binary for bgpdump can't be STATed. quitting")
		return
	}
	for fname := range f {
		cmd := exec.Command(bin, fname)
		cmdout, err := cmd.StdoutPipe()
		if err != nil {
			fmt.Printf("err:%s\n", err)
			return
		}
		scanner := bufio.NewScanner(cmdout)
		if err := cmd.Start(); err != nil {
			fmt.Printf("running cmd err:%s\n", err)
			return
		}

		fp := foundPrefs{
			fname:         fname,
			foundPrefTree: rad.New(),
		}

		for scanner.Scan() {
			octx.parseBgpdumpLine(scanner.Text(), fp)
		}
		res <- fp
	}
	wg.Done()
	fmt.Printf("worker exiting\n")
}

func collectResults(res <-chan foundPrefs, o *observectx, wg *sync.WaitGroup) {
	for r := range res {
		//fmt.Printf("collected result:%s\n", r)
		summarize(r, o)
	}
	fmt.Printf("collector exiting\n")
	wg.Done()
}

func main() {
	var (
		scanner    *bufio.Scanner
		inworkchan chan string
		reschan    chan foundPrefs
	)
	inworkchan, reschan = make(chan string), make(chan foundPrefs)
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
	dp := 0
	octx.regPrefTree.Walk(func(s string, v interface{}) bool {
		pk, paren, hasparent := octx.regPrefTree.LongestPrefix(s)
		if hasparent && pk != s {
			fmt.Printf("%s has parent %s\n", v.(IpMask), paren.(IpMask))
			dp += octx.regPrefTree.DeletePrefix(s)
		}
		return false
	})
	fmt.Printf("already covered prefixes deleted:%d. Tree has %d now\n", dp, octx.regPrefTree.Len())
	//fire up the workers
	wg := &sync.WaitGroup{}
	for i := 0; i < nworkers; i++ {
		wg.Add(1)
		go launchWorker(i, inworkchan, bgpdumpbin, reschan, octx, wg)
	}
	wg.Add(1)
	go collectResults(reschan, octx, wg)

	scanner = bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		inworkchan <- scanner.Text()
	}
	close(inworkchan)
	close(reschan)
	wg.Wait()
	return
}
