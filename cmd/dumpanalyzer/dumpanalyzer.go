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
		defaultArg   = "notset"
		defaultDelta = 1440
	)
	flag.StringVar(&clusterDurationStart, "s", defaultArg, "clustering duration start date (format: YYYYMMDDHHMM)")
	flag.StringVar(&clusterDurationEnd, "e", defaultArg, "clustering duration end date (format: YYYYMMDDHHMM)")
	flag.IntVar(&clusterDurationDelta, "d", defaultDelta, "clustering duration delta in minutes (default 1440 minutes in a day)")
}

type DateValuer interface {
	Add(string, float64)
}

type DateValueVector struct {
	date time.Time
	vals map[string][]float64
}

func NewDateValueVector(date time.Time) *DateValueVector {
	return &DateValueVector{
		date,
		make(map[string][]float64),
	}
}

func (d *DateValueVector) Add(key string, nval float64) {
	if val, ok := d.vals[key]; !ok {
		d.vals[key] = make([]float64, 0)
	} else {
		d.vals[key] = append(val, nval)
	}
}

type DateValueScalar struct {
	date time.Time
	vals map[string]float64
}

func NewDateValueScalar(date time.Time) *DateValueScalar {
	return &DateValueScalar{
		date,
		make(map[string]float64),
	}
}

func (d *DateValueScalar) Add(key string, nval float64) {
	d.vals[key] = nval
}

func BuildDateValueVectorSlice(start time.Time, end time.Time, dur time.Duration) ([]*DateValueVector, error) {
	fmt.Printf("got called with start:%s end:%s dur:%s\n", start, end, dur)
	if end.Before(start) {
		return nil, fmt.Errorf("start before end")
	}
	ret := []*DateValueVector{}
	for ctime := start; ctime.Before(end); ctime = ctime.Add(dur) {
		ret = append(ret, NewDateValueVector(ctime))
	}
	return ret, nil
}

func main() {
	flag.Parse()
	if len(flag.Args()) != 1 {
		fmt.Println("requires a gob file to decode")
		return
	}
	t1, e1 := time.Parse(timeFrmt, clusterDurationStart)
	t2, e2 := time.Parse(timeFrmt, clusterDurationEnd)
	// this is ugly to get the type system to work. doesn't happen with const decls cause it gets promoted
	dur := time.Duration(clusterDurationDelta) * time.Minute
	if e1 != nil || e2 != nil {
		fmt.Printf("error parsing clustering time start:%s, time end:%s\n", e1, e2)
		return
	}
	dvvecs, err := BuildDateValueVectorSlice(t1, t2, dur)
	if err != nil {
		fmt.Printf("couldn't build date value vector:%s", err)
		return
	}
	gfd, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Printf("error opening file:%s\n", err)
		return
	}
	defer gfd.Close()
	dec := gob.NewDecoder(gfd)
	count := 0
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
		count++
		//fmt.Printf("[%d]:%+v\n", count, ph)
	}
	fmt.Printf("will cluster those in these dvvecs:%+v", dvvecs)
}
