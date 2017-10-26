package gobgpdump

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

type BucketManager struct {
	intervalMins time.Duration
	buckets      []time.Time
	mux          *sync.Mutex
}

type Bucketer interface {
	GetBucket(a time.Time) int
}

func NewBucketManager(a int) *BucketManager {
	return &BucketManager{
		time.Duration(a) * time.Minute,
		make([]time.Time, 0),
		&sync.Mutex{},
	}
}

func (b *BucketManager) String() string {
	ret := fmt.Sprintf("intervalMin:%s [", b.intervalMins)
	for i, buck := range b.buckets {
		ret += fmt.Sprintf(" i:%d v:%s ", i, buck)
	}
	ret += "]"
	return ret
}

func (b *BucketManager) GetBucket(a time.Time) int {
	b.mux.Lock()
	defer b.mux.Unlock()
	if len(b.buckets) == 0 { //create the first bucket
		b.buckets = append(b.buckets, a)
		return 0
	}
	ind1 := sort.Search(len(b.buckets), func(i int) bool { return b.buckets[i].After(a) })
	ind2 := sort.Search(len(b.buckets), func(i int) bool { return b.buckets[i].Add(b.intervalMins).After(a) })
	//fmt.Printf("i1:%d i2:%d\n", ind1, ind2)
	if ind1 == ind2 { // need to expand
		// add all the inbetween buckets to keep it sorted
		for cdate := b.buckets[len(b.buckets)-1].Add(b.intervalMins); a.After(cdate); cdate = cdate.Add(b.intervalMins) {
			b.buckets = append(b.buckets, cdate)
		}
		return len(b.buckets) - 1
	}
	return ind1 - 1
}

type zeroBucketer struct{}

func (z zeroBucketer) GetBucket(a time.Time) int {
	return 0
}
