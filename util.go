package gobgpdump

import (
	"bufio"
	"compress/bzip2"
	"fmt"
	"github.com/CSUNetSec/protoparse/protocol/mrt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
)

// The dump, stat, and log files are all accessed by multiple
// goroutines. This is a simple file wrapper to lock on a write,
// and unlock once the write is complete
type MultiWriteFile struct {
	base io.WriteCloser
	mx   *sync.Mutex
}

func NewMultiWriteFile(w io.WriteCloser) *MultiWriteFile {
	return &MultiWriteFile{w, &sync.Mutex{}}
}

func (mwf *MultiWriteFile) WriteString(s string) (n int, err error) {
	mwf.mx.Lock()

	// This is to trash output if it's directed to a file that doesn't exist
	if mwf.base == nil {
		return 0, nil
	}
	n, err = mwf.base.Write([]byte(s))
	mwf.mx.Unlock()
	return
}

func (mwf *MultiWriteFile) Write(data []byte) (n int, err error) {
	mwf.mx.Lock()

	if mwf.base == nil {
		return 0, nil
	}
	n, err = mwf.base.Write(data)
	mwf.mx.Unlock()
	return
}

func (mwf *MultiWriteFile) Close() error {
	if mwf.base == nil {
		return nil
	}

	return mwf.base.Close()
}

func debugPrintf(format string, a ...interface{}) {
	if DEBUG {
		fmt.Printf(format, a)
	}
}

func debugSprintf(format string, a ...interface{}) string {
	if DEBUG {
		return fmt.Sprintf(format, a...)
	}
	return ""
}

func getScanner(fd *os.File) (scanner *bufio.Scanner) {
	if isBz2(fd.Name()) {
		bzreader := bzip2.NewReader(fd)
		scanner = bufio.NewScanner(bzreader)
	} else {
		scanner = bufio.NewScanner(fd)
	}
	scanner.Split(mrt.SplitMrt)
	scanbuffer := make([]byte, 2<<24)
	scanner.Buffer(scanbuffer, cap(scanbuffer))
	return
}

func GetMRTScanner(fd *os.File) *bufio.Scanner {
	return getScanner(fd)
}

func isBz2(fname string) bool {
	fext := filepath.Ext(fname)
	if fext == ".bz2" {
		return true
	}
	return false
}

type DiscardCloser struct{}

func (d DiscardCloser) Write(data []byte) (n int, err error) { return ioutil.Discard.Write(data) }

func (d DiscardCloser) Close() error { return nil }
