// This file is all the code necessary to set up a message dump
// It parses command line options, reads configuration from files,
// and returns all the parameters to the main logic of the program.

// Has passed fairly rigorous testing.
// Passes normal options, config files with multiple
// collectors over multiple months

//TODO: Add into the configuration option a list of allowed file
// extnsions, default being all, -conf option only
package gobgpdump

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	golog "log"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	DEBUG bool
)

// This is a struct to store all options in.
// This is just convenient so it can be read
// as a json object
type ConfigFile struct {
	Collist  []string //List of collectors
	Start    string   // Start month		These first three are only used in configuration option, which is why they don't have flags
	End      string   //end month
	Lo       string   //Log output
	So       string   //Stat output
	Do       string   //dump output
	Wc       int      //worker count
	Fmtr     string   //output format
	Conf     bool     //get config from a file
	Srcas    string   `json:"Srcas,omitempty"`
	Destas   string   `json:"Destas,omitempty"`
	PrefList string   `json:"prefixes,omitempty"`
	Debug    bool     // sets the global debug flag for the package
}

// This struct is the complete parameter set for a file
// dump.
type DumpConfig struct {
	workers int
	source  stringsource
	fmtr    Formatter
	filters []Filter
	dump    *MultiWriteFile
	log     *MultiWriteFile
	stat    *MultiWriteFile
}

func (dc *DumpConfig) GetWorkers() int {
	return dc.workers
}

func (dc *DumpConfig) SummarizeAndClose(start time.Time) {
	dc.fmtr.summarize()
	dc.stat.WriteString(fmt.Sprintf("Total time taken: %s\n", time.Since(start)))
	dc.CloseAll()
}

func (dc *DumpConfig) CloseAll() {
	dc.dump.Close()
	dc.log.Close()
	dc.stat.Close()
}

func GetDumpConfig(configFile ConfigFile) (*DumpConfig, error) {
	args := flag.Args()
	var dc DumpConfig
	if configFile.Debug == true {
		DEBUG = true
	} else {
		DEBUG = false
	}
	if configFile.Conf {
		if len(args) != 2 {
			return nil, fmt.Errorf("Incorrect number of arguments for -conf option.\nShould be: -conf <collector formats> <config file>")
		}
		newConfig, ss, err := parseConfig(args[0], args[1])
		if err != nil {
			return nil, fmt.Errorf("Error parsing configuration: %s", err)
		}
		configFile = newConfig
		dc.source = ss
	} else {
		dc.source = NewStringArray(args)
	}

	dc.workers = configFile.Wc

	// This error is ignored. If there is an error, output to that file just gets trashed
	var dump *os.File
	if configFile.Do == "stdout" || configFile.Do == "" {
		dump = os.Stdout
	} else {
		dump, _ = os.Create(configFile.Do)
	}
	dc.dump = NewMultiWriteFile(dump)

	var stat *os.File
	if configFile.So == "stdout" || configFile.Do == "" {
		stat = os.Stdout
	} else {
		stat, _ = os.Create(configFile.So)
	}
	dc.stat = NewMultiWriteFile(stat)

	var log *os.File
	if configFile.Lo == "stdout" || configFile.Do == "" {
		log = os.Stdout
	} else {
		log, _ = os.Create(configFile.Lo)
	}
	dc.log = NewMultiWriteFile(log)
	golog.SetOutput(dc.log)

	// This will need access to redirected output files
	dc.fmtr = getFormatter(configFile, dump)

	filts, err := getFilters(configFile)
	dc.filters = filts
	if err != nil {
		return nil, err
	}

	return &dc, nil
}

func getFilters(configFile ConfigFile) ([]Filter, error) {
	var filters []Filter
	if configFile.Srcas != "" {
		srcFilt, err := NewASFilter(configFile.Srcas, true)
		if err != nil {
			return nil, err
		}
		filters = append(filters, srcFilt)
	}

	if configFile.Destas != "" {
		destFilt, err := NewASFilter(configFile.Destas, false)
		if err != nil {
			return nil, err
		}
		filters = append(filters, destFilt)
	}

	if configFile.PrefList != "" {
		prefFilt := NewPrefixFilter(configFile.PrefList)
		filters = append(filters, prefFilt)
	}
	return filters, nil
}

// Consider putting this in format.go
func getFormatter(configFile ConfigFile, dumpOut *os.File) (fmtr Formatter) {
	switch configFile.Fmtr {
	case "json":
		fmtr = NewJSONFormatter()
	case "pup":
		fmtr = NewUniquePrefixList(dumpOut)
	case "pts":
		fmtr = NewUniquePrefixSeries(dumpOut)
	case "day":
		fmtr = NewDayFormatter(dumpOut)
	case "text":
		fmtr = NewTextFormatter()
	case "id":
		fmtr = NewIdentityFormatter()
	default:
		fmtr = NewTextFormatter()
	}
	return
}

// This is a wrapper so the source of the file names
// can come from an array, or from a directory listing
// in the case that the -conf option is used

// Stringsources are accessed from multiple goroutines, so
// they MUST be thread-safe
type stringsource interface {
	Next() (string, error)
}

// This is the normal error returned by a stringsource, indicating
// there were no failures, there are just no more strings to recieve
var EOP error = fmt.Errorf("End of paths")

// Simple wrapper for a string array, so it can be accessed
// concurrently, and in the same way as a DirectorySource
type StringArray struct {
	pos  int
	base []string
	mux  *sync.Mutex
}

func NewStringArray(buf []string) *StringArray {
	return &StringArray{0, buf, &sync.Mutex{}}
}

func (sa *StringArray) Next() (string, error) {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	if sa.pos >= len(sa.base) {
		return "", EOP
	}
	ret := sa.base[sa.pos]
	sa.pos++
	return ret, nil
}

type DirectorySource struct {
	dirList  []string
	curDir   int
	fileList []os.FileInfo
	curFile  int
	mux      *sync.Mutex
}

func NewDirectorySource(dirs []string) *DirectorySource {
	return &DirectorySource{dirs, 0, nil, 0, &sync.Mutex{}}
}

func (ds *DirectorySource) Next() (string, error) {
	ds.mux.Lock()
	defer ds.mux.Unlock()

	// This should end all threads accessing it in the same way
	// but warrants testing
	if ds.fileList == nil {
		err := ds.loadNextDir()
		if err != nil {
			return "", err
		}
	}

	fName := ds.fileList[ds.curFile].Name()
	pathPrefix := ds.dirList[ds.curDir]

	ds.curFile++
	if ds.curFile >= len(ds.fileList) {
		ds.fileList = nil
		ds.curDir++
	}

	return pathPrefix + fName, nil
}

func (ds *DirectorySource) loadNextDir() error {
	if ds.curDir >= len(ds.dirList) {
		return EOP
	}
	dirFd, err := os.Open(ds.dirList[ds.curDir])
	if err != nil {
		return err
	}
	defer dirFd.Close()
	ds.fileList, err = dirFd.Readdir(0)
	if err != nil {
		return err
	}
	ds.curFile = 0
	return nil
}

//This parses the configuration file
func parseConfig(colfmt, config string) (ConfigFile, stringsource, error) {
	var cf ConfigFile
	// Parse the collector format file
	formats, err := readCollectorFormat(colfmt)
	if err != nil {
		return cf, nil, err
	}

	// Read the config as a json object from the file
	fd, err := os.Open(config)
	if err != nil {
		return cf, nil, err
	}
	defer fd.Close()

	dec := json.NewDecoder(fd)
	dec.Decode(&cf)

	// Create a list of directories
	start, err := time.Parse("2006.01", cf.Start)
	if err != nil {
		return cf, nil, fmt.Errorf("Error parsing start date: %s", cf.Start)
	}

	end, err := time.Parse("2006.01", cf.End)
	if err != nil {
		return cf, nil, fmt.Errorf("Error parsing end date: %s", cf.End)
	}

	paths := []string{}

	// Start at start, increment by 1 months, until it's past 1 day
	// past end, so end is included
	for mon := start; mon.Before(end.AddDate(0, 0, 1)); mon = mon.AddDate(0, 1, 0) {
		for _, col := range cf.Collist {
			curPath, exists := formats[col]
			// If the collector does not have a special rule,
			// use the default rule
			if !exists {
				curPath = formats["_default"]
				curPath = strings.Replace(curPath, "{x}", col, -1)
			}
			// Remove all placeholders from the path
			curPath = strings.Replace(curPath, "{yyyy.mm}", mon.Format("2006.01"), -1)
			fmt.Printf("Adding path: %s\n", curPath)
			paths = append(paths, curPath)
		}
	}

	return cf, NewDirectorySource(paths), nil
}

func readCollectorFormat(fname string) (map[string]string, error) {
	fd, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	reader := bufio.NewReader(fd)
	formats := make(map[string]string)

	_, base, err := readPairWithRule(reader, "{base}")
	if err != nil {
		return nil, err
	}

	_, def, err := readPairWithRule(reader, "{default}")
	if err != nil {
		return nil, err
	}
	formats["_default"] = base + def

	for err == nil {
		name, path, err := readPairWithRule(reader, "")
		if err == io.EOF {
			break
		}

		formats[name] = base + path
	}

	// Error must be non-nil at this point, but it may still
	// be normal, so check if it's not
	if err != nil && err != io.EOF {
		return nil, err
	}

	return formats, nil

}

//This is a weird function, but it makes the code less messy
// Reads two strings, separated by a space, ending with a newline, and
// checks if the first string matches <expect>
// Fails on any other condition
func readPairWithRule(reader *bufio.Reader, expect string) (string, string, error) {
	str, err := reader.ReadString('\n')
	if err != nil {
		return "", "", err
	}

	parts := strings.Split(str, " ")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("Badly formatted string: %s\n", str)
	}

	first := strings.Trim(parts[0], "\n")
	second := strings.Trim(parts[1], "\n")
	if expect != "" && first != expect {
		return "", "", fmt.Errorf("First string does not match rule\n")
	}

	return first, second, nil

}
