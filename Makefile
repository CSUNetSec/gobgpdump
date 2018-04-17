OUT=gobgpdump
DAOUT=dumpanalyzer

all: build

gobgpdump:
	go build -o ${OUT} cmd/gobgpdump/gobgpdump.go || (echo "running go get, retry"; go get; go get -u;);
dumpanalyzer:
	go build -o ${DAOUT} cmd/dumpanalyzer/dumpanalyzer.go || (echo "running go get, retry"; go get; go get -u;);

build: gobgpdump dumpanalyzer

clean:
	rm -f ${OUT}
	rm -f ${DAOUT}
