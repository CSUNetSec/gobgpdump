OUT=gobgpdump

all: build

gobgpdump:
	GO111MODULE=on go build -o ${OUT} cmd/gobgpdump/gobgpdump.go;

build: gobgpdump

clean:
	rm -f ${OUT}
