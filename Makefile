BIN := webdav-server
LDFLAGS := -s -w -X main.Version=$(shell date "+%Y%m%d%H%M") -X main.GitCommit=$(shell git rev-parse HEAD)

run: build
	./build/debug/$(BIN) --conf webdav-server-local.yaml | jq

build: 
	go build -race -ldflags "$(LDFLAGS)" -o build/debug/$(BIN) main.go

build-release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o build/release/$(BIN) main.go

clean:
	rm -fr build/debug/ build/release/

.PHONY: run build build-release clean 
