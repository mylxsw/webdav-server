BIN := webdav-server
LDFLAGS := -s -w -X main.Version=$(shell date "+%Y%m%d%H%M") -X main.GitCommit=$(shell git rev-parse HEAD)

run: build-server
	./build/debug/$(BIN) --conf webdav-server-local.yaml | jq

build-server:
	go build -race -ldflags "$(LDFLAGS)" -o build/debug/$(BIN) cmd/server/main.go

build-tool:
	go build -race -ldflags "$(LDFLAGS)" -o build/debug/$(BIN)-tool cmd/tool/main.go

build-release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o build/release/$(BIN) cmd/server/main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o build/release/$(BIN)-tool cmd/tool/main.go
clean:
	rm -fr build/debug/ build/release/

.PHONY: run build build-release clean build-server build-tool
