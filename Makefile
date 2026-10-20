VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: run build test kali dist clean

run:            ## 本地运行（http://127.0.0.1:8080）
	go run .

build:          ## 编译当前平台
	go build -ldflags "$(LDFLAGS)" -o bin/go-scan-ui .

test:
	go vet ./... && go test ./...

kali:           ## 交叉编译 Kali 常见架构（amd64 / arm64）
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/go-scan-ui-linux-amd64 .
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/go-scan-ui-linux-arm64 .

dist: kali      ## 编译全部平台
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/go-scan-ui-windows-amd64.exe .
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/go-scan-ui-darwin-arm64 .

clean:
	rm -rf bin dist
