VERSION ?= $(shell cat VERSION)
GO ?= go
LDFLAGS := -s -w -X main.version=$(VERSION) -X github.com/ridd1e1337/sb-manager-web/internal/agent.Version=$(VERSION)

.PHONY: all fmt test vet build release clean

all: test build

fmt:
	gofmt -w cmd internal tests web

test:
	CGO_ENABLED=0 $(GO) test ./...

vet:
	CGO_ENABLED=0 $(GO) vet ./...

build: fmt vet test
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/sb-web-linux-amd64 ./cmd/sb-web

release: fmt vet test
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/sb-web-linux-amd64 ./cmd/sb-web
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/sb-web-linux-arm64 ./cmd/sb-web
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/sb-web-linux-armv7 ./cmd/sb-web
	cd dist && sha256sum sb-web-linux-* > SHA256SUMS

clean:
	rm -rf dist
