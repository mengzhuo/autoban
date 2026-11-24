BIN := bin
GO ?= go
VERSION ?= $(shell sed -n 's/.*const Version = "\([^"]*\)".*/\1/p' internal/engine/engine.go)

.PHONY: all build test race vet demo deb apk packages clean clean-packages

all: build

build:
	mkdir -p $(BIN)
	$(GO) build -trimpath -o $(BIN)/autoban ./cmd/autoban
	$(GO) build -trimpath -o $(BIN)/autoban-ctl ./cmd/autoban-ctl
	$(GO) build -trimpath -o $(BIN)/autoban-regex ./cmd/autoban-regex

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

demo: build
	./scripts/demo.sh

deb:
	VERSION=$(VERSION) ./scripts/build-deb.sh

apk:
	VERSION=$(VERSION) ./scripts/build-apk.sh

packages: deb apk

clean:
	rm -rf $(BIN)

clean-packages:
	rm -rf dist
