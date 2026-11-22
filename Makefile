BIN := bin
GO ?= go

.PHONY: all build test race vet demo clean

all: build

build:
	mkdir -p $(BIN)
	$(GO) build -trimpath -o $(BIN)/gojail ./cmd/gojail
	$(GO) build -trimpath -o $(BIN)/gj ./cmd/gj
	$(GO) build -trimpath -o $(BIN)/gj-regex ./cmd/gj-regex

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

demo: build
	./scripts/demo.sh

clean:
	rm -rf $(BIN)
