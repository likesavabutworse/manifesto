BINARY := manifesto
BIN_DIR := bin

VERSION ?= dev

.PHONY: all build test vet fmt fmt-check clean install

all: fmt-check vet test build

build:
	go build -o $(BIN_DIR)/$(BINARY) ./cmd/manifesto

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi

install:
	go install ./cmd/manifesto

clean:
	rm -rf $(BIN_DIR)
