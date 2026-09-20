NAME = xcert
COMMIT = $(shell git rev-parse --short HEAD 2>/dev/null)
GOHOSTOS = $(shell go env GOHOSTOS)
GOHOSTARCH = $(shell go env GOHOSTARCH)
MAIN = ./cmd/xcert
PREFIX ?= $(shell go env GOPATH)
PARAMS = -v -trimpath -ldflags "-s -w -buildid="

.PHONY: all build race test vet fmt install clean

all: build

build:
	export GOTOOLCHAIN=local && \
	go build $(PARAMS) -o $(NAME) $(MAIN)

race:
	export GOTOOLCHAIN=local && \
	go build -race -o $(NAME) $(MAIN)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

install:
	go build -o $(PREFIX)/bin/$(NAME) $(PARAMS) $(MAIN)

clean:
	rm -f $(NAME)
