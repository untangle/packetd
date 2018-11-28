build:
	go get -d -v ./...
	go build -ldflags "-X main.Version=$(shell git describe --tags --always --long --dirty)"

.PHONY: build
