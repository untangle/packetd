# default to vendor mod, since our minimal supported version of Go is
# 1.11
GOFLAGS ?= "-mod=vendor"

all: build-packetd build-settingsd

build-%:
	cd cmd/$* ; \
	export GO111MODULE=on ; \
	go build $(GOFLAGS) -ldflags "-X main.Version=$(shell git describe --tags --always --long --dirty)"

.PHONY: build
