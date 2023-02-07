.PHONY: deps build

SHELL = /bin/bash
APP = veinmind-sensitive
CMD = cmd/

deps:
	go env -w GOPROXY=https://goproxy.io,direct && go mod tidy

build: deps
	go build -ldflags '-s -w' -v -trimpath -a -o ${APP} ${CMD}