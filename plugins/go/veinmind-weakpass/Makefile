.PHONY: deps build

SHELL = /bin/bash
APP = veinmind-weakpass
CMD = cmd/cli.go
TAGS = dynamic

deps:
	go env -w GOPROXY=https://goproxy.io,direct && go mod tidy

build: deps
	go build -ldflags '-s -w' -trimpath -tags ${TAGS} -a -o ${APP} ${CMD}

build-arm64: deps
	sudo apt-get update && sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
	sudo apt-get install libssl-dev
	export CC="aarch64-linux-gnu-gcc" CXX="aarch64-linux-gnu-g++"
	export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig
	export CGO_ENABLED=1 GOOS="$CI_GOOS" GOARCH="$CI_GOARCH" TAGS="$TAGS"
	go build -ldflags '-s -w' -trimpath -tags ${TAGS} -a -o ${APP} ${CMD}