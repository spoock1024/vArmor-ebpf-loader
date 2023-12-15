export GO111MODULE=on
export PATH := $(shell go env GOPATH)/bin:$(shell go env GOROOT)/bin:$(PATH)



all: clean build run

build:
	@echo "Building..."
	go build -ldflags "-s -w" -o bin/varmor_socket_connect ./...


clean:
	@echo "Cleaning..."
	rm -rf bin/varmor_socket_connect


run:
	@echo "Running as root..."
	 ./bin/varmor_socket_connect
