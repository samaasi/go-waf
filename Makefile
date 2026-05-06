SHELL := /bin/sh

.PHONY: build run test race bench lint

build:
	go build ./cmd/server

run:
	go run ./cmd/server/main.go

test:
	go test ./...

race:
	go test -race ./...

bench:
	go test -bench=. -benchtime=2s ./...

lint:
	golangci-lint run || echo "golangci-lint not installed"

fetch-crs:
	rm -rf tmp/crs
	git clone -b v3.3/master https://github.com/coreruleset/coreruleset.git tmp/crs

compile-crs:
	go run cmd/seclang-compiler/main.go --input tmp/crs/rules --output configs/rules/owasp-crs