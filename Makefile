SHELL := /bin/sh

.PHONY: build run test race bench lint

build:
	go build ./cmd/waf-server

run:
	go run ./cmd/waf-server/main.go

test:
	go test ./...

race:
	go test -race ./...

bench:
	go test -bench=. -benchtime=2s ./...

lint:
	golangci-lint run || echo "golangci-lint not installed"