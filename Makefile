GO ?= go
NPM ?= npm
GOCACHE ?= $(CURDIR)/.cache/go-build
GO_BUILD_FLAGS ?= -buildvcs=false

export GOCACHE

BIN_DIR := bin
WEBUI_DIR := webui

GO_SOURCES := $(shell find cmd internal -name '*.go')

.PHONY: all build deps web go test

all: build

build: web go

deps: $(WEBUI_DIR)/node_modules/.package-lock.json

$(WEBUI_DIR)/node_modules/.package-lock.json: $(WEBUI_DIR)/package.json $(WEBUI_DIR)/package-lock.json
	$(NPM) --prefix $(WEBUI_DIR) ci

web: deps
	$(NPM) --prefix $(WEBUI_DIR) run build

go: $(BIN_DIR)/autofuzz $(BIN_DIR)/autofuzz-web

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/autofuzz: $(GO_SOURCES) | $(BIN_DIR)
	$(GO) build $(GO_BUILD_FLAGS) -o $@ ./cmd/autofuzz

$(BIN_DIR)/autofuzz-web: web $(GO_SOURCES) | $(BIN_DIR)
	$(GO) build $(GO_BUILD_FLAGS) -o $@ ./cmd/autofuzz-web

test: web
	$(NPM) --prefix $(WEBUI_DIR) test
	$(GO) test ./...
