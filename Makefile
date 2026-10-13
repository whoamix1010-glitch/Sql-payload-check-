BIN      := floppy
PKG      := ./cmd/floppy
VERSION  := 1.0.0
LDFLAGS  := -s -w -X main.version=$(VERSION)

.PHONY: all build run dash install clean test vet

all: build

build: ## Build the static binary into ./bin/floppy
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/$(BIN) $(PKG)

run: build ## Build then launch the dashboard
	./bin/$(BIN)

dash: run ## Alias for run

install: ## Install to $GOBIN / $GOPATH/bin
	CGO_ENABLED=0 go install -ldflags="$(LDFLAGS)" $(PKG)

vet: ## go vet
	go vet ./...

test: ## Run tests
	go test ./...

clean: ## Remove build artifacts
	rm -rf bin
