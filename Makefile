GO_VERSION = 1.14
GOLANGCI_LINT_VERSION=1.23.7

# set goos by detecting environment
# this is useful for cross compiling in linux container for local os
ifeq ($(GOOS), "")
	ifeq ($(OS), Windows_NT)
		GOOS=windows
	else
		ifeq ($(shell uname -s),Linux)
			GOOS=linux
		else
			GOOS=darwin
		endif
	endif
endif

.PHONY: deafult
default: build

.PHONY: install-gobuild
install-gobuild:
	go get github.com/jstemmer/go-junit-report
	go get github.com/signalfx/gobuild

.PHONY: install-golangci-lint
install-golangci-lint:
	curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(shell go env GOPATH)/bin v${GOLANGCI_LINT_VERSION}

.PHONY: install-build-tools
install-build-tools: install-gobuild install-golangci-lint
#	# install tools used for building
#	# we must explicitly turn on GO111MODULE to install packages with a version number
#	# see: https://github.com/golang/go/issues/29415

.PHONY: vendor
vendor:
	# vendors modules
	docker run --rm -t \
		-e GOOS=$(GOOS) \
		-e GO111MODULE=on \
		-v $(CURDIR):/go/src/github.com/signalfx/pops \
		-w /go/src/github.com/signalfx/pops \
		golang:$(GO_VERSION) /bin/bash -c "go mod tidy; go mod vendor"

.PHONY: test
test:
	GO111MODULE=on gobuild test

.PHONY: test-in-container
test-in-container:
	docker run --rm -t \
		-e GO111MODULE=on \
		-v $(CURDIR):/go/src/github.com/signalfx/pops \
        -w /go/src/github.com/signalfx/pops \
        golang:$(GO_VERSION) /bin/bash -c "make install-gobuild; make test"

.PHONY: lint
lint:
	golangci-lint run

.PHONY: lint-in-container
lint-in-container:
	docker run --rm -t \
		-v $(CURDIR):/go/src/github.com/signalfx/pops \
		-w /go/src/github.com/signalfx/pops \
		golang:$(GO_VERSION) /bin/bash -c "make install-golangci-lint; make lint"

.PHONY: clean
clean:
	# remove previous output
	rm -rf $(CURDIR)/output/*

.PHONY: build-info
build-info:
	# generate build info to be stored in the pops container
	sh $(CURDIR)/scripts/buildInfo.sh

.PHONY: build
build: clean
	# build to a target directory
	mkdir -p $(CURDIR)/output/$(GOOS)
	# turn on GO111MODULE and set -mod flag to "vendor" to build using the vendored dependencies
	GO111MODULE=on CGO_ENABLED=0 GOOS=$(GOOS) go build -mod=vendor -v -o $(CURDIR)/output/$(GOOS)/pops $(CURDIR)/cmd/pops.go
	ls -la $(CURDIR)/output/$(GOOS)/

.PHONY: build-in-container
build-in-container:
	# run a go distributed docker container and build for the target os inside the container
	docker run --rm -t \
		-e GOOS=$(GOOS) \
		-e GO111MODULE=on \
		-v $(CURDIR):/go/src/github.com/signalfx/pops \
		-w /go/src/github.com/signalfx/pops \
		golang:$(GO_VERSION) /bin/bash -c "set -e; make build"

.PHONY: container
container: clean
	# build container for pops service
	docker build --no-cache -f $(CURDIR)/Dockerfile --build-arg GO_VERSION=$(GO_VERSION) --target=final -t quay.io/signalfx/pops:$(shell git describe --tag) .


