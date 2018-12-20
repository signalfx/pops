GO_VERSION = 1.11.4

.PHONY: deafult
default: build

.PHONY: vendor
vendor:
	# vendors modules
	docker run --rm -t \
		-e GOOS=linux \
		-v $(CURDIR):/usr/local/go/src/github.com/signalfx/pops \
		-w /usr/local/go/src/github.com/signalfx/pops \
		golang:$(GO_VERSION) /bin/bash -c "set -e; go mod vendor"

.PHONY: install-build-tools
install-build-tools:
	# install tools used for building
	# we want to install gobuild and gometalinter
	# without adding them to this project's modules
	# so set GO111MODULE=off
	GO111MODULE=off go get -u github.com/signalfx/gobuild
	GO111MODULE=off gobuild install
	GO111MODULE=off gometalinter --install

.PHONY: clean
clean:
	# remove previous output
	rm -rf $(CURDIR)/output

.PHONY: gobuild
gobuild:
	# run gobuild to do everything except build
	#
	# Turn off GO111MODULE becuase gometalinter and down stream
	# linters do not adquately support modules yet...
	# See: https://github.com/alecthomas/gometalinter/issues/562
	#
	# This is ok, becuase we still vendor our dependencies with go mod
	# so the linters can rely on the vendored deps
	GO111MODULE=off gobuild list
	GO111MODULE=off gobuild lint
	GO111MODULE=off gobuild dupl
	GO111MODULE=off gobuild test

.PHONY: build
build: clean
	# build to a target directory with cgo disabled
	mkdir -p $(CURDIR)/output/$(GOOS)
	# set -mod flag to "vendor" to build using the vendored dependencies
	CGO_ENABLED=0 GOOS=$(GOOS) go build -mod=vendor -v -o $(CURDIR)/output/$(GOOS)/pops $(CURDIR)/cmd/pops/pops.go
	ls -la $(CURDIR)/output/$(GOOS)/

.PHONY: with-container
with-container:
	# run a go distributed docker container and build for the target os inside the container
	docker run --rm -t \
		-e GOOS=linux \
		-v $(CURDIR):/usr/local/go/src/github.com/signalfx/pops \
		-w /usr/local/go/src/github.com/signalfx/pops \
		golang:$(GO_VERSION) /bin/bash -c "set -e; make install-build-tools; make gobuild; make build"

.PHONY: buildInfo
buildInfo:
	# generate build info to be stored in the pops container
	sh $(CURDIR)/buildInfo.sh

.PHONY: container
container: buildInfo with-container
	# build container for pops service
	docker build --no-cache -f $(CURDIR)/Dockerfile -t quay.io/signalfx/pops:$(shell git describe --tags) .

