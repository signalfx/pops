GO_VERSION = 1.11.4

.PHONY: deafult
default: build

.PHONY: vendor
vendor:
	# vendors modules
	docker run --rm -t \
		-e GOOS=linux \
		-e GO111MODULE=on \
		-v $(CURDIR):/go/src/github.com/signalfx/pops \
		-w /go/src/github.com/signalfx/pops \
		golang:$(GO_VERSION) go mod vendor

.PHONY: install-build-tools
install-build-tools:
	# install tools used for building
	# we want to install gobuild and gometalinter
	# without adding them to this project's modules
	# leave GO111MODULE off to avoid this
	go get -u github.com/signalfx/gobuild
	gobuild install
	gometalinter --install

.PHONY: clean
clean:
	# remove previous output
	rm -rf $(CURDIR)/output

.PHONY: gobuild
gobuild:
	# run gobuild to do everything except build
	#
	# Leave GO111MODULE off becuase gometalinter and down stream
	# linters do not adquately support modules yet...
	# See: https://github.com/alecthomas/gometalinter/issues/562
	gobuild list
	gobuild lint
	gobuild dupl
	gobuild test

.PHONY: build
build: clean
	# build to a target directory with cgo disabled
	mkdir -p $(CURDIR)/output/$(GOOS)
	# turn on GO111MODULE and set -mod flag to "vendor" to build using the vendored dependencies
	GO111MODULE=on CGO_ENABLED=0 GOOS=$(GOOS) go build -mod=vendor -v -o $(CURDIR)/output/$(GOOS)/pops $(CURDIR)/cmd/pops/pops.go
	ls -la $(CURDIR)/output/$(GOOS)/

.PHONY: with-container
with-container:
	# run a go distributed docker container and build for the target os inside the container
	# turn off GO111MODULE because most of gobuild and linters are not compatible
	# This is ok, becuase we still vendor our dependencies with go mod
	# so the linters can rely on the vendored deps
	docker run --rm -t \
		-e GOOS=linux \
		-e GO111MODULE=off \
		-v $(CURDIR):/go/src/github.com/signalfx/pops \
		-w /go/src/github.com/signalfx/pops \
		golang:$(GO_VERSION) /bin/bash -c "set -e; make install-build-tools; make gobuild; make build"

.PHONY: buildInfo
buildInfo:
	# generate build info to be stored in the pops container
	sh $(CURDIR)/buildInfo.sh

.PHONY: container
container: buildInfo with-container
	# build container for pops service
	docker build --no-cache -f $(CURDIR)/Dockerfile -t quay.io/signalfx/pops:$(shell git describe --tags) .

