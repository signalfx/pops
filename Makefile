GO_VERSION = 1.11.0

.PHONY: deafult
default: build

.PHONY: install-build-tools
install-build-tools:
	# install tools used for building
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
	# we build in the build target with custom options
	gobuild list
	gobuild lint
	gobuild dupl
	gobuild test

.PHONY: build
build: clean
	# build to a target directory with cgo disabled
	mkdir -p $(CURDIR)/output/$(GOOS)
	CGO_ENABLED=0 GOOS=$(GOOS) go build -v -o $(CURDIR)/output/$(GOOS)/pops $(CURDIR)/cmd/pops/pops.go
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
