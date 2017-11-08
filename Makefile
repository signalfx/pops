GO_VERSION=1.9

default: binary

with-container: # run a go distributed docker container and build for the target os inside the container
	docker run --rm -t -e GOOS=linux -v $(CURDIR):/usr/local/go/src/github.com/signalfx/pops -w /usr/local/go/src/github.com/signalfx/pops golang:$(GO_VERSION) make in-container

in-container:
	make setup-build-tools
	make gobuild
	make race
	make binary

setup-build-tools:
	go get -u github.com/signalfx/gobuild
	gobuild install
	gometalinter --install

gobuild:
	gobuild --verbose check

race:
	go test -race ./...

binary: # create an output directory and build the binaries for the desired version
	mkdir -p $(CURDIR)/output/$(GOOS)
	CGO_ENABLED=0 go build -v -o $(CURDIR)/output/$(GOOS)/pops $(CURDIR)/cmd/pops/pops.go

container: with-container # build container for pops service
	docker build -f $(CURDIR)/Dockerfile -t quay.io/signalfx/pops .
