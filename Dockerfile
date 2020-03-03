ARG GO_VERSION=1.14

# download build tools
FROM golang:${GO_VERSION} AS build-tools
ENV GO111MODULE=on
COPY ./Makefile /usr/src/github.com/signalfx/pops/Makefile
WORKDIR /usr/src/github.com/signalfx/pops
RUN go version
RUN make install-build-tools

# lint using golangci-lint
FROM build-tools AS lint
COPY . /usr/src/github.com/signalfx/pops
WORKDIR /usr/src/github.com/signalfx/pops
RUN gobuild list
RUN make lint

# test using gobuild
FROM build-tools AS test
COPY . /usr/src/github.com/signalfx/pops
WORKDIR /usr/src/github.com/signalfx/pops
RUN gobuild list
RUN gobuild test

# build
FROM build-tools AS build
ENV BUILDER=docker
COPY . /usr/src/github.com/signalfx/pops
WORKDIR /usr/src/github.com/signalfx/pops
RUN go version
RUN BUILDER=docker make build-info
RUN cat buildInfo.json
RUN make build

# get the latest ca cert bundle
FROM centos:7 as certs
RUN update-ca-trust

# final build
FROM scratch AS final
COPY --from=certs /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
COPY --from=build /usr/src/github.com/signalfx/pops/output/pops /pops
COPY --from=build /usr/src/github.com/signalfx/pops/buildInfo.json /buildInfo.json
CMD ["/pops"]
