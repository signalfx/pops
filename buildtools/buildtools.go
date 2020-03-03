// +build tools

package buildtools

//  The go.mod and go.sum were getting modified by the verification process.  Installing gocov and other build tools
//  would update the go.mod, but then running go mod tidy would remove them.  To avoid this back and forth
//  (and to help with git diff-ing for changes) this module imports any tools that we need to go get in order to to
//  test/vet.
//
//	see: https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module


import (
	_ "github.com/jstemmer/go-junit-report"
	_ "github.com/signalfx/gobuild"
)