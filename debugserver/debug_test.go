package debugserver

import (
	"testing"

	"github.com/gorilla/mux"
	"github.com/signalfx/golib/v3/distconf"
	"github.com/stretchr/testify/assert"
)

func TestNewDebugServer(t *testing.T) {
	conf := &Config{}
	handler := mux.NewRouter()

	conf.DebugPort = 123456
	server, err := NewDebugServer(conf, nil, handler)
	assert.Error(t, err, "Error when port is invalid")
	assert.Nil(t, server)

	mem := distconf.Mem()
	mem.Write("POPS_DEBUGPORT", []byte("112"))
	dconf := distconf.New([]distconf.Reader{mem})
	conf.Load(dconf)
	assert.Equal(t, int64(112), conf.DebugPort)

	conf.DebugPort = 0
	server, err = NewDebugServer(conf, nil, handler)
	assert.NoError(t, err)
	assert.NoError(t, server.Close())
}
