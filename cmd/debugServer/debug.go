package debugServer

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/gorilla/mux"
	"github.com/signalfx/golib/distconf"
	"github.com/signalfx/golib/explorable"
	"github.com/signalfx/golib/expvar2"
)

// Config configures what port the debug server listens to
type Config struct {
	DebugPort int64
}

// Load the server config values from distconf
func (c *Config) Load(d *distconf.Distconf) {
	c.DebugPort = d.Int("POPS_DEBUGPORT", 6060).Get()
}

// DebugServer listens to a private debugging port to explose internal metrics for debug purposes
type DebugServer struct {
	debugServer       *http.Server
	debugHTTPListener net.Listener
	ExpvarHandler     *expvar2.Handler
}

// NewDebugServer creates a new listener for debugging the golang server
func NewDebugServer(conf *Config, explorableObject interface{}, handler *mux.Router) (*DebugServer, error) {
	listenAddr := fmt.Sprintf(":%d", conf.DebugPort)
	clientTimeout := time.Minute * 30
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	debugHTTPListener := listener
	handler.PathPrefix("/debug/pprof/profile").HandlerFunc(pprof.Profile)
	handler.PathPrefix("/debug/pprof/trace").HandlerFunc(pprof.Trace)
	handler.PathPrefix("/debug/pprof/").HandlerFunc(pprof.Index)
	e := &explorable.Handler{
		Val:      explorableObject,
		BasePath: "/debug/explorer/",
	}
	handler.PathPrefix("/debug/explorer/").Handler(e)

	debugServer := &http.Server{
		Handler:      handler,
		Addr:         listenAddr,
		ReadTimeout:  clientTimeout,
		WriteTimeout: clientTimeout,
	}
	ret := &DebugServer{
		debugServer:       debugServer,
		debugHTTPListener: debugHTTPListener,
		ExpvarHandler:     expvar2.New(),
	}
	handler.Path("/debug/vars").Handler(ret.ExpvarHandler)
	go debugServer.Serve(debugHTTPListener)
	return ret, nil
}

// Close stops the listening server
func (d *DebugServer) Close() error {
	return d.debugHTTPListener.Close()
}
