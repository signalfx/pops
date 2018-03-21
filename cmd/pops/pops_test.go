package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/signalfx/golib/clientcfg"
	"github.com/signalfx/golib/distconf"
	"github.com/signalfx/golib/log"
	"github.com/signalfx/golib/sfxclient"
	"github.com/signalfx/golib/timekeeper/timekeepertest"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var osGetenv = os.Getenv

func setupServer(m *Server, overrides map[string]string) distconf.ReaderWriter {
	if m.logger == nil {
		m.logger = log.Discard
	}
	mem := distconf.Mem()
	for key, val := range overrides {
		_ = mem.Write(key, []byte(val)) // set bogus debug port
	}
	m.conf = distconf.New([]distconf.Reader{mem})
	return mem
}

func TestCoverErrorLogger(t *testing.T) {
	assert.NotPanics(t, func() {
		s := NewServer()
		s.ErrorLogger(nil).Log("hello world")
	})
}

func TestGetDefaultDims(t *testing.T) {
	Convey("Testing default dims", t, func() {
		s := NewServer()
		_ = setupServer(s, map[string]string{})
		sfxc := clientcfg.ClientConfig{}
		sfxc.Load(s.conf)
		c := &clientConfig{sfxc}
		m := popsConfig{}
		m.Load(s.conf)
		s.configs.mainConfig = m
		// c.clientConfig.SourceName = d.Str("SOURCE", "") // hostname isn't used if there's a default value for SourceName
		c.clientConfig.OsHostname = func() (string, error) {
			return "hello", nil
		}
		So(s.getDefaultDims(&c.clientConfig), ShouldResemble, map[string]string{"sf_source": "hello", "host_name": "hello"})
		c.clientConfig.OsHostname = func() (string, error) {
			return "", errors.New("nope")
		}
		So(s.getDefaultDims(&c.clientConfig), ShouldResemble, map[string]string{"sf_source": "unknown"})
	})
}

func TestSetupRetry(t *testing.T) {
	setups := []setupFunction{
		func() error {
			return nil
		},
	}
	m := NewServer()
	m.SetupRetryAttempts = 2
	m.SetupRetryDelay = time.Hour * 1000
	_ = setupServer(m, map[string]string{
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	// Should finish
	assert.NoError(t, m.setupRetry(setups))

	setups = []setupFunction{
		func() error {
			return errors.New("nope")
		},
	}

	m = NewServer()
	_ = setupServer(m, map[string]string{
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	m.SetupRetryAttempts = 2
	m.SetupRetryDelay = time.Millisecond
	// Should finish
	assert.Error(t, m.setupRetry(setups))
}

// // Incremented each setupServerZkFailure() call
// var setupIndex = int64(0)

// type metadata int
func TestMainFunction(_ *testing.T) {
	_ = setupServer(MainServerInstance, map[string]string{
		"LOG_DIR": "/tmp",
	})
	mainDoneChan := make(chan struct{})
	go func() {
		osGetenv = func(string) string {
			return ""
		}
		main()
		osGetenv = os.Getenv
		mainDoneChan <- struct{}{}
	}()
	<-MainServerInstance.setupDone
	MainServerInstance.Close()
	<-mainDoneChan
	MainServerInstance = NewServer()
}

func TestLogger(t *testing.T) {
	mem := distconf.Mem()
	mem.Write("LOG_DIR", []byte("/tmp"))
	l := getLogger(distconf.New([]distconf.Reader{mem}))
	assert.NotNil(t, l)
}

func TestSetupDebugServer(t *testing.T) {
	m := NewServer()
	defer m.Close()
	_ = setupServer(m, map[string]string{
		"POPS_DEBUGPORT":       "1234",
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	go m.main()
	<-m.setupDone
	// Shouldn't be able to set it up again if port 1234 is already taken
	assert.Error(t, m.setupDebugServer())
}

type errListener struct{}

func (e *errListener) Accept() (net.Conn, error) {
	return nil, errors.New("bad")
}

func (e *errListener) Addr() net.Addr {
	return nil
}

func (e *errListener) Close() error {
	return errors.New("bad")
}

func TestClose1(t *testing.T) {
	m := NewServer()
	_ = setupServer(m, map[string]string{
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	go m.main()
	<-m.setupDone
	m.httpListener.Close()
	m.httpListener = &errListener{}
	err := m.Close()
	assert.Error(t, err)
}

type doubleCheckCloseContext struct {
	context.Context
	at int
}

func (d *doubleCheckCloseContext) Done() <-chan struct{} {
	d.at++
	if d.at > 1 {
		s := make(chan struct{})
		close(s)
		return s
	}
	return d.Context.Done()
}

func TestECSMetadata(t *testing.T) {
	Convey("", t, func() {
		m := NewServer()
		meta := &ecsMetadata{
			Cluster:              "testCluster",
			ContainerInstanceARN: "testCARN",
			ContainerID:          "testCID",
			ContainerName:        "testCName",
			TaskARN:              "testARN",
			DockerContainerName:  "testDCName",
			ImageID:              "testIID",
			ImageName:            "testIName",
		}
		dims := map[string]string{}
		expected := map[string]string{
			"cluster":                "testCluster",
			"container_instance_arn": "testCARN",
			"container_id":           "testCID",
			"container_name":         "testCName",
			"task_arn":               "testARN",
			"docker_container_name":  "testDCName",
			"image_id":               "testIID",
			"image_name":             "testIName",
		}
		m.addECSDims(meta, dims)
		So(dims, ShouldResemble, expected)

	})
}

func TestScheduledService(t *testing.T) {
	Convey("With a scheduledServices", t, func() {
		c := int64(0)
		s := scheduledServices{
			closedService: make(chan struct{}),
			ErrorHandler: func(error) {
				atomic.AddInt64(&c, 1)
			},
		}
		onBlock := make(chan struct{})
		contextClosed := make(chan struct{})
		functionHappening := make(chan struct{})
		blockingBackground := func(ctx context.Context) error {
			close(functionHappening)
			<-ctx.Done()
			close(contextClosed)
			<-onBlock
			return nil
		}

		earlyClose := func(ctx context.Context) error {
			close(functionHappening)
			<-onBlock
			return errors.New("ended early")
		}
		ctx := context.Background()

		Convey("Already dead context should not block", func() {
			var can context.CancelFunc
			ctx, can = context.WithCancel(ctx)
			can()
			s.Add(ctx, nil)
		})

		Convey("We should cover checking twice", func() {
			s.Add(&doubleCheckCloseContext{Context: ctx}, nil)
			So(s.Close(), ShouldBeNil)
		})
		Convey("Double check should work", func() {
			So(s.Close(), ShouldBeNil)
			s.Add(ctx, nil)
		})

		Convey("Early close should work", func() {
			go s.Add(ctx, earlyClose)
			<-functionHappening
			close(onBlock)
			for atomic.LoadInt64(&c) == 0 {
				runtime.Gosched()
			}
			So(s.Close(), ShouldBeNil)
		})

		Convey("Early closed service should end stuff", func() {
			go s.Add(ctx, blockingBackground)
			<-functionHappening
			go func() {
				<-contextClosed
				close(onBlock)
			}()
			So(s.Close(), ShouldBeNil)
		})
	})
}

func TestMainFailSetup(t *testing.T) {
	m := NewServer()
	_ = setupServer(m, map[string]string{
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	defer m.Close()
	m.SetupRetryDelay = time.Millisecond * 1
	close(m.setupDone) // prematurely close the setupDone channel
	assert.Panics(t, m.main)
}

func TestSetupRetryFailure(t *testing.T) {
	m := NewServer()
	m.SetupRetryDelay = time.Second
	m.SetupRetryAttempts = 1
	_ = setupServer(m, map[string]string{
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	defer m.Close()
	listener, err := net.Listen("tcp", ":7891") // block the debug port
	assert.NoError(t, err)
	_ = setupServer(m, map[string]string{
		"POPS_DEBUGPORT":       "7891",
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	defer listener.Close()
	assert.EqualError(t, m.setupServer(), "listen tcp :7891: bind: address already in use")
}

func TestMainSetupFailure(t *testing.T) {
	m := NewServer()
	m.SetupRetryDelay = time.Second
	m.SetupRetryAttempts = 1
	_ = setupServer(m, map[string]string{
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	defer m.Close()
	listener, err := net.Listen("tcp", ":7891") // block the debug port
	assert.NoError(t, err)
	_ = setupServer(m, map[string]string{"POPS_DEBUGPORT": "7891"})
	defer listener.Close()
	assert.Panics(t, m.main)
}

func TestSbingestExpvar(t *testing.T) {
	m := NewServer()
	_ = setupServer(m, map[string]string{
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	defer m.Close()
	go m.main()
	<-m.setupDone

	rw := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "", nil)
	require.NoError(t, err)
	m.debugServer.ExpvarHandler.ServeHTTP(rw, req)
	require.Equal(t, http.StatusOK, rw.Code)
	require.Contains(t, rw.Body.String(), runtime.Version())
}

func TestSetupHttpServerFailure(t *testing.T) {
	m := NewServer()
	defer m.Close()
	mem := setupServer(m, map[string]string{
		"POPS_PORT":            "99999",
		"SF_SOURCE_NAME":       "pops",
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	assert.NoError(t, m.setupConfig())
	assert.Error(t, m.setupHTTPServer())

	err := mem.Write("POPS_PORT", []byte("99999"))
	assert.NoError(t, err)
	assert.Error(t, m.setupHTTPServer())
}

func TestHealthCheck(t *testing.T) {
	m := NewServer()
	_ = setupServer(m, map[string]string{
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	now := time.Now()
	stubTime := timekeepertest.NewStubClock(now)
	m.timeKeeper = stubTime
	go m.main()
	<-m.setupDone

	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/healthz", nil)
	m.server.Handler.ServeHTTP(rw, req)
	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, "OK", rw.Body.String())

	m.signalChan <- syscall.SIGTERM
	time.Sleep(time.Millisecond)

	for atomic.LoadInt32(&m.closeHeader.SetCloseHeader) == 0 {
		time.Sleep(time.Millisecond)
	}

	rw = httptest.NewRecorder()
	m.server.Handler.ServeHTTP(rw, req)
	assert.Equal(t, http.StatusNotFound, rw.Code)

	stubTime.Incr(m.configs.mainConfig.minimalGracefulWaitTime.Get())
	stubTime.Incr(time.Millisecond)
	time.Sleep(time.Millisecond)

	// In graceful shutdown, requests should send connection:close
	func() {
		rw := httptest.NewRecorder()
		body := bytes.NewBuffer([]byte(fmt.Sprintf(`
	{
	  "gauge":[{"metric":"load.shortterm", "dimensions":{"host":"i-b0ec6a41", "plugin": "load"}, "value":%d}],
	  "counter":[{"metric":"load.shortterm2", "dimensions":{"host":"i-b0ec6a41", "plugin": "load"}, "value":%d}],
	  "cumulative_counter":[{"metric":"load.shortterm3", "dimensions":{"host":"i-b0ec6a41", "plugin": "load"}, "value":%d}]
	}`, 123, 123, 123)))
		req, _ := http.NewRequest("POST", "http://localhost:8080/v2/datapoint", body)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add(sfxclient.TokenHeaderName, "ABCD")
		m.server.Handler.ServeHTTP(rw, req)
		assert.Equal(t, "Close", rw.Header().Get("Connection"))
	}()

	stubTime.Incr(m.configs.mainConfig.gracefulCheckInterval.Get())

	startingSleepTime := stubTime.Now()
	for startingSleepTime.Add(m.configs.mainConfig.silentGracefulTime.Get()).After(stubTime.Now()) {
		stubTime.Incr(m.configs.mainConfig.gracefulCheckInterval.Get())
		time.Sleep(time.Millisecond)
	}

	stubTime.Incr(m.configs.mainConfig.gracefulCheckInterval.Get())
	stubTime.Incr(m.configs.mainConfig.gracefulCheckInterval.Get())
	time.Sleep(time.Millisecond)

	// Eventually this will finish if the channel is closed
	_, ok := <-m.closeChan
	if ok {
		t.Error("Expected the channel to close")
	}
}

func TestShutdown(t *testing.T) {
	m := NewServer()
	_ = setupServer(m, map[string]string{
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
		"LOG_DIR":              "/tmp",
	})
	now := time.Now()
	stubTime := timekeepertest.NewStubClock(now)
	m.timeKeeper = stubTime
	defer m.Close()
	go m.main()
	<-m.setupDone
}

func TestEventualGracefulShutdown(t *testing.T) {
	m := NewServer()
	_ = setupServer(m, map[string]string{
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	now := time.Now()
	stubTime := timekeepertest.NewStubClock(now)
	m.timeKeeper = stubTime
	go m.main()
	<-m.setupDone

	shouldBeDoneTime := stubTime.Now().Add(m.configs.mainConfig.maxGracefulWaitTime.Get())
	m.signalChan <- syscall.SIGTERM

	for atomic.LoadInt32(&m.closeHeader.SetCloseHeader) != 1 {
		time.Sleep(time.Millisecond)
	}

	for shouldBeDoneTime.After(stubTime.Now()) {
		stubTime.Incr(m.configs.mainConfig.gracefulCheckInterval.Get())
		time.Sleep(time.Millisecond)
		func() {
			rw := httptest.NewRecorder()
			body := bytes.NewBuffer([]byte(``))
			req, _ := http.NewRequest("POST", "http://localhost:8080/v2/datapoint", body)
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add(sfxclient.TokenHeaderName, "ABCD")
			m.server.Handler.ServeHTTP(rw, req)
			assert.Equal(t, "Close", rw.Header().Get("Connection"))
		}()
	}
	stubTime.Incr(m.configs.mainConfig.gracefulCheckInterval.Get())
	stubTime.Incr(m.configs.mainConfig.gracefulCheckInterval.Get())
	stubTime.Incr(time.Millisecond)
	time.Sleep(time.Millisecond)
	stubTime.Incr(time.Millisecond)
	time.Sleep(time.Millisecond)

	select {
	case <-m.closeChan:
	default:
		panic("closeChan should be closed after a graceful shutdown")
	}
}

func TestUnauthSend(t *testing.T) {
	m := NewServer()
	_ = setupServer(m, map[string]string{
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	defer m.Close()
	go m.main()
	<-m.setupDone

	rw := httptest.NewRecorder()
	body := bytes.NewBuffer([]byte(fmt.Sprintf(`{"gauge":[{"metric":"load.shortterm", "dimensions":{"host":"i-b0ec6a41", "plugin": "load"}, "value":%d}]}`, 123)))
	req, _ := http.NewRequest("POST", "http://localhost:8080/v2/datapoint", body)
	req.Header.Add("Content-Type", "application/json")
	m.server.Handler.ServeHTTP(rw, req)
	assert.Equal(t, http.StatusUnauthorized, rw.Code)
}

func TestSendDatapointV2(t *testing.T) {
	m := NewServer()
	_ = setupServer(m, map[string]string{
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	defer m.Close()
	go m.main()
	<-m.setupDone

	rw := httptest.NewRecorder()
	body := bytes.NewBuffer([]byte(fmt.Sprintf(`
	{
	  "gauge":[{"metric":"load.shortterm", "dimensions":{"host":"i-b0ec6a41", "plugin": "load"}, "value":%d}],
	  "counter":[{"metric":"load.shortterm2", "dimensions":{"host":"i-b0ec6a41", "plugin": "load"}, "value":%d}],
	  "cumulative_counter":[{"metric":"load.shortterm3", "dimensions":{"host":"i-b0ec6a41", "plugin": "load"}, "value":%d}]
	}`, 123, 123, 123)))
	req, _ := http.NewRequest("POST", "http://localhost:8080/v2/datapoint", body)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(sfxclient.TokenHeaderName, "ABCD")
	m.server.Handler.ServeHTTP(rw, req)

	// Will get dropped
	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, `"OK"`, rw.Body.String())
}

func TestSendDatapointV1(t *testing.T) {
	m := NewServer()
	_ = setupServer(m, map[string]string{
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	defer m.Close()
	go m.main()
	<-m.setupDone

	rw := httptest.NewRecorder()
	body := bytes.NewBuffer([]byte(fmt.Sprintf(`{"value":123, "metric":"m1", "source":"hi2"}{"metric":"m2", "source":"hi2", "value":1234}`)))
	req, _ := http.NewRequest("POST", "http://localhost:8080/v1/datapoint", body)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(sfxclient.TokenHeaderName, "ABCD")
	m.server.Handler.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, `"OK"`, rw.Body.String())
}

func TestDecodeDatapointsBadDecoder(t *testing.T) {
	m := NewServer()
	_ = setupServer(m, map[string]string{
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	defer m.Close()
	go m.main()
	<-m.setupDone

	rw := httptest.NewRecorder()
	body := bytes.NewBuffer([]byte(`INVALID_BODY`))
	req, _ := http.NewRequest("POST", "http://localhost:8080/v1/collectd", body)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(sfxclient.TokenHeaderName, "ABCD")
	m.server.Handler.ServeHTTP(rw, req)
	assert.Equal(t, http.StatusBadRequest, rw.Code)
}

func TestSendCollectdDatapoint(t *testing.T) {
	m := NewServer()
	_ = setupServer(m, map[string]string{
		"NUM_DRAINING_THREADS": "2",
		"CHANNEL_SIZE":         "10",
		"MAX_DRAIN_SIZE":       "50",
	})
	defer m.Close()
	go m.main()
	<-m.setupDone

	rw := httptest.NewRecorder()
	body := bytes.NewBuffer([]byte(testCollectdBody))
	req, _ := http.NewRequest("POST", "http://localhost:8080/v1/collectd", body)
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth("auth", "ABCDEFG")
	m.server.Handler.ServeHTTP(rw, req)
	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, `"OK"`, rw.Body.String())
}

func BenchmarkBadAuthToken(b *testing.B) {
	m := NewServer()
	_ = setupServer(m, map[string]string{})
	defer m.Close()
	go m.main()
	<-m.setupDone

	bodyBytes := []byte(fmt.Sprintf(`
	{
	  "gauge":[{"metric":"load.shortterm", "dimensions":{"host":"i-b0ec6a41", "plugin": "load"}, "value":%d}]
	}`, 123))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		req, _ := http.NewRequest("POST", "http://localhost:8080/v2/datapoint", bytes.NewBuffer(bodyBytes))
		rw := httptest.NewRecorder()
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add(sfxclient.TokenHeaderName, "ABCD")
		b.StartTimer()
		m.server.Handler.ServeHTTP(rw, req)
		b.StopTimer()
		assert.Equal(b, http.StatusUnauthorized, rw.Code)
	}
}

const testCollectdBody = `[
    {
        "dsnames": [
            "shortterm",
            "midterm",
            "longterm"
        ],
        "dstypes": [
            "gauge",
            "gauge",
            "gauge"
        ],
        "host": "i-b13d1e5f",
        "interval": 10.0,
        "plugin": "load",
        "plugin_instance": "",
        "time": 1415062577.4960001,
        "type": "load",
        "type_instance": "",
        "values": [
            0.37,
            0.60999999999999999,
            0.76000000000000001
        ]
    },
    {
        "dsnames": [
            "value"
        ],
        "dstypes": [
            "gauge"
        ],
        "host": "i-b13d1e5f",
        "interval": 10.0,
        "plugin": "memory",
        "plugin_instance": "",
        "time": 1415062577.4960001,
        "type": "memory",
        "type_instance": "used",
        "values": [
            1524310000.0
        ]
    },
    {
        "dsnames": [
            "value"
        ],
        "dstypes": [
            "derive"
        ],
        "host": "i-b13d1e5f",
        "interval": 10.0,
        "plugin": "df",
        "plugin_instance": "dev",
        "time": 1415062577.4949999,
        "type": "df_complex",
        "type_instance": "free",
        "values": [
            1962600000.0
        ]
    },
    {
        "dsnames": [
            "value"
        ],
        "dstypes": [
            "gauge"
        ],
        "host": "mwp-signalbox[a=b]",
        "interval": 10.0,
        "plugin": "tail",
        "plugin_instance": "analytics[f=x]",
        "time": 1434477504.484,
        "type": "memory",
        "type_instance": "old_gen_end[k1=v1,k2=v2]",
        "values": [
            26790
        ]
    },
    {
        "dsnames": [
            "value"
        ],
        "dstypes": [
            "gauge"
        ],
        "host": "mwp-signalbox[a=b]",
        "interval": 10.0,
        "plugin": "tail",
        "plugin_instance": "analytics[f=x]",
        "time": 1434477504.484,
        "type": "memory",
        "type_instance": "total_heap_space[k1=v1,k2=v2]",
        "values": [
            1035520.0
        ]
    },
    {
        "dsnames": [
            "value"
        ],
        "dstypes": [
            "gauge"
        ],
        "host": "some-host",
        "interval": 10.0,
        "plugin": "dogstatsd",
        "plugin_instance": "[env=dev,k1=v1]",
        "time": 1434477504.484,
        "type": "gauge",
        "type_instance": "page.loadtime",
        "values": [
            12.0
        ]
    },
    {
        "host": "mwp-signalbox",
        "message": "my message",
        "meta": {
            "key": "value"
        },
        "plugin": "my_plugin",
        "plugin_instance": "my_plugin_instance[f=x]",
        "severity": "OKAY",
        "time": 1435104306.0,
        "type": "imanotify",
        "type_instance": "notify_instance[k=v]"
    },
    {
        "time": 1436546167.739,
        "severity": "UNKNOWN",
        "host": "mwp-signalbox",
        "plugin": "tail",
        "plugin_instance": "quantizer",
        "type": "counter",
        "type_instance": "exception[level=error]",
        "message": "the value was found"
    }
]`
