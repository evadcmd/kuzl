package telemetry

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// captureStderr runs f and returns what it wrote to os.Stderr.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()
	f()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// setEnv sets the OTEL_* variables Setup reads to env, clearing the others.
func setEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for _, k := range []string{
		"OTEL_SDK_DISABLED",
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
		"OTEL_LOGS_EXPORTER",
		"OTEL_EXPORTER_OTLP_PROTOCOL",
		"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
	} {
		t.Setenv(k, env[k])
	}
}

func TestSetupExports(t *testing.T) {
	tests := []map[string]string{
		{},
		{"OTEL_LOGS_EXPORTER": "console,otlp"},
		{"OTEL_EXPORTER_OTLP_PROTOCOL": "grpc", "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL": "http/protobuf"},
	}
	for _, env := range tests {
		got := make(chan string, 10)
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			got <- r.URL.Path + " " + string(body)
		}))
		env["OTEL_EXPORTER_OTLP_ENDPOINT"] = srv.URL
		setEnv(t, env)

		logger, shutdown := Setup(context.Background())
		logger.Info("hello from the test")
		shutdown()
		srv.Close()

		select {
		case req := <-got:
			if want := "/v1/logs "; len(req) < len(want) || req[:len(want)] != want {
				t.Errorf("env %v: collector got %.80q, want a request to /v1/logs", env, req)
			}
		default:
			t.Errorf("env %v: nothing was exported", env)
		}
	}
}

func TestSetupDisabled(t *testing.T) {
	const endpoint = "http://127.0.0.1:1"
	tests := []map[string]string{
		{},
		{"OTEL_EXPORTER_OTLP_ENDPOINT": endpoint, "OTEL_SDK_DISABLED": "true"},
		{"OTEL_EXPORTER_OTLP_ENDPOINT": endpoint, "OTEL_LOGS_EXPORTER": "none"},
		{"OTEL_EXPORTER_OTLP_ENDPOINT": endpoint, "OTEL_LOGS_EXPORTER": "console"},
		{"OTEL_EXPORTER_OTLP_ENDPOINT": endpoint, "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc"},
		{"OTEL_EXPORTER_OTLP_ENDPOINT": endpoint, "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL": "http/json"},
	}
	for _, env := range tests {
		setEnv(t, env)
		logger, shutdown := Setup(context.Background())
		if logger.Enabled(context.Background(), 0) {
			t.Errorf("env %v: the logger is enabled, want it to discard", env)
		}
		shutdown()
	}
}

// An unreachable collector must neither print anything nor hold up the exit
// for longer than shutdownTimeout.
func TestSetupUnreachable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	setEnv(t, map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://" + addr})
	checkShutdown(t)
}

// A collector that accepts the request and never answers is what
// shutdownTimeout is for: the exit must still not wait longer than that.
func TestSetupHangingCollector(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// release is closed first, or srv.Close would wait for the handler.
	defer srv.Close()
	defer close(release)
	setEnv(t, map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": srv.URL})
	checkShutdown(t)
}

// checkShutdown logs a record and checks that the flush prints nothing and
// gives up within about shutdownTimeout.
func checkShutdown(t *testing.T) {
	t.Helper()
	var took time.Duration
	out := captureStderr(t, func() {
		logger, shutdown := Setup(context.Background())
		logger.Info("lost")
		start := time.Now()
		shutdown()
		took = time.Since(start)
	})
	if out != "" {
		t.Errorf("stderr got %q, want nothing", out)
	}
	if took > shutdownTimeout+time.Second {
		t.Errorf("shutdown took %v, want at most about %v", took, shutdownTimeout)
	}
}
