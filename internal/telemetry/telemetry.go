// Package telemetry sends kuzl's own logs over OTLP, to where the agent that
// runs kuzl can't see them. curl prints no such logs, so kuzl mustn't either:
// nothing here ever writes to stdout or stderr, and without an OTLP endpoint
// configured the logs are dropped.
package telemetry

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
)

// serviceName is the service.name the logs carry unless OTEL_SERVICE_NAME or
// OTEL_RESOURCE_ATTRIBUTES say otherwise.
const serviceName = "kuzl"

// shutdownTimeout bounds how long the exit waits for the logs to be sent, so
// that an unreachable collector doesn't hang every command.
const shutdownTimeout = 2 * time.Second

// Setup returns a logger exporting over OTLP/HTTP, configured by the standard
// OTEL_* variables, and a func that flushes it, to be called before exiting.
// The logger discards everything if OTEL_SDK_DISABLED is true, no OTLP
// endpoint is set, OTEL_LOGS_EXPORTER doesn't include otlp, or the exporter
// can't be created.
//
// Only OTLP/HTTP with protobuf is supported. A protocol other than
// http/protobuf in OTEL_EXPORTER_OTLP_LOGS_PROTOCOL or
// OTEL_EXPORTER_OTLP_PROTOCOL also discards everything, rather than sending
// HTTP requests that a gRPC collector would reject.
func Setup(ctx context.Context) (*slog.Logger, func()) {
	discard := slog.New(slog.DiscardHandler)
	if !enabled() {
		return discard, func() {}
	}
	// The SDK reports its errors, such as a failed export, to stderr by
	// default.
	otel.SetLogger(logr.Discard())
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) {}))

	exporter, err := otlploghttp.New(ctx)
	if err != nil {
		return discard, func() {}
	}
	// resource.WithFromEnv comes last so the OTEL_* variables win.
	// The error is ignored: with a non-nil resource it only reports a partial
	// resource, which still works.
	res, _ := resource.New(ctx,
		resource.WithTelemetrySDK(),
		resource.WithAttributes(semconv.ServiceName(serviceName)),
		resource.WithFromEnv(),
	)
	if res == nil {
		res = resource.Empty()
	}
	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
		sdklog.WithResource(res),
	)
	logger := slog.New(otelslog.NewHandler(serviceName, otelslog.WithLoggerProvider(provider)))
	return logger, func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		_ = provider.Shutdown(ctx)
	}
}

func enabled() bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("OTEL_SDK_DISABLED")), "true") {
		return false
	}
	if !otlpExporter() || !httpProtobuf() {
		return false
	}
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT") != ""
}

// otlpExporter reports whether OTEL_LOGS_EXPORTER, a comma-separated list
// defaulting to otlp, asks for the OTLP exporter. Other exporters, such as
// console, are ignored: kuzl never writes its logs to the output.
func otlpExporter() bool {
	v := strings.TrimSpace(os.Getenv("OTEL_LOGS_EXPORTER"))
	if v == "" {
		return true
	}
	for e := range strings.SplitSeq(v, ",") {
		if strings.EqualFold(strings.TrimSpace(e), "otlp") {
			return true
		}
	}
	return false
}

// httpProtobuf reports whether the OTLP protocol for logs, defaulting to
// http/protobuf, is the one the exporter speaks.
func httpProtobuf() bool {
	p := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_LOGS_PROTOCOL"))
	if p == "" {
		p = strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"))
	}
	return p == "" || p == "http/protobuf"
}
