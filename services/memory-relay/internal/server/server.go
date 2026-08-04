// Package server exposes relay operator endpoints.
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	metricsContentType = "text/plain; version=0.0.4; charset=utf-8"
	relayMetricsBody   = "# HELP scalevault_memory_relay_info Static service information.\n" +
		"# TYPE scalevault_memory_relay_info gauge\n" +
		"scalevault_memory_relay_info 1\n"
)

type statusResponse struct {
	Status string `json:"status"`
}

// NewHandler returns the relay's minimal fail-closed HTTP surface.
func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, statusResponse{Status: "ok"})
	})
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusServiceUnavailable, statusResponse{Status: "not_ready"})
	})
	mux.HandleFunc("GET /metrics", func(writer http.ResponseWriter, _ *http.Request) {
		writeMetrics(writer, relayMetricsBody)
	})
	return mux
}

func writeJSON(writer http.ResponseWriter, status int, value statusResponse) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeMetrics(writer http.ResponseWriter, body string) {
	writer.Header().Set("Content-Type", metricsContentType)
	writer.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(writer, body)
}
