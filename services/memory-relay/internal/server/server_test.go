package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadinessFailsClosed(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()

	NewHandler().ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, response.Code)
	}
}

func TestMetricsExposeOnlyServiceInformation(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()

	NewHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, response.Code)
	}
	if contentType := response.Header().Get("Content-Type"); contentType != metricsContentType {
		t.Fatalf("expected content type %q, got %q", metricsContentType, contentType)
	}
	if body := response.Body.String(); body != relayMetricsBody {
		t.Fatalf("unexpected metrics body %q", body)
	}

	for _, forbidden := range []string{"installation", "request", "trace", "upstream", "payload"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("metrics body contains sensitive label or field %q", forbidden)
		}
	}
}
