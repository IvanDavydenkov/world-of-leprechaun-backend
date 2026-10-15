package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthAndReadinessDuringStorageOutage(t *testing.T) {
	router := NewRouter(func(context.Context) error { return errors.New("private database detail") })
	for _, tc := range []struct {
		path   string
		status int
		body   string
	}{
		{"/healthz", http.StatusOK, "{\"status\":\"ok\"}\n"},
		{"/readyz", http.StatusServiceUnavailable, "{\"status\":\"unavailable\"}\n"},
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if response.Code != tc.status || response.Body.String() != tc.body {
			t.Fatalf("%s: status=%d body=%q", tc.path, response.Code, response.Body.String())
		}
	}
}

func TestReadinessWhenStorageAvailable(t *testing.T) {
	router := NewRouter(func(context.Context) error { return nil })
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
}
