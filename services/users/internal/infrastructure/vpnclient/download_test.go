package vpnclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOwnDownloadPreservesFileAndHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/me/configs/own/download" || r.Header.Get("X-Actor-ID") != "owner" || r.Header.Get("Cookie") != "" {
			t.Error("untrusted forwarding")
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=config-own.conf")
		w.Write([]byte("private-file"))
	}))
	defer server.Close()
	client, err := New(server.URL, strings.Repeat("s", 40))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Forward(context.Background(), "owner", "GET", "/me/configs/own/download", "", nil)
	if err != nil || response.Status != 200 || string(response.Body) != "private-file" || response.Disposition != "attachment; filename=config-own.conf" || response.ContentType != "application/octet-stream" {
		t.Fatal("download forwarding failed", err)
	}
}
