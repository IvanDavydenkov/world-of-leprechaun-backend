package vpnclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyUsesTrustedActorAndServiceIdentity(t *testing.T) {
	token := strings.Repeat("s", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Service-Token") != token || r.Header.Get("X-Actor-ID") != "admin-id" || r.Header.Get("Idempotency-Key") != "key" {
			t.Error("trusted identity not forwarded")
		}
		if r.Header.Get("Cookie") != "" {
			t.Error("browser session forwarded to VPN")
		}
		w.Header().Set("Location", "/admin/users/owner/config-operations/op")
		w.WriteHeader(202)
		_, _ = w.Write([]byte("{\"operation_id\":\"op\"}"))
	}))
	defer server.Close()
	client, err := New(server.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Forward(context.Background(), "admin-id", "POST", "/admin/users/owner/configs", "key", []byte("{\"count\":2}"))
	if err != nil || response.Status != 202 || response.Location == "" {
		t.Fatalf("%+v %v", response, err)
	}
}
