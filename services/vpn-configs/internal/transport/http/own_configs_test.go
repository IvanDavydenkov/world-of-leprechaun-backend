package http

import (
	"context"
	"leprechaun/vpn-configs/internal/application"
	"leprechaun/vpn-configs/internal/domain"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOwnInternalRoutesAuthenticateAndDownload(t *testing.T) {
	store := &apiStore{account: domain.Account{Configs: []domain.ManagedConfig{{ID: "own", Desired: true, Provisioned: true, Generation: "g", Version: 1}}}}
	m := application.NewManager(store, apiAccess{}, nil, apiFiles{}, nil, time.Now)
	token := strings.Repeat("s", 40)
	router := NewRouter(func(context.Context) error { return nil }, NewBatchAPI(m, token).Register)
	for _, tc := range []struct {
		path, secret, actor string
		status              int
	}{{"/me/configs", "", "owner", 401}, {"/me/configs", token, "owner", 200}, {"/me/configs/own/download", token, "owner", 200}, {"/me/configs/foreign/download", token, "owner", 404}, {"/me/configs/own/download", token, "unknown", 404}} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.Header.Set("X-Service-Token", tc.secret)
		r.Header.Set("X-Actor-ID", tc.actor)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatal(tc.path, w.Code, w.Body.String())
		}
		if tc.path == "/me/configs/own/download" && w.Code == 200 {
			if w.Body.String() != "config" || w.Header().Get("Content-Disposition") != "attachment; filename=config-own.conf" {
				t.Fatal("download response invalid")
			}
		}
	}
}
