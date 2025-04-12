package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const sampleToken = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiw..."

func TestPermissionHandler_OK(t *testing.T) {
	cfg := &Config{
		TokenEndpoint: "http://localhost:8080/realms/demo/protocol/openid-connect/token",
		ClientID:      "traefik-gateway-client",
	}

	ctx := context.Background()

	mockNext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler, err := New(ctx, mockNext, cfg, "AuthzGateway")
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/user/getAll", nil)
	req.Header.Set("X-Auth-Request-Access-Token", sampleToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", recorder.Code)
	}
}
