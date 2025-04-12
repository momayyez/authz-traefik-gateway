package authztraefikgateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0MnJYRGJOb2hScWpuRkhQWmxEa1pYanZPNXhDQ2g4TlB4c2dwWTlkdDZ3In0.eyJleHAiOjE3NDQ0NDY1OTMsImlhdCI6MTc0NDQ0NjI5MywianRpIjoiMmY4NjFkMWUtM2UwZC00YWM0LTkzZDgtNjgyZmFlZmU2ZGViIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLnNlcGFodGFuLm5ldDo4NDQzL3JlYWxtcy9tenVzZXJ0ZXN0IiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjY1MjQ0NThjLTE2MzYtNDZmYy1iOTkwLTAzNTQzZjYzYWVhOSIsInR5cCI6IkJlYXJlciIsImF6cCI6Indob2FtaS1jbGllbnQiLCJzaWQiOiI3NWU4MGMwZi00MDRmLTQ5ZGEtOTNhZi0wNTY1MmRlYzk5ZjUiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtbXp1c2VydGVzdCIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJ3aG9hbWktY2xpZW50Ijp7InJvbGVzIjpbInVzZXIiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiaCBtb21heXlleiIsInByZWZlcnJlZF91c2VybmFtZSI6InRlc3R1c2VyIiwiZ2l2ZW5fbmFtZSI6ImgiLCJmYW1pbHlfbmFtZSI6Im1vbWF5eWV6IiwiZW1haWwiOiJob3NzZWlubW9tYXl5ZXpAZ21haWwuY29tIn0.oJNhNPTzQRo6-1L29wqjmuEmfM4zZJwANA1QrS4jWFFVs9T1siBGmA7P0DK-ESf7GgAte0xhIVGRHpZgaLLBYYwBot-iQuDqXu5U71N-Ozjajjwjdkr1CCh_D3PJYRL-HwloRMivJAD4wMWMXUBRjytWAgf49DgyLZAIdPUfXnbkAYcRLKdic_SprCQ_MUQZXwiXQ2AuMJsM2QBP4-v-wAdrPj8wUMs0aHgQpjSy7qBgQ0yLyoFb8tVL02_vaSuvYheePH4Q6Sjv3gquyjsN2tbMFm6wCzFW76PlDGsLku3XtAlAn6BFM4EgjD0y_M9OY3XPK15P98_ElBd4NTDAAw"

func TestAuthorization(t *testing.T) {
	config := &Config{
		KeycloakURL:      "http://keycloak:8080/realms/demo/protocol/openid-connect/token",
		KeycloakClientId: "traefik-gateway-client",
	}

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	ctx := context.Background()
	handler, _ := New(ctx, next, config, "AuthMiddleware")

	recorder := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://keycloak:8080/whoami", nil)
	req.Header.Set("X-Auth-Request-Access-Token", token)
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Error("expected 200 OK")
	}
}
