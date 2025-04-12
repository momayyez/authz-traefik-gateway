package authz_traefik_gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoSGd4cWs3Z1B2NTJHTC1GZEFFN1l1THd1QXhDY3AwLXNHcUtzbTFiOHJ3In0.eyJleHAiOjE3Mjk1MjA2NDAsImlhdCI6MTcyOTQ4NDY0MCwiYXV0aF90aW1lIjoxNzI5NDg0NjQwLCJqdGkiOiIyNjBjNWJjMS02MzgzLTRkYTAtYmQxNC1mYTdlMDZjNmNiODgiLCJpc3MiOiJodHRwOi8vMTcyLjE2LjEwMi4xNDA6MzA4NDIvYXV0aC9yZWFsbXMvbWluZ3lhbmciLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiNjU0ZGQ2Y2QtNzBkNy00NmUzLWE2OTMtNGUzNTRiYTY3ZmU1IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoib2F1dGgyLXByb3h5Iiwic2lkIjoiZGRlNDVmZDctNTExYi00NmRiLTkyYTMtYmYzYmEwNTFjMzk2IiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJFRElUT1IiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIiwiZGVmYXVsdC1yb2xlcy1taW5neWFuZyJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInJvbGVzIjpbIkVESVRPUiIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJkZWZhdWx0LXJvbGVzLW1pbmd5YW5nIl0sIm5hbWUiOiJodWFuZ2ppYW4gSHVhbmciLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJodWFuZ2ppYW4iLCJnaXZlbl9uYW1lIjoiaHVhbmdqaWFuIiwiZmFtaWx5X25hbWUiOiJIdWFuZyIsImVtYWlsIjoiaHVhbmdqaWFuQG1pbmd5YW5ndGVjaC5jb20uY24ifQ.bygBSQ3izXqDLOfbKGZjTYJzZNA3mxb9NbHgJvzymsZ5-ts_PmLhCuxIqbYtoEpA8lgCq0_r24uRM38qISfCldIBD-o8CfeXbAdbKq9_eeSIsAv-FhS3UuCYYKR2mLUv6YCpnjKCjehIhOFnFVSSkrg5Mt-nEbLWU0YOuNk-bdMlDtvP8BwaGTxMcxaNMOnu64na2u2zkUdiu0s3BCHUn90rXHeQmx9L64yOTaivzWtlY6f1k3JacG4hY5MUKWVMlbsedNvW57pQko4ZYG9nPUKuUfM8OZoLQ0YbTZVSIPRTg2Mut4C2VV5uU_o5x_VjS0SFLQSI5k1tF7bTRiXJog"

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
