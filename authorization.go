package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
)

// Config defines config fields used by the middleware
type Config struct {
	TokenEndpoint string `json:"token_endpoint,omitempty" yaml:"token_endpoint"`
	ClientID      string `json:"client_id,omitempty" yaml:"client_id"`
}

// CreateConfig returns default config
func CreateConfig() *Config {
	return &Config{
		TokenEndpoint: "",
		ClientID:      "",
	}
}

// PermissionHandler represents the middleware structure
type PermissionHandler struct {
	next       http.Handler
	clientID   string
	endpoint   string
	middleware string
}

// ServeHTTP checks user permissions using UMA ticket flow
func (ph *PermissionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resource := r.URL.Path
	scope := r.Method
	perm := resource + "#" + scope

	data := url.Values{}
	data.Set("permission", perm)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	data.Set("audience", ph.clientID)

	authReq, err := http.NewRequest("POST", ph.endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		http.Error(w, "auth request creation failed", http.StatusUnauthorized)
		return
	}
	authReq.Header.Set("Authorization", "Bearer "+r.Header.Get("X-Auth-Request-Access-Token"))
	authReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	resp, err := (&http.Client{}).Do(authReq)
	if err != nil {
		http.Error(w, "keycloak unreachable", http.StatusUnauthorized)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		ph.next.ServeHTTP(w, r)
	} else {
		http.Error(w, "access denied", http.StatusUnauthorized)
	}
}

// New creates the middleware handler
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &PermissionHandler{
		next:       next,
		middleware: name,
		endpoint:   config.TokenEndpoint,
		clientID:   config.ClientID,
	}, nil
}
