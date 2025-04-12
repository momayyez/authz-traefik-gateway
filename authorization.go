package authztraefikgateway

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
)

// Config holds the plugin configuration
type Config struct {
	KeycloakURL      string `yaml:"keycloak_url"`
	KeycloakClientId string `yaml:"keycloak_client_id"`
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
	return &Config{
		KeycloakURL:      "",
		KeycloakClientId: "",
	}
}

type AuthMiddleware struct {
	next             http.Handler
	keycloakClientId string
	keycloakUrl      string
	name             string
}

func (am *AuthMiddleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	resourceUrl := req.URL.Path
	method := req.Method
	permission := resourceUrl + "#" + method

	formData := url.Values{}
	formData.Set("permission", permission)
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	formData.Set("audience", am.keycloakClientId)
	kcReq, err := http.NewRequest("POST", am.keycloakUrl, strings.NewReader(formData.Encode()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return // Added return statement to prevent further execution
	}
	kcReq.Header.Set("Authorization", "Bearer "+req.Header.Get("X-Auth-Request-Access-Token"))
	kcReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{}
	kcResp, err := client.Do(kcReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return // Added return statement to prevent further execution
	}
	defer kcResp.Body.Close()

	if kcResp.StatusCode == http.StatusOK {
		am.next.ServeHTTP(w, req)
	} else {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &AuthMiddleware{
		next:             next,
		name:             name,
		keycloakUrl:      config.KeycloakURL,
		keycloakClientId: config.KeycloakClientId,
	}, nil
}
