package authztraefikgateway

import (
	"context"
	"crypto/tls"
	"fmt"
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
	fmt.Println("🔎 ServeHTTP Called")
	fmt.Println("🔎 keycloakUrl:", am.keycloakUrl)
	fmt.Println("🔎 keycloakClientId:", am.keycloakClientId)

	authorizationHeader := req.Header.Get("Authorization")
	fmt.Println("🔎 Authorization Header:", authorizationHeader)

	resourceUrl := req.URL.Path
	method := req.Method
	permission := resourceUrl + "#" + method
	fmt.Println("🔎 Permission to check:", permission)

	formData := url.Values{}
	formData.Set("permission", permission)
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	formData.Set("audience", am.keycloakClientId)

	kcReq, err := http.NewRequest("POST", am.keycloakUrl, strings.NewReader(formData.Encode()))
	if err != nil {
		fmt.Println("❌ Error creating Keycloak request:", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	kcReq.Header.Set("Authorization", authorizationHeader)
	kcReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{}
	kcResp, err := client.Do(kcReq)
	if err != nil {
		fmt.Println("❌ Error performing Keycloak request:", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer kcResp.Body.Close()

	fmt.Println("🔎 Keycloak response status:", kcResp.Status)

	if kcResp.StatusCode == http.StatusOK {
		fmt.Println("✅ Authorized")
		am.next.ServeHTTP(w, req)
	} else {
		fmt.Println("❌ Unauthorized by Keycloak")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	fmt.Println("🔧 New Middleware Initialization")
	fmt.Println("🔧 Received config.keycloak_url:", config.KeycloakURL)
	fmt.Println("🔧 Received config.keycloak_client_id:", config.KeycloakClientId)

	return &AuthMiddleware{
		next:             next,
		name:             name,
		keycloakUrl:      config.KeycloakURL,
		keycloakClientId: config.KeycloakClientId,
	}, nil
}
