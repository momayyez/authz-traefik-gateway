package authztraefikgateway

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Config holds the plugin configuration
type Config struct {
    KeycloakURL      string `json:"keycloak_url" yaml:"keycloak_url"`
    KeycloakClientId string `json:"keycloak_client_id" yaml:"keycloak_client_id"`
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
	fmt.Println("🔎 [AUTH] ServeHTTP Called")

	authorizationHeader := req.Header.Get("Authorization")
	if authorizationHeader == "" {
		fmt.Println("❌ [AUTH] Authorization header is missing")
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}
	fmt.Println("🔎 [AUTH] Authorization Header:", authorizationHeader)

	resourceUrl := req.URL.Path
	method := req.Method
	permission := resourceUrl + "#" + method
	fmt.Println("🔎 [AUTH] Permission to check:", permission)

	formData := url.Values{}
	formData.Set("permission", permission)
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	formData.Set("audience", am.keycloakClientId)

	if am.keycloakUrl == "" {
		fmt.Println("❌ [CONFIG] Keycloak URL is empty in middleware. Cannot proceed.")
		http.Error(w, "Misconfigured Keycloak URL", http.StatusInternalServerError)
		return
	}

	kcReq, err := http.NewRequest("POST", am.keycloakUrl, strings.NewReader(formData.Encode()))
	if err != nil {
		fmt.Println("❌ [HTTP] Error creating Keycloak request:", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	kcReq.Header.Set("Authorization", authorizationHeader)
	kcReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	fmt.Println("🔄 [REQUEST] Sending request to Keycloak:", am.keycloakUrl)
	client := &http.Client{}
	kcResp, err := client.Do(kcReq)
	if err != nil {
		fmt.Println("❌ [HTTP] Error performing Keycloak request:", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer kcResp.Body.Close()

	bodyBytes, _ := io.ReadAll(kcResp.Body)
	bodyString := string(bodyBytes)

	fmt.Println("🔎 [HTTP] Keycloak response status:", kcResp.Status)
	fmt.Println("📦 [HTTP] Keycloak response body:", bodyString)

	if kcResp.StatusCode == http.StatusOK {
		fmt.Println("✅ [AUTHZ] Access granted by Keycloak")
		am.next.ServeHTTP(w, req)
	} else {
		fmt.Printf("❌ [AUTHZ] Access denied by Keycloak. Status code: %d\n", kcResp.StatusCode)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	fmt.Println("🔧 [INIT] New Middleware Initialization")
	fmt.Printf("🔧 [INIT] Config pointer: %p\n", config)
	fmt.Printf("🔧 [CONFIG] Raw config: %+v\n", config)

	if config == nil {
		fmt.Println("❌ [CONFIG] Received nil config! Middleware cannot proceed.")
		return nil, fmt.Errorf("nil config provided")
	}

	fmt.Printf("🔧 [CONFIG] Received config.KeycloakURL: [%s]\n", config.KeycloakURL)
	fmt.Printf("🔧 [CONFIG] Received config.KeycloakClientId: [%s]\n", config.KeycloakClientId)

	if strings.TrimSpace(config.KeycloakURL) == "" {
		fmt.Println("⚠️  [CONFIG] KeycloakURL is empty! Make sure you define it in the dynamic middleware config.")
	}
	if strings.TrimSpace(config.KeycloakClientId) == "" {
		fmt.Println("⚠️  [CONFIG] KeycloakClientId is empty! Make sure you define it in the dynamic middleware config.")
	}

	mw := &AuthMiddleware{
		next:             next,
		name:             name,
		keycloakUrl:      config.KeycloakURL,
		keycloakClientId: config.KeycloakClientId,
	}

	fmt.Printf("🔧 [INIT] Middleware initialized with keycloakUrl: [%s], keycloakClientId: [%s]\n", mw.keycloakUrl, mw.keycloakClientId)

	return mw, nil
}
