package traefikauthz

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// StaticPermission maps a path prefix to a specific resource-scope
type StaticPermission struct {
	Prefix   string `json:"prefix,omitempty"`   // e.g. "/custom/test"
	Resource string `json:"resource,omitempty"` // e.g. "user"
	Scope    string `json:"scope,omitempty"`    // e.g. "getall"
}

// Config holds the plugin configuration
type Config struct {
	KeycloakURL       string             `json:"keycloakURL,omitempty"`
	KeycloakClientId  string             `json:"keycloakClientId,omitempty"`
	ResourceIndex     int                `json:"resourceIndex,omitempty"`
	ScopeIndex        int                `json:"scopeIndex,omitempty"`
	StaticPermissions []StaticPermission `json:"staticPermissions,omitempty"` // New: static prefix -> resource#scope
}

// CreateConfig creates an empty config
func CreateConfig() *Config {
	return &Config{}
}

// AuthMiddleware holds the plugin state
type AuthMiddleware struct {
	next              http.Handler
	keycloakClientId  string
	keycloakUrl       string
	name              string
	resourceIndex     int
	scopeIndex        int
	staticPermissions []StaticPermission
}

// ServeHTTP handles the incoming request and checks permission via Keycloak
func (am *AuthMiddleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	fmt.Println("🔎 [AUTH] ServeHTTP Called")

	authorizationHeader := req.Header.Get("Authorization")
	if authorizationHeader == "" {
		fmt.Println("❌ [AUTH] Authorization header is missing")
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}
	fmt.Println("🔎 [AUTH] Authorization Header:", authorizationHeader)

	var permission string

	// 🔍 First check if path matches any static permission
	for _, sp := range am.staticPermissions {
		if strings.HasPrefix(req.URL.Path, sp.Prefix) {
			permission = "/" + sp.Resource + "#" + sp.Scope
			fmt.Println("🔁 [STATIC] Matched static prefix. Using static permission:", permission)
			break
		}
	}

	// 🔁 If no static permission matched, use dynamic extraction
	if permission == "" {
		pathParts := strings.Split(req.URL.Path, "/")
		if len(pathParts) <= am.scopeIndex {
			fmt.Println("❌ [AUTH] Path too short. Must have at least", am.scopeIndex+1, "parts.")
			http.Error(w, "Invalid path format. Too short.", http.StatusBadRequest)
			return
		}

		resource := pathParts[am.resourceIndex]
		scope := pathParts[am.scopeIndex]
		permission = "/" + resource + "#" + scope
		fmt.Println("🔎 [AUTH] Derived permission:", permission)
	}

	// Prepare request payload
	formData := url.Values{}
	formData.Set("permission", permission)
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	formData.Set("audience", am.keycloakClientId)

	if am.keycloakUrl == "" {
		fmt.Println("❌ [CONFIG] Keycloak URL is empty in middleware. Cannot proceed.")
		http.Error(w, "Misconfigured Keycloak URL", http.StatusInternalServerError)
		return
	}

	// Create request
	kcReq, err := http.NewRequest("POST", am.keycloakUrl, strings.NewReader(formData.Encode()))
	if err != nil {
		fmt.Println("❌ [HTTP] Error creating Keycloak request:", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	kcReq.Header.Set("Authorization", authorizationHeader)
	kcReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	fmt.Println("🔄 [REQUEST] Sending request to Keycloak:", am.keycloakUrl)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

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

// New is called by Traefik to create the middleware instance
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	fmt.Println("🔧 [INIT] New Middleware Initialization")
	fmt.Printf("🔧 [CONFIG] Raw config: %+v\n", config)

	if config == nil {
		return nil, fmt.Errorf("nil config provided")
	}
	if strings.TrimSpace(config.KeycloakURL) == "" {
		fmt.Println("⚠️  [CONFIG] KeycloakURL is empty!")
	}
	if strings.TrimSpace(config.KeycloakClientId) == "" {
		fmt.Println("⚠️  [CONFIG] KeycloakClientId is empty!")
	}

	resourceIndex := config.ResourceIndex
	scopeIndex := config.ScopeIndex
	if resourceIndex <= 0 {
		resourceIndex = 3
	}
	if scopeIndex <= 0 {
		scopeIndex = 4
	}

	mw := &AuthMiddleware{
		next:              next,
		name:              name,
		keycloakUrl:       config.KeycloakURL,
		keycloakClientId:  config.KeycloakClientId,
		resourceIndex:     resourceIndex,
		scopeIndex:        scopeIndex,
		staticPermissions: config.StaticPermissions,
	}

	fmt.Printf("🔧 [INIT] Middleware initialized with keycloakUrl: [%s], clientId: [%s], rIdx: %d, sIdx: %d\n",
		mw.keycloakUrl, mw.keycloakClientId, resourceIndex, scopeIndex)

	return mw, nil
}
