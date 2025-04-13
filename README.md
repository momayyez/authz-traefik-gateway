# AuthZ Traefik Gateway

**AuthZ Traefik Gateway** is a custom authorization middleware plugin for [Traefik](https://traefik.io/) that validates access permissions using [Keycloak](https://www.keycloak.org/) and the [UMA 2.0 protocol](https://datatracker.ietf.org/doc/html/rfc8693).

It works by extracting the request path and method (e.g. `GET /api/v1/user`) and converting it into a permission format like `user#get`, then querying Keycloak’s token endpoint using a valid access token and the `uma-ticket` flow to determine if the user has access.

---

### 🔐 Features
- 🔧 Authorization based on **resource + scope**
- 🔄 Uses `uma-ticket` grant type for permission evaluation
- ✅ Works with any token issued by Keycloak
- 🚀 Lightweight and easy to plug into your Traefik stack

---

### 📦 Plugin Usage Example

```yaml
http:
  middlewares:
    keycloak-authz:
      plugin:
        authztraefikgateway:
          keycloakURL: "https://keycloak.local/realms/demo/protocol/openid-connect/token"
          keycloakClientId: "traefik-gateway-client"
