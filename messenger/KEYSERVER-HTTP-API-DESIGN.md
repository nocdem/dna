# DNA Messenger Keyserver - HTTP API Design

**Date:** 2025-10-16
**Status:** Design Phase
**Endpoint:** `https://cpunk.io/api/keyserver`

---

## Executive Summary

HTTP REST API keyserver for DNA Messenger identity management. Users register their post-quantum public keys and lookup others' keys via simple HTTP endpoints.

**Key Features:**
- RESTful HTTP API
- Dilithium3 signature verification
- PostgreSQL backend
- Rate limiting & DDoS protection
- Simple, no authentication required (public keyserver)

---

## API Endpoints

### Base URL

```
https://cpunk.io/api/keyserver
```

---

## 1. Register Identity

**Endpoint:** `POST /api/keyserver/register`

**Purpose:** Publish identity and public keys to keyserver

**Request:**
```http
POST /api/keyserver/register HTTP/1.1
Host: cpunk.io
Content-Type: application/json

{
  "v": 1,
  "handle": "alice",
  "device": "default",
  "dilithium_pub": "<base64-encoded public key>",
  "kyber_pub": "<base64-encoded public key>",
  "inbox_key": "<hex 32-byte key for P2P/future use>",
  "version": 1,
  "updated_at": 1729637452,
  "sig": "<base64 Dilithium3 signature of this JSON>"
}
```

**Response (Success):**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "identity": "alice/default",
  "version": 1,
  "message": "Identity registered successfully"
}
```

**Response (Error - Invalid Signature):**
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "success": false,
  "error": "Invalid signature",
  "details": "Dilithium3 signature verification failed"
}
```

**Response (Error - Version Conflict):**
```http
HTTP/1.1 409 Conflict
Content-Type: application/json

{
  "success": false,
  "error": "Version must be greater than 5",
  "current_version": 5
}
```

**Validation Rules:**
- ✅ Schema version must be 1
- ✅ Handle: alphanumeric + underscore, 3-32 chars
- ✅ Device: alphanumeric + underscore, 3-32 chars
- ✅ Dilithium3 public key: base64, ~2605 bytes decoded
- ✅ Kyber512 public key: base64, ~1096 bytes decoded
- ✅ inbox_key: 64 hex chars (32 bytes)
- ✅ Version: integer > 0, must be greater than current
- ✅ Timestamp: within 1 hour of server time
- ✅ Signature: valid Dilithium3 signature of canonical JSON

---

## 2. Lookup Identity

**Endpoint:** `GET /api/keyserver/lookup/<identity>`

**Purpose:** Retrieve public keys for an identity

**Request:**
```http
GET /api/keyserver/lookup/alice/default HTTP/1.1
Host: cpunk.io
```

**Response (Success):**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "identity": "alice/default",
  "data": {
    "v": 1,
    "handle": "alice",
    "device": "default",
    "dilithium_pub": "<base64>",
    "kyber_pub": "<base64>",
    "inbox_key": "<hex>",
    "version": 5,
    "updated_at": 1729637452,
    "sig": "<base64>"
  },
  "registered_at": "2025-10-14T19:50:32Z",
  "last_updated": "2025-10-16T20:30:52Z"
}
```

**Response (Not Found):**
```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{
  "success": false,
  "error": "Identity not found",
  "identity": "alice/default"
}
```

**Shorthand Lookup:**
```http
GET /api/keyserver/lookup/alice
```
Defaults to `alice/default` if no device specified.

---

## 3. List All Identities

**Endpoint:** `GET /api/keyserver/list`

**Purpose:** List all registered identities (for discovery)

**Request:**
```http
GET /api/keyserver/list HTTP/1.1
Host: cpunk.io
```

**Query Parameters:**
- `limit` (optional): Number of results (default: 100, max: 1000)
- `offset` (optional): Pagination offset (default: 0)
- `search` (optional): Filter by handle prefix

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "total": 42,
  "identities": [
    {
      "identity": "alice/default",
      "handle": "alice",
      "device": "default",
      "version": 5,
      "registered_at": "2025-10-14T19:50:32Z",
      "last_updated": "2025-10-16T20:30:52Z"
    },
    {
      "identity": "bob/laptop",
      "handle": "bob",
      "device": "laptop",
      "version": 3,
      "registered_at": "2025-10-15T10:20:00Z",
      "last_updated": "2025-10-15T10:20:00Z"
    }
  ],
  "pagination": {
    "limit": 100,
    "offset": 0,
    "has_more": false
  }
}
```

---

## 4. Health Check

**Endpoint:** `GET /api/keyserver/health`

**Purpose:** Check if keyserver is operational

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "ok",
  "version": "0.1.0",
  "uptime": 3600,
  "database": "connected",
  "total_identities": 42
}
```

---

## Database Schema

### PostgreSQL Table: `keyserver_identities`

```sql
CREATE TABLE keyserver_identities (
    id SERIAL PRIMARY KEY,

    -- Identity
    handle VARCHAR(32) NOT NULL,
    device VARCHAR(32) NOT NULL,
    identity VARCHAR(65) UNIQUE NOT NULL, -- "handle/device"

    -- Public keys (base64)
    dilithium_pub TEXT NOT NULL,
    kyber_pub TEXT NOT NULL,
    inbox_key CHAR(64) NOT NULL, -- hex, 32 bytes

    -- Versioning
    version INTEGER NOT NULL,
    updated_at INTEGER NOT NULL, -- Unix timestamp from client

    -- Signature
    sig TEXT NOT NULL, -- base64 Dilithium3 signature

    -- Metadata
    schema_version INTEGER NOT NULL DEFAULT 1,
    registered_at TIMESTAMP DEFAULT NOW(),
    last_updated TIMESTAMP DEFAULT NOW(),

    -- Constraints
    CONSTRAINT unique_identity UNIQUE(handle, device)
);

-- Indexes for performance
CREATE INDEX idx_identity ON keyserver_identities(identity);
CREATE INDEX idx_handle ON keyserver_identities(handle);
CREATE INDEX idx_registered_at ON keyserver_identities(registered_at DESC);
CREATE INDEX idx_last_updated ON keyserver_identities(last_updated DESC);
```

---

## Implementation Options

### Option 1: Pure C with libmicrohttpd (Recommended)

**Pros:**
- Fast, low memory
- Direct integration with C utilities
- No dependencies on Node.js/Python

**Cons:**
- More code to write
- Manual HTTP parsing

**Dependencies:**
- `libmicrohttpd` - HTTP server
- `libpq` - PostgreSQL client
- `json-c` - JSON parsing
- Existing C utilities (sign_json, verify_json)

**File Structure:**
```
keyserver-http/
├── src/
│   ├── main.c           # HTTP server entry point
│   ├── api_register.c   # POST /register handler
│   ├── api_lookup.c     # GET /lookup handler
│   ├── api_list.c       # GET /list handler
│   ├── db.c             # PostgreSQL wrapper
│   ├── validation.c     # Request validation
│   ├── signature.c      # Call verify_json utility
│   └── rate_limit.c     # Rate limiting
├── CMakeLists.txt
└── config.conf
```

---

### Option 2: Go with C FFI (Fast Alternative)

**Pros:**
- Built-in HTTP server (net/http)
- Easy JSON handling
- Good performance
- Call C utilities via cgo

**Cons:**
- Need Go compiler
- Slightly larger binary

**File Structure:**
```
keyserver-http/
├── main.go
├── handlers.go
├── database.go
├── signature.go  # Call verify_json via exec
└── go.mod
```

---

### Option 3: Node.js Express (Rapid Prototyping)

**Pros:**
- Fastest to implement
- Easy HTTP/JSON handling
- Good for prototyping

**Cons:**
- Higher memory usage
- Slower than C/Go
- Need Node.js runtime

**File Structure:**
```
keyserver-http/
├── server.js
├── routes/
│   ├── register.js
│   ├── lookup.js
│   └── list.js
├── db.js
├── signature.js  # Call verify_json via child_process
└── package.json
```

---

## Recommended: C Implementation with libmicrohttpd

### Dependencies Installation

```bash
# Debian/Ubuntu
sudo apt-get install libmicrohttpd-dev libpq-dev libjson-c-dev

# Arch Linux
sudo pacman -S libmicrohttpd postgresql-libs json-c
```

### Example: Main HTTP Server (C)

```c
#include <microhttpd.h>
#include <json-c/json.h>
#include <libpq-fe.h>
#include <stdio.h>
#include <string.h>

#define PORT 8080

// Route handlers
int handle_register(struct MHD_Connection *connection,
                   const char *upload_data, size_t *upload_data_size);
int handle_lookup(struct MHD_Connection *connection, const char *identity);
int handle_list(struct MHD_Connection *connection);

// Main request handler
static int answer_to_connection(void *cls, struct MHD_Connection *connection,
                               const char *url, const char *method,
                               const char *version, const char *upload_data,
                               size_t *upload_data_size, void **con_cls) {

    // Route: POST /api/keyserver/register
    if (strcmp(method, "POST") == 0 &&
        strcmp(url, "/api/keyserver/register") == 0) {
        return handle_register(connection, upload_data, upload_data_size);
    }

    // Route: GET /api/keyserver/lookup/<identity>
    if (strcmp(method, "GET") == 0 &&
        strncmp(url, "/api/keyserver/lookup/", 22) == 0) {
        const char *identity = url + 22;
        return handle_lookup(connection, identity);
    }

    // Route: GET /api/keyserver/list
    if (strcmp(method, "GET") == 0 &&
        strcmp(url, "/api/keyserver/list") == 0) {
        return handle_list(connection);
    }

    // 404 Not Found
    const char *page = "{\"error\":\"Not found\"}";
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(page), (void*)page, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(response, "Content-Type", "application/json");
    int ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
    MHD_destroy_response(response);
    return ret;
}

int main() {
    struct MHD_Daemon *daemon;

    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
                             &answer_to_connection, NULL, MHD_OPTION_END);
    if (daemon == NULL) {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    printf("Keyserver listening on http://0.0.0.0:%d\n", PORT);
    printf("Endpoints:\n");
    printf("  POST /api/keyserver/register\n");
    printf("  GET  /api/keyserver/lookup/<identity>\n");
    printf("  GET  /api/keyserver/list\n");

    getchar(); // Wait for enter key

    MHD_stop_daemon(daemon);
    return 0;
}
```

---

## Client Integration (messenger.c)

### Register Identity

```c
// In messenger.c
int messenger_register_identity(messenger_context_t *ctx) {
    // 1. Load public keys
    char dilithium_pub[4096], kyber_pub[2048];
    load_and_encode_pubkey(ctx->identity, "dilithium", dilithium_pub);
    load_and_encode_pubkey(ctx->identity, "kyber512", kyber_pub);

    // 2. Build JSON payload
    json_object *payload = json_object_new_object();
    json_object_object_add(payload, "v", json_object_new_int(1));
    json_object_object_add(payload, "handle", json_object_new_string(ctx->identity));
    json_object_object_add(payload, "device", json_object_new_string("default"));
    json_object_object_add(payload, "dilithium_pub", json_object_new_string(dilithium_pub));
    json_object_object_add(payload, "kyber_pub", json_object_new_string(kyber_pub));
    json_object_object_add(payload, "inbox_key", json_object_new_string("0000...0000")); // Placeholder
    json_object_object_add(payload, "version", json_object_new_int(1));
    json_object_object_add(payload, "updated_at", json_object_new_int(time(NULL)));

    // 3. Sign with sign_json utility
    const char *json_str = json_object_to_json_string(payload);
    char signature[4096];
    sign_json(ctx->identity, json_str, signature);

    json_object_object_add(payload, "sig", json_object_new_string(signature));

    // 4. HTTP POST to keyserver
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "https://cpunk.io/api/keyserver/register");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_object_to_json_string(payload));

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
    json_object_put(payload);

    return (res == CURLE_OK) ? 0 : -1;
}
```

### Lookup Identity

```c
int messenger_lookup_identity(messenger_context_t *ctx, const char *identity,
                              uint8_t **dilithium_pub, size_t *dil_len,
                              uint8_t **kyber_pub, size_t *kyber_len) {
    // 1. HTTP GET from keyserver
    char url[512];
    snprintf(url, sizeof(url), "https://cpunk.io/api/keyserver/lookup/%s/default", identity);

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);

    // Buffer for response
    struct MemoryStruct response = {0};
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return -1;

    // 2. Parse JSON response
    json_object *root = json_tokener_parse(response.memory);
    json_object *data;
    json_object_object_get_ex(root, "data", &data);

    // 3. Extract and decode public keys
    json_object *dil_obj, *kyber_obj;
    json_object_object_get_ex(data, "dilithium_pub", &dil_obj);
    json_object_object_get_ex(data, "kyber_pub", &kyber_obj);

    const char *dil_b64 = json_object_get_string(dil_obj);
    const char *kyber_b64 = json_object_get_string(kyber_obj);

    *dilithium_pub = base64_decode(dil_b64, dil_len);
    *kyber_pub = base64_decode(kyber_b64, kyber_len);

    json_object_put(root);
    free(response.memory);

    return 0;
}
```

---

## Security Considerations

### 1. Rate Limiting

**Per-IP limits:**
- Register: 10 requests/hour
- Lookup: 100 requests/minute
- List: 10 requests/minute

**Implementation:**
```c
// Simple token bucket rate limiter
typedef struct {
    char ip[46]; // IPv6 max length
    time_t last_request;
    int tokens;
} rate_limit_t;

int check_rate_limit(const char *ip, const char *endpoint) {
    // Check if IP has tokens available
    // Refill tokens based on time elapsed
    // Return 0 if allowed, -1 if rate limited
}
```

### 2. DDoS Protection

- Nginx reverse proxy with rate limiting
- CloudFlare in front of cpunk.io
- Connection limits per IP

### 3. SQL Injection Prevention

- Always use parameterized queries
- Never concatenate user input into SQL

```c
// GOOD
PQexecParams(conn, "SELECT * FROM keyserver_identities WHERE identity = $1",
            1, NULL, &identity, NULL, NULL, 0);

// BAD - NEVER DO THIS
sprintf(sql, "SELECT * FROM keyserver_identities WHERE identity = '%s'", identity);
```

### 4. Signature Verification

- Always verify Dilithium3 signature
- Use timeout (5 seconds) to prevent DoS
- Run verify_json in separate process

### 5. Input Validation

- Check all field lengths
- Validate base64 encoding
- Validate hex encoding (inbox_key)
- Check timestamp is reasonable (±1 hour)

---

## Deployment

### Systemd Service

```ini
[Unit]
Description=DNA Messenger Keyserver
After=network.target postgresql.service

[Service]
Type=simple
User=keyserver
WorkingDirectory=/opt/dna-keyserver
ExecStart=/opt/dna-keyserver/keyserver
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Nginx Reverse Proxy

```nginx
server {
    listen 443 ssl http2;
    server_name cpunk.io;

    ssl_certificate /etc/letsencrypt/live/cpunk.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cpunk.io/privkey.pem;

    location /api/keyserver/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # Rate limiting
        limit_req zone=keyserver burst=10 nodelay;
    }
}

# Rate limit zone
limit_req_zone $binary_remote_addr zone=keyserver:10m rate=10r/s;
```

---

## Testing

### Test Registration

```bash
curl -X POST https://cpunk.io/api/keyserver/register \
  -H "Content-Type: application/json" \
  -d '{
    "v": 1,
    "handle": "alice",
    "device": "default",
    "dilithium_pub": "...",
    "kyber_pub": "...",
    "inbox_key": "0000000000000000000000000000000000000000000000000000000000000000",
    "version": 1,
    "updated_at": 1729637452,
    "sig": "..."
  }'
```

### Test Lookup

```bash
curl https://cpunk.io/api/keyserver/lookup/alice/default
```

### Test List

```bash
curl https://cpunk.io/api/keyserver/list?limit=10
```

---

## Migration from Current System

### Step 1: Deploy HTTP Keyserver

1. Set up PostgreSQL database
2. Build and deploy C keyserver
3. Configure Nginx reverse proxy
4. Set up SSL with Let's Encrypt

### Step 2: Update Client (messenger.c)

1. Replace keyserver_lookup() with HTTP GET
2. Replace keyserver_publish() with HTTP POST
3. Update messenger_init() to auto-register on first run

### Step 3: Data Migration

```sql
-- Export from current keyserver table
SELECT handle, dilithium_pub, kyber_pub
FROM keyserver_identities;

-- Import to new HTTP keyserver
-- (POST /api/keyserver/register for each identity)
```

---

## Performance Targets

### C Implementation

| Operation | Target | Notes |
|-----------|--------|-------|
| Register | < 100ms | Including signature verification |
| Lookup | < 10ms | PostgreSQL query |
| List | < 50ms | With pagination |
| Concurrent | > 1000 req/s | On modest hardware |
| Memory | < 50 MB | Baseline |

---

## Future Enhancements

### 1. Device Management

Allow multiple devices per handle:
- `alice/laptop`
- `alice/phone`
- `alice/desktop`

### 2. Key Rotation

Support for updating keys:
- Increment version
- Keep old versions for grace period

### 3. Revocation

Mark keys as revoked:
- Add `revoked` boolean field
- Return 410 Gone for revoked identities

### 4. Verification Badges

Trust system:
- Email verification
- Domain verification
- Web of trust

---

## Conclusion

**Recommended Implementation:**
1. Start with **C + libmicrohttpd** for production
2. Use existing C utilities (sign_json, verify_json)
3. PostgreSQL for storage
4. Nginx reverse proxy with rate limiting
5. Deploy at `https://cpunk.io/api/keyserver`

**Next Steps:**
1. Set up PostgreSQL schema
2. Implement C HTTP server
3. Test registration and lookup
4. Update messenger client
5. Deploy to cpunk.io

---

**END OF DESIGN DOCUMENT**
