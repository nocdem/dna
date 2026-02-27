# CPUNK Platform API Reference

## DNA API Endpoints

The CPUNK platform provides several API endpoints for interacting with the DNA (Distributed Naming & Addressing) system.

### Base URL
- Primary: `https://api.dna.cpunk.club`
- Proxy: `https://cpunk.club/dna-proxy.php`

### Endpoints

#### 1. Check DNA Registration
```
GET /check?dna_nickname={nickname}
```
Returns information about a DNA registration.

**Response:**
```json
{
  "exists": true,
  "data": {
    "dna_nickname": "username",
    "wallets": ["wallet_address"],
    "social_accounts": {
      "github": "github_username",
      "twitter": "twitter_handle"
    }
  }
}
```

#### 2. Update DNA Record
```
POST /update
Content-Type: application/json

{
  "dna_nickname": "username",
  "field": "social_github",
  "value": "github_username"
}
```

### Dashboard API

Local dashboard connector for node statistics.

**Base URL:** `http://localhost:8045/`

#### Node Status
```
GET /node_status
```
Returns current node synchronization and network status.

#### Wallet Balance
```
POST /wallet_balance
Content-Type: application/json

{
  "wallet_name": "wallet_name",
  "wallet_path": "/path/to/wallet"
}
```

### Authentication

DNA-based authentication is used for secure operations:

1. User proves ownership of DNA nickname
2. Session token is generated
3. Token is included in subsequent requests

### Rate Limiting

- Public endpoints: 60 requests per minute
- Authenticated endpoints: 120 requests per minute

### Error Responses

Standard HTTP status codes are used:
- 200: Success
- 400: Bad Request
- 401: Unauthorized
- 404: Not Found
- 429: Too Many Requests
- 500: Server Error

### CORS

All API endpoints support CORS for browser-based access.