# QR Authentication Protocol

**Last Updated:** 2026-01-14
**Version:** v3 (current) | v2, v1 (legacy)
**Implementation:** `dna_messenger_flutter/lib/services/qr_auth_service.dart`

---

## Overview

DNA Messenger supports QR-based authentication allowing external services to authenticate users via their DNA identity. The app acts as an authenticator (similar to WebAuthn/FIDO2) where:

1. Service displays QR code with auth challenge
2. User scans QR with DNA Messenger
3. App signs challenge with user's Dilithium5 key
4. App sends signed response to service callback URL
5. Service verifies signature and authenticates user

**Security Properties:**
- Post-quantum signatures (Dilithium5 / ML-DSA-87)
- HTTPS-only callbacks
- RP (Relying Party) binding prevents phishing (v2+)
- Challenge/nonce prevents replay attacks
- Expiration timestamps prevent stale requests

---

## Protocol Versions

| Version | Features | Status |
|---------|----------|--------|
| v1 | Basic signing (origin, session, nonce) | Legacy |
| v2 | + RP binding (`rp_id` validation) | Supported |
| v3 | + `rp_id_hash` in signed payload | **Current** |

**Version Selection:**
- QR payload specifies version via `v` field
- App enforces version-specific requirements
- Response echoes the effective version used

---

## QR Payload Formats

### JSON Format (Preferred)

```json
{
  "type": "dna.auth.request",
  "v": 3,
  "app": "Example Service",
  "origin": "https://example.com",
  "rp_id": "example.com",
  "rp_name": "Example Inc.",
  "rp_id_hash": "n4bQgYhMfWWaL28...",
  "session_id": "abc123xyz",
  "nonce": "random-challenge-string",
  "expires_at": 1705276800,
  "scopes": ["login", "profile"],
  "callback": "https://example.com/auth/callback"
}
```

### URI Format (Compact)

```
dna://auth?v=3&app=Example+Service&origin=https://example.com&rp_id=example.com&rp_id_hash=n4bQgYhMfWWaL28...&session_id=abc123xyz&nonce=random-challenge&expires_at=1705276800&callback=https://example.com/auth/callback
```

### Field Reference

| Field | Required | Version | Description |
|-------|----------|---------|-------------|
| `type` | No | All | `"dna.auth.request"`, `"auth"`, or `"login"` |
| `v` | No | All | Protocol version (1, 2, or 3). Default: 1 |
| `app` | No | All | Human-readable application name |
| `origin` | **Yes** | All | Service origin URL (e.g., `https://example.com`) |
| `rp_id` | **Yes** | v2+ | Relying Party ID (domain, e.g., `example.com`) |
| `rp_name` | No | v2+ | Human-readable RP name |
| `rp_id_hash` | **Yes** | v3 | `base64(SHA-256(rp_id))` |
| `session_id` | **Yes** | All | Server-generated session identifier |
| `nonce` | **Yes** | All | Server-generated challenge (alias: `challenge`) |
| `expires_at` | No | All | Unix timestamp for expiration |
| `scopes` | No | All | Requested permissions (comma-separated or array) |
| `callback` | **Yes** | All | HTTPS URL for response delivery |

**Field Aliases (for compatibility):**
- `origin`: `domain`, `service`
- `session_id`: `sessionId`, `session`
- `nonce`: `challenge`
- `expires_at`: `expiresAt`, `expires`
- `callback`: `callback_url`, `callbackUrl`
- `rp_id`: `rpId`
- `rp_id_hash`: `rpIdHash`

---

## RP Binding (v2+)

### Purpose

RP binding prevents phishing attacks where a malicious site displays a QR code from a legitimate service. Without RP binding, users might unknowingly authenticate to the attacker's session.

### Validation Rules

1. **`rp_id` presence**: Required for v2+
2. **`rp_id_hash` presence**: Required for v3
3. **Origin host match**: `origin` host must match or be subdomain of `rp_id`
4. **Callback host match**: `callback` host must match or be subdomain of `rp_id`
5. **HTTPS enforcement**: Callback URL must use HTTPS scheme

### Host Matching Algorithm

```
hostMatchesRp(host, rpId):
  if host == rpId: return true           // exact match
  if host.endsWith("." + rpId): return true  // subdomain
  return false
```

**Examples:**
| Host | RP ID | Match |
|------|-------|-------|
| `example.com` | `example.com` | ✅ Yes |
| `auth.example.com` | `example.com` | ✅ Yes |
| `api.auth.example.com` | `example.com` | ✅ Yes |
| `example.com` | `auth.example.com` | ❌ No |
| `malicious.com` | `example.com` | ❌ No |
| `example.com.evil.com` | `example.com` | ❌ No |

### rp_id_hash Computation (v3)

```
rp_id_hash = base64_encode(SHA-256(lowercase(rp_id)))
```

**Example:**
```
rp_id = "example.com"
sha256("example.com") = 0xa379a6f6eeafb9a55e378c...
rp_id_hash = "o3mm9u6vuZpeN4x..." (standard base64)
```

**Important:** The app recomputes `rp_id_hash` from `rp_id` for signing rather than echoing the QR value. This prevents hash injection attacks.

---

## Canonical Signing

### Signed Payload Construction

The app constructs a **canonical JSON string** that is signed. Canonicalization ensures byte-for-byte consistency between signer and verifier.

**Rules:**
1. Keys in strict alphabetical order
2. No whitespace after colons or commas
3. No trailing newlines
4. UTF-8 encoding

### Canonical Payload by Version

**v1 (no RP binding):**
```json
{"expires_at":1705276800,"issued_at":1705276700,"nonce":"challenge","origin":"https://example.com","session_id":"abc123"}
```

**v2 (+ rp_id):**
```json
{"expires_at":1705276800,"issued_at":1705276700,"nonce":"challenge","origin":"https://example.com","rp_id":"example.com","session_id":"abc123"}
```

**v3 (+ rp_id_hash):**
```json
{"expires_at":1705276800,"issued_at":1705276700,"nonce":"challenge","origin":"https://example.com","rp_id":"example.com","rp_id_hash":"o3mm9u6vuZpeN4x...","session_id":"abc123"}
```

### Key Order Reference

| Version | Key Order |
|---------|-----------|
| v1 | `expires_at`, `issued_at`, `nonce`, `origin`, `session_id` |
| v2 | `expires_at`, `issued_at`, `nonce`, `origin`, `rp_id`, `session_id` |
| v3 | `expires_at`, `issued_at`, `nonce`, `origin`, `rp_id`, `rp_id_hash`, `session_id` |

### Normalization

| Field | Normalization |
|-------|---------------|
| `origin` | Trimmed (whitespace removed) |
| `rp_id` | Trimmed + lowercase |
| `rp_id_hash` | Trimmed (recomputed from normalized `rp_id`) |
| `nonce` | As-is from QR |
| `session_id` | As-is from QR |
| `issued_at` | Current Unix timestamp (app-generated) |
| `expires_at` | From QR, or `issued_at + 120` if absent |

---

## Response Format

### HTTP Request

```
POST {callback_url}
Content-Type: application/json
Accept: application/json

{response_body}
```

### Response Body

```json
{
  "type": "dna.auth.response",
  "v": 3,
  "session_id": "abc123",
  "fingerprint": "a1b2c3d4...128hex...",
  "pubkey_b64": "base64-encoded-dilithium5-public-key",
  "signature": "base64-encoded-dilithium5-signature",
  "signed_payload": {
    "origin": "https://example.com",
    "session_id": "abc123",
    "nonce": "challenge",
    "issued_at": 1705276700,
    "expires_at": 1705276800,
    "rp_id": "example.com",
    "rp_id_hash": "o3mm9u6vuZpeN4x..."
  }
}
```

### Response Fields

| Field | Description |
|-------|-------------|
| `type` | Always `"dna.auth.response"` |
| `v` | Protocol version used (1, 2, or 3) |
| `session_id` | Echo of session ID from QR |
| `fingerprint` | User's DNA identity fingerprint (128 hex chars) |
| `pubkey_b64` | Dilithium5 public key (base64, 2592 bytes decoded) |
| `signature` | Dilithium5 signature over canonical payload (base64) |
| `signed_payload` | The payload object that was signed |

### Signature Verification (Server-Side)

```python
import json
from dilithium import verify  # Post-quantum library

def verify_auth_response(response: dict) -> bool:
    # 1. Decode public key and signature
    pubkey = base64.b64decode(response["pubkey_b64"])
    signature = base64.b64decode(response["signature"])

    # 2. Reconstruct canonical payload (MUST match app's construction)
    payload = response["signed_payload"]
    canonical = build_canonical_json(payload, version=response["v"])

    # 3. Verify Dilithium5 signature
    return verify(pubkey, canonical.encode("utf-8"), signature)

def build_canonical_json(payload: dict, version: int) -> str:
    # Keys MUST be in alphabetical order, no whitespace
    if version >= 3:
        return json.dumps(payload, sort_keys=True, separators=(',', ':'))
    elif version >= 2:
        # Exclude rp_id_hash for v2
        p = {k: v for k, v in payload.items() if k != "rp_id_hash"}
        return json.dumps(p, sort_keys=True, separators=(',', ':'))
    else:
        # v1: exclude rp_id and rp_id_hash
        p = {k: v for k, v in payload.items() if k not in ("rp_id", "rp_id_hash")}
        return json.dumps(p, sort_keys=True, separators=(',', ':'))
```

---

## Error Handling

### Client-Side Errors (App)

| Error | Cause | User Message |
|-------|-------|--------------|
| Missing required fields | QR lacks `origin`, `session_id`, `nonce`, or `callback` | "Invalid authorization request" |
| Expired request | `expires_at` < current time | "Request expired" |
| Invalid callback URL | Malformed or non-HTTPS | "Callback URL must use HTTPS" |
| Missing `rp_id` (v2+) | QR lacks `rp_id` | "Missing rp_id in QR payload (v2+)" |
| Missing `rp_id_hash` (v3) | QR lacks `rp_id_hash` | "Missing rp_id_hash in QR payload (v3)" |
| Origin mismatch | Origin host doesn't match `rp_id` | "Origin host does not match rp_id" |
| Callback mismatch | Callback host doesn't match `rp_id` | "Callback host does not match rp_id" |
| No identity | No identity loaded in app | "No identity loaded" |
| Signing failed | Crypto error | "Signing failed: {details}" |

### Server-Side Error Response

If the callback endpoint returns an error, the app parses and displays it:

```json
{
  "detail": {
    "message": "Session expired or invalid"
  }
}
```

The app displays the `detail.message` value to the user.

---

## Security Considerations

### Downgrade Prevention

- v3 QRs **must** include `rp_id_hash` - omission is rejected
- v2 QRs **must** include `rp_id` - omission is rejected
- Attackers cannot forge v1 QRs to bypass RP checks on v2/v3 servers (server determines expected version)

### Replay Prevention

- `nonce` must be unique per request (server responsibility)
- `issued_at` is app-generated, not from QR
- `expires_at` enforced client-side and should be verified server-side

### Phishing Mitigation

- RP binding ensures callback goes to legitimate domain
- User sees origin/app name before approving
- HTTPS-only callbacks prevent MITM

### Key Security

- Private keys never leave device
- Dilithium5 provides NIST Category 5 (256-bit quantum) security
- Signature is over the canonical payload, not raw QR content

---

## Dart API Reference

### Classes

**`QrPayload`** (`lib/utils/qr_payload_parser.dart`)
```dart
class QrPayload {
  final QrPayloadType type;      // contact, auth, plainText
  final String rawContent;
  final String? origin;
  final String? rpId;
  final String? rpIdHash;        // v3
  final int? v;                  // Protocol version
  final String? sessionId;
  final String? nonce;
  final int? expiresAt;
  final String? callbackUrl;
  // ... other fields

  bool get hasRequiredAuthFields;
  bool get isExpired;
  Uri? get originUri;
  Uri? get callbackUri;
}
```

**`QrAuthService`** (`lib/services/qr_auth_service.dart`)
```dart
class QrAuthService {
  QrAuthService(DnaEngine engine);

  Future<QrAuthResult> approve(QrPayload payload);
  void deny(QrPayload payload);
}
```

**`QrAuthResult`** (`lib/services/qr_auth_service.dart`)
```dart
class QrAuthResult {
  final bool success;
  final String? errorMessage;
  final int? statusCode;

  const QrAuthResult.success();
  const QrAuthResult.failure(String message, {int? statusCode});
}
```

### Functions

**`parseQrPayload(String content)`** → `QrPayload`
- Parses raw QR content (JSON or URI format)
- Detects payload type (contact, auth, plainText)

**`validateRpBinding(QrPayload p)`** → `String?`
- Returns `null` if valid, error message if invalid
- Checks RP binding rules for v2+

### Usage Example

```dart
import 'package:dna_messenger_flutter/utils/qr_payload_parser.dart';
import 'package:dna_messenger_flutter/services/qr_auth_service.dart';

// Parse scanned QR code
final payload = parseQrPayload(qrContent);

if (payload.type == QrPayloadType.auth) {
  // Validate RP binding
  final error = validateRpBinding(payload);
  if (error != null) {
    showError(error);
    return;
  }

  // Approve with user consent
  final authService = QrAuthService(engine);
  final result = await authService.approve(payload);

  if (result.success) {
    showSuccess("Authenticated with ${payload.origin}");
  } else {
    showError(result.errorMessage ?? "Authentication failed");
  }
}
```

---

## C API Reference

See [functions/public-api.md](functions/public-api.md) §1.20 for native signing functions:

| Function | Description |
|----------|-------------|
| `dna_engine_sign_data()` | Sign arbitrary data with Dilithium5 |
| `dna_engine_get_signing_public_key()` | Get Dilithium5 public key |

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| v3 | 2026-01-14 | Added `rp_id_hash` to signed payload for additional RP binding |
| v2 | 2026-01-13 | Added RP binding (`rp_id` validation) |
| v1 | 2026-01-12 | Initial implementation (basic signing) |
