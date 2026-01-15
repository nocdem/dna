# QR Authentication Protocol v4 (Stateless/CDN-Scale)

**Last Updated:** 2026-01-15
**Version:** v4
**Implementation:** `dna_messenger_flutter/lib/services/qr_auth_service.dart`

---

## Overview

v4 is a stateless QR authentication protocol designed for CDN-scale deployments. Unlike v1-v3 which require server-generated session state and callback URLs, v4 embeds all authentication context in a signed token (`st`) that can be verified by any server instance without shared state.

**Key Differences from v3:**
| Aspect | v3 | v4 |
|--------|-----|-----|
| Session state | Server-side | Stateless (in token) |
| Callback URL | Required in QR | Not needed |
| Verify endpoint | Custom callback | Fixed: `{origin}/api/v4/verify` |
| RP binding | Via `rp_id` + host checks | Inside `st` payload |
| Scalability | Single server | CDN/load-balanced |

---

## QR Payload Format

### URI Format

```
dna://auth?v=4&st=<token>
```

### JSON Format

```json
{
  "type": "dna.auth.request",
  "v": 4,
  "st": "v4.<b64url(payload)>.<b64url(sig)>"
}
```

### Field Reference

| Field | Required | Description |
|-------|----------|-------------|
| `v` | **Yes** | Must be `4` or higher |
| `st` | **Yes** | Stateless token (see below) |
| `app` | No | Human-readable app name (for UI display) |

---

## Stateless Token (st) Format

The `st` token is a server-signed JWT-like structure:

```
v4.<base64url(payload_json)>.<base64url(signature)>
```

### Token Parts

| Part | Description |
|------|-------------|
| `v4` | Version prefix (literal string) |
| Payload | Base64url-encoded JSON (see below) |
| Signature | Base64url-encoded Ed25519 signature (server key) |

### Payload Fields

```json
{
  "sid": "unique-session-id",
  "origin": "https://example.com",
  "rp_id_hash": "base64(sha256(rp_id))",
  "nonce": "random-challenge",
  "issued_at": 1705276700,
  "expires_at": 1705276800
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `sid` | **Yes** | Session identifier |
| `origin` | **Yes** | Service origin URL |
| `rp_id_hash` | **Yes** | `base64(SHA-256(rp_id))` |
| `nonce` | **Yes** | Server-generated challenge |
| `issued_at` | **Yes** | Unix timestamp of token creation |
| `expires_at` | **Yes** | Unix timestamp of expiration |

**Note:** The phone does NOT verify the server's Ed25519 signature on `st`. The signature is for server-side token validation.

---

## Phone-Side Processing

### Step 1: Parse QR

```dart
// Detect v4 by version and st presence
final pv = payload.v ?? 1;
final isV4 = pv >= 4 && payload.st != null && payload.st!.trim().isNotEmpty;
```

### Step 2: Decode st Token

```dart
// Split: "v4.<payload>.<sig>"
final parts = st.split('.');
assert(parts[0] == 'v4' && parts.length == 3);

// Decode payload (base64url -> JSON)
final payloadBytes = base64UrlDecode(parts[1]);
final payload = jsonDecode(utf8.decode(payloadBytes));
```

### Step 3: Validate Locally

```dart
// Check expiry
final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
if (now > payload['expires_at']) {
  throw 'Auth request has expired';
}
```

### Step 4: Compute st_hash

**IMPORTANT:** Use STANDARD base64, not base64url.

```dart
// st_hash = base64(sha256(utf8(st)))
final stHash = base64Encode(sha256.convert(utf8.encode(st)).bytes);
```

### Step 5: Build Canonical Payload

The canonical payload MUST have keys in exact alphabetical order with no whitespace:

```json
{"expires_at":1705276800,"issued_at":1705276700,"nonce":"challenge","origin":"https://example.com","rp_id_hash":"abc123...","session_id":"sid-value","sid":"sid-value","st_hash":"xyz789..."}
```

**Key Order:**
1. `expires_at` (int)
2. `issued_at` (int)
3. `nonce` (string)
4. `origin` (string)
5. `rp_id_hash` (string)
6. `session_id` (string) - same as `sid`
7. `sid` (string)
8. `st_hash` (string)

### Step 6: Sign with Dilithium5

```dart
final canonicalBytes = utf8.encode(canonicalPayloadString);
final signature = engine.signData(canonicalBytes);
final signatureB64 = base64Encode(signature);
final pubkeyB64 = base64Encode(engine.signingPublicKey);
```

### Step 7: POST to Verify Endpoint

```
POST {origin}/api/v4/verify
Content-Type: application/json
```

---

## Request Body Format

```json
{
  "type": "dna.auth.response",
  "v": 4,
  "st": "v4.<payload>.<sig>",
  "session_id": "sid-value",
  "fingerprint": "128-hex-chars...",
  "pubkey_b64": "base64(dilithium5-public-key)",
  "signature": "base64(dilithium5-signature)",
  "signed_payload": {
    "sid": "sid-value",
    "origin": "https://example.com",
    "rp_id_hash": "abc123...",
    "nonce": "challenge",
    "issued_at": 1705276700,
    "expires_at": 1705276800,
    "st_hash": "xyz789...",
    "session_id": "sid-value"
  }
}
```

### Response Fields

| Field | Description |
|-------|-------------|
| `type` | Always `"dna.auth.response"` |
| `v` | Always `4` |
| `st` | Echo of original st token |
| `session_id` | Same as `sid` from st payload |
| `fingerprint` | User's DNA identity (128 hex chars) |
| `pubkey_b64` | Dilithium5 public key (base64) |
| `signature` | Dilithium5 signature over canonical payload (base64) |
| `signed_payload` | Object containing all signed fields |

---

## Server-Side Verification

### Python Example

```python
import json
import base64
import hashlib
from dilithium import verify  # Post-quantum library

def verify_v4_auth(request: dict) -> bool:
    # 1. Verify st token (your Ed25519 signature)
    st = request["st"]
    if not verify_st_token(st):
        return False

    # 2. Decode public key and signature
    pubkey = base64.b64decode(request["pubkey_b64"])
    signature = base64.b64decode(request["signature"])

    # 3. Reconstruct canonical payload
    sp = request["signed_payload"]
    canonical = build_canonical_v4(sp)

    # 4. Verify Dilithium5 signature
    return verify(pubkey, canonical.encode("utf-8"), signature)

def build_canonical_v4(p: dict) -> str:
    # Keys MUST be in alphabetical order
    return json.dumps({
        "expires_at": p["expires_at"],
        "issued_at": p["issued_at"],
        "nonce": p["nonce"],
        "origin": p["origin"],
        "rp_id_hash": p["rp_id_hash"],
        "session_id": p["session_id"],
        "sid": p["sid"],
        "st_hash": p["st_hash"],
    }, separators=(',', ':'), sort_keys=True)

def verify_st_hash(request: dict) -> bool:
    st = request["st"]
    expected_hash = base64.b64encode(
        hashlib.sha256(st.encode("utf-8")).digest()
    ).decode("ascii")
    return request["signed_payload"]["st_hash"] == expected_hash
```

---

## Security Considerations

### Token Binding

The `st_hash` in the signed payload cryptographically binds the phone's response to the specific `st` token. This prevents:
- Token substitution attacks
- Replay with different tokens

### Stateless Verification

Servers can verify requests without shared session state:
1. Verify `st` signature (Ed25519) to confirm token authenticity
2. Check `expires_at` for freshness
3. Verify phone signature (Dilithium5) to confirm user identity
4. Verify `st_hash` matches the provided `st`

### RP Binding

RP binding is enforced via `rp_id_hash` inside the signed `st` token. The phone includes this in its signed payload, ensuring the authentication is bound to the intended relying party.

### Downgrade Prevention

- v4 requires `st` token - cannot be faked with v3 parameters
- Phone rejects v4 requests without valid `st`
- Server should reject responses claiming v4 without proper `st_hash`

---

## Error Handling

### Client-Side Errors

| Error | Cause |
|-------|-------|
| `Missing st token in QR payload (v4)` | QR has v>=4 but no `st` |
| `Invalid st token format` | `st` not in `v4.<payload>.<sig>` format |
| `Missing sid in st payload` | Decoded payload lacks `sid` |
| `Missing origin in st payload` | Decoded payload lacks `origin` |
| `Missing rp_id_hash in st payload` | Decoded payload lacks `rp_id_hash` |
| `Missing nonce in st payload` | Decoded payload lacks `nonce` |
| `Auth request has expired` | Current time > `expires_at` |

### Server-Side Errors

Return errors as:
```json
{
  "detail": {
    "message": "Human-readable error message"
  }
}
```

---

## Version Selection Logic

The phone automatically selects v4 when:
1. `v >= 4` in QR payload
2. `st` field is present and non-empty

Otherwise, falls back to v3/v2/v1 flow unchanged.

```dart
final pv = payload.v ?? 1;
final isV4 = pv >= 4 && payload.st != null && payload.st!.trim().isNotEmpty;
if (isV4) {
  return await _approveV4(payload);
}
// Continue with v3 flow...
```

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| v4 | 2026-01-15 | Initial stateless/CDN-scale protocol |

---

## See Also

- [QR_AUTH.md](QR_AUTH.md) - v1-v3 protocol specification
- [DNA_ENGINE_API.md](DNA_ENGINE_API.md) - Signing functions reference
