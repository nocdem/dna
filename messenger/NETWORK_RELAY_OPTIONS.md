# DNA Messenger - Network Relay Architecture Options

**Status**: 📋 Planning Document (Implementation: Post-GUI Phase)
**Date**: 2025-10-15
**Phase**: Network Layer Design (Phase 4+)

---

## Overview

This document outlines three approaches for implementing DNA Messenger's network layer using **GDB relay servers**. These options defer Cellframe node requirements from clients to centralized relay servers, enabling lightweight client applications.

**Key Benefits:**
- ✅ Clients don't need to run Cellframe nodes
- ✅ Centralized control and access management
- ✅ API gateway for mobile/desktop apps
- ✅ Caching layer to reduce GDB load
- ✅ Real-time push notifications possible

---

## Architecture Comparison

### Current Architecture (Phase 3)
```
DNA Messenger Client
    ↓ (libpq)
PostgreSQL Server
    ↓ (SQL)
Message/Key Storage
```

**Limitations:**
- No distributed keyserver
- No network sync
- Centralized single point of failure

---

### Proposed Architecture (Phase 4+)
```
DNA Messenger Client
    ↓ (HTTP/WebSocket)
DNA Relay Server (ai.cpunk.io)
    ↓ (CLI commands)
Cellframe Node + GDB
    ↓ (MDBX)
Distributed Global Database
```

**Advantages:**
- Lightweight clients (no Cellframe dependency)
- Distributed keyserver via Cellframe network
- Your servers control access and caching
- Real-time messaging possible

---

## Option 1: REST API Gateway

### Description
Simple HTTP REST API that wraps Cellframe GDB CLI commands. Clients make HTTP requests, server executes `cellframe-node-cli global_db` commands and returns results.

### Server Setup (ai.cpunk.io)

#### Install Dependencies
```bash
# Install Cellframe Node
wget https://debian.pub.demlabs.net/public/pool/main/c/cellframe-node/cellframe-node_5.5-3_amd64.deb
sudo dpkg -i cellframe-node_5.5-3_amd64.deb
sudo systemctl start cellframe-node
sudo systemctl enable cellframe-node

# Install Python and Flask
sudo apt-get install -y python3 python3-pip
pip3 install flask
```

#### Relay Server Implementation (`dna_gdb_relay.py`)

```python
#!/usr/bin/env python3
from flask import Flask, request, jsonify
import subprocess
import json

app = Flask(__name__)

def exec_gdb_cli(args):
    """Execute cellframe-node-cli global_db command"""
    cmd = ['cellframe-node-cli', 'global_db'] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return {'success': True, 'output': result.stdout, 'error': result.stderr}
    except Exception as e:
        return {'success': False, 'error': str(e)}

@app.route('/keyserver/store', methods=['POST'])
def keyserver_store():
    """Store public keys in GDB"""
    data = request.json
    identity = data.get('identity')
    keys = json.dumps({
        'signing_pubkey': data.get('signing_pubkey'),
        'encryption_pubkey': data.get('encryption_pubkey')
    })

    result = exec_gdb_cli([
        'write',
        '-group', 'local.dna.keyserver',
        '-key', identity,
        '-value', keys
    ])
    return jsonify(result)

@app.route('/keyserver/load/<identity>', methods=['GET'])
def keyserver_load(identity):
    """Load public keys from GDB"""
    result = exec_gdb_cli([
        'read',
        '-group', 'local.dna.keyserver',
        '-key', identity
    ])
    return jsonify(result)

@app.route('/keyserver/list', methods=['GET'])
def keyserver_list():
    """List all identities in keyserver"""
    result = exec_gdb_cli([
        'get_keys',
        '-group', 'local.dna.keyserver'
    ])
    return jsonify(result)

@app.route('/messages/store', methods=['POST'])
def message_store():
    """Store encrypted message"""
    data = request.json
    message_id = data.get('message_id')
    message_data = '|'.join([
        data.get('sender'),
        data.get('recipient'),
        str(data.get('timestamp')),
        data.get('ciphertext')
    ])

    result = exec_gdb_cli([
        'write',
        '-group', 'local.dna.messages',
        '-key', message_id,
        '-value', message_data
    ])
    return jsonify(result)

@app.route('/messages/load/<message_id>', methods=['GET'])
def message_load(message_id):
    """Load encrypted message"""
    result = exec_gdb_cli([
        'read',
        '-group', 'local.dna.messages',
        '-key', message_id
    ])
    return jsonify(result)

@app.route('/notify/<recipient>', methods=['POST'])
def notify_message(recipient):
    """Increment notification counter"""
    # Read current count
    result = exec_gdb_cli([
        'read',
        '-group', 'local.dna.notifications',
        '-key', recipient
    ])

    # Parse and increment
    current = 0
    if result['success'] and result['output']:
        try:
            current = int(result['output'].strip())
        except:
            pass

    new_count = current + 1

    # Write new count
    result = exec_gdb_cli([
        'write',
        '-group', 'local.dna.notifications',
        '-key', recipient,
        '-value', str(new_count)
    ])
    return jsonify(result)

@app.route('/notifications/count/<recipient>', methods=['GET'])
def notification_count(recipient):
    """Get pending notification count"""
    result = exec_gdb_cli([
        'read',
        '-group', 'local.dna.notifications',
        '-key', recipient
    ])

    count = 0
    if result['success'] and result['output']:
        try:
            count = int(result['output'].strip())
        except:
            pass

    return jsonify({'count': count})

@app.route('/notifications/clear/<recipient>', methods=['POST'])
def notification_clear(recipient):
    """Clear notification counter"""
    result = exec_gdb_cli([
        'delete',
        '-group', 'local.dna.notifications',
        '-key', recipient
    ])
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

#### Run the Relay Server
```bash
chmod +x dna_gdb_relay.py
python3 dna_gdb_relay.py

# Or run as systemd service
sudo nano /etc/systemd/system/dna-relay.service
# Add service definition (see below)
sudo systemctl start dna-relay
sudo systemctl enable dna-relay
```

**Systemd Service File:**
```ini
[Unit]
Description=DNA Messenger GDB Relay Server
After=network.target cellframe-node.service

[Service]
Type=simple
User=nocdem
WorkingDirectory=/opt/dna-messenger
ExecStart=/usr/bin/python3 /opt/dna-messenger/dna_gdb_relay.py
Restart=always

[Install]
WantedBy=multi-user.target
```

### Client Modifications

Update `dna_gdb.c` to use HTTP instead of local CLI commands:

```c
#include <curl/curl.h>

// Response buffer for libcurl
struct curl_response {
    char *data;
    size_t size;
};

static size_t curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct curl_response *mem = (struct curl_response *)userp;

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) return 0;

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

static int exec_gdb_command_http(const char *endpoint, const char *method,
                                  const char *json_data, char **output) {
    CURL *curl = curl_easy_init();
    if (!curl) return DNA_GDB_ERROR;

    char url[512];
    snprintf(url, sizeof(url), "http://ai.cpunk.io:8080%s", endpoint);

    struct curl_response response = {0};

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

    if (strcmp(method, "POST") == 0 && json_data) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
    }

    CURLcode res = curl_easy_perform(curl);

    int ret = DNA_GDB_ERROR;
    if (res == CURLE_OK) {
        *output = response.data;
        ret = DNA_GDB_SUCCESS;
    } else {
        free(response.data);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return ret;
}

int dna_gdb_keyserver_store(const char *identity,
                            const uint8_t *signing_pubkey,
                            size_t signing_pubkey_len,
                            const uint8_t *encryption_pubkey,
                            size_t encryption_pubkey_len) {
    char json[8192];
    snprintf(json, sizeof(json),
        "{\"identity\":\"%s\",\"signing_pubkey\":\"%s\",\"encryption_pubkey\":\"%s\"}",
        identity, signing_pubkey, encryption_pubkey);

    char *response = NULL;
    int ret = exec_gdb_command_http("/keyserver/store", "POST", json, &response);
    free(response);

    return ret;
}

int dna_gdb_keyserver_load(const char *identity,
                           uint8_t **signing_pubkey_out,
                           size_t *signing_pubkey_len_out,
                           uint8_t **encryption_pubkey_out,
                           size_t *encryption_pubkey_len_out) {
    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/keyserver/load/%s", identity);

    char *response = NULL;
    int ret = exec_gdb_command_http(endpoint, "GET", NULL, &response);

    if (ret == DNA_GDB_SUCCESS) {
        // Parse JSON response and extract keys
        // ... JSON parsing logic ...
    }

    free(response);
    return ret;
}
```

**CMakeLists.txt Changes:**
```cmake
# Add libcurl dependency
find_package(CURL REQUIRED)

target_link_libraries(dna_lib
    OpenSSL::Crypto
    CURL::libcurl
    kyber512
    dilithium
    ${PLATFORM_LIBS}
)
```

### Pros/Cons

**Pros:**
- ✅ Simple to implement (Flask + subprocess)
- ✅ RESTful, standard HTTP
- ✅ Easy to test with curl/Postman
- ✅ Cacheable (add Redis/memcached layer)
- ✅ Stateless (scalable with load balancer)

**Cons:**
- ❌ No real-time push notifications
- ❌ Polling required for new messages
- ❌ Higher latency than WebSocket

---

## Option 2: WebSocket Real-Time Relay

### Description
Persistent WebSocket connections for real-time bidirectional communication. Clients connect once and receive push notifications for new messages.

### Server Implementation (`dna_websocket_relay.py`)

```python
#!/usr/bin/env python3
from flask import Flask
from flask_socketio import SocketIO, emit, join_room, leave_room
import subprocess
import json

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Track connected users
connected_users = {}  # {identity: session_id}

def exec_gdb_cli(args):
    """Execute cellframe-node-cli global_db command"""
    cmd = ['cellframe-node-cli', 'global_db'] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return {'success': True, 'output': result.stdout, 'error': result.stderr}
    except Exception as e:
        return {'success': False, 'error': str(e)}

@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')
    emit('connected', {'status': 'ok'})

@socketio.on('login')
def handle_login(data):
    """User logs in with their identity"""
    identity = data.get('identity')
    connected_users[identity] = request.sid
    join_room(identity)  # Join room for push notifications
    emit('login_success', {'identity': identity})

@socketio.on('keyserver_store')
def handle_keyserver_store(data):
    """Store public keys in GDB"""
    identity = data['identity']
    keys = json.dumps({
        'signing_pubkey': data['signing_pubkey'],
        'encryption_pubkey': data['encryption_pubkey']
    })

    result = exec_gdb_cli([
        'write',
        '-group', 'local.dna.keyserver',
        '-key', identity,
        '-value', keys
    ])

    emit('keyserver_store_result', result)

@socketio.on('keyserver_load')
def handle_keyserver_load(data):
    """Load public keys from GDB"""
    identity = data['identity']

    result = exec_gdb_cli([
        'read',
        '-group', 'local.dna.keyserver',
        '-key', identity
    ])

    emit('keyserver_load_result', result)

@socketio.on('message_send')
def handle_message_send(data):
    """Send encrypted message"""
    message_id = data['message_id']
    sender = data['sender']
    recipient = data['recipient']
    ciphertext = data['ciphertext']
    timestamp = data.get('timestamp', int(time.time()))

    # Store message in GDB
    message_data = f"{sender}|{recipient}|{timestamp}|{ciphertext}"
    result = exec_gdb_cli([
        'write',
        '-group', 'local.dna.messages',
        '-key', message_id,
        '-value', message_data
    ])

    if result['success']:
        # Increment notification counter
        notify_result = exec_gdb_cli([
            'read',
            '-group', 'local.dna.notifications',
            '-key', recipient
        ])

        count = 0
        if notify_result['success'] and notify_result['output']:
            try:
                count = int(notify_result['output'].strip())
            except:
                pass

        count += 1
        exec_gdb_cli([
            'write',
            '-group', 'local.dna.notifications',
            '-key', recipient,
            '-value', str(count)
        ])

        # Real-time push notification to recipient if online
        if recipient in connected_users:
            emit('new_message', {
                'message_id': message_id,
                'sender': sender,
                'timestamp': timestamp
            }, room=recipient)

    emit('message_send_result', result)

@socketio.on('message_load')
def handle_message_load(data):
    """Load encrypted message"""
    message_id = data['message_id']

    result = exec_gdb_cli([
        'read',
        '-group', 'local.dna.messages',
        '-key', message_id
    ])

    emit('message_load_result', result)

@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnected"""
    # Remove from connected users
    for identity, sid in list(connected_users.items()):
        if sid == request.sid:
            del connected_users[identity]
            leave_room(identity)
            break

    print(f'Client disconnected: {request.sid}')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8080)
```

**Install Dependencies:**
```bash
pip3 install flask-socketio python-socketio
```

### Client Implementation (JavaScript Example for GUI)

```javascript
import io from 'socket.io-client';

const socket = io('http://ai.cpunk.io:8080');

socket.on('connect', () => {
    console.log('Connected to relay server');

    // Login with identity
    socket.emit('login', {identity: 'alice'});
});

socket.on('login_success', (data) => {
    console.log('Logged in as:', data.identity);
});

// Listen for incoming messages
socket.on('new_message', (data) => {
    console.log('New message from:', data.sender);

    // Load the actual message
    socket.emit('message_load', {message_id: data.message_id});
});

socket.on('message_load_result', (result) => {
    if (result.success) {
        // Decrypt and display message
        const [sender, recipient, timestamp, ciphertext] = result.output.split('|');
        decryptAndDisplay(ciphertext);
    }
});

// Send a message
function sendMessage(recipient, plaintext) {
    const ciphertext = encrypt(plaintext, recipient);
    const message_id = generateMessageId();

    socket.emit('message_send', {
        message_id: message_id,
        sender: 'alice',
        recipient: recipient,
        ciphertext: ciphertext,
        timestamp: Date.now()
    });
}
```

### Pros/Cons

**Pros:**
- ✅ Real-time push notifications
- ✅ No polling (efficient)
- ✅ Bidirectional communication
- ✅ Perfect for chat applications
- ✅ Presence detection (online/offline)

**Cons:**
- ❌ Stateful (harder to scale)
- ❌ Requires WebSocket support in client
- ❌ More complex server infrastructure

---

## Option 3: Hybrid (PostgreSQL + GDB Relay) - RECOMMENDED

### Description
Best of both worlds: Use **PostgreSQL** for fast message storage and **GDB relay** for distributed keyserver.

### Architecture
```
DNA Messenger Client
    ↓ (libpq)
PostgreSQL Server (ai.cpunk.io:5432)
    ↓
Message Storage (fast, private)

DNA Messenger Client
    ↓ (HTTP/WebSocket)
GDB Relay Server (ai.cpunk.io:8080)
    ↓ (CLI commands)
Cellframe Node + GDB
    ↓
Keyserver (distributed, synced)
```

### Why This is Best

| Feature | PostgreSQL | GDB Relay |
|---------|-----------|-----------|
| **Message Storage** | ✅ Fast, proven | ❌ Slower (CLI overhead) |
| **Keyserver** | ❌ Centralized | ✅ Distributed (Cellframe network) |
| **Privacy** | ✅ You control it | ⚠️ Public/synced |
| **Performance** | ✅ Optimized queries | ⚠️ Limited by CLI |
| **Scaling** | ✅ Well understood | 🔄 Depends on Cellframe |

### Implementation

**Server Side:**
```bash
# PostgreSQL for messages (existing Phase 3 setup)
sudo apt-get install postgresql
# ... existing message table setup ...

# GDB relay for keyserver only (Option 1 or 2)
python3 dna_gdb_relay.py
```

**Client Side (`dna_gdb.c`):**
```c
// Keyserver functions use HTTP/WebSocket relay
int dna_gdb_keyserver_store(...) {
    // Use HTTP to ai.cpunk.io:8080
    return exec_gdb_command_http("/keyserver/store", ...);
}

// Message functions use direct PostgreSQL (existing code)
// No changes needed - keep using libpq
```

**Client Side (`messenger.c`):**
```c
// Messages: Use PostgreSQL (Phase 3 code, unchanged)
PGconn *db_conn = PQconnectdb("host=ai.cpunk.io dbname=dna_messenger ...");

// Keys: Use GDB relay
dna_gdb_init("http://ai.cpunk.io:8080");  // Point to relay server
dna_gdb_keyserver_store(identity, signing_key, enc_key);
```

### Pros/Cons

**Pros:**
- ✅ **Fast messages** (PostgreSQL optimized)
- ✅ **Distributed keyserver** (Cellframe network)
- ✅ **Privacy** (messages stay on your server)
- ✅ **Reliability** (proven database technology)
- ✅ **Best of both worlds**

**Cons:**
- ❌ Two separate systems to maintain
- ❌ More complex architecture

---

## Security Considerations

### Access Control

#### Option A: Public Relay (No Auth)
```python
# No authentication - anyone can use
@app.route('/keyserver/store', methods=['POST'])
def keyserver_store():
    # ... execute GDB command ...
```

**Use Case:** Public keyserver (like PGP keyservers)

---

#### Option B: API Key Authentication
```python
import secrets

# Generate API keys
API_KEYS = {
    'alice': secrets.token_urlsafe(32),
    'bob': secrets.token_urlsafe(32)
}

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key not in API_KEYS.values():
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/keyserver/store', methods=['POST'])
@require_api_key
def keyserver_store():
    # ... execute GDB command ...
```

**Use Case:** Controlled access for known users

---

#### Option C: Rate Limiting
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)

@app.route('/keyserver/store', methods=['POST'])
@limiter.limit("10 per minute")
def keyserver_store():
    # ... execute GDB command ...
```

**Use Case:** Prevent abuse and DoS attacks

---

#### Option D: IP Whitelist
```python
ALLOWED_IPS = ['203.0.113.0', '198.51.100.0']

def check_ip(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.remote_addr not in ALLOWED_IPS:
            return jsonify({'error': 'Unauthorized IP'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/keyserver/store', methods=['POST'])
@check_ip
def keyserver_store():
    # ... execute GDB command ...
```

**Use Case:** Private relay for specific clients only

---

### SSL/TLS

Always use HTTPS in production:

```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Get Let's Encrypt certificate
sudo certbot --nginx -d ai.cpunk.io

# Flask with SSL
if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=443,
        ssl_context=(
            '/etc/letsencrypt/live/ai.cpunk.io/fullchain.pem',
            '/etc/letsencrypt/live/ai.cpunk.io/privkey.pem'
        )
    )
```

Update client:
```c
snprintf(url, sizeof(url), "https://ai.cpunk.io:443%s", endpoint);
```

---

## Caching Layer (Optional)

Add Redis caching to reduce GDB load:

```python
import redis

redis_client = redis.Redis(host='localhost', port=6379, db=0)

@app.route('/keyserver/load/<identity>', methods=['GET'])
def keyserver_load(identity):
    # Check cache first
    cached = redis_client.get(f'key:{identity}')
    if cached:
        return jsonify({'success': True, 'output': cached.decode()})

    # Cache miss - query GDB
    result = exec_gdb_cli([
        'read',
        '-group', 'local.dna.keyserver',
        '-key', identity
    ])

    # Cache for 1 hour
    if result['success']:
        redis_client.setex(f'key:{identity}', 3600, result['output'])

    return jsonify(result)
```

**Install Redis:**
```bash
sudo apt-get install redis-server
pip3 install redis
```

---

## Deployment Checklist

When implementing the network layer (post-GUI):

### Server Setup
- [ ] Install Cellframe node on relay server
- [ ] Verify `cellframe-node-cli global_db` works
- [ ] Choose relay option (REST/WebSocket/Hybrid)
- [ ] Implement relay server (Python/Node.js)
- [ ] Add authentication (API key/IP whitelist)
- [ ] Add rate limiting
- [ ] Set up SSL/TLS certificates
- [ ] Configure firewall rules
- [ ] Set up systemd service
- [ ] Add monitoring/logging
- [ ] Test with load testing tools

### Client Modifications
- [ ] Add libcurl dependency (for REST)
- [ ] Update `dna_gdb.c` to use HTTP/WebSocket
- [ ] Add relay server URL to config
- [ ] Test keyserver operations via relay
- [ ] Handle connection failures gracefully
- [ ] Add retry logic
- [ ] Update documentation

### Testing
- [ ] Unit tests for relay endpoints
- [ ] Integration tests (client → relay → GDB)
- [ ] Load testing (concurrent connections)
- [ ] Failure recovery testing
- [ ] Security testing (auth bypass attempts)
- [ ] Performance benchmarks

---

## Performance Benchmarks (Estimated)

| Operation | PostgreSQL (Direct) | GDB (CLI) | GDB (Relay) |
|-----------|---------------------|-----------|-------------|
| Store Message | ~1ms | ~50ms | ~100ms |
| Load Message | ~2ms | ~50ms | ~100ms |
| Store Key | ~1ms | ~50ms | ~100ms |
| Load Key | ~2ms | ~50ms | ~100ms |

**Conclusion:** Use PostgreSQL for messages, GDB relay for keyserver (Hybrid approach).

---

## Migration Path

### Phase 3 (Current)
```
Client → PostgreSQL → Messages + Keys
```

### Phase 4a (GDB Integration)
```
Client → dna_gdb.c → CLI commands → Local Cellframe Node
```

### Phase 5 (Network Layer - Future)
```
Client → HTTP/WebSocket → Relay Server → Cellframe Node → GDB
```

### Phase 6 (Hybrid - Recommended)
```
Client → PostgreSQL → Messages
Client → Relay Server → GDB → Keys
```

---

## References

- **Cellframe GDB Documentation**: https://wiki.cellframe.net/en/soft/cellframe-node/global-db
- **Flask Documentation**: https://flask.palletsprojects.com/
- **Flask-SocketIO**: https://flask-socketio.readthedocs.io/
- **WebSocket Protocol**: RFC 6455
- **REST API Design**: https://restfulapi.net/

---

## Next Steps

1. **Complete GUI** (Phase 5) - Qt/Flutter desktop/mobile apps
2. **Implement Network Layer** (Phase 6) - Choose relay option
3. **Deploy Relay Servers** - Set up ai.cpunk.io infrastructure
4. **Test at Scale** - Load testing and optimization
5. **Add Forward Secrecy** (Phase 7) - Session keys, X3DH

---

**Last Updated:** 2025-10-15
**Status:** Planning Document
**Implementation Target:** Post-GUI Phase
**Recommended Approach:** Option 3 (Hybrid - PostgreSQL + GDB Relay)
