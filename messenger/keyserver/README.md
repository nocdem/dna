# DNA Messenger Keyserver

HTTP REST API keyserver for DNA Messenger identity management.

## Features

- RESTful HTTP API
- Dilithium3 signature verification
- PostgreSQL backend
- Rate limiting
- Version monotonicity (anti-replay)

## API Endpoints

- `POST /api/keyserver/register` - Register identity + public keys
- `GET /api/keyserver/lookup/<identity>` - Lookup recipient keys
- `GET /api/keyserver/list` - List all registered users
- `GET /api/keyserver/health` - Health check

## Building

### Dependencies

```bash
# Debian/Ubuntu
sudo apt-get install libmicrohttpd-dev libpq-dev libjson-c-dev

# Arch Linux
sudo pacman -S libmicrohttpd postgresql-libs json-c
```

### Compile

```bash
mkdir build
cd build
cmake ..
make
```

## Setup

### 1. Database Setup

```bash
# Create database
sudo -u postgres createdb dna_keyserver

# Create user
sudo -u postgres psql -c "CREATE USER keyserver_user WITH PASSWORD 'your_password';"

# Load schema
psql -U keyserver_user -d dna_keyserver -f sql/schema.sql
```

### 2. Configuration

Copy and edit config file:

```bash
cp config/keyserver.conf.example config/keyserver.conf
nano config/keyserver.conf
```

### 3. Run

```bash
./build/keyserver config/keyserver.conf
```

## Testing

### Register Identity

```bash
curl -X POST http://localhost:8080/api/keyserver/register \
  -H "Content-Type: application/json" \
  -d @test_register.json
```

### Lookup Identity

```bash
curl http://localhost:8080/api/keyserver/lookup/alice/default
```

### List All Identities

```bash
curl http://localhost:8080/api/keyserver/list
```

## Deployment

See `KEYSERVER-HTTP-API-DESIGN.md` in the root directory for full deployment guide.

### Production Setup

1. Deploy behind Nginx reverse proxy
2. Enable SSL with Let's Encrypt
3. Configure rate limiting
4. Set up monitoring

### Systemd Service

```bash
sudo cp config/keyserver.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable keyserver
sudo systemctl start keyserver
```

## Architecture

```
Client (messenger.c)
    ↓
    HTTP POST/GET
    ↓
Nginx (reverse proxy + SSL)
    ↓
Keyserver (C + libmicrohttpd)
    ↓
PostgreSQL Database
```

## Security

- Dilithium3 signature verification on all registrations
- Version monotonicity prevents replay attacks
- Rate limiting per IP address
- Input validation (handle format, key sizes, timestamps)
- Parameterized SQL queries (SQL injection protection)

## File Structure

```
keyserver/
├── src/
│   ├── main.c           # HTTP server entry point
│   ├── api_register.c   # POST /register handler
│   ├── api_lookup.c     # GET /lookup handler
│   ├── api_list.c       # GET /list handler
│   ├── db.c             # PostgreSQL wrapper
│   ├── validation.c     # Request validation
│   ├── signature.c      # Dilithium3 verification
│   └── rate_limit.c     # Rate limiting
├── sql/
│   └── schema.sql       # PostgreSQL schema
├── config/
│   ├── keyserver.conf.example
│   └── keyserver.service
├── CMakeLists.txt
└── README.md
```

## License

GPL-3.0 (same as DNA Messenger)
