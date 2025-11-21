# DNA Messenger - API Quick Reference

**Last Updated:** 2025-11-21

---

## DNA Core API (dna_api.h)

### Context Management
```c
dna_context_t* dna_context_new(void);
void dna_context_free(dna_context_t* ctx);
```

### Message Encryption/Decryption
```c
int dna_encrypt_message(
    const uint8_t *plaintext,
    size_t len,
    const public_key_t *key,
    dna_buffer_t *out
);

int dna_decrypt_message(
    const uint8_t *ciphertext,
    size_t len,
    const private_key_t *key,
    dna_buffer_t *out
);
```

### Multi-Recipient Encryption
```c
int dna_encrypt_multi_recipient(
    const uint8_t *plaintext,
    size_t len,
    const public_key_t **recipient_keys,
    size_t num_recipients,
    dna_buffer_t *out
);
```

---

## Cellframe RPC API (cellframe_rpc.h)

### RPC Call
```c
int cellframe_rpc_call(
    cellframe_rpc_request_t *req,
    cellframe_rpc_response_t **resp
);
```

### Balance Query
```c
int cellframe_rpc_get_balance(
    const char *address,
    const char *network,
    const char *token,
    char *balance_out
);
```

---

## Wallet API (wallet.h)

### List Wallets
```c
int wallet_list_cellframe(wallet_list_t **list);
```

### Get Address
```c
int wallet_get_address(
    const cellframe_wallet_t *wallet,
    const char *network,
    char *out
);
```

### Sign Transaction
```c
int wallet_sign_transaction(
    const cellframe_wallet_t *wallet,
    const uint8_t *tx_data,
    size_t tx_len,
    uint8_t *signature_out
);
```

---

## Messenger API (messenger.h)

### Send Message
```c
int messenger_send_message(
    messenger_context_t *ctx,
    const char *recipient,
    const char *message,
    message_type_t type
);
```

### Receive Messages
```c
int messenger_receive_messages(
    messenger_context_t *ctx,
    message_info_t **messages,
    size_t *count
);
```

---

## DHT API (dht_keyserver.h)

### Publish Key
```c
int dht_keyserver_publish(
    dht_context_t *ctx,
    const char *identity,
    const uint8_t *dilithium_pubkey,
    const uint8_t *kyber_pubkey
);
```

### Lookup Key
```c
int dht_keyserver_lookup(
    dht_context_t *ctx,
    const char *identity,
    uint8_t *dilithium_pubkey_out,
    uint8_t *kyber_pubkey_out
);
```

### Reverse Lookup
```c
int dht_keyserver_reverse_lookup(
    dht_context_t *ctx,
    const uint8_t *fingerprint,
    char *identity_out
);
```

---

## Error Codes

```c
#define DNA_SUCCESS           0
#define DNA_ERROR            -1
#define DNA_ERROR_NOMEM      -2
#define DNA_ERROR_INVALID    -3
#define DNA_ERROR_NOTFOUND   -4
#define DNA_ERROR_EXISTS     -5
#define DNA_ERROR_CRYPTO     -6
```

---

## Return Value Convention

- **0** = Success
- **-1** = Generic error
- **-2** = Not found
- **-3** = Verification failed

Always check return values!

---

**See also:**
- [Full API Spec](DNA_API_INTEGRATION_SPEC.md) - Comprehensive API documentation
- [Development Guidelines](DEVELOPMENT.md) - Usage patterns and best practices
