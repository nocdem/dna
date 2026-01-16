# Plan: 1-1 Mesajlaşma Daily Bucket Migrasyonu

**Tarih:** 2026-01-16
**Durum:** CHECKPOINT 3 - Plan Onay Bekliyor
**Hedef:** Mevcut Spillway (statik key) sistemini grup mesajlaşma gibi günlük bucket sistemine taşımak

---

## 1. Mevcut Sistem Analizi

### 1.1 Spillway Protocol (Current)

```
Key Format: SHA3-512(sender + ":outbox:" + recipient)
           ↓
     TEK STATİK KEY per sender-recipient pair
           ↓
     Tüm mesajlar append → replace (signed put, value_id=1)
```

**Dosyalar:**
- `dht/shared/dht_offline_queue.h` - API tanımları
- `dht/shared/dht_offline_queue.c` - Implementation (~700 satır)
- `src/api/dna_engine.c` - Watermark listeners (~200 satır)
- `messenger/messages.c:515` - `messenger_queue_to_dht()` çağrısı

**Watermark Sistemi:**
- Key: `SHA3-512(recipient + ":watermark:" + sender)`
- Recipient, aldığı en yüksek seq_num'u publish eder
- Sender, gönderirken watermark fetch edip eski mesajları prune eder
- Listener: Her kontak için ayrı watermark listener

### 1.2 Group Outbox (Hedef Model)

```
Key Format: dna:group:<uuid>:out:<day_bucket>
            where day_bucket = unix_timestamp / 86400

Örnek:
├── dna:group:550e8400...:out:20470  (bugün)
├── dna:group:550e8400...:out:20469  (dün)
└── ...7 gün TTL ile otomatik expire
```

**Avantajlar:**
- Watermark sistemi YOK - TTL ile otomatik pruning
- Daha küçük DHT değerleri (günlük)
- Incremental sync (gün bazlı)
- Day rotation ile listener yönetimi

---

## 2. Yeni Sistem Tasarımı

### 2.1 Key Format

```
Yeni: dna:dm:<sender_fp_short>:<recipient_fp_short>:out:<day_bucket>

Örnek (sender=alice, recipient=bob, bugün=20470):
  dna:dm:a3f9e2d1:b4a7f890:out:20470

Not: Fingerprint'in ilk 8 karakteri yeterli (collision önlemek için)
     Ya da tam fingerprint kullanılabilir (daha güvenli ama uzun)
```

**Alternatif (daha kısa):**
```
SHA3-512(sender + ":outbox:" + recipient + ":" + day_bucket)[0:32]
```

### 2.2 Veri Yapısı

```c
// Mevcut dht_offline_message_t korunur, seq_num artık day içi sıralama için
typedef struct {
    uint64_t seq_num;       // Gün içi sıralama (artık watermark için değil)
    uint64_t timestamp;     // Unix timestamp
    uint64_t expiry;        // timestamp + 7 days (day_bucket + 7)
    char *sender;
    char *recipient;
    uint8_t *ciphertext;
    size_t ciphertext_len;
} dht_offline_message_t;
```

### 2.3 Yeni API

```c
// Yeni key oluşturma
int dht_dm_outbox_make_key(
    const char *sender_fp,
    const char *recipient_fp,
    uint64_t day_bucket,      // 0 = current day
    char *key_out,
    size_t key_out_size
);

// Mesaj gönderme (günlük bucket'a)
int dht_dm_queue_message(
    dht_context_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint32_t ttl_seconds      // 0 = default 7 days
);

// Mesaj alma (tek kontak, son N gün)
int dht_dm_retrieve_messages(
    dht_context_t *ctx,
    const char *my_fp,
    const char *contact_fp,
    uint64_t from_day,        // 0 = 7 gün önce
    dht_offline_message_t **messages_out,
    size_t *count_out
);

// Tüm kontaklardan mesaj alma (paralel)
int dht_dm_retrieve_all_contacts_parallel(
    dht_context_t *ctx,
    const char *my_fp,
    const char **contact_list,
    size_t contact_count,
    uint64_t from_day,
    dht_offline_message_t **messages_out,
    size_t *count_out
);
```

---

## 3. Implementation Adımları

### Adım 1: Yeni Header Dosyası
**Dosya:** `dht/shared/dht_dm_outbox.h`

- Yeni API tanımları
- `DNA_DM_OUTBOX_KEY_FMT` sabiti
- `DNA_DM_OUTBOX_SECONDS_PER_DAY` (86400)
- `DNA_DM_OUTBOX_MAX_CATCHUP_DAYS` (7)
- Listen context yapısı

### Adım 2: Yeni Implementation
**Dosya:** `dht/shared/dht_dm_outbox.c`

- `dht_dm_outbox_make_key()` - Key oluşturma
- `dht_dm_queue_message()` - Mesaj gönderme (fetch → append → put)
- `dht_dm_retrieve_messages()` - Tek kontak retrieve
- `dht_dm_retrieve_all_contacts_parallel()` - Paralel retrieve
- `dht_dm_outbox_sync()` - Son sync'ten bu yana mesaj sync
- Local cache (mevcut `outbox_cache` benzeri)

### Adım 3: Listen API
**Dosya:** `dht/shared/dht_dm_outbox.c` (devam)

```c
typedef struct {
    char my_fp[129];
    char contact_fp[129];
    uint64_t current_day;
    size_t listen_token;
    void (*callback)(const char *contact_fp, size_t new_count, void *user_data);
    void *user_data;
    dht_context_t *dht_ctx;
} dht_dm_listen_ctx_t;

// Subscribe to contact's outbox for today
int dht_dm_outbox_subscribe(
    dht_context_t *dht_ctx,
    const char *my_fp,
    const char *contact_fp,
    void (*callback)(const char *contact_fp, size_t new_count, void *user_data),
    void *user_data,
    dht_dm_listen_ctx_t **ctx_out
);

// Unsubscribe
void dht_dm_outbox_unsubscribe(dht_context_t *dht_ctx, dht_dm_listen_ctx_t *ctx);

// Day rotation check (call every 4 minutes like group)
int dht_dm_outbox_check_day_rotation(dht_context_t *dht_ctx, dht_dm_listen_ctx_t *ctx);
```

### Adım 4: Engine Entegrasyonu
**Dosya:** `src/api/dna_engine.c`

Değişiklikler:
1. `dna_engine_start_contact_listeners()` - Yeni daily bucket listener kullan
2. `dna_engine_heartbeat()` - Day rotation kontrolü ekle (mevcut 4 dakika timer)
3. **KORU:** Watermark listener fonksiyonları (delivery report için):
   - `dna_engine_start_watermark_listener()` - DELIVERED status tetikler
   - `dna_engine_cancel_watermark_listener()`
   - `watermark_listener_callback()` - Mesaj status günceller

### Adım 5: Messenger Entegrasyonu
**Dosya:** `messenger/messages.c`

Değişiklik:
- `messenger_queue_to_dht()` → `dht_dm_queue_message()` çağır (satır 515)
- seq_num artık watermark için değil, gün içi sıralama için

### Adım 6: Watermark Sadeleştirme (Pruning Kaldır, Delivery Report Koru)

**KALDIRILACAK (pruning mantığı):**
- `dht_queue_message()` içindeki watermark fetch + prune logic
- Mesaj gönderirken watermark kontrolü

**KORUNACAK (delivery report için):**
- `dht_generate_watermark_key()` - Key oluşturma
- `dht_publish_watermark_async()` - Recipient mesaj aldığında publish
- `dht_get_watermark()` - İsteğe bağlı sorgu
- `dht_listen_watermark()` - Real-time delivery notification
- `dht_cancel_watermark_listener()` - Listener iptal
- Watermark listener'lar `dna_engine.c`'de - DELIVERED status için

**Yeni Watermark Akışı (Sadeleştirilmiş):**
```
1. Alice → Bob mesaj gönderir (daily bucket'a PUT)
2. Bob mesajı alır, watermark publish eder (seq_num)
3. Alice'in watermark listener'ı tetiklenir
4. Alice mesaj status'unu DELIVERED yapar
5. ✗ Pruning YOK - TTL ile otomatik expire
```

**Korunacaklar:**
- `dht_serialize_messages()` / `dht_deserialize_messages()` - Yeni sistemde de kullanılacak
- `dht_offline_message_t` yapısı
- Memory free fonksiyonları

### Adım 7: Database Sync State
**Dosya:** `message_backup.c` veya yeni `dht_dm_outbox.c`

```sql
-- Yeni tablo: Her kontak için son sync günü
CREATE TABLE IF NOT EXISTS dm_sync_state (
    contact_fp TEXT PRIMARY KEY,
    last_sync_day INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
```

### Adım 8: CMake Güncelleme
**Dosya:** `dht/CMakeLists.txt`

```cmake
# Yeni dosya ekle
set(DHT_SHARED_SOURCES
    ...
    shared/dht_dm_outbox.c
    ...
)
```

---

## 4. Migration Stratejisi

### 4.1 Breaking Change Handling

**Durum:** Bu breaking change'dir. Mevcut offline mesajlar kaybolacak.

**Gerekçe:**
- Watermark sistemi tamamen değişiyor
- Key format değişiyor
- Geriye uyumluluk karmaşıklığı çok yüksek

**Kullanıcı Etkisi:**
- Henüz teslim edilmemiş offline mesajlar kaybolur (max 7 gün)
- Online mesajlar etkilenmez (zaten anlık)
- Mesaj geçmişi (SQLite) etkilenmez

### 4.2 Version Bump

- C Library: `0.4.80` → `0.4.81`
- Commit message: `feat: Migrate 1-1 messaging to daily buckets (v0.4.81)`

---

## 5. Dosya Değişiklik Özeti

| Dosya | İşlem | Satır Tahmini |
|-------|-------|---------------|
| `dht/shared/dht_dm_outbox.h` | YENİ | ~150 |
| `dht/shared/dht_dm_outbox.c` | YENİ | ~500 |
| `dht/shared/dht_offline_queue.h` | GÜNCELLE | -20 (pruning logic kaldır) |
| `dht/shared/dht_offline_queue.c` | GÜNCELLE | -80 (pruning logic kaldır, watermark koru) |
| `src/api/dna_engine.c` | GÜNCELLE | +50 (day rotation), watermark listener koru |
| `messenger/messages.c` | GÜNCELLE | ~10 |
| `dht/CMakeLists.txt` | GÜNCELLE | +1 |
| `message_backup.c` | GÜNCELLE | +30 (dm_sync_state table) |
| `docs/DHT_SYSTEM.md` | GÜNCELLE | ~50 |
| `docs/MESSAGE_SYSTEM.md` | GÜNCELLE | ~30 |
| `include/dna/version.h` | GÜNCELLE | +1 |

**Toplam:** ~600 yeni satır, ~350 silinen satır

---

## 6. Test Planı

1. **Build Test:** Linux + Windows cross-compile
2. **Unit Test (CLI):**
   - `./dna-messenger-cli send <contact> "test message"`
   - `./dna-messenger-cli check-offline`
   - Day rotation simülasyonu
3. **Integration Test:**
   - İki client arası mesajlaşma
   - Offline → online geçiş
   - 7 gün TTL expiry

---

## 7. Rollback Planı

Eğer production'da sorun çıkarsa:
1. Git revert ile eski koda dön
2. Eski key format'ı kullanan version deploy et
3. Kullanıcılar eski sürüme güncelleme yapabilir

---

## Onay Bekleniyor

**Sorular:**
1. Key format: Tam fingerprint mi yoksa kısaltılmış (8 char) mı?
2. Öneri: Tam fingerprint (güvenlik için)

**Devam etmek için "APPROVED" veya "PROCEED" yazın.**
