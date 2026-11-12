/**
 * @file amm_price.c
 * @brief nodus-amm ETH price adapter (see amm_price.h).
 */
#include "amm_price.h"

#include <curl/curl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "AMM_PRICE"
#define N_SOURCES 4

typedef struct {
    unsigned    bit;
    const char *url;
    const char *name;       /* what the log line calls the source */
} src_def_t;

static const src_def_t SRC[N_SOURCES] = {
    {AMM_PRICE_KRAKEN,   "https://api.kraken.com/0/public/Ticker?pair=ETHUSDT", "kraken"},
    {AMM_PRICE_BINANCE,  "https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT", "binance"},
    {AMM_PRICE_BITFINEX, "https://api.bitfinex.com/v2/ticker/tETHUST", "bitfinex"},
    {AMM_PRICE_COINBASE, "https://api.exchange.coinbase.com/products/ETH-USDT/ticker", "coinbase"},
};

static uint64_t mono_ms(void);

const char *amm_price_source_url(unsigned bit) {
    for (int i = 0; i < N_SOURCES; i++)
        if (SRC[i].bit == bit) return SRC[i].url;
    return NULL;
}

/* ── decimal text -> price_e6 ─────────────────────────────────────────── */

/* digits [ '.' digits ]; at most 7 integer digits; truncated to 6 fraction
 * digits; zero refused. */
static int dec_e6(const char *s, size_t n, uint64_t *out) {
    uint64_t ip = 0, fp = 0;
    size_t i = 0, idig = 0, fdig = 0;
    for (; i < n && s[i] >= '0' && s[i] <= '9'; i++) {
        if (++idig > 7) return -1;
        ip = ip * 10 + (uint64_t)(s[i] - '0');
    }
    if (idig == 0) return -1;
    if (i < n && s[i] == '.') {
        i++;
        size_t start = i;
        for (; i < n && s[i] >= '0' && s[i] <= '9'; i++) {
            if (fdig < 6) { fp = fp * 10 + (uint64_t)(s[i] - '0'); fdig++; }
        }
        if (i == start) return -1;          /* "12." is not a number       */
    }
    if (i != n) return -1;                  /* exponent, sign, junk        */
    while (fdig < 6) { fp *= 10; fdig++; }
    uint64_t v = ip * 1000000ULL + fp;
    if (v == 0) return -1;
    *out = v;
    return 0;
}

/* ── ticker shapes ────────────────────────────────────────────────────── */

static const char *skip_ws(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    return p;
}

/* The text after the FIRST `"key"` `:` : returns a pointer to the value's
 * start, or NULL. */
static const char *after_key(const char *b, const char *end, const char *key) {
    char pat[24];
    size_t kl = strlen(key);
    if (kl + 3 > sizeof(pat)) return NULL;
    pat[0] = '"'; memcpy(pat + 1, key, kl); pat[kl + 1] = '"'; pat[kl + 2] = '\0';
    size_t pl = kl + 2;
    for (const char *p = b; (size_t)(end - p) >= pl; p++) {
        if (memcmp(p, pat, pl) != 0) continue;
        const char *q = skip_ws(p + pl, end);
        if (q < end && *q == ':') return skip_ws(q + 1, end);
    }
    return NULL;
}

/* A value that is a "string" or a bare number token: [start, start+n). */
static int token_at(const char *p, const char *end, const char **s, size_t *n) {
    if (!p || p >= end) return -1;
    if (*p == '"') {
        const char *q = p + 1;
        while (q < end && *q != '"') {
            if (*q == '\\') return -1;
            q++;
        }
        if (q >= end) return -1;
        *s = p + 1; *n = (size_t)(q - p - 1);
        return 0;
    }
    const char *q = p;
    while (q < end && ((*q >= '0' && *q <= '9') || *q == '.' || *q == 'e' ||
                       *q == 'E' || *q == '+' || *q == '-')) q++;
    if (q == p) return -1;
    *s = p; *n = (size_t)(q - p);
    return 0;
}

int amm_price_parse(unsigned bit, const char *body, size_t len, uint64_t *price_e6) {
    if (!body || !price_e6 || len == 0 || len > AMM_PRICE_RESP_MAX) return -1;
    const char *end = body + len, *p, *s;
    size_t n;
    switch (bit) {
    case AMM_PRICE_BINANCE:
    case AMM_PRICE_COINBASE:                     /* {"price":"3421.56", ...} */
        p = after_key(body, end, "price");
        break;
    case AMM_PRICE_KRAKEN:                       /* result.<pair>.c[0]       */
        p = after_key(body, end, "result");
        if (!p) return -1;
        p = after_key(p, end, "c");
        if (!p || *p != '[') return -1;
        p = skip_ws(p + 1, end);
        break;
    case AMM_PRICE_BITFINEX: {                   /* [ ... ] element 6        */
        p = skip_ws(body, end);
        if (p >= end || *p != '[') return -1;
        p++;
        for (int idx = 0; idx < 6; idx++) {      /* skip six numeric elements */
            const char *c = memchr(p, ',', (size_t)(end - p));
            if (!c) return -1;
            p = c + 1;
        }
        p = skip_ws(p, end);
        break;
    }
    default:
        return -1;
    }
    if (token_at(p, end, &s, &n) != 0) return -1;
    return dec_e6(s, n, price_e6);
}

uint64_t amm_price_median(const uint64_t *v, int n) {
    uint64_t t[N_SOURCES];
    if (n < 1) return 0;
    if (n > N_SOURCES) n = N_SOURCES;
    memcpy(t, v, (size_t)n * sizeof(uint64_t));
    for (int i = 1; i < n; i++) {                /* insertion sort            */
        uint64_t x = t[i];
        int k = i - 1;
        while (k >= 0 && t[k] > x) { t[k + 1] = t[k]; k--; }
        t[k + 1] = x;
    }
    if (n % 2) return t[n / 2];
    return t[n / 2 - 1] + (t[n / 2] - t[n / 2 - 1]) / 2;   /* floor of the mean */
}

/* ── the adapter ──────────────────────────────────────────────────────── */

struct amm_price {
    amm_price_cfg_t cfg;
    pthread_mutex_t mu;            /* guards have / at / price: the poll thread
                                    * writes them, a quote reads them          */
    int      have[N_SOURCES];
    uint64_t at[N_SOURCES];        /* fetched_at, seconds                     */
    uint64_t price[N_SOURCES];
};

amm_price_t *amm_price_new(const amm_price_cfg_t *cfg) {
    if (!cfg || !cfg->get || !cfg->now_s || cfg->max_age_seconds == 0 ||
        cfg->min_sources == 0 || (cfg->sources & ~AMM_PRICE_ALL) || !cfg->sources)
        return NULL;
    uint64_t n = 0;
    for (unsigned m = cfg->sources; m; m >>= 1) n += m & 1u;
    if (cfg->min_sources > n) return NULL;
    amm_price_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->cfg = *cfg;
    pthread_mutex_init(&p->mu, NULL);
    return p;
}

void amm_price_free(amm_price_t *p) {
    if (!p) return;
    pthread_mutex_destroy(&p->mu);
    free(p);
}

static int fresh(const amm_price_t *p, int i, uint64_t now) {
    return p->have[i] && now >= p->at[i] && now - p->at[i] <= p->cfg.max_age_seconds;
}

/* The cache is read by quotes (another thread) while the poll thread writes
 * it: every access to have / at / price is under p->mu. The network GET is
 * made WITHOUT the lock, so a quote never waits for a slow source. */
int amm_price_poll(amm_price_t *p, uint64_t deadline_ms) {
    if (!p) return 0;
    uint64_t now = p->cfg.now_s(p->cfg.now_ctx);
    uint64_t due = p->cfg.max_age_seconds / 2;
    if (due == 0) due = 1;
    int nfresh = 0;
    for (int i = 0; i < N_SOURCES; i++) {
        if (!(p->cfg.sources & SRC[i].bit)) continue;
        pthread_mutex_lock(&p->mu);
        const int is_due = !p->have[i] || now < p->at[i] || now - p->at[i] >= due;
        pthread_mutex_unlock(&p->mu);
        if (is_due) {
            uint8_t buf[AMM_PRICE_RESP_MAX];
            size_t len = 0;
            uint64_t v = 0;
            const uint64_t t0 = mono_ms();
            const int got = p->cfg.get(p->cfg.get_ctx, SRC[i].url, buf, sizeof(buf), &len,
                                       deadline_ms) == AMM_ETH_OK;
            const unsigned long long ms = (unsigned long long)(mono_ms() - t0);
            if (got && amm_price_parse(SRC[i].bit, (const char *)buf, len, &v) == 0) {
                pthread_mutex_lock(&p->mu);
                p->have[i] = 1;
                p->at[i] = now;
                p->price[i] = v;
                pthread_mutex_unlock(&p->mu);
                QGP_LOG_INFO(LOG_TAG, "price source %s: ETH/USDT %llu.%06llu read in %llu ms",
                             SRC[i].name, (unsigned long long)(v / 1000000ULL),
                             (unsigned long long)(v % 1000000ULL), ms);
            } else if (!got) {
                QGP_LOG_WARN(LOG_TAG, "price source %s: the read failed after %llu ms "
                             "(no answer or a status other than 200)", SRC[i].name, ms);
            } else {
                QGP_LOG_WARN(LOG_TAG, "price source %s: the answer of %zu bytes holds no "
                             "usable price (read in %llu ms)", SRC[i].name, len, ms);
            }
        }
        pthread_mutex_lock(&p->mu);
        if (fresh(p, i, now)) nfresh++;
        pthread_mutex_unlock(&p->mu);
    }
    return nfresh;
}

int amm_price_get(amm_price_t *p, uint64_t *price_e6) {
    if (!p || !price_e6) return AMM_ETH_ERR;
    uint64_t now = p->cfg.now_s(p->cfg.now_ctx);
    uint64_t v[N_SOURCES];
    int n = 0;
    pthread_mutex_lock(&p->mu);
    for (int i = 0; i < N_SOURCES; i++)
        if ((p->cfg.sources & SRC[i].bit) && fresh(p, i, now)) v[n++] = p->price[i];
    pthread_mutex_unlock(&p->mu);
    if ((uint64_t)n < p->cfg.min_sources || n == 0) {
        QGP_LOG_WARN(LOG_TAG, "no price: %d fresh source(s), %llu required (a source is "
                     "fresh for %llu s)", n, (unsigned long long)p->cfg.min_sources,
                     (unsigned long long)p->cfg.max_age_seconds);
        return AMM_ETH_ERR;
    }
    uint64_t m = amm_price_median(v, n);
    if (m == 0) return AMM_ETH_ERR;
    *price_e6 = m;
    QGP_LOG_INFO(LOG_TAG, "price: median ETH/USDT %llu.%06llu of %d fresh source(s)",
                 (unsigned long long)(m / 1000000ULL), (unsigned long long)(m % 1000000ULL), n);
    return AMM_ETH_OK;
}

int amm_price_convert(uint64_t gas_limit, uint64_t max_fee_per_gas,
                      uint64_t price_e6, uint64_t *usdt_raw) {
    if (!usdt_raw || price_e6 == 0) return AMM_ETH_ERR;
    unsigned __int128 wei = (unsigned __int128)gas_limit * max_fee_per_gas;
    const unsigned __int128 U128_MAX = ~(unsigned __int128)0;
    if (wei != 0 && wei > U128_MAX / price_e6) return AMM_ETH_ERR;
    unsigned __int128 prod = wei * price_e6;
    const unsigned __int128 E18 = (unsigned __int128)1000000000000000000ULL;
    unsigned __int128 q = prod / E18;
    if (prod % E18) q += 1;                       /* round UP                  */
    if (q > UINT64_MAX) return AMM_ETH_ERR;
    *usdt_raw = (uint64_t)q;
    QGP_LOG_INFO(LOG_TAG, "fee conversion: gas limit %llu x max fee per gas %llu wei at "
                 "price %llu (e6) = %llu raw USDT (rounded up)", (unsigned long long)gas_limit,
                 (unsigned long long)max_fee_per_gas, (unsigned long long)price_e6,
                 (unsigned long long)*usdt_raw);
    return AMM_ETH_OK;
}

static int seam_fee(void *ctx, uint64_t gas_limit, uint64_t max_fee_per_gas,
                    uint64_t *usdt_raw, uint64_t deadline_ms) {
    (void)deadline_ms;
    uint64_t price = 0;
    if (amm_price_get((amm_price_t *)ctx, &price) != AMM_ETH_OK) return AMM_ETH_ERR;
    return amm_price_convert(gas_limit, max_fee_per_gas, price, usdt_raw);
}

void amm_price_seam(amm_price_t *p, amm_eth_price_t *out) {
    out->ctx = p;
    out->fee_usdt = seam_fee;
}

/* ═══ libcurl GET ═══════════════════════════════════════════════════════ */

struct amm_price_curl { uint32_t cap_ms; };

amm_price_curl_t *amm_price_curl_new(uint32_t timeout_cap_ms) {
    if (timeout_cap_ms == 0) return NULL;
    amm_price_curl_t *c = calloc(1, sizeof(*c));
    if (c) c->cap_ms = timeout_cap_ms;
    return c;
}

void amm_price_curl_free(amm_price_curl_t *c) { free(c); }

typedef struct { uint8_t *buf; size_t cap, len; } pw_t;

static size_t pw_cb(char *p, size_t sz, size_t nm, void *u) {
    pw_t *w = u;
    if (sz != 0 && nm > SIZE_MAX / sz) return 0;
    size_t n = sz * nm;
    if (n > w->cap - w->len) return 0;      /* over the bound: abort the transfer */
    memcpy(w->buf + w->len, p, n);
    w->len += n;
    return n;
}

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

int amm_price_curl_get(void *ctx, const char *url, uint8_t *resp, size_t resp_cap,
                       size_t *resp_len, uint64_t deadline_ms) {
    amm_price_curl_t *c = ctx;
    if (!c || !url || !resp || !resp_len || strncmp(url, "https://", 8) != 0)
        return AMM_ETH_ERR;
    uint64_t tmo = c->cap_ms;
    if (deadline_ms != 0) {
        uint64_t now = mono_ms();
        if (now >= deadline_ms) return AMM_ETH_ERR;
        if (deadline_ms - now < tmo) tmo = deadline_ms - now;
    }
    CURL *h = curl_easy_init();
    if (!h) return AMM_ETH_ERR;
    pw_t w = { resp, resp_cap, 0 };
    CURLcode rc = CURLE_OK;
    rc |= curl_easy_setopt(h, CURLOPT_URL, url);
    rc |= curl_easy_setopt(h, CURLOPT_HTTPGET, 1L);
    rc |= curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, pw_cb);
    rc |= curl_easy_setopt(h, CURLOPT_WRITEDATA, &w);
    /* the options of amm_eth_rpc.c's POST: TLS verification ON, https only,
     * no redirect */
    rc |= curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
    rc |= curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
    rc |= curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "https");
    rc |= curl_easy_setopt(h, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    rc |= curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);
    rc |= curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    rc |= curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, (long)tmo);
    rc |= curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS, (long)tmo);
    int ok = rc == CURLE_OK;
    long code = 0;
    if (ok) {
        CURLcode pr = curl_easy_perform(h);
        ok = pr == CURLE_OK &&
             curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &code) == CURLE_OK &&
             code == 200;
        if (pr != CURLE_OK)
            QGP_LOG_WARN(LOG_TAG, "price get: transfer failed: %s", curl_easy_strerror(pr));
        else if (!ok)
            QGP_LOG_WARN(LOG_TAG, "price get: HTTP status %ld", code);
    }
    curl_easy_cleanup(h);
    if (!ok) return AMM_ETH_ERR;
    *resp_len = w.len;
    return AMM_ETH_OK;
}
