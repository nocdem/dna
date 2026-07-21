/* scan.cpunk.io — DNAC block explorer frontend.
 *
 * No framework, no build step, no external CDN. Talks to the same-origin
 * /api/* endpoints exposed by explorer/src/exp_http.c. Field names below
 * are grounded on that file (and exp_db.h for row shapes) — do not add
 * fields that route wasn't seen to emit.
 *
 * window.API_BASE lets a local dev copy point at a non-same-origin daemon
 * (e.g. http://127.0.0.1:8390) during manual verification. Production pages
 * never set it, so it defaults to '' (same-origin relative paths).
 */
(function () {
  'use strict';

  var API_BASE = window.API_BASE || '';

  /* ── tx type map — grounded on dnac/include/dnac/dnac.h dnac_tx_type_t.
   * Value 8 has no defined enum member (7 -> 9 skips it) — render unknown
   * numeric values as "TYPE n" rather than inventing a label. */
  var TX_TYPE_NAMES = {
    0: 'GENESIS',
    1: 'SPEND',
    2: 'BURN',
    3: 'TOKEN_CREATE',
    4: 'STAKE',
    5: 'DELEGATE',
    6: 'UNSTAKE',
    7: 'UNDELEGATE',
    9: 'VALIDATOR_UPDATE',
    10: 'CHAIN_CONFIG',
    11: 'SHIELDED'
  };

  var ZERO_TOKEN_ID =
    '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';

  /* ── fetch helper ─────────────────────────────────────────────────── */

  /* exp_http.c (exp_json_u64/json_i64) emits amount-bearing fields as bare
   * JSON numbers, not strings. DNAC supply is on the order of 1e17 raw
   * units (1e9 tokens * 1e8 decimals) — well above Number.MAX_SAFE_INTEGER
   * (~9.007e15) — so native JSON.parse would silently round these before
   * fmtDnac ever sees them, no matter how carefully fmtDnac itself does
   * BigInt math. Wrap only the known amount-bearing keys in quotes at the
   * text level, before parsing, so their full-precision decimal digits
   * survive as strings. Height/seq/count/size fields are left as native
   * numbers (they stay far below 2^53 for the foreseeable life of the
   * chain) and are never routed through fmtDnac. */
  var BIGINT_KEYS = ['balance', 'fee', 'amount', 'supply_current', 'supply_burned', 'supply_genesis'];
  var BIGINT_KEY_RE = new RegExp('"(' + BIGINT_KEYS.join('|') + ')":(-?\\d+)(?=[,}\\]])', 'g');

  function preserveBigIntPrecision(text) {
    return text.replace(BIGINT_KEY_RE, function (_, key, num) {
      return '"' + key + '":"' + num + '"';
    });
  }

  /* Throws an Error whose .message is the API's {"error":"..."} string
   * when present, else a generic "HTTP <status>" — callers show this to
   * the user via renderError(). */
  function fetchJson(path) {
    return fetch(API_BASE + path, { headers: { Accept: 'application/json' } }).then(function (res) {
      return res.text().then(function (text) {
        var body = null;
        try {
          body = text ? JSON.parse(preserveBigIntPrecision(text)) : null;
        } catch (e) {
          body = null;
        }
        if (!res.ok) {
          var msg = body && typeof body.error === 'string' ? body.error : 'HTTP ' + res.status;
          throw new Error(msg);
        }
        return body;
      });
    });
  }

  /* ── BigInt-safe DNAC amount formatting ──────────────────────────── */

  /* raw is a non-negative integer amount in base units (10^8 / DNAC), as
   * a JS number (from JSON, safe for balances/fees that fit 2^53) OR a
   * string of decimal digits (used for the signed address balance, which
   * can be large). Accepts either and does all division in BigInt so
   * values above Number.MAX_SAFE_INTEGER never lose precision. Returns a
   * trimmed decimal string, e.g. "12.5", "0", "1000000". */
  function fmtDnac(raw) {
    var neg = false;
    var s = typeof raw === 'string' ? raw : String(raw);
    if (s.charAt(0) === '-') {
      neg = true;
      s = s.slice(1);
    }
    var v;
    try {
      v = BigInt(s);
    } catch (e) {
      return String(raw);
    }
    var base = 100000000n; // 1e8 (8 decimals)
    var whole = v / base;
    var frac = v % base;
    var fracStr = frac.toString();
    while (fracStr.length < 8) fracStr = '0' + fracStr;
    fracStr = fracStr.replace(/0+$/, '');
    var out = whole.toString() + (fracStr ? '.' + fracStr : '');
    return (neg ? '-' : '') + out;
  }

  /* ── DOM helpers (no innerHTML with untrusted data — attacker-influenced
   * hashes/addresses/memos go through textContent only) ─────────────── */

  function el(tag, attrs, children) {
    var e = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var val = attrs[k];
        if (val === undefined || val === null) return;
        if (k === 'class') e.className = val;
        else if (k === 'text') e.textContent = val;
        else if (k.indexOf('on') === 0 && typeof val === 'function') e.addEventListener(k.slice(2), val);
        else e.setAttribute(k, val);
      });
    }
    if (children) {
      (Array.isArray(children) ? children : [children]).forEach(function (c) {
        if (c === null || c === undefined) return;
        e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
      });
    }
    return e;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function setText(id, text) {
    var e = document.getElementById(id);
    if (e) e.textContent = text;
  }

  /* Truncated "abcd1234…ef567890" hash/address display: full value goes in
   * the title attribute, and clicking copies the full value to the
   * clipboard (best-effort — clipboard API may be unavailable, silently
   * no-ops). head/tail char counts default to 8/6. */
  function hashSpan(full, opts) {
    opts = opts || {};
    var head = opts.head || 10;
    var tail = opts.tail || 8;
    var span = el('span', { class: 'hash' + (opts.cls ? ' ' + opts.cls : ''), title: full });
    var display = full.length > head + tail + 1 ? full.slice(0, head) + '…' + full.slice(-tail) : full;
    span.textContent = display;
    span.tabIndex = 0;
    span.addEventListener('click', function () {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(full).then(
          function () {
            flashCopied(span);
          },
          function () {}
        );
      }
    });
    return span;
  }

  function flashCopied(span) {
    var prev = span.textContent;
    span.classList.add('copied');
    span.textContent = 'copied';
    setTimeout(function () {
      span.classList.remove('copied');
      span.textContent = prev;
    }, 900);
  }

  function hashLink(full, href, opts) {
    var a = el('a', { href: href });
    a.appendChild(hashSpan(full, opts));
    return a;
  }

  /* ── time formatting (UTC absolute + relative) ───────────────────── */

  function fmtTime(unixSeconds) {
    var ts = Number(unixSeconds) * 1000;
    if (!isFinite(ts) || ts <= 0) return { rel: '—', abs: '—' };
    var d = new Date(ts);
    var abs = d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
    var deltaS = Math.floor((Date.now() - ts) / 1000);
    var rel;
    if (deltaS < 5) rel = 'just now';
    else if (deltaS < 60) rel = deltaS + 's ago';
    else if (deltaS < 3600) rel = Math.floor(deltaS / 60) + 'm ago';
    else if (deltaS < 86400) rel = Math.floor(deltaS / 3600) + 'h ago';
    else rel = Math.floor(deltaS / 86400) + 'd ago';
    return { rel: rel, abs: abs };
  }

  function timeNode(unixSeconds) {
    var t = fmtTime(unixSeconds);
    return el('span', { title: t.abs, text: t.rel });
  }

  /* ── tx type ──────────────────────────────────────────────────────── */

  function txTypeName(t) {
    return TX_TYPE_NAMES[t] !== undefined ? TX_TYPE_NAMES[t] : 'TYPE ' + t;
  }

  function txTypeBadge(t) {
    var name = txTypeName(t);
    return el('span', { class: 'badge badge-type-' + t, text: name });
  }

  /* ── token id display ────────────────────────────────────────────── */

  function tokenNode(tokenId) {
    if (tokenId === ZERO_TOKEN_ID) return el('span', { class: 'token-native', text: 'DNAC' });
    return hashSpan(tokenId, { head: 8, tail: 6, cls: 'token-id' });
  }

  /* ── query string helper ─────────────────────────────────────────── */

  function qparam(name) {
    var m = new URLSearchParams(window.location.search);
    return m.get(name);
  }

  /* ── generic page error / loading states ─────────────────────────── */

  function renderError(container, err) {
    clear(container);
    container.appendChild(
      el('div', { class: 'error-box' }, [
        el('strong', { text: 'Error: ' }),
        el('span', { text: err && err.message ? err.message : String(err) })
      ])
    );
  }

  function renderLoading(container) {
    clear(container);
    container.appendChild(el('div', { class: 'loading', text: 'Loading…' }));
  }

  /* ── staleness banner ─────────────────────────────────────────────── */

  function updateStalenessBanner(stats) {
    var banner = document.getElementById('staleness-banner');
    if (!banner) return;
    var tip = stats && stats.tip_seq;
    var indexed = stats && stats.indexed_seq;
    if (typeof tip === 'number' && typeof indexed === 'number' && tip - indexed > 10) {
      banner.textContent =
        'Index catching up: indexed seq ' + indexed + ' of tip ' + tip + '. Recent data may be incomplete.';
      banner.classList.remove('hidden');
    } else {
      banner.classList.add('hidden');
      clear(banner);
    }
  }

  /* ── search box (shared by all pages) ────────────────────────────── */

  function targetHref(match) {
    if (match.type === 'tx') return 'tx.html?hash=' + encodeURIComponent(match.target);
    if (match.type === 'block') return 'block.html?h=' + encodeURIComponent(match.target);
    if (match.type === 'address') return 'address.html?fp=' + encodeURIComponent(match.target);
    return null;
  }

  function wireSearch() {
    var form = document.getElementById('search-form');
    if (!form) return;
    var input = document.getElementById('search-input');
    var results = document.getElementById('search-results');

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var q = (input.value || '').trim();
      if (!q) return;
      clear(results);
      results.appendChild(el('div', { class: 'loading', text: 'Searching…' }));
      fetchJson('/api/search?q=' + encodeURIComponent(q))
        .then(function (body) {
          var matches = (body && body.matches) || [];
          clear(results);
          if (matches.length === 0) {
            results.appendChild(el('div', { class: 'search-empty', text: 'No matches found for "' + q + '".' }));
            return;
          }
          if (matches.length === 1) {
            var href = targetHref(matches[0]);
            if (href) {
              window.location.href = href;
              return;
            }
          }
          var list = el('ul', { class: 'search-list' });
          matches.forEach(function (m) {
            var href = targetHref(m);
            var li = el('li');
            var label = el('span', { class: 'search-type', text: m.type });
            if (href) {
              var a = el('a', { href: href });
              a.appendChild(hashSpan(m.target, { head: 16, tail: 10 }));
              li.appendChild(label);
              li.appendChild(a);
            } else {
              li.appendChild(label);
              li.appendChild(el('span', { text: m.target }));
            }
            list.appendChild(li);
          });
          results.appendChild(list);
        })
        .catch(function (err) {
          clear(results);
          results.appendChild(el('div', { class: 'error-box', text: err.message }));
        });
    });
  }

  /* ── index.html ───────────────────────────────────────────────────── */

  function chainIdShort(hex) {
    if (!hex) return '—';
    return hex.slice(0, 8) + '…' + hex.slice(-6);
  }

  function loadStats() {
    var cardsEl = document.getElementById('stats-cards');
    if (!cardsEl) return Promise.resolve();
    return fetchJson('/api/stats')
      .then(function (stats) {
        updateStalenessBanner(stats);
        setText('stat-height', stats.indexed_height !== null && stats.indexed_height !== undefined ? String(stats.indexed_height) : '—');
        setText(
          'stat-supply',
          stats.supply_current !== null && stats.supply_current !== undefined ? fmtDnac(stats.supply_current) + ' DNAC' : '—'
        );
        setText(
          'stat-burned',
          stats.supply_burned !== null && stats.supply_burned !== undefined ? fmtDnac(stats.supply_burned) + ' DNAC' : '—'
        );
        var chainIdEl = document.getElementById('stat-chain-id');
        if (chainIdEl) {
          chainIdEl.textContent = '';
          if (stats.chain_id) {
            chainIdEl.title = stats.chain_id;
            chainIdEl.textContent = chainIdShort(stats.chain_id);
          } else {
            chainIdEl.textContent = '—';
          }
        }
        return stats;
      })
      .catch(function (err) {
        renderError(cardsEl, err);
      });
  }

  function blockRow(b) {
    var tr = el('tr');
    var heightTd = el('td');
    heightTd.appendChild(el('a', { href: 'block.html?h=' + b.height, text: String(b.height) }));
    tr.appendChild(heightTd);

    var hashTd = el('td', { class: 'mono' });
    if (b.block_hash) {
      hashTd.appendChild(hashLink(b.block_hash, 'block.html?h=' + encodeURIComponent(b.block_hash)));
    } else {
      hashTd.appendChild(el('span', { class: 'muted', text: 'pending' }));
    }
    tr.appendChild(hashTd);

    var timeTd = el('td');
    timeTd.appendChild(timeNode(b.timestamp));
    tr.appendChild(timeTd);

    tr.appendChild(el('td', { text: String(b.tx_count) }));
    return tr;
  }

  function loadLatestBlocks() {
    var tbody = document.getElementById('blocks-tbody');
    if (!tbody) return Promise.resolve();
    return fetchJson('/api/blocks?limit=25')
      .then(function (body) {
        clear(tbody);
        var blocks = (body && body.blocks) || [];
        if (blocks.length === 0) {
          tbody.appendChild(el('tr', {}, el('td', { colspan: '4', class: 'muted', text: 'No blocks indexed yet.' })));
          return;
        }
        blocks.forEach(function (b) {
          tbody.appendChild(blockRow(b));
        });
      })
      .catch(function (err) {
        clear(tbody);
        var tr = el('tr');
        var td = el('td', { colspan: '4' });
        renderError(td, err);
        tr.appendChild(td);
        tbody.appendChild(tr);
      });
  }

  function initIndexPage() {
    loadStats();
    loadLatestBlocks();
    setInterval(function () {
      loadStats();
      loadLatestBlocks();
    }, 30000);
  }

  /* ── block.html ───────────────────────────────────────────────────── */

  function txSummaryRow(t) {
    var tr = el('tr');
    var hashTd = el('td', { class: 'mono' });
    var hashHex = bytesToHexIfNeeded(t.hash);
    hashTd.appendChild(hashLink(hashHex, 'tx.html?hash=' + encodeURIComponent(hashHex)));
    tr.appendChild(hashTd);
    tr.appendChild(el('td', {}, txTypeBadge(t.tx_type)));
    tr.appendChild(el('td', { class: 'mono', text: fmtDnac(t.fee) + ' DNAC' }));
    tr.appendChild(el('td', {}, timeNode(t.timestamp)));
    return tr;
  }

  /* tx.hash from emit_tx_summary is already a JSON hex string ("hash":
   * exp_json_hex(...)) — this identity helper exists so txSummaryRow can
   * be reused unchanged if a future endpoint ever nests raw bytes. */
  function bytesToHexIfNeeded(v) {
    return v;
  }

  function initBlockPage() {
    var ident = qparam('h');
    var content = document.getElementById('block-content');
    if (!ident) {
      renderError(content, new Error('missing block height or hash (?h=)'));
      return;
    }
    renderLoading(content);
    fetchJson('/api/block/' + encodeURIComponent(ident))
      .then(function (body) {
        clear(content);
        var b = body.block;
        var header = el('div', { class: 'detail-grid' });
        function field(label, node) {
          header.appendChild(el('div', { class: 'detail-label', text: label }));
          header.appendChild(el('div', { class: 'detail-value' }, node));
        }
        field('Height', el('span', { text: String(b.height) }));
        field('Block hash', b.block_hash ? hashSpan(b.block_hash, { head: 20, tail: 12 }) : el('span', { class: 'muted', text: 'pending (tip, not yet confirmed by a child block)' }));
        field('Transaction root', hashSpan(b.tx_root, { head: 20, tail: 12 }));
        field('Timestamp', timeNode(b.timestamp));
        field('Proposer', hashSpan(b.proposer, { head: 20, tail: 12 }));
        field('Transaction count', el('span', { text: String(b.tx_count) }));
        content.appendChild(el('h2', { text: 'Block' }));
        content.appendChild(header);

        content.appendChild(el('h2', { text: 'Transactions' }));
        var table = el('table', { class: 'data-table' });
        var thead = el('thead', {}, el('tr', {}, [
          el('th', { text: 'Hash' }),
          el('th', { text: 'Type' }),
          el('th', { text: 'Fee' }),
          el('th', { text: 'Time' })
        ]));
        var tbody = el('tbody');
        var txs = body.txs || [];
        if (txs.length === 0) {
          tbody.appendChild(el('tr', {}, el('td', { colspan: '4', class: 'muted', text: 'No transactions in this block.' })));
        } else {
          txs.forEach(function (t) {
            tbody.appendChild(txSummaryRow(t));
          });
        }
        table.appendChild(thead);
        table.appendChild(tbody);
        content.appendChild(table);
      })
      .catch(function (err) {
        renderError(content, err);
      });
  }

  /* ── tx.html ──────────────────────────────────────────────────────── */

  function ioRow(io, kind) {
    var tr = el('tr');
    if (kind === 'in') {
      tr.appendChild(el('td', { class: 'mono' }, hashSpan(io.address, { head: 16, tail: 10 })));
    } else {
      var addrTd = el('td', { class: 'mono' });
      addrTd.appendChild(hashLink(io.address, 'address.html?fp=' + encodeURIComponent(io.address), { head: 16, tail: 10 }));
      tr.appendChild(addrTd);
    }
    tr.appendChild(el('td', { class: 'mono', text: fmtDnac(io.amount) + ' DNAC' }));
    tr.appendChild(el('td', {}, tokenNode(io.token_id)));
    return tr;
  }

  function initTxPage() {
    var hash = qparam('hash');
    var content = document.getElementById('tx-content');
    if (!hash) {
      renderError(content, new Error('missing transaction hash (?hash=)'));
      return;
    }
    renderLoading(content);
    fetchJson('/api/tx/' + encodeURIComponent(hash))
      .then(function (body) {
        clear(content);
        var t = body.tx;

        var titleRow = el('div', { class: 'tx-title-row' }, [
          txTypeBadge(t.tx_type),
          t.multi_signer ? el('span', { class: 'badge badge-multisig', text: 'multi-signer' }) : null
        ]);
        content.appendChild(titleRow);

        var header = el('div', { class: 'detail-grid' });
        function field(label, node) {
          header.appendChild(el('div', { class: 'detail-label', text: label }));
          header.appendChild(el('div', { class: 'detail-value' }, node));
        }
        field('Hash', hashSpan(t.hash, { head: 24, tail: 14 }));
        field('Block height', el('a', { href: 'block.html?h=' + t.height, text: String(t.height) }));
        field('Sequence', el('span', { text: String(t.seq) }));
        field('Timestamp', timeNode(t.timestamp));
        field('Fee', el('span', { class: 'mono', text: fmtDnac(t.fee) + ' DNAC' }));
        field('Size', el('span', { text: t.size + ' bytes' }));
        content.appendChild(header);

        var ins = (body.ios || []).filter(function (io) {
          return io.direction === 'in';
        });
        var outs = (body.ios || []).filter(function (io) {
          return io.direction === 'out';
        });

        content.appendChild(el('h2', { text: 'Inputs (' + ins.length + ')' }));
        var inTable = el('table', { class: 'data-table' });
        inTable.appendChild(
          el('thead', {}, el('tr', {}, [el('th', { text: 'Nullifier' }), el('th', { text: 'Amount' }), el('th', { text: 'Token' })]))
        );
        var inBody = el('tbody');
        if (ins.length === 0) inBody.appendChild(el('tr', {}, el('td', { colspan: '3', class: 'muted', text: 'None' })));
        ins.forEach(function (io) {
          inBody.appendChild(ioRow(io, 'in'));
        });
        inTable.appendChild(inBody);
        content.appendChild(inTable);

        content.appendChild(el('h2', { text: 'Outputs (' + outs.length + ')' }));
        var outTable = el('table', { class: 'data-table' });
        outTable.appendChild(
          el('thead', {}, el('tr', {}, [el('th', { text: 'Address' }), el('th', { text: 'Amount' }), el('th', { text: 'Token' })]))
        );
        var outBody = el('tbody');
        if (outs.length === 0) outBody.appendChild(el('tr', {}, el('td', { colspan: '3', class: 'muted', text: 'None' })));
        outs.forEach(function (io) {
          outBody.appendChild(ioRow(io, 'out'));
        });
        outTable.appendChild(outBody);
        content.appendChild(outTable);

        if (body.raw) {
          var details = el('details', { class: 'raw-hex' });
          details.appendChild(el('summary', { text: 'Raw transaction hex (' + body.raw.length / 2 + ' bytes)' }));
          var pre = el('pre', { class: 'mono raw-hex-body' });
          pre.textContent = body.raw;
          details.appendChild(pre);
          content.appendChild(details);
        }
      })
      .catch(function (err) {
        renderError(content, err);
      });
  }

  /* ── address.html ─────────────────────────────────────────────────── */

  var addressState = { fp: null, lowestSeq: null, loading: false };

  function addrHistoryRow(t) {
    var tr = el('tr');
    var hashTd = el('td', { class: 'mono' });
    hashTd.appendChild(hashLink(t.hash, 'tx.html?hash=' + encodeURIComponent(t.hash), { head: 14, tail: 8 }));
    tr.appendChild(hashTd);
    tr.appendChild(el('td', {}, txTypeBadge(t.tx_type)));
    var heightTd = el('td');
    heightTd.appendChild(el('a', { href: 'block.html?h=' + t.height, text: String(t.height) }));
    tr.appendChild(heightTd);
    tr.appendChild(el('td', {}, timeNode(t.timestamp)));
    tr.appendChild(el('td', { class: 'mono', text: fmtDnac(t.fee) + ' DNAC' }));
    return tr;
  }

  function loadAddressHistoryPage(before) {
    if (addressState.loading) return;
    addressState.loading = true;
    var loadMoreBtn = document.getElementById('load-more-btn');
    if (loadMoreBtn) loadMoreBtn.disabled = true;

    var path = '/api/address/' + encodeURIComponent(addressState.fp) + '?limit=25' + (before !== undefined ? '&before=' + before : '');
    fetchJson(path)
      .then(function (body) {
        var tbody = document.getElementById('address-history-tbody');
        var txs = body.txs || [];
        if (before === undefined) clear(tbody);
        if (txs.length === 0 && before === undefined) {
          tbody.appendChild(el('tr', {}, el('td', { colspan: '5', class: 'muted', text: 'No transactions for this address.' })));
        }
        txs.forEach(function (t) {
          tbody.appendChild(addrHistoryRow(t));
          if (addressState.lowestSeq === null || t.seq < addressState.lowestSeq) addressState.lowestSeq = t.seq;
        });
        if (loadMoreBtn) {
          loadMoreBtn.disabled = false;
          loadMoreBtn.classList.toggle('hidden', txs.length < 25);
        }
      })
      .catch(function (err) {
        var tbody = document.getElementById('address-history-tbody');
        var tr = el('tr');
        var td = el('td', { colspan: '5' });
        renderError(td, err);
        tr.appendChild(td);
        tbody.appendChild(tr);
      })
      .then(function () {
        addressState.loading = false;
      });
  }

  function renderUtxoSection(utxos) {
    var section = document.getElementById('utxo-section');
    if (!section) return;
    clear(section);
    section.appendChild(el('h2', { text: 'Live from witnesses' }));
    if (!utxos || utxos.error) {
      section.appendChild(el('div', { class: 'muted', text: 'Live data unavailable.' }));
      return;
    }
    section.appendChild(el('div', { class: 'muted', text: 'As of witness block ' + utxos.block_height }));
    var table = el('table', { class: 'data-table' });
    table.appendChild(
      el('thead', {}, el('tr', {}, [
        el('th', { text: 'Nullifier' }),
        el('th', { text: 'Amount' }),
        el('th', { text: 'Token' }),
        el('th', { text: 'Source tx' }),
        el('th', { text: 'Block' })
      ]))
    );
    var tbody = el('tbody');
    var entries = utxos.entries || [];
    if (entries.length === 0) {
      tbody.appendChild(el('tr', {}, el('td', { colspan: '5', class: 'muted', text: 'No unspent outputs.' })));
    }
    entries.forEach(function (e) {
      var tr = el('tr');
      tr.appendChild(el('td', { class: 'mono' }, hashSpan(e.nullifier, { head: 14, tail: 8 })));
      tr.appendChild(el('td', { class: 'mono', text: fmtDnac(e.amount) + ' DNAC' }));
      tr.appendChild(el('td', {}, tokenNode(e.token_id)));
      var txTd = el('td', { class: 'mono' });
      txTd.appendChild(hashLink(e.tx_hash, 'tx.html?hash=' + encodeURIComponent(e.tx_hash), { head: 12, tail: 6 }));
      tr.appendChild(txTd);
      var blkTd = el('td');
      blkTd.appendChild(el('a', { href: 'block.html?h=' + e.block_height, text: String(e.block_height) }));
      tr.appendChild(blkTd);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    section.appendChild(table);
  }

  function initAddressPage() {
    var fp = qparam('fp');
    var content = document.getElementById('address-content');
    if (!fp) {
      renderError(content, new Error('missing address fingerprint (?fp=)'));
      return;
    }
    addressState.fp = fp;
    renderLoading(content);

    fetchJson('/api/address/' + encodeURIComponent(fp) + '?limit=25&utxos=1')
      .then(function (body) {
        clear(content);

        var native = (body.balances || []).filter(function (b) {
          return b.token === 'DNAC';
        })[0];

        var summary = el('div', { class: 'detail-grid' });
        function field(label, node) {
          summary.appendChild(el('div', { class: 'detail-label', text: label }));
          summary.appendChild(el('div', { class: 'detail-value' }, node));
        }
        field('Address', hashSpan(fp, { head: 24, tail: 14 }));
        field('Balance', el('span', { class: 'mono', text: (native ? fmtDnac(native.balance) : '0') + ' DNAC' }));
        field('Transaction count', el('span', { text: String(native ? native.tx_count : 0) }));
        content.appendChild(el('h2', { text: 'Address' }));
        content.appendChild(summary);

        var utxoSection = el('div', { id: 'utxo-section' });
        content.appendChild(utxoSection);
        renderUtxoSection(body.utxos);

        content.appendChild(el('h2', { text: 'Transaction history' }));
        var table = el('table', { class: 'data-table' });
        table.appendChild(
          el('thead', {}, el('tr', {}, [
            el('th', { text: 'Hash' }),
            el('th', { text: 'Type' }),
            el('th', { text: 'Height' }),
            el('th', { text: 'Time' }),
            el('th', { text: 'Fee' })
          ]))
        );
        var tbody = el('tbody', { id: 'address-history-tbody' });
        table.appendChild(tbody);
        content.appendChild(table);

        var txs = body.txs || [];
        txs.forEach(function (t) {
          tbody.appendChild(addrHistoryRow(t));
          if (addressState.lowestSeq === null || t.seq < addressState.lowestSeq) addressState.lowestSeq = t.seq;
        });
        if (txs.length === 0) {
          tbody.appendChild(el('tr', {}, el('td', { colspan: '5', class: 'muted', text: 'No transactions for this address.' })));
        }

        var loadMoreBtn = el('button', { id: 'load-more-btn', class: 'btn-secondary' + (txs.length < 25 ? ' hidden' : ''), text: 'Load more' });
        loadMoreBtn.addEventListener('click', function () {
          if (addressState.lowestSeq !== null) loadAddressHistoryPage(addressState.lowestSeq);
        });
        content.appendChild(loadMoreBtn);
      })
      .catch(function (err) {
        renderError(content, err);
      });
  }

  /* ── page bootstrap ───────────────────────────────────────────────── */

  document.addEventListener('DOMContentLoaded', function () {
    wireSearch();
    var page = document.body.getAttribute('data-page');
    if (page === 'index') initIndexPage();
    else if (page === 'block') initBlockPage();
    else if (page === 'tx') initTxPage();
    else if (page === 'address') initAddressPage();
  });

  /* Exposed for potential reuse/testing; not part of a stable public API. */
  window.__scanApp = { fmtDnac: fmtDnac, txTypeName: txTypeName };
})();
