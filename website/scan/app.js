// Nodus Scan. Wire fields and base units follow explorer/src/exp_http.c (index schema v2,
// version-3 chain: blocks carry items, an item is addressed by "height:index").
// Amounts stay decimal strings / BigInt. API data is never rendered as HTML.
(() => {
  'use strict';
  const tr = window.nodusLanguage === 'tr';
  const t = (en, turkish) => tr ? turkish : en;
  const $ = id => document.getElementById(id);
  const zeroToken = '0'.repeat(128);
  const page = document.body.dataset.page;
  const query = new URLSearchParams(location.search);
  const rawIdentifier = query.get(page === 'block' ? 'h' : page === 'tx' ? 'hash' : 'fp');
  const identifier = rawIdentifier && /^[a-fA-F0-9]{128}$/.test(rawIdentifier) ? rawIdentifier.toLowerCase() : rawIdentifier;
  let pageNumber = 1, snapshotTip = null, lastPage = 1, blockRequest = 0, searchRequest = 0;
  let nextCursor = null, historyLoading = false, refreshing = false;
  const el = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  };
  const link = (href, label) => {
    const a = el('a', label); a.href = window.nodusLink(href); return a;
  };
  function amount(raw) {
    if (raw === null || raw === undefined || !/^-?\d+$/.test(String(raw))) return '—';
    if (typeof raw === 'number' && !Number.isSafeInteger(raw)) return '—';
    const value = BigInt(raw), negative = value < 0n, magnitude = negative ? -value : value;
    const fraction = (magnitude % 100000000n).toString().padStart(8, '0').replace(/0+$/, '');
    return (negative ? '-' : '') + (magnitude / 100000000n) + (fraction ? '.' + fraction : '');
  }
  const money = raw => amount(raw) === '—' ? '—' : amount(raw) + ' NODUS';
  const short = value => value.length > 28 ? value.slice(0, 14) + '…' + value.slice(-10) : value;
  function hash(value, destination) {
    if (typeof value !== 'string' || !value) return el('span', '—', 'muted');
    if (destination) { const a = link(destination, short(value)); a.title = value; return a; }
    const wrap = el('span', undefined, 'hash-value');
    const full = el('span', value, 'mono');
    const copy = el('button', t('Copy', 'Kopyala'), 'hash copy-hash'); copy.type = 'button';
    copy.setAttribute('aria-label', t('Copy full identifier', 'Tam kimliği kopyala'));
    copy.addEventListener('click', async () => {
      try {
        if (!navigator.clipboard) throw new Error();
        await navigator.clipboard.writeText(value);
        copy.textContent = t('Copied', 'Kopyalandı');
      } catch {
        copy.textContent = t('Select text to copy', 'Kopyalamak için metni seç');
        const selection = window.getSelection(), range = document.createRange();
        range.selectNodeContents(full); selection.removeAllRanges(); selection.addRange(range);
      }
    });
    wrap.append(full, copy); return wrap;
  }
  // Block time is milliseconds since the Unix epoch (the block header's time).
  function time(ms) {
    const date = new Date(Number(ms));
    if (!Number.isFinite(date.getTime()) || Number(ms) <= 0) return el('span', '—');
    const node = el('time', date.toISOString().slice(0, 19).replace('T', ' ') + ' UTC');
    node.dateTime = date.toISOString(); return node;
  }
  const opLabel = item => typeof item.op === 'string' && item.op ? item.op.toUpperCase() : String(item.kind ?? '—').toUpperCase();
  function opBadges(item) {
    const wrap = el('span', undefined, 'tx-title-row');
    wrap.append(el('span', opLabel(item), 'badge'));
    if (typeof item.name === 'string' && item.name) wrap.append(el('span', t('Name: ', 'İsim: ') + item.name, 'badge'));
    if (item.refused) wrap.append(el('span', t('Refused', 'Reddedildi') + ' · ' + t('code ', 'kod ') + item.code, 'badge'));
    return wrap;
  }
  const position = item => typeof item.position === 'string' ? item.position : '—';
  // A block with no items is a heartbeat: the chain commits one while idle
  // (create_empty_blocks_interval) — shown as such instead of "0" (operator 2026-10-01).
  const itemCount = n => Number(n) === 0 ? el('span', 'Heartbeat', 'badge') : n;
  // The index API does not percent-decode: a height, a hex id or a "height:index" position is
  // sent as it is (all of [0-9a-f:], legal in a path and a query); anything else is encoded.
  const apiValue = value => /^[0-9a-f:]+$/.test(String(value)) ? String(value) : encodeURIComponent(value);
  const txHref = item => 'tx.html?hash=' + encodeURIComponent(position(item));
  const token = value => value === zeroToken ? el('span', 'NODUS', 'token-native') : el('span', typeof value === 'string' ? short(value) : '—', 'mono');
  async function api(path) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    try {
      const response = await fetch('api' + path, { headers: { Accept: 'application/json' }, signal: controller.signal, cache: 'no-store' });
      if (!response.ok) {
        const error = new Error(response.status === 404 ? t('Record not found.', 'Kayıt bulunamadı.') : response.status === 400 ? t('Check the identifier and try again.', 'Kimliği kontrol edip tekrar dene.') : t('The chain index is unavailable. Try refreshing shortly.', 'Zincir indeksine erişilemiyor. Biraz sonra yenilemeyi dene.'));
        error.status = response.status; throw error;
      }
      const body = await response.json();
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error(t('Unexpected index response.', 'Beklenmeyen indeks yanıtı.'));
      return body;
    } catch (error) {
      if (error instanceof TypeError || error.name === 'AbortError' || error instanceof SyntaxError) throw new Error(t('The chain index is unavailable. Try refreshing shortly.', 'Zincir indeksine erişilemiyor. Biraz sonra yenilemeyi dene.'));
      throw error;
    } finally { clearTimeout(timer); }
  }
  function errorBox(container, error) { container.replaceChildren(el('div', error.message, 'error-box')); }
  function row(cells) {
    const node = el('tr');
    cells.forEach(cell => { const td = el('td'); td.append(cell instanceof Node ? cell : document.createTextNode(String(cell))); node.append(td); });
    return node;
  }
  function messageRow(body, message, columns, isError = false) {
    const td = el('td'); td.colSpan = columns; td.append(el('div', message, isError ? 'error-box' : 'muted'));
    const r = el('tr'); r.append(td); body.replaceChildren(r);
  }
  function table(headers, rows, empty, id) {
    const table = el('table', undefined, 'data-table');
    table.tabIndex = 0;
    const head = el('thead'), hr = el('tr');
    headers.forEach(label => { const th = el('th', label); th.scope = 'col'; hr.append(th); });
    head.append(hr); const body = el('tbody'); if (id) body.id = id;
    body.append(...rows); if (!rows.length) messageRow(body, empty, headers.length);
    table.append(head, body); return table;
  }
  function fields(entries) {
    const grid = el('div', undefined, 'detail-grid');
    entries.forEach(([label, value]) => { const node = el('div', undefined, 'detail-value'); node.append(value instanceof Node ? value : document.createTextNode(String(value))); grid.append(el('div', label, 'detail-label'), node); });
    return grid;
  }
  function moreButton(onClick) {
    const more = el('button', t('Load more', 'Daha fazla yükle'), 'btn-secondary'); more.id = 'load-more-btn'; more.type = 'button';
    more.hidden = nextCursor === null; more.addEventListener('click', onClick);
    const error = el('div'); error.id = 'history-error'; error.setAttribute('role', 'status');
    return [error, more];
  }
  function displayStats(stats) {
    const indexed = stats.indexed_height, tip = stats.tip_height;
    const known = Number.isSafeInteger(indexed) && Number.isSafeInteger(tip);
    const behind = known && tip > indexed;
    const banner = $('staleness-banner'); banner.classList.toggle('hidden', !behind);
    banner.textContent = behind ? t(`Index catching up: ${indexed} of ${tip} blocks indexed.`, `İndeks güncelleniyor: ${tip} bloğun ${indexed} adedi indekslendi.`) : '';
    $('api-status').textContent = known ? (behind ? t('Index catching up', 'İndeks güncelleniyor') : t('Index matches the last reported tip', 'İndeks son bildirilen blokla eşleşiyor')) : t('Index connected · synchronization status unknown', 'İndekse bağlandı · eşitleme durumu bilinmiyor');
    if (!$('stats-cards')) return;
    $('stat-height').textContent = indexed ?? '—';
    // Supply buckets (explorer /api/stats; decision 2026-09-30-scan-supply-buckets.md): the
    // total is supply_genesis (fixed), circulating is the explorer's own figure. treasury is
    // pool 1..9; Scan shows the four service pools. A null (older node) renders "—".
    $('stat-total').textContent = money(stats.supply_genesis);
    $('stat-circulating').textContent = money(stats.circulating);
    const pools = Array.isArray(stats.treasury) && stats.treasury.length === 9 ? stats.treasury : [];
    $('bucket-reward').textContent = money(stats.reward_pool);
    $('bucket-storage').textContent = money(pools[0]);
    $('bucket-compute').textContent = money(pools[1]);
    $('bucket-bandwidth').textContent = money(pools[2]);
    $('bucket-future').textContent = money(pools[3]);
    $('bucket-unclaimed').textContent = money(stats.unclaimed);
  }
  function statsUnavailable() {
    $('api-status').textContent = t('Index unavailable', 'İndekse erişilemiyor');
    $('staleness-banner').classList.add('hidden');
    for (const id of ['height', 'total', 'circulating']) if ($('stat-' + id)) $('stat-' + id).textContent = '—';
    for (const id of ['reward', 'storage', 'compute', 'bandwidth', 'future', 'unclaimed']) if ($('bucket-' + id)) $('bucket-' + id).textContent = '—';
  }
  async function loadBlocks(requested, fresh = false, providedStats) {
    const current = ++blockRequest, body = $('blocks-tbody');
    try {
      if (fresh || snapshotTip === null) {
        const stats = providedStats ?? await api('/stats');
        if (current !== blockRequest) return;
        displayStats(stats);
        if (stats.indexed_height === null || stats.indexed_height === undefined) {
          messageRow(body, t('No blocks indexed yet.', 'Henüz indekslenmiş blok yok.'), 4);
          $('blocks-pager').classList.add('hidden'); return;
        }
        if (!Number.isSafeInteger(stats.indexed_height) || stats.indexed_height < 0) {
          messageRow(body, t('Indexed height is not available yet.', 'İndeks yüksekliği henüz bilinmiyor.'), 4);
          $('blocks-pager').classList.add('hidden'); return;
        }
        snapshotTip = stats.indexed_height;
      }
      if (snapshotTip === 0) {
        messageRow(body, t('No blocks indexed yet.', 'Henüz indekslenmiş blok yok.'), 4); $('blocks-pager').classList.add('hidden'); return;
      }
      lastPage = Math.max(1, Math.ceil(snapshotTip / 25));
      const target = Math.min(Math.max(1, requested), lastPage);
      const data = await api('/blocks?before=' + (snapshotTip - (target - 1) * 25 + 1) + '&limit=25');
      if (current !== blockRequest) return;
      if (!Array.isArray(data.blocks)) throw new Error(t('Unexpected block response.', 'Beklenmeyen blok yanıtı.'));
      body.replaceChildren(...data.blocks.map(b => row([link('block.html?h=' + encodeURIComponent(b.height), b.height), hash(b.block_id, b.block_id ? 'block.html?h=' + encodeURIComponent(b.block_id) : null), time(b.time), itemCount(b.n_items)])));
      if (!data.blocks.length) messageRow(body, t('No blocks on this page.', 'Bu sayfada blok yok.'), 4);
      pageNumber = target;
      $('pg-total').textContent = lastPage; $('pg-input').value = pageNumber;
      $('pg-first').disabled = $('pg-prev').disabled = pageNumber <= 1;
      $('pg-next').disabled = $('pg-last').disabled = pageNumber >= lastPage;
      $('blocks-pager').classList.remove('hidden');
    } catch (error) {
      if (current !== blockRequest) return;
      messageRow(body, error.message, 4, true);
    }
  }
  const itemRow = item => row([link(txHref(item), position(item)), opBadges(item), money(item.fee), hash(item.wire_id, item.wire_id ? 'tx.html?hash=' + encodeURIComponent(item.wire_id) : null)]);
  const historyRow = item => row([link(txHref(item), position(item)), opBadges(item), link('block.html?h=' + encodeURIComponent(item.height), item.height), time(item.time), money(item.fee)]);
  const assetAmount = io => io.token_id === zeroToken ? money(io.amount) : (io.amount === null || io.amount === undefined ? '—' : String(io.amount) + t(' base units', ' temel birim'));
  const addressCell = io => typeof io.address === 'string' ? hash(io.address, 'address.html?fp=' + encodeURIComponent(io.address)) : el('span', t('Not in the index', 'İndekste yok'), 'muted');
  const inputRow = io => row([el('span', short(io.coin_id ?? '—'), 'mono'), addressCell(io), assetAmount(io), io.token_id ? token(io.token_id) : el('span', '—', 'muted')]);
  const outputRow = io => row([el('span', short(io.coin_id ?? '—'), 'mono'), addressCell(io), assetAmount(io), token(io.token_id), io.unlock_block ? io.unlock_block : t('Unlocked', 'Kilitsiz')]);
  function renderBlock(data, content) {
    if (!data.block || !Array.isArray(data.items)) throw new Error(t('Unexpected block response.', 'Beklenmeyen blok yanıtı.'));
    const b = data.block;
    const previous = Number(b.height) > 1 ? link('block.html?h=' + encodeURIComponent(Number(b.height) - 1), short(b.prev_id ?? '—')) : hash(b.prev_id);
    content.replaceChildren(fields([
      [t('Height','Yükseklik'), b.height], [t('Block ID','Blok kimliği'), hash(b.block_id)], [t('Previous block','Önceki blok'), previous],
      [t('Timestamp','Zaman damgası'), time(b.time)], [t('Proposer','Öneren'), hash(b.proposer)], [t('State root','Durum kökü'), hash(b.global_root)],
      [t('Applied transactions','Uygulanan işlemler'), b.applied_count], [t('Items in block','Bloktaki kayıtlar'), itemCount(b.n_items)]
    ]), el('h2', t('Transactions','İşlemler')), table([t('Position','Konum'),t('Type','Tür'),t('Fee','Ücret'),t('Wire ID','Kablo kimliği')], data.items.map(itemRow), t('No transactions in this block.','Bu blokta işlem yok.'), 'block-items-tbody'));
    nextCursor = Number.isSafeInteger(data.next_from) ? data.next_from : null;
    content.append(...moreButton(() => loadMore('/block/' + apiValue(identifier) + '?from=', 'block-items-tbody', 'items', itemRow, d => Number.isSafeInteger(d.next_from) ? d.next_from : null)));
  }
  const recordNames = { stake: t('Stake','Stake'), delegate: t('Delegation','Delegasyon'), unstake: t('Unstake','Stake çözme'), undelegate: t('Undelegation','Delegasyon çözme'), validator_update: t('Validator update','Doğrulayıcı güncellemesi'), chain_config: t('Chain configuration','Zincir yapılandırması') };
  function renderRecord(record) {
    const entries = [[t('Record','Kayıt'), recordNames[record.kind] ?? String(record.kind)]];
    const fp = (label, value) => { if (typeof value === 'string') entries.push([label, hash(value, 'address.html?fp=' + encodeURIComponent(value))]); };
    fp(t('Validator','Doğrulayıcı'), record.validator); fp(t('Delegator','Delege eden'), record.delegator); fp(t('Destination','Hedef'), record.destination);
    if (record.kind === 'chain_config') entries.push([t('Parameter','Parametre'), record.param_id], [t('New value','Yeni değer'), record.new_value], [t('Effective height','Geçerlilik yüksekliği'), record.effective_height]);
    else { entries.push([t('Amount','Tutar'), money(record.amount)]); if (record.kind === 'validator_update' || record.kind === 'stake') entries.push([t('Commission','Komisyon'), (Number(record.commission_bps) / 100) + ' %']); }
    return fields(entries);
  }
  function renderTx(data, content) {
    if (!data.tx || !Array.isArray(data.inputs) || !Array.isArray(data.outputs)) throw new Error(t('Unexpected transaction response.', 'Beklenmeyen işlem yanıtı.'));
    const tx = data.tx;
    const entries = [[t('Position','Konum'), position(tx)], [t('Block height','Blok yüksekliği'), link('block.html?h=' + encodeURIComponent(tx.height), tx.height)], [t('Timestamp','Zaman damgası'), time(tx.time)],
      [t('Status','Durum'), tx.refused ? t('Refused by the chain (code ','Zincir tarafından reddedildi (kod ') + tx.code + ')' : t('Applied','Uygulandı')],
      [t('Wire ID','Kablo kimliği'), tx.wire_id ? hash(tx.wire_id) : el('span', t('Not assigned','Atanmadı'), 'muted')], [t('Intent ID','Niyet kimliği'), tx.intent_id ? hash(tx.intent_id) : el('span', '—', 'muted')],
      [t('Fee','Ücret'), money(tx.fee)]];
    if (tx.burned !== null && tx.burned !== undefined) entries.push([t('Burned','Yakılan'), money(tx.burned)]);
    // HF-4 name registration (explorer item name / name_price / name_owner): the price goes to
    // the reward pool — it is not a burn. The owner is shown in full beside the name (look-alikes).
    if (typeof tx.name === 'string' && tx.name) {
      entries.push([t('Name registered','Kaydedilen isim'), el('strong', tx.name)], [t('Name price (to the reward pool)','İsim ücreti (ödül havuzuna)'), money(tx.name_price)],
        [t('Name owner','İsim sahibi'), typeof tx.name_owner === 'string' ? hash(tx.name_owner, 'address.html?fp=' + encodeURIComponent(tx.name_owner)) : el('span', t('Not in the index', 'İndekste yok'), 'muted')]);
    }
    content.replaceChildren(opBadges(tx), fields(entries));
    if (tx.refused) content.append(el('p', t('A refused transaction stays in the block but changes nothing: no coins are spent or created.', 'Reddedilen işlem blokta kalır ama hiçbir şeyi değiştirmez: coin harcanmaz, oluşturulmaz.'), 'muted'));
    if (tx.record) content.append(el('h2', t('Recorded change','Kaydedilen değişiklik')), renderRecord(tx.record));
    content.append(el('h2', t('Inputs','Girdiler') + ' (' + data.inputs.length + ')'), table([t('Coin','Coin'),t('Address','Adres'),t('Amount','Tutar'),t('Token','Token')], data.inputs.map(inputRow), t('None','Yok')));
    content.append(el('h2', t('Outputs','Çıktılar') + ' (' + data.outputs.length + ')'), table([t('Coin','Coin'),t('Address','Adres'),t('Amount','Tutar'),t('Token','Token'),t('Unlock block','Kilit açılış bloğu')], data.outputs.map(outputRow), t('None','Yok')));
  }
  // Balances come from the network (the node's dnac_balance, transparent coins only): per token the
  // total, the part spendable in the next block (locked coins excluded) and the coin count.
  // "unavailable" is shown as such — never as a zero.
  const balanceRow = b => row([token(b.token_id), assetAmount({ token_id: b.token_id, amount: b.total }), assetAmount({ token_id: b.token_id, amount: b.spendable }), Number.isSafeInteger(b.coins) ? b.coins : '—']);
  function balanceSummary(data) {
    if (data.balance_status !== 'ok' || !Array.isArray(data.balances)) return el('span', t('Unavailable right now — the network did not answer. Try refreshing shortly.', 'Şu an alınamıyor — ağ yanıt vermedi. Biraz sonra yenilemeyi dene.'), 'muted');
    const native = data.balances.find(b => b && b.token_id === zeroToken);
    return money(native ? native.total : '0');
  }
  function renderAddress(data, content) {
    if (!Array.isArray(data.items)) throw new Error(t('Unexpected address response.', 'Beklenmeyen adres yanıtı.'));
    content.replaceChildren(fields([[t('Address','Adres'),hash(identifier)],[t('Balance','Bakiye'),balanceSummary(data)]]));
    if (data.balance_status === 'ok' && Array.isArray(data.balances)) {
      content.append(el('h2', t('Balances by token', 'Token bazında bakiyeler')), table([t('Token','Token'),t('Total','Toplam'),t('Spendable now','Şu an harcanabilir'),t('Coins','Coin sayısı')], data.balances.filter(b => b && typeof b === 'object').map(balanceRow), t('This address holds no coins.', 'Bu adreste coin yok.')));
    }
    nextCursor = typeof data.next_before === 'string' ? data.next_before : null;
    content.append(el('h2',t('Transaction history','İşlem geçmişi')),table([t('Position','Konum'),t('Type','Tür'),t('Height','Yükseklik'),t('Time','Zaman'),t('Fee','Ücret')],data.items.map(historyRow),t('No transactions for this address.','Bu adres için işlem yok.'),'address-history-tbody'));
    content.append(...moreButton(() => loadMore('/address/' + apiValue(identifier) + '?limit=25&before=', 'address-history-tbody', 'items', historyRow, d => typeof d.next_before === 'string' ? d.next_before : null)));
  }
  async function loadMore(prefix, tbodyId, key, render, cursorOf) {
    if (historyLoading || nextCursor === null) return;
    historyLoading=true;const button=$('load-more-btn');button.disabled=true;$('history-error').replaceChildren();
    try {
      const data=await api(prefix+apiValue(nextCursor));
      if (!Array.isArray(data[key])) throw new Error(t('Unexpected index response.','Beklenmeyen indeks yanıtı.'));
      $(tbodyId).append(...data[key].map(render));
      nextCursor=cursorOf(data);
      button.hidden=nextCursor===null;
    } catch(error) {errorBox($('history-error'),error);}
    finally {historyLoading=false;button.disabled=false;}
  }
  async function loadDetail() {
    const content=$(page+'-content');
    const valid = identifier && (page==='block' ? /^(?:[1-9]\d*|[a-f0-9]{128})$/.test(identifier) : page==='tx' ? /^(?:[a-f0-9]{128}|[1-9]\d*:\d+)$/.test(identifier) : /^[a-f0-9]{128}$/.test(identifier));
    if (!valid) {errorBox(content,new Error(t('Use the search above to choose a valid record.','Geçerli bir kayıt seçmek için yukarıdaki aramayı kullan.')));return;}
    content.replaceChildren(el('div',t('Loading…','Yükleniyor…'),'loading'));
    try {
      const data=await api('/'+page+'/'+apiValue(identifier)+(page==='address'?'?limit=25':''));
      if(page==='block')renderBlock(data,content);else if(page==='tx')renderTx(data,content);else renderAddress(data,content);
    } catch(error){errorBox(content,error);}
  }
  // Hard forks (explorer /api/governance: every applied chain_config vote, (height, index)
  // ascending). The rules are the runbook's "Live hard forks" table (nodus/docs/DEPLOY_RUNBOOK.md
  // §2.2); param ids are dnac/include/dnac/dnac.h DNAC_CFG_*. HF-1 is set by the genesis
  // document (gas price 121 raw units per gas unit, effective at block 0) — not a block item,
  // so it is a fixed row here. Every other param is an ordinary governance change.
  const hardForks = [
    { fork: 'HF-1', param: 5, genesisValue: '121', name: t('Gas price', 'Gas fiyatı'),
      rule: t('A transaction with a non-system part pays at least its declared gas units × the gas price, never less than the flat minimum fee.', 'Sistem dışı bir bölümü olan işlem, en az bildirdiği gas birimi × gas fiyatı öder; sabit asgari ücretin altına inmez.') },
    { fork: 'HF-2', param: 7, name: t('Governance by stake weight', 'Stake ağırlıklı yönetişim'),
      rule: t('Governance approvals are weighed by validator voting power (more than 2/3), not by seat count; a block that leaves a touched domain unchanged still applies.', 'Yönetişim onayları koltuk sayısıyla değil validator oy gücüyle (2/3’ten fazla) tartılır; dokunduğu alanı değiştirmeyen bir blok yine uygulanır.') },
    { fork: 'HF-3', param: 8, name: t('Consensus-only block bounds', 'Yalnız konsensüs blok sınırları'),
      rule: t('Blocks are bounded by the consensus engine’s limits only (the 2 MiB / 2 097 152-unit bound is removed); proposals are checked for gas price, committed replay and units ≤ INT64_MAX.', 'Bloklar yalnız konsensüs motorunun sınırlarıyla sınırlanır (2 MiB / 2 097 152 birim sınırı kalkar); öneriler gas fiyatı, işlenmiş tekrar ve birim ≤ INT64_MAX için denetlenir.') },
    { fork: 'HF-4', param: 9, name: t('Rule-set generation 2 + on-chain names', 'Kural seti nesil 2 + zincir üstü isimler'),
      rule: t('The rule registry switches to generation 2 at the end of the block before activation; on-chain name registration and the name-price parameters 10–13 are in force from activation.', 'Kural kaydı, etkinleşmeden önceki bloğun sonunda 2. nesle geçer; zincir üstü isim kaydı ve 10–13 isim fiyatı parametreleri etkinleşmeden itibaren geçerlidir.') }
  ];
  const idleBlockSeconds = 60;
  function duration(seconds) {
    const minutes = Math.round(seconds / 60);
    if (minutes < 60) return minutes + t(' min', ' dk');
    const hours = Math.floor(minutes / 60), rest = minutes % 60;
    if (hours < 48) return hours + t(' h ', ' sa ') + rest + t(' min', ' dk');
    return Math.floor(hours / 24) + t(' days ', ' gün ') + (hours % 24) + t(' h', ' sa');
  }
  // ACTIVE when the chain's last reported tip has reached the effective height, else PENDING
  // with the distance in blocks and a time estimate at the idle block pace (an estimate only:
  // blocks with transactions commit faster).
  function forkStatus(effective, tip) {
    if (!Number.isSafeInteger(effective)) return el('span', '—', 'muted');
    if (!Number.isSafeInteger(tip)) return el('span', t('Unknown — tip not reported', 'Bilinmiyor — son blok bildirilmedi'), 'muted');
    if (tip >= effective) return el('span', t('Active', 'Etkin'), 'badge');
    const left = effective - tip, wrap = el('span');
    wrap.append(el('span', t('Pending', 'Bekliyor'), 'badge'), document.createTextNode(' ' + left + t(' blocks to go (~', ' blok kaldı (~') + duration(left * idleBlockSeconds) + t(' at ~60 s per idle block — estimate)', ', boş blok başına ~60 sn ile — tahmin)')));
    return wrap;
  }
  const recordValue = r => typeof r.new_value === 'string' && /^\d+$/.test(r.new_value) ? r.new_value : '—';
  const recordParam = r => (typeof r.param_name === 'string' && r.param_name ? r.param_name + ' (' + r.param_id + ')' : t('Parameter ', 'Parametre ') + r.param_id);
  const voteCell = r => Number.isSafeInteger(r.height) ? link(txHref(r), r.height) : el('span', '—', 'muted');
  function renderGovernance(data, content) {
    if (!Array.isArray(data.records)) throw new Error(t('Unexpected index response.', 'Beklenmeyen indeks yanıtı.'));
    const tip = data.tip, records = data.records.filter(r => r && typeof r === 'object' && Number.isSafeInteger(r.param_id));
    const forkParams = new Set(hardForks.filter(f => !f.genesisValue).map(f => f.param));
    const forkRows = [];
    for (const f of hardForks) {
      if (f.genesisValue) {
        forkRows.push(row([f.fork + ' · ' + f.name, f.rule, recordParam({ param_id: f.param, param_name: 'GAS_PRICE_RAW_PER_UNIT' }) + ' = ' + f.genesisValue, el('span', t('Genesis document', 'Genesis belgesi'), 'muted'), 0, forkStatus(0, tip)]));
        continue;
      }
      const votes = records.filter(r => r.param_id === f.param);
      if (!votes.length) forkRows.push(row([f.fork + ' · ' + f.name, f.rule, recordParam({ param_id: f.param }), el('span', t('Not voted yet', 'Henüz oylanmadı'), 'muted'), '—', el('span', '—', 'muted')]));
      for (const r of votes) forkRows.push(row([f.fork + ' · ' + f.name, f.rule, recordParam(r) + ' = ' + recordValue(r), voteCell(r), Number.isSafeInteger(r.effective_height) ? r.effective_height : '—', forkStatus(r.effective_height, tip)]));
    }
    const other = records.filter(r => !forkParams.has(r.param_id)).map(r => row([recordParam(r), recordValue(r), voteCell(r), time(r.time), Number.isSafeInteger(r.effective_height) ? r.effective_height : '—', forkStatus(r.effective_height, tip)]));
    content.replaceChildren(
      el('p', t('Hard forks on Nodus Chain activate at a block height after a validator vote; every node switches at the same block.', 'Nodus Chain’deki hard fork’lar bir validator oylamasından sonra belirli bir blok yüksekliğinde etkinleşir; her düğüm aynı blokta geçiş yapar.'), 'scan-explanation'),
      el('p', t('Last reported tip: ', 'Son bildirilen blok: ') + (Number.isSafeInteger(tip) ? tip : '—'), 'muted'),
      el('h2', t('Hard forks', 'Hard fork’lar')),
      table([t('Fork', 'Fork'), t('What it changes', 'Neyi değiştirir'), t('Parameter', 'Parametre'), t('Voted in block', 'Oylandığı blok'), t('Effective block', 'Geçerlilik bloğu'), t('Status', 'Durum')], forkRows, t('None', 'Yok')),
      el('h2', t('Other governance changes', 'Diğer yönetişim değişiklikleri')),
      table([t('Parameter', 'Parametre'), t('New value', 'Yeni değer'), t('Voted in block', 'Oylandığı blok'), t('Time', 'Zaman'), t('Effective block', 'Geçerlilik bloğu'), t('Status', 'Durum')], other, t('No other governance changes.', 'Başka yönetişim değişikliği yok.')));
    if (data.truncated === true) content.append(el('p', t('Only the first 1000 governance records are shown.', 'Yalnız ilk 1000 yönetişim kaydı gösteriliyor.'), 'muted'));
  }
  async function loadGovernance() {
    const content = $('hardforks-content');
    content.replaceChildren(el('div', t('Loading…', 'Yükleniyor…'), 'loading'));
    try { renderGovernance(await api('/governance'), content); } catch (error) { errorBox(content, error); }
  }
  async function refresh() {
    if(refreshing)return;refreshing=true;$('refresh-data').disabled=true;
    const detail = page==='hardforks' ? loadGovernance() : page!=='index' ? loadDetail() : null;
    try {
      const stats=await api('/stats');displayStats(stats);
      if(page==='index')await loadBlocks(pageNumber,pageNumber===1,stats);
    }catch(error){statsUnavailable();if(page==='index')messageRow($('blocks-tbody'),error.message,4,true);}
    finally {await detail;refreshing=false;$('refresh-data').disabled=false;}
  }
  $('search-form').addEventListener('submit',async event=>{
    event.preventDefault();const typed=$('search-input').value.trim();if(!typed)return;
    // A 128-hex id, or a chain name (HF-4: the chain stores names lower-case; A-Z is mapped with
    // an ASCII-only table, never a locale's lower-casing), is sent lower-case.
    const asciiLower=s=>s.replace(/[A-Z]/g,c=>String.fromCharCode(c.charCodeAt(0)+32));
    const term=/^[a-fA-F0-9]{128}$/.test(typed)?typed.toLowerCase():/^[A-Za-z0-9]{3,36}$/.test(typed)?asciiLower(typed):typed;
    const current=++searchRequest,results=$('search-results');results.replaceChildren(el('div',t('Searching…','Aranıyor…'),'loading'));
    try{
      const data=await api('/search?q='+apiValue(term));if(current!==searchRequest)return;
      if(!Array.isArray(data.matches))throw new Error(t('Unexpected search response.','Beklenmeyen arama yanıtı.'));
      const matches=data.matches.filter(m=>['tx','block','address','name'].includes(m.type)&&typeof m.target==='string');
      // A "name" match (HF-4) targets the registering transaction's position.
      const href=m=>(m.type==='name'?'tx':m.type)+'.html?'+(m.type==='tx'||m.type==='name'?'hash':m.type==='block'?'h':'fp')+'='+encodeURIComponent(m.target);
      if(matches.length===1){location.assign(window.nodusLink(href(matches[0])));return;}
      results.replaceChildren();if(!matches.length){results.append(el('p',t('No matching records.','Eşleşen kayıt yok.'),'search-empty'));return;}
      const label=m=>m.type==='block'?t('Block','Blok'):m.type==='tx'?t('Transaction','İşlem'):m.type==='name'?t('Chain name','Zincir ismi'):t('Address','Adres');
      const list=el('ul',undefined,'search-list');for(const match of matches){const li=el('li');li.append(el('span',label(match),'search-type'),hash(match.target,href(match)));list.append(li);}results.append(list);
    }catch(error){if(current===searchRequest)errorBox(results,error);}
  });
  $('search-input').addEventListener('input',()=>{searchRequest++;$('search-results').replaceChildren();});
  $('refresh-data').addEventListener('click',refresh);
  if(page==='index'){
    // Circulating supply "Details": shows / hides the bucket table below the cards.
    $('supply-details-toggle').addEventListener('click',event=>{const open=$('supply-details').hidden;$('supply-details').hidden=!open;event.currentTarget.setAttribute('aria-expanded',String(open));});
    $('pg-first').addEventListener('click',()=>loadBlocks(1,true));$('pg-prev').addEventListener('click',()=>loadBlocks(pageNumber-1));$('pg-next').addEventListener('click',()=>loadBlocks(pageNumber+1));$('pg-last').addEventListener('click',()=>loadBlocks(lastPage));
    $('pg-input').addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();if(/^\d+$/.test(event.target.value))loadBlocks(Number(event.target.value));}});
    setInterval(()=>{if(!document.hidden && pageNumber===1)refresh();},30000);
  }
  refresh();
})();
