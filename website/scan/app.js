// Nodus Scan. Wire fields and base units follow explorer/src/exp_http.c.
// Amounts stay decimal strings / BigInt. API data is never rendered as HTML.
(() => {
  'use strict';
  const tr = window.nodusLanguage === 'tr';
  const t = (en, turkish) => tr ? turkish : en;
  const $ = id => document.getElementById(id);
  const zeroToken = '0'.repeat(128);
  const types = { 0:'GENESIS',1:'SPEND',2:'BURN',3:'TOKEN_CREATE',4:'STAKE',5:'DELEGATE',6:'UNSTAKE',7:'UNDELEGATE',9:'VALIDATOR_UPDATE',10:'CHAIN_CONFIG',11:'SHIELDED' };
  const page = document.body.dataset.page;
  const query = new URLSearchParams(location.search);
  const identifier = query.get(page === 'block' ? 'h' : page === 'tx' ? 'hash' : 'fp');
  let pageNumber = 1, snapshotTip = null, lastPage = 1, blockRequest = 0, searchRequest = 0;
  let oldestSequence = null, historyLoading = false, refreshing = false;
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
  const money = raw => amount(raw) === '—' ? '—' : amount(raw) + ' DNAC';
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
  function time(seconds) {
    const date = new Date(Number(seconds) * 1000);
    if (!Number.isFinite(date.getTime()) || Number(seconds) <= 0) return el('span', '—');
    const node = el('time', date.toISOString().slice(0, 19).replace('T', ' ') + ' UTC');
    node.dateTime = date.toISOString(); return node;
  }
  const type = value => el('span', types[value] ?? 'TYPE ' + value, 'badge');
  const token = value => value === zeroToken ? el('span', 'DNAC', 'token-native') : el('span', typeof value === 'string' ? short(value) : '—', 'mono');
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
  function displayStats(stats) {
    const indexed = stats.indexed_seq, tip = stats.tip_seq;
    const known = Number.isSafeInteger(indexed) && Number.isSafeInteger(tip);
    const behind = known && tip > indexed;
    const banner = $('staleness-banner'); banner.classList.toggle('hidden', !behind);
    banner.textContent = behind ? t(`Index catching up: ${indexed} of ${tip} transactions indexed.`, `İndeks güncelleniyor: ${tip} işlemin ${indexed} adedi indekslendi.`) : '';
    $('api-status').textContent = known ? (behind ? t('Index catching up', 'İndeks güncelleniyor') : t('Index matches the last reported tip', 'İndeks son bildirilen kayıtla eşleşiyor')) : t('Index connected · synchronization status unknown', 'İndekse bağlandı · eşitleme durumu bilinmiyor');
    if (!$('stats-cards')) return;
    $('stat-height').textContent = stats.indexed_height ?? '—';
    $('stat-supply').textContent = money(stats.supply_current);
    $('stat-burned').textContent = money(stats.supply_burned);
    $('stat-chain-id').textContent = typeof stats.chain_id === 'string' ? stats.chain_id.slice(0,8) + '…' + stats.chain_id.slice(-6) : '—';
    $('stat-chain-id').title = stats.chain_id ?? '';
  }
  function statsUnavailable() {
    $('api-status').textContent = t('Index unavailable', 'İndekse erişilemiyor');
    $('staleness-banner').classList.add('hidden');
    for (const id of ['height', 'supply', 'burned', 'chain-id']) if ($('stat-' + id)) $('stat-' + id).textContent = '—';
  }
  async function loadBlocks(requested, fresh = false, providedStats) {
    const current = ++blockRequest, body = $('blocks-tbody');
    try {
      if (fresh || snapshotTip === null) {
        const stats = providedStats ?? await api('/stats');
        if (current !== blockRequest) return;
        displayStats(stats);
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
      body.replaceChildren(...data.blocks.map(b => row([link('block.html?h=' + encodeURIComponent(b.height), b.height), hash(b.block_hash, b.block_hash ? 'block.html?h=' + encodeURIComponent(b.block_hash) : null), time(b.timestamp), b.tx_count])));
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
  const txRow = tx => row([hash(tx.hash, 'tx.html?hash=' + encodeURIComponent(tx.hash)), type(tx.tx_type), money(tx.fee), time(tx.timestamp)]);
  const historyRow = tx => row([hash(tx.hash, 'tx.html?hash=' + encodeURIComponent(tx.hash)), type(tx.tx_type), link('block.html?h=' + encodeURIComponent(tx.height), tx.height), time(tx.timestamp), money(tx.fee)]);
  const assetAmount = io => io.token_id === zeroToken ? money(io.amount) : String(io.amount ?? '—') + t(' base units', ' temel birim');
  const ioRow = io => row([hash(io.address, 'address.html?fp=' + encodeURIComponent(io.address)), assetAmount(io), token(io.token_id)]);
  function renderBlock(data, content) {
    if (!data.block || !Array.isArray(data.txs)) throw new Error(t('Unexpected block response.', 'Beklenmeyen blok yanıtı.'));
    const b = data.block;
    content.replaceChildren(fields([
      [t('Height','Yükseklik'), b.height], [t('Block hash','Blok hash’i'), b.block_hash ? hash(b.block_hash) : t('Not available in the index', 'İndekste mevcut değil')],
      [t('Transaction root','İşlem kökü'), hash(b.tx_root)], [t('Timestamp','Zaman damgası'), time(b.timestamp)], [t('Proposer','Öneren'), hash(b.proposer)], [t('Transactions','İşlemler'), b.tx_count]
    ]), el('h2', t('Transactions','İşlemler')), table([t('Hash','Hash'),t('Type','Tür'),t('Fee','Ücret'),t('Time','Zaman')], data.txs.map(txRow), t('No transactions in this block.','Bu blokta işlem yok.')));
  }
  function renderTx(data, content) {
    if (!data.tx || !Array.isArray(data.ios)) throw new Error(t('Unexpected transaction response.', 'Beklenmeyen işlem yanıtı.'));
    const tx = data.tx, badges = el('div', undefined, 'tx-title-row'); badges.append(type(tx.tx_type));
    if (tx.multi_signer) badges.append(el('span',t('Multi-signer','Çok imzalı'),'badge'));
    content.replaceChildren(badges, fields([[t('Hash','Hash'),hash(tx.hash)],[t('Block height','Blok yüksekliği'),link('block.html?h='+encodeURIComponent(tx.height),tx.height)],[t('Sequence','Sıra'),tx.seq],[t('Timestamp','Zaman damgası'),time(tx.timestamp)],[t('Fee','Ücret'),money(tx.fee)],[t('Size','Boyut'),tx.size + t(' bytes',' bayt')]]));
    for (const [direction, label] of [['in',t('Inputs','Girdiler')],['out',t('Outputs','Çıktılar')]]) {
      const ios = data.ios.filter(io=>io.direction===direction);
      content.append(el('h2',label+' ('+ios.length+')'),table([t('Address','Adres'),t('Amount','Tutar'),t('Token','Token')],ios.map(ioRow),t('None','Yok')));
    }
    if (typeof data.raw === 'string' && data.raw) {
      const details = el('details',undefined,'raw-hex');
      details.append(el('summary',t('Raw transaction','Ham işlem')+' ('+data.raw.length/2+t(' bytes)',' bayt)')),el('pre',data.raw,'mono raw-hex-body')); content.append(details);
    }
  }
  function renderAddress(data, content) {
    if (!Array.isArray(data.balances) || !Array.isArray(data.txs)) throw new Error(t('Unexpected address response.', 'Beklenmeyen adres yanıtı.'));
    const native = data.balances.find(b=>b.token==='DNAC');
    content.replaceChildren(fields([[t('Address','Adres'),hash(identifier)],[t('Indexed native balance','İndekslenmiş yerel bakiye'),money(native?.balance)],[t('Transaction count','İşlem sayısı'),native?.tx_count ?? '—']]));
    content.append(el('h2',t('Unspent outputs · witness data','Harcanmamış çıktılar · doğrulayıcı verisi')));
    const utxos = data.utxos;
    if (!utxos || utxos.error || !Array.isArray(utxos.entries)) content.append(el('p',t('Live witness data is unavailable. The indexed balance above is a separate source.','Canlı doğrulayıcı verisine erişilemiyor. Yukarıdaki indekslenmiş bakiye ayrı bir kaynaktır.'),'muted'));
    else {
      content.append(el('p',t('Reported at witness block ','Doğrulayıcı blok yüksekliği: ')+utxos.block_height,'muted'));
      content.append(table([t('Nullifier','Nullifier'),t('Amount','Tutar'),t('Token','Token'),t('Source transaction','Kaynak işlem'),t('Block','Blok')],utxos.entries.map(u=>row([el('span',short(u.nullifier),'mono'),assetAmount(u),token(u.token_id),hash(u.tx_hash,'tx.html?hash='+encodeURIComponent(u.tx_hash)),link('block.html?h='+encodeURIComponent(u.block_height),u.block_height)])),t('No unspent outputs.','Harcanmamış çıktı yok.')));
    }
    oldestSequence = data.txs.length ? Math.min(...data.txs.map(tx=>tx.seq)) : null;
    content.append(el('h2',t('Transaction history','İşlem geçmişi')),table([t('Hash','Hash'),t('Type','Tür'),t('Height','Yükseklik'),t('Time','Zaman'),t('Fee','Ücret')],data.txs.map(historyRow),t('No transactions for this address.','Bu adres için işlem yok.'),'address-history-tbody'));
    const more = el('button',t('Load more','Daha fazla yükle'),'btn-secondary'); more.id='load-more-btn';more.type='button';more.hidden=data.txs.length<25;more.addEventListener('click',loadMore);
    const error=el('div');error.id='history-error';error.setAttribute('role','status');content.append(error,more);
  }
  async function loadMore() {
    if (historyLoading || oldestSequence === null) return;
    historyLoading=true;const button=$('load-more-btn');button.disabled=true;$('history-error').replaceChildren();
    try {
      const data=await api('/address/'+encodeURIComponent(identifier)+'?before='+oldestSequence+'&limit=25');
      if (!Array.isArray(data.txs)) throw new Error(t('Unexpected address response.','Beklenmeyen adres yanıtı.'));
      $('address-history-tbody').append(...data.txs.map(historyRow));
      if (data.txs.length) oldestSequence=Math.min(...data.txs.map(tx=>tx.seq));
      button.hidden=data.txs.length<25;
    } catch(error) {errorBox($('history-error'),error);}
    finally {historyLoading=false;button.disabled=false;}
  }
  async function loadDetail() {
    const content=$(page+'-content');
    const valid = identifier && (page==='block' ? /^(?:[1-9]\d*|[a-fA-F0-9]{128})$/.test(identifier) : /^[a-fA-F0-9]{128}$/.test(identifier));
    if (!valid) {errorBox(content,new Error(t('Use the search above to choose a valid record.','Geçerli bir kayıt seçmek için yukarıdaki aramayı kullan.')));return;}
    content.replaceChildren(el('div',t('Loading…','Yükleniyor…'),'loading'));
    try {
      const data=await api('/'+page+'/'+encodeURIComponent(identifier)+(page==='address'?'?limit=25&utxos=1':''));
      if(page==='block')renderBlock(data,content);else if(page==='tx')renderTx(data,content);else renderAddress(data,content);
    } catch(error){errorBox(content,error);}
  }
  async function refresh() {
    if(refreshing)return;refreshing=true;$('refresh-data').disabled=true;
    const detail = page!=='index' ? loadDetail() : null;
    try {
      const stats=await api('/stats');displayStats(stats);
      if(page==='index')await loadBlocks(pageNumber,pageNumber===1,stats);
    }catch(error){statsUnavailable();if(page==='index')messageRow($('blocks-tbody'),error.message,4,true);}
    finally {await detail;refreshing=false;$('refresh-data').disabled=false;}
  }
  $('search-form').addEventListener('submit',async event=>{
    event.preventDefault();const term=$('search-input').value.trim();if(!term)return;
    const current=++searchRequest,results=$('search-results');results.replaceChildren(el('div',t('Searching…','Aranıyor…'),'loading'));
    try{
      const data=await api('/search?q='+encodeURIComponent(term));if(current!==searchRequest)return;
      if(!Array.isArray(data.matches))throw new Error(t('Unexpected search response.','Beklenmeyen arama yanıtı.'));
      const matches=data.matches.filter(m=>['tx','block','address'].includes(m.type)&&typeof m.target==='string');
      const href=m=>m.type+'.html?'+(m.type==='tx'?'hash':m.type==='block'?'h':'fp')+'='+encodeURIComponent(m.target);
      if(matches.length===1){location.assign(window.nodusLink(href(matches[0])));return;}
      results.replaceChildren();if(!matches.length){results.append(el('p',t('No matching records.','Eşleşen kayıt yok.'),'search-empty'));return;}
      const list=el('ul',undefined,'search-list');for(const match of matches){const li=el('li');li.append(el('span',match.type==='block'?t('Block','Blok'):match.type==='tx'?t('Transaction','İşlem'):t('Address','Adres'),'search-type'),hash(match.target,href(match)));list.append(li);}results.append(list);
    }catch(error){if(current===searchRequest)errorBox(results,error);}
  });
  $('search-input').addEventListener('input',()=>{searchRequest++;$('search-results').replaceChildren();});
  $('refresh-data').addEventListener('click',refresh);
  if(page==='index'){
    $('pg-first').addEventListener('click',()=>loadBlocks(1,true));$('pg-prev').addEventListener('click',()=>loadBlocks(pageNumber-1));$('pg-next').addEventListener('click',()=>loadBlocks(pageNumber+1));$('pg-last').addEventListener('click',()=>loadBlocks(lastPage));
    $('pg-input').addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();if(/^\d+$/.test(event.target.value))loadBlocks(Number(event.target.value));}});
    setInterval(()=>{if(!document.hidden && pageNumber===1)refresh();},30000);
  }
  refresh();
})();
