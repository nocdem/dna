import { writeFile, mkdir } from 'node:fs/promises';
import { guides } from './wiki/content.mjs';

const escape = value => String(value).replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const text = (en, tr, tag = 'span', attrs = '') => `<${tag} ${attrs} data-tr="${escape(tr)}">${en}</${tag}>`;
const groupNames = { connect: ['Use Connect', 'Connect’i kullan'], network: ['Understand the network', 'Ağı anla'], build: ['Explore & build', 'Keşfet ve geliştir'] };
const output = async (path, body) => writeFile(new URL(path, import.meta.url), body + '\n');
const anchor = (href, en, tr, attrs = '') => `<a href="${href}" ${attrs}>${text(en, tr)}</a>`;
function shell(site, slug, title, description, content) {
  const origin = `https://${site}.nodusnetwork.io`;
  const suffix = site === 'wiki' ? 'Wiki' : 'Scan';
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#141612"><title>${escape(title[0])} — Nodus ${suffix}</title>
<meta name="description" content="${escape(description[0])}">
<link rel="canonical" href="${origin}/${slug === 'index' ? '' : slug + '.html'}">
<meta property="og:title" content="${escape(title[0])} — Nodus ${suffix}"><meta property="og:description" content="${escape(description[0])}">
<meta property="og:type" content="website"><meta property="og:site_name" content="Nodus ${suffix}">
<meta property="og:url" content="${origin}/${slug === 'index' ? '' : slug + '.html'}">
<meta name="robots" content="${site === 'scan' && slug !== 'index' ? 'noindex, follow' : 'index, follow'}">
<link rel="icon" href="../assets/nodus-mark.svg" type="image/svg+xml">
<link rel="preload" href="../assets/fonts/inter-latin.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="../portal.css"><script src="../portal.js" defer></script>
${site === 'wiki' ? (slug === 'index' ? '<script src="search.js" defer></script>' : '') : '<script src="app.js" defer></script>'}
</head><body class="${site}-site" data-page="${slug}" data-title-tr="${escape(title[1])} — Nodus ${suffix}">
${anchor('#main', 'Skip to content', 'İçeriğe geç', 'class="skip-link"')}
<header class="portal-header"><div class="wrap"><a class="portal-brand" href="./" aria-label="Nodus ${suffix}"><img src="../assets/nodus-mark.svg" alt="" width="34" height="34">nodus<span class="portal-name">${suffix.toLowerCase()}</span></a>
<nav class="portal-nav" aria-label="Main navigation" data-label-tr="Ana gezinme">${anchor('https://nodusnetwork.io/', 'Nodus ↗', 'Nodus ↗')}${anchor('https://wiki.nodusnetwork.io/', 'Wiki', 'Wiki')}${anchor('https://scan.nodusnetwork.io/', 'Scan', 'Scan')}${anchor('https://nodusnetwork.io/docs.html', 'Developers', 'Geliştiriciler')}${anchor('https://nodusnetwork.io/connect.html#download', 'Get Connect ↗', 'Connect’i indir ↗', 'class="wide-only"')}</nav><button type="button" class="portal-language" aria-label="Switch to Turkish">EN</button></div></header>
<main class="wrap" id="main">${content}</main>
<footer class="portal-footer"><div class="wrap"><div><p>© 2026 Nodus · ${suffix}</p>${site === 'scan' ? text('Read-only index from the witness cluster. Consensus certificates are not independently re-verified. DNAC devnet; NODUS naming is planned with testnet.', 'Doğrulayıcı kümesinden salt okunur indeks. Konsensüs sertifikaları bağımsız olarak yeniden doğrulanmaz. DNAC devnet; NODUS adı testnet ile planlanır.', 'p') : text('Independent by nature. Connected by Nodus.', 'Doğasında bağımsızlık. Bağlantısında Nodus.', 'p')}</div><nav>${anchor('https://nodusnetwork.io/manifesto.html', 'Manifesto ↗', 'Manifesto ↗')}${anchor('https://nodusnetwork.io/roadmap.html', 'Roadmap ↗', 'Yol haritası ↗')}${anchor('https://github.com/nocdem/dna', 'Source ↗', 'Kaynak ↗')}</nav></div></footer>
</body></html>`;
}
function sidebars(current) {
  const links = guides.map(g => anchor(g.slug + '.html', ...g.title, g.slug === current ? 'aria-current="page"' : '')).join('');
  const sidebar = `<aside class="wiki-sidebar"><a href="./" class="sidebar-home">${text('← Knowledge home', '← Bilgi merkezi')}</a>${Object.entries(groupNames).map(([group, name]) => `<div class="sidebar-group">${text(...name, 'h2')}${guides.filter(g => g.group === group).map(g => anchor(g.slug + '.html', ...g.title, g.slug === current ? 'aria-current="page"' : '')).join('')}</div>`).join('')}</aside>`;
  return { sidebar, mobile: `<details class="mobile-guides">${text('Browse all guides', 'Tüm rehberleri göster', 'summary')}<nav aria-label="Guides" data-label-tr="Rehberler">${anchor('./', 'Knowledge home', 'Bilgi merkezi')}${links}</nav></details>` };
}
function guideLink(g, i) {
  return `<a class="guide-link" href="${g.slug}.html"><span class="number">${String(i + 1).padStart(2, '0')}</span><div>${text(...g.title, 'h3')}${text(...g.lead, 'p')}</div><span class="arrow" aria-hidden="true">↗</span></a>`;
}
await mkdir(new URL('scan/', import.meta.url), { recursive: true });
const homeSides = sidebars('index');
await output('wiki/index.html', shell('wiki', 'index', ['Knowledge, shared.', 'Bilgi, paylaştıkça.'], ['Guides for Connect, the Nodus resource network and developers.', 'Connect, Nodus kaynak ağı ve geliştiriciler için rehberler.'], `<div class="wiki-layout">${homeSides.sidebar}<div class="wiki-main">${homeSides.mobile}<section class="wiki-hero">${text('NODUS / KNOWLEDGE BASE', 'NODUS / BİLGİ MERKEZİ', 'span', 'class="portal-kicker"')}${text('Find your way.<br>Make it yours.', 'Yolunu bul.<br>Kendine ait kıl.', 'h1')}${text('From your first conversation to building on the network. Clear guides for every step.', 'İlk sohbetinden ağ üzerinde geliştirmeye kadar. Her adım için anlaşılır rehberler.', 'p', 'class="lead"')}<div class="wiki-search">${text('Search the guides', 'Rehberlerde ara', 'label', 'for="wiki-search"')}<input id="wiki-search" type="search" placeholder="Try recovery, storage or transactions…" data-placeholder-tr="Kurtarma, depolama veya işlem ara…" autocomplete="off"><span class="search-hint" aria-hidden="true">⌕</span><div id="wiki-results" class="wiki-search-results" aria-live="polite"></div><noscript><p>Browse the guides below. / Aşağıdaki rehberleri kullanabilirsin.</p></noscript></div></section>${Object.entries(groupNames).map(([group, name]) => `<section><div class="section-heading">${text(...name, 'h2')}${text('A little knowledge goes a long way.', 'Biraz bilgi, çok yol aldırır.')}</div><div class="guide-list">${guides.filter(g => g.group === group).map(guideLink).join('')}</div></section>`).join('')}<section class="wiki-highlight"><div>${text('Privacy is a human right.', 'Gizlilik bir insan hakkıdır.', 'h2')}${text('The belief behind the network we are building.', 'İnşa ettiğimiz ağın arkasındaki inanç.', 'p')}</div>${anchor('https://nodusnetwork.io/manifesto.html', 'Read the manifesto ↗', 'Manifestoyu oku ↗', 'class="button"')}</section></div></div>`));
for (const [i, guide] of guides.entries()) {
  const sides = sidebars(guide.slug);
  const prev = guides[i - 1], next = guides[i + 1];
  const pager = `<nav class="article-pager" aria-label="Related guides" data-label-tr="Diğer rehberler">${prev ? `<a href="${prev.slug}.html">${text('Previous', 'Önceki')}${text('← ' + prev.title[0], '← ' + prev.title[1], 'strong')}</a>` : '<div></div>'}${next ? `<a href="${next.slug}.html">${text('Next', 'Sonraki')}${text(next.title[0] + ' →', next.title[1] + ' →', 'strong')}</a>` : anchor('./', 'All guides →', 'Tüm rehberler →')}</nav>`;
  const article = `<div class="wiki-layout">${sides.sidebar}<div class="wiki-main">${sides.mobile}<div class="article-grid"><article class="wiki-article"><nav class="breadcrumbs">${anchor('./', 'Knowledge home', 'Bilgi merkezi')}<span>/</span>${text(...groupNames[guide.group])}</nav><header class="article-header">${text(...guide.title, 'h1')}${text(...guide.lead, 'p', 'class="lead"')}<div class="article-meta">${text('REVIEWED SEPTEMBER 2026', 'EYLÜL 2026’DA İNCELENDİ')}${text('EN / TR', 'EN / TR')}</div></header>${guide.sections.map(section => `<section id="${section.id}">${text(...section.title, 'h2')}${text(...section.body, 'div', 'class="guide-body"')}</section>`).join('')}${pager}</article><aside class="article-toc">${text('On this page', 'Bu sayfada', 'h2')}${guide.sections.map(s => anchor('#' + s.id, ...s.title)).join('')}</aside></div></div></div>`;
  await output(`wiki/${guide.slug}.html`, shell('wiki', guide.slug, guide.title, guide.lead, article));
}
const searchIndex = guides.map(g => ({ slug: g.slug, title: g.title, lead: g.lead, text: [0, 1].map(i => g.sections.map(s => s.title[i] + ' ' + s.body[i].replace(/<[^>]*>/g, ' ')).join(' ')) }));
await output('wiki/search-index.json', JSON.stringify(searchIndex));
const search = `<label class="search-label" for="search-input">${text('Block height, full hash or address fingerprint', 'Blok yüksekliği, tam hash veya adres parmak izi')}</label><form id="search-form" class="search-form" autocomplete="off"><input id="search-input" class="search-input" type="search" maxlength="128" placeholder="Search the development ledger…" data-placeholder-tr="Geliştirme zincirinde ara…" required><button type="submit" class="btn-primary">${text('Search →', 'Ara →')}</button></form><div id="search-results" class="search-results" aria-live="polite"></div><div id="staleness-banner" class="staleness-banner hidden" role="status"></div>`;
for (const slug of ['index', 'block', 'tx', 'address']) {
  const titles = { index: ['Read the network.', 'Ağı incele.'], block: ['Block details', 'Blok ayrıntıları'], tx: ['Transaction details', 'İşlem ayrıntıları'], address: ['Address overview', 'Adres özeti'] };
  const desc = ['Blocks, transactions and address history on the DNAC development network.', 'DNAC geliştirme ağındaki bloklar, işlemler ve adres geçmişi.'];
  const hero = `<section class="scan-hero"><div>${text('NODUS SCAN / DNAC DEVNET', 'NODUS SCAN / DNAC DEVNET', 'span', 'class="devnet-tag"')}${text(...titles[slug], 'h1')}${text(...desc, 'p')}</div>${slug === 'index' ? '<div class="scan-art" aria-hidden="true"><img src="../assets/artwork/scan-v1.webp" width="220" height="147" alt=""></div>' : ''}</section>`;
  const status = `<div class="scan-status"><span id="api-status" role="status">${text('Connecting to the index…', 'İndekse bağlanıyor…')}</span><button id="refresh-data" type="button" class="btn-secondary">${text('Refresh ↻', 'Yenile ↻')}</button></div>`;
  const stats = `<section class="stats-grid" id="stats-cards" aria-label="Chain statistics" data-label-tr="Zincir istatistikleri">${[['height','Indexed height','İndeks yüksekliği'],['supply','Current devnet supply','Mevcut devnet arzı'],['burned','Burned','Yakılan'],['chain-id','Chain ID','Zincir kimliği']].map(([id,en,tr]) => `<div class="stat-card">${text(en,tr,'div','class="stat-label"')}<div class="stat-value mono" id="stat-${id}">—</div></div>`).join('')}</section>${text('Amounts use DNAC, the current devnet unit. Supply is reported by the chain; it is not market circulation.', 'Tutarlar mevcut devnet birimi DNAC ile gösterilir. Arz zincirin bildirdiği değerdir; piyasa dolaşımı değildir.', 'p', 'class="scan-explanation"')}`;
  const blocks = `<section>${text('Latest blocks', 'Son bloklar', 'h2', 'class="section-title"')}${text('Scroll horizontally to see every column ↔', 'Tüm sütunları görmek için yana kaydır ↔', 'p', 'class="table-hint"')}<div class="table-scroll" tabindex="0" role="region" aria-label="Latest blocks" data-label-tr="Son bloklar"><table class="data-table"><thead><tr>${[['Height','Yükseklik'],['Block hash','Blok hash’i'],['Time','Zaman'],['Transactions','İşlemler']].map(t => text(...t,'th','scope="col"')).join('')}</tr></thead><tbody id="blocks-tbody"><tr><td colspan="4" class="loading">${text('Loading…', 'Yükleniyor…')}</td></tr></tbody></table></div><div id="blocks-pager" class="pager hidden"><button id="pg-first" class="btn-page" aria-label="Newest page" data-label-tr="En yeni sayfa">«</button><button id="pg-prev" class="btn-page" aria-label="Previous page" data-label-tr="Önceki sayfa">‹</button><span class="pager-label">${text('Page', 'Sayfa')}<input id="pg-input" class="pager-input" type="text" inputmode="numeric" aria-label="Go to page" data-label-tr="Sayfaya git"> / <span id="pg-total">1</span></span><button id="pg-next" class="btn-page" aria-label="Next page" data-label-tr="Sonraki sayfa">›</button><button id="pg-last" class="btn-page" aria-label="Oldest page" data-label-tr="En eski sayfa">»</button></div></section>`;
  const details = `<div id="${slug}-content" class="detail-content" aria-live="polite"></div>`;
  const footer = `<div class="scan-guide-link">${text('Make sense of what you see.', 'Gördüğün veriyi anlamlandır.')}${anchor('https://wiki.nodusnetwork.io/explorer.html', 'How to use Nodus Scan ↗', 'Nodus Scan nasıl kullanılır? ↗')}${anchor('https://wiki.nodusnetwork.io/developers.html#api', 'API reference ↗', 'API rehberi ↗')}</div><noscript><p>Scan needs JavaScript to request chain data. / Zincir verisini almak için JavaScript gerekir.</p></noscript>`;
  await output(`scan/${slug}.html`, shell('scan', slug, titles[slug], desc, hero + search + status + (slug === 'index' ? stats + blocks : details) + footer));
}
for (const site of ['wiki', 'scan']) {
  const pages = site === 'wiki' ? ['', ...guides.map(g => g.slug + '.html')] : [''];
  await output(`${site}/sitemap.xml`, `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${pages.map(p => `<url><loc>https://${site}.nodusnetwork.io/${p}</loc></url>`).join('')}</urlset>`);
  await output(`${site}/robots.txt`, `User-agent: *\nAllow: /\n${site === 'scan' ? 'Disallow: /api/\n' : ''}\nSitemap: https://${site}.nodusnetwork.io/sitemap.xml`);
}
console.log(`Built ${guides.length + 1} Wiki pages and 4 Scan pages.`);
