import { guides } from './wiki/content.mjs';

export const files = new Map([
  ['/robots.txt', ['robots.txt', 'text/plain; charset=utf-8']],
  ['/sitemap.xml', ['sitemap.xml', 'application/xml; charset=utf-8']],
  ['/assets/artwork/nodus-share-v1.jpg', ['assets/artwork/nodus-share-v1.jpg', 'image/jpeg']],
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/index.html', ['index.html', 'text/html; charset=utf-8']],
  ['/docs.html', ['docs.html', 'text/html; charset=utf-8']],
  ['/ecosystem.html', ['ecosystem.html', 'text/html; charset=utf-8']],
  ['/network.html', ['network.html', 'text/html; charset=utf-8']],
  ['/manifesto.html', ['manifesto.html', 'text/html; charset=utf-8']],
  ['/roadmap.html', ['roadmap.html', 'text/html; charset=utf-8']],
  ['/connect.html', ['connect.html', 'text/html; charset=utf-8']],
  ['/wallet.html', ['wallet.html', 'text/html; charset=utf-8']],
  ['/identity.html', ['identity.html', 'text/html; charset=utf-8']],
  ['/chain.html', ['chain.html', 'text/html; charset=utf-8']],
  ['/scan.html', ['scan.html', 'text/html; charset=utf-8']],
  ['/terms.html', ['terms.html', 'text/html; charset=utf-8']],
  ['/privacy.html', ['privacy.html', 'text/html; charset=utf-8']],
  ['/styles.css', ['styles.css', 'text/css; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/network.js', ['network.js', 'text/javascript; charset=utf-8']],
  ['/visuals.js', ['visuals.js', 'text/javascript; charset=utf-8']],
  ['/assets/artwork/network-v1.webp', ['assets/artwork/network-v1.webp', 'image/webp']],
  ['/assets/artwork/home-infrastructure-v1.webp', ['assets/artwork/home-infrastructure-v1.webp', 'image/webp']],
  ['/assets/artwork/home-applications-v1.webp', ['assets/artwork/home-applications-v1.webp', 'image/webp']],
  ['/assets/artwork/connect-v1.webp', ['assets/artwork/connect-v1.webp', 'image/webp']],
  ['/assets/artwork/wallet-v1.webp', ['assets/artwork/wallet-v1.webp', 'image/webp']],
  ['/assets/artwork/identity-v1.webp', ['assets/artwork/identity-v1.webp', 'image/webp']],
  ['/assets/artwork/chain-v1.webp', ['assets/artwork/chain-v1.webp', 'image/webp']],
  ['/assets/artwork/scan-v1.webp', ['assets/artwork/scan-v1.webp', 'image/webp']],
  ['/assets/artwork/manifesto-v1.webp', ['assets/artwork/manifesto-v1.webp', 'image/webp']],
  ['/assets/artwork/storage-v1.webp', ['assets/artwork/storage-v1.webp', 'image/webp']],
  ['/assets/artwork/bandwidth-v1.webp', ['assets/artwork/bandwidth-v1.webp', 'image/webp']],
  ['/assets/artwork/compute-v1.webp', ['assets/artwork/compute-v1.webp', 'image/webp']],
  ['/assets/nodus-mark.svg', ['assets/nodus-mark.svg', 'image/svg+xml']],
  ['/assets/fonts/inter-latin.woff2', ['assets/fonts/inter-latin.woff2', 'font/woff2']],
  ['/assets/fonts/inter-latin-ext.woff2', ['assets/fonts/inter-latin-ext.woff2', 'font/woff2']],
  ['/assets/fonts/OFL.txt', ['assets/fonts/OFL.txt', 'text/plain; charset=utf-8']],
]);

const shared = ['portal.css', 'portal.js', 'assets/nodus-mark.svg', 'assets/fonts/inter-latin.woff2', 'assets/fonts/inter-latin-ext.woff2', 'assets/fonts/OFL.txt'];
const wikiPages = ['index', ...guides.map(guide => guide.slug)];
const scanPages = ['index', 'block', 'tx', 'address'];
const mime = path => ({html:'text/html; charset=utf-8',css:'text/css; charset=utf-8',js:'text/javascript; charset=utf-8',json:'application/json; charset=utf-8',xml:'application/xml; charset=utf-8',txt:'text/plain; charset=utf-8',svg:'image/svg+xml',webp:'image/webp',woff2:'font/woff2'})[path.split('.').pop()];
export const siteFiles = {
 'nodusnetwork.io': new Map([...files.values()].map(([source]) => [source, source])),
 'wiki.nodusnetwork.io': new Map([...shared.map(path => [path, path]), ...wikiPages.map(name => [name + '.html', 'wiki/' + name + '.html']), ...['search.js','search-index.json','robots.txt','sitemap.xml'].map(path => [path, 'wiki/' + path])]),
 'scan.nodusnetwork.io': new Map([...shared.map(path => [path, path]), ...scanPages.map(name => [name + '.html', 'scan/' + name + '.html']), ...['app.js','robots.txt','sitemap.xml'].map(path => [path, 'scan/' + path]), ['assets/artwork/scan-v1.webp','assets/artwork/scan-v1.webp']])
};
for (const path of shared) files.set('/' + path, [path, mime(path)]);
for (const site of ['wiki', 'scan']) {
 for (const [path, source] of siteFiles[site + '.nodusnetwork.io']) {
  files.set('/' + site + '/' + path, [source, mime(path)]);
 }
 files.set('/' + site + '/', [site + '/index.html', 'text/html; charset=utf-8']);
}
