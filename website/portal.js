// Shared navigation for the static Wiki and Scan sites.
(() => {
  const origins = ['https://nodusnetwork.io', 'https://wiki.nodusnetwork.io', 'https://scan.nodusnetwork.io'];
  const prefixes = ['/', '/wiki/', '/scan/'];
  const query = new URLSearchParams(location.search);
  let lang = query.get('lang');
  if (!lang) { try { lang = localStorage.getItem('nodus-language'); } catch {} }
  lang = lang === 'tr' ? 'tr' : 'en';
  window.nodusLanguage = lang;
  document.documentElement.lang = lang;
  document.querySelectorAll('[data-tr]').forEach(element => {
    // Only trusted, authored guide HTML is translated here. Search/API data uses textContent.
    if (lang === 'tr') element.innerHTML = element.dataset.tr;
  });
  document.querySelectorAll('[data-placeholder-tr]').forEach(element => {
    if (lang === 'tr') element.placeholder = element.dataset.placeholderTr;
  });
  document.querySelectorAll('[data-label-tr]').forEach(element => {
    if (lang === 'tr') element.setAttribute('aria-label', element.dataset.labelTr);
  });
  if (lang === 'tr' && document.body.dataset.titleTr) document.title = document.body.dataset.titleTr;
  try { localStorage.setItem('nodus-language', lang); } catch {}
  window.nodusLink = value => {
    const url = new URL(value, location.href);
    const index = origins.indexOf(url.origin);
    if (index >= 0 && !origins.includes(location.origin)) {
      url.host = location.host;
      url.protocol = location.protocol;
      url.pathname = prefixes[index] + url.pathname.slice(1);
    }
    if (url.origin === location.origin || origins.includes(url.origin)) url.searchParams.set('lang', lang);
    return url.href;
  };
  document.querySelectorAll('a[href]').forEach(link => {
    if (!link.getAttribute('href').startsWith('#')) link.href = window.nodusLink(link.href);
  });
  const toggle = document.querySelector('.portal-language');
  if (toggle) {
    toggle.textContent = lang.toUpperCase();
    toggle.setAttribute('aria-label', lang === 'en' ? 'Switch to Turkish' : 'İngilizceye geç');
    toggle.addEventListener('click', () => {
      const url = new URL(location.href);
      url.searchParams.set('lang', lang === 'en' ? 'tr' : 'en');
      location.assign(url);
    });
  }
  const activeLinks = document.querySelectorAll('.article-toc a');
  if ('IntersectionObserver' in window && activeLinks.length) {
    const observer = new IntersectionObserver(entries => {
      for (const entry of entries) if (entry.isIntersecting) {
        activeLinks.forEach(link => link.classList.toggle('active', link.hash === '#' + entry.target.id));
      }
    }, { rootMargin: '-100px 0px -55% 0px' });
    document.querySelectorAll('.wiki-article section[id]').forEach(section => observer.observe(section));
  }
})();
