(() => {
  const input = document.querySelector('#wiki-search');
  const results = document.querySelector('#wiki-results');
  const tr = window.nodusLanguage === 'tr';
  const normalize = value => value.toLocaleLowerCase(tr ? 'tr' : 'en').normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  let indexPromise;
  let version = 0;
  input.addEventListener('input', async () => {
    const current = ++version;
    const query = normalize(input.value.trim());
    results.replaceChildren();
    if (!query) return;
    try {
      indexPromise ??= fetch('search-index.json').then(r => { if (!r.ok) throw new Error(); return r.json(); });
      const index = await indexPromise;
      if (current !== version) return;
      const tokens = query.split(/\s+/);
      const matches = index.filter(g => tokens.every(token => normalize([...g.title, ...g.text].join(' ')).includes(token)));
      if (!matches.length) {
        const p = document.createElement('p');
        p.textContent = tr ? 'Sonuç bulunamadı. Başka bir kelime dene.' : 'No guides found. Try another word.';
        results.append(p);
      }
      for (const guide of matches) {
        const a = document.createElement('a');
        a.href = window.nodusLink(guide.slug + '.html');
        const title = document.createElement('strong'), detail = document.createElement('p');
        title.textContent = guide.title[tr ? 1 : 0];
        detail.textContent = guide.lead[tr ? 1 : 0];
        a.append(title, detail); results.append(a);
      }
    } catch {
      indexPromise = undefined;
      if (current !== version) return;
      const p = document.createElement('p');
      p.textContent = tr ? 'Arama yüklenemedi. Aşağıdaki rehberleri kullanabilirsin.' : 'Search is unavailable. Browse the guides below.';
      results.append(p);
    }
  });
})();
