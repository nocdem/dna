/**
 * cpunk.io i18n engine
 *
 * Usage:
 *   <span data-i18n="hero.title">CPUNK</span>
 *   <input data-i18n-placeholder="search.hint" placeholder="Search...">
 *   <meta data-i18n-content="meta.description" content="...">
 *
 * Supported languages are defined in LANGUAGES array.
 * User preference is stored in localStorage('cpunk-lang').
 * Falls back to browser language, then English.
 */
(function () {
  'use strict';

  /* ── Supported languages ── */
  /* Add new languages here as JSON files are created in /i18n/ */
  var LANGUAGES = [
    { code: 'en', name: 'English',    native: 'English',    flag: '🇬🇧' },
    { code: 'tr', name: 'Turkish',    native: 'Türkçe',     flag: '🇹🇷' },
    { code: 'de', name: 'German',     native: 'Deutsch',    flag: '🇩🇪' },
    { code: 'ar', name: 'Arabic',     native: 'العربية',    flag: '🇸🇦', dir: 'rtl' },
    { code: 'es', name: 'Spanish',    native: 'Español',    flag: '🇪🇸' },
    { code: 'it', name: 'Italian',    native: 'Italiano',   flag: '🇮🇹' },
    { code: 'ja', name: 'Japanese',   native: '日本語',      flag: '🇯🇵' },
    { code: 'nl', name: 'Dutch',      native: 'Nederlands', flag: '🇳🇱' },
    { code: 'pt', name: 'Portuguese', native: 'Português',  flag: '🇵🇹' },
    { code: 'ru', name: 'Russian',    native: 'Русский',    flag: '🇷🇺' },
    { code: 'zh', name: 'Chinese',    native: '中文',        flag: '🇨🇳' }
  ];

  var STORAGE_KEY = 'cpunk-lang';
  var DEFAULT_LANG = 'en';
  var cache = {};       /* { 'en': { key: value, ... }, ... } */
  var currentLang = DEFAULT_LANG;

  /* ── Helpers ── */

  function getLangMeta(code) {
    for (var i = 0; i < LANGUAGES.length; i++) {
      if (LANGUAGES[i].code === code) return LANGUAGES[i];
    }
    return null;
  }

  function detectLanguage() {
    /* 1. localStorage */
    var stored = localStorage.getItem(STORAGE_KEY);
    if (stored && getLangMeta(stored)) return stored;

    /* 2. Browser language */
    var nav = (navigator.language || navigator.userLanguage || '').toLowerCase();
    var prefix = nav.split('-')[0];
    if (getLangMeta(prefix)) return prefix;

    /* 3. Default */
    return DEFAULT_LANG;
  }

  function fetchJSON(url, cb) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, true);
    xhr.onreadystatechange = function () {
      if (xhr.readyState === 4) {
        if (xhr.status === 200) {
          try { cb(null, JSON.parse(xhr.responseText)); }
          catch (e) { cb(e, null); }
        } else {
          cb(new Error('HTTP ' + xhr.status), null);
        }
      }
    };
    xhr.send();
  }

  function getTranslation(data, key) {
    return data[key] || null;
  }

  /* ── DOM update ── */

  function applyTranslations(data) {
    /* data-i18n → textContent */
    var els = document.querySelectorAll('[data-i18n]');
    for (var i = 0; i < els.length; i++) {
      var key = els[i].getAttribute('data-i18n');
      var val = getTranslation(data, key);
      if (val) els[i].textContent = val;
    }

    /* data-i18n-placeholder → placeholder attribute */
    var phEls = document.querySelectorAll('[data-i18n-placeholder]');
    for (var k = 0; k < phEls.length; k++) {
      var pkey = phEls[k].getAttribute('data-i18n-placeholder');
      var pval = getTranslation(data, pkey);
      if (pval) phEls[k].setAttribute('placeholder', pval);
    }

    /* data-i18n-content → content attribute (for meta tags) */
    var cEls = document.querySelectorAll('[data-i18n-content]');
    for (var m = 0; m < cEls.length; m++) {
      var ckey = cEls[m].getAttribute('data-i18n-content');
      var cval = getTranslation(data, ckey);
      if (cval) cEls[m].setAttribute('content', cval);
    }

    /* Update <html lang=""> and dir */
    var meta = getLangMeta(currentLang);
    document.documentElement.lang = currentLang;
    document.documentElement.dir = (meta && meta.dir) || 'ltr';

    /* Update language selector display */
    updateSelectorDisplay();
  }

  /* ── Language switching ── */

  function loadLanguage(code, cb) {
    if (cache[code]) {
      currentLang = code;
      applyTranslations(cache[code]);
      if (cb) cb();
      return;
    }

    fetchJSON('/i18n/' + code + '.json', function (err, data) {
      if (err || !data) {
        /* Fallback to English if translation file missing */
        if (code !== DEFAULT_LANG) {
          loadLanguage(DEFAULT_LANG, cb);
        }
        return;
      }
      cache[code] = data;
      currentLang = code;
      applyTranslations(data);
      if (cb) cb();
    });
  }

  function switchLanguage(code) {
    if (!getLangMeta(code)) return;
    localStorage.setItem(STORAGE_KEY, code);
    loadLanguage(code);
  }

  /* ── Language selector UI ── */

  function updateSelectorDisplay() {
    var meta = getLangMeta(currentLang);
    var btn = document.getElementById('lang-current');
    if (btn && meta) {
      btn.textContent = meta.flag + ' ' + meta.code.toUpperCase();
    }

    /* Mark active item */
    var items = document.querySelectorAll('.lang-option');
    for (var i = 0; i < items.length; i++) {
      var isActive = items[i].getAttribute('data-lang') === currentLang;
      items[i].classList.toggle('active', isActive);
    }
  }

  function buildSelector() {
    /* Find the placeholder in nav */
    var container = document.getElementById('lang-selector');
    if (!container) return;

    var btn = document.createElement('button');
    btn.className = 'lang-btn';
    btn.id = 'lang-current';
    btn.type = 'button';
    btn.setAttribute('aria-label', 'Select language');

    var dropdown = document.createElement('div');
    dropdown.className = 'lang-dropdown';

    for (var i = 0; i < LANGUAGES.length; i++) {
      var lang = LANGUAGES[i];
      var item = document.createElement('button');
      item.type = 'button';
      item.className = 'lang-option';
      item.setAttribute('data-lang', lang.code);
      item.textContent = lang.flag + '  ' + lang.native;
      item.addEventListener('click', (function (code) {
        return function () {
          switchLanguage(code);
          dropdown.classList.remove('open');
        };
      })(lang.code));
      dropdown.appendChild(item);
    }

    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      dropdown.classList.toggle('open');
    });

    /* Close on outside click */
    document.addEventListener('click', function () {
      dropdown.classList.remove('open');
    });

    container.appendChild(btn);
    container.appendChild(dropdown);
  }

  /* ── Init ── */

  function init() {
    buildSelector();
    var lang = detectLanguage();
    loadLanguage(lang);
  }

  /* Run on DOM ready */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  /* ── Public API ── */
  window.cpunkI18n = {
    switchLanguage: switchLanguage,
    getCurrentLanguage: function () { return currentLang; },
    getLanguages: function () { return LANGUAGES.slice(); }
  };
})();
