/* Small shared helpers for the embedded tool apps (static/tools/*): UI
   language, string lookup with {placeholders}, copy, download, escaping.
   Loaded by the apps added in the redesign; older apps keep their own code. */
(function () {
  'use strict';
  var LANGS = ['en', 'it', 'es', 'de', 'fr', 'pt'];
  function detectLang() {
    var q = new URLSearchParams(location.search).get('lang');
    if (q && LANGS.indexOf(q.toLowerCase()) >= 0) return q.toLowerCase();
    var m = location.pathname.match(/^\/(en|it|es|de|fr|pt)\//);
    if (m) return m[1];
    var n = (navigator.language || 'en').slice(0, 2).toLowerCase();
    return LANGS.indexOf(n) >= 0 ? n : 'en';
  }
  var TK = window.TK = { lang: detectLang(), dict: {} };
  document.documentElement.lang = TK.lang;

  /** TK.init({en: {...}, it: {...}}): pick the language and fill [data-i18n*] elements. */
  TK.init = function (strings) {
    TK.dict = Object.assign({}, strings.en, strings[TK.lang] || {});
    var each = function (attr, fn) { document.querySelectorAll('[' + attr + ']').forEach(function (el) { fn(el, TK.t(el.getAttribute(attr))); }); };
    each('data-i18n', function (el, s) { el.textContent = s; });
    each('data-i18n-html', function (el, s) { el.innerHTML = s; });
    each('data-i18n-placeholder', function (el, s) { el.placeholder = s; });
    each('data-i18n-title', function (el, s) { el.title = s; });
    each('data-i18n-aria', function (el, s) { el.setAttribute('aria-label', s); });
  };

  /** TK.t('key', {n: 3}) -> the string with {n} replaced. */
  TK.t = function (key, vars) {
    var s = TK.dict[key];
    if (s === undefined) s = key;
    if (vars) s = s.replace(/\{(\w+)\}/g, function (m, k) { return vars[k] !== undefined ? vars[k] : m; });
    return s;
  };

  var ENT = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  TK.esc = function (s) { return String(s).replace(/[&<>"']/g, function (c) { return ENT[c]; }); };
  TK.num = function (n) { return Number(n).toLocaleString(TK.lang); };

  /** Copy text to the clipboard; flashes the button label. */
  TK.copy = function (text, btn) {
    function done() {
      if (!btn) return;
      var old = btn.getAttribute('data-label') || btn.textContent;
      btn.setAttribute('data-label', old);
      btn.textContent = TK.t('copied');
      btn.classList.add('is-done');
      setTimeout(function () { btn.textContent = old; btn.classList.remove('is-done'); }, 1500);
    }
    function fallback() {
      var ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); done(); } catch (e) { /* nothing to do */ }
      ta.remove();
    }
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, fallback);
    else fallback();
  };

  /** Save a Blob as a file (the iframe needs allow-downloads in its sandbox). */
  TK.download = function (blob, name) {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 30000);
  };

  /** Delegated copy buttons: <button data-copy="#id"> or data-copy-text="...". */
  document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('[data-copy],[data-copy-text]');
    if (!b) return;
    var text = b.getAttribute('data-copy-text');
    if (text === null) {
      var el = document.querySelector(b.getAttribute('data-copy'));
      text = !el ? '' : ('value' in el ? el.value : el.textContent);
    }
    TK.copy(text, b);
  });
})();
