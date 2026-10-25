// Site-wide behaviour (loaded deferred on every page; fingerprinted by Hugo).
// Everything here is progressive enhancement: without JS the nav stays
// visible, the language menu is a plain <details>, code and tables still scroll.
(function () {
  'use strict';
  var doc = document.documentElement;

  /* ── Header: hamburger, language menu, shadow once scrolled ── */
  var header = document.getElementById('site-header');
  var nav = document.getElementById('site-nav');
  var toggle = header && header.querySelector('.nav-toggle');
  var lang = header && header.querySelector('.lang-menu');
  if (header) header.classList.add('js');

  function setNav(open) {
    if (!toggle) return;
    toggle.setAttribute('aria-expanded', String(open));
    header.classList.toggle('nav-open', open);
  }
  if (toggle) toggle.addEventListener('click', function () {
    setNav(toggle.getAttribute('aria-expanded') !== 'true');
    if (lang) lang.open = false;
  });
  if (lang) lang.addEventListener('toggle', function () { if (lang.open) setNav(false); });
  document.addEventListener('click', function (e) {
    if (lang && lang.open && !lang.contains(e.target)) lang.open = false;
    if (header && header.classList.contains('nav-open') && !header.contains(e.target)) setNav(false);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    if (lang && lang.open) { lang.open = false; lang.querySelector('summary').focus(); }
    if (header && header.classList.contains('nav-open')) { setNav(false); toggle.focus(); }
  });
  // Leaving the mobile breakpoint with the menu open must not leave it stuck open.
  var wide = window.matchMedia('(min-width: 768px)');
  (wide.addEventListener ? wide.addEventListener.bind(wide, 'change') : wide.addListener.bind(wide))(function () { setNav(false); });

  /* ── Back to top: after 1.5 viewports, never over a heading, a control
        or the tool iframe (it hides while one of those is under it) ── */
  var top = document.getElementById('top-link');
  var AVOID = 'h1, h2, h3, iframe, a, button, input, select, textarea, label, summary, .code-block, .ad-slot';
  function blocked(r) {
    var pts = [[r.left + 2, r.top + 2], [r.right - 2, r.top + 2], [r.left + 2, r.bottom - 2], [r.right - 2, r.bottom - 2], [(r.left + r.right) / 2, (r.top + r.bottom) / 2]];
    for (var i = 0; i < pts.length; i++) {
      var stack = document.elementsFromPoint(pts[i][0], pts[i][1]);
      for (var j = 0; j < stack.length; j++) {
        var el = stack[j];
        if (el === top || top.contains(el)) continue;
        if (el.closest && el.closest(AVOID)) return true;
      }
    }
    return false;
  }

  /* ── Scroll handler (rAF-throttled) ── */
  var ticking = false;
  function onScroll() {
    ticking = false;
    var y = window.scrollY;
    if (header) header.classList.toggle('scrolled', y > 4);
    if (top) {
      var show = y > window.innerHeight * 1.5;
      if (show) show = !blocked(top.getBoundingClientRect());
      top.classList.toggle('visible', show);
    }
  }
  window.addEventListener('scroll', function () { if (!ticking) { ticking = true; requestAnimationFrame(onScroll); } }, { passive: true });
  window.addEventListener('resize', onScroll, { passive: true });
  onScroll();

  /* ── Horizontal scrollers (code, tables): fade the edge that has more.
        [data-scroll-x] is the non-scrolling frame that paints the fade;
        the scroller is the <pre> or .table-wrap inside it. ── */
  document.querySelectorAll('[data-scroll-x]').forEach(function (frame) {
    var sc = frame.querySelector('pre, .table-wrap');
    if (!sc) return;
    var update = function () {
      var max = sc.scrollWidth - sc.clientWidth;
      frame.classList.toggle('more-right', max > 1 && sc.scrollLeft < max - 1);
      frame.classList.toggle('more-left', sc.scrollLeft > 1);
    };
    sc.addEventListener('scroll', update, { passive: true });
    if (window.ResizeObserver) new ResizeObserver(update).observe(sc);
    update();
  });

  /* ── Copy buttons on code blocks ── */
  document.querySelectorAll('.code-copy').forEach(function (btn) {
    var label = btn.querySelector('.code-copy-text');
    var idle = label.textContent;
    btn.addEventListener('click', function () {
      var code = btn.closest('.code-block').querySelector('pre code') || btn.closest('.code-block').querySelector('pre');
      var text = code.innerText.replace(/\n$/, '');
      var done = function () {
        label.textContent = btn.getAttribute('data-copied');
        btn.classList.add('copied');
        setTimeout(function () { label.textContent = idle; btn.classList.remove('copied'); }, 1800);
      };
      if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, fallback);
      else fallback();
      function fallback() {
        var ta = document.createElement('textarea');
        ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); done(); } catch (e) { /* nothing to do */ }
        ta.remove();
      }
    });
  });

  doc.classList.add('js');
})();
