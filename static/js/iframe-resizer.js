(function(){
  'use strict';

  var BUFFER = 20;
  var THRESHOLD = 15;
  var DEBOUNCE_MS = 250;
  var managed = new WeakSet();

  /* Aggressive CSS injection to kill viewport-filling behavior */
  function injectCSS(doc){
    var style = doc.createElement('style');
    style.textContent =
      'html, body, #app, .app, .container, .main, [class*="wrap"] {' +
        'height: auto !important;' +
        'min-height: 0 !important;' +
        'box-sizing: border-box !important;' +
        'overflow-y: hidden !important;' +
      '}';
    doc.head.appendChild(style);
  }

  /* Read content height — NEVER reset iframe height here */
  function readHeight(iframe){
    try {
      var body = iframe.contentWindow.document.body;
      return body ? body.scrollHeight : 0;
    } catch(e){
      return 0;
    }
  }

  /* Apply height only if change exceeds threshold */
  function syncHeight(iframe){
    var newH = readHeight(iframe);
    if (newH <= 0) return;
    newH += BUFFER;
    var curH = parseInt(iframe.style.height, 10) || 0;
    if (Math.abs(newH - curH) > THRESHOLD){
      iframe.style.height = newH + 'px';
    }
  }

  function debounce(fn, ms){
    var timer;
    return function(){
      clearTimeout(timer);
      timer = setTimeout(fn, ms);
    };
  }

  /* Initial measurement: collapse once to get true content size */
  function initialMeasure(iframe){
    try {
      iframe.style.height = '0px';
      var body = iframe.contentWindow.document.body;
      var h = body ? body.scrollHeight : 0;
      iframe.style.height = (h > 0 ? h + BUFFER : 800) + 'px';
    } catch(e){
      iframe.style.height = '800px';
    }
  }

  function setupObserver(iframe){
    try {
      var doc = iframe.contentWindow.document;
      if (!doc || !doc.body) return;

      var debouncedSync = debounce(function(){ syncHeight(iframe); }, DEBOUNCE_MS);

      if (typeof ResizeObserver !== 'undefined'){
        var ro = new ResizeObserver(debouncedSync);
        ro.observe(doc.body);
      }
    } catch(e){}
  }

  function initIframe(iframe){
    if (managed.has(iframe)) return;
    managed.add(iframe);

    iframe.style.overflow = 'hidden';
    iframe.setAttribute('scrolling', 'no');

    var onReady = function(){
      try { injectCSS(iframe.contentWindow.document); } catch(e){ return; }

      /* Let injected CSS take effect, then measure once */
      requestAnimationFrame(function(){
        initialMeasure(iframe);
        setupObserver(iframe);
        /* One delayed pass for async SPAs */
        setTimeout(function(){ syncHeight(iframe); }, 800);
      });
    };

    if (iframe.contentWindow &&
        iframe.contentWindow.document &&
        iframe.contentWindow.document.readyState === 'complete'){
      onReady();
    } else {
      iframe.addEventListener('load', onReady);
    }
  }

  function initAll(){
    var iframes = document.querySelectorAll('iframe[src*="/tools/"]');
    for (var i = 0; i < iframes.length; i++) initIframe(iframes[i]);
  }

  /* Parent resize (orientation / browser window) */
  window.addEventListener('resize', debounce(function(){
    var iframes = document.querySelectorAll('iframe[src*="/tools/"]');
    for (var i = 0; i < iframes.length; i++) syncHeight(iframes[i]);
  }, DEBOUNCE_MS));

  if (document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', initAll);
  } else {
    initAll();
  }
})();
