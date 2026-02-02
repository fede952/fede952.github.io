(function(){
  'use strict';

  var BUFFER = 20;
  var DEBOUNCE_MS = 200;
  var managed = new WeakSet();
  var resizing = false;

  /* Inject CSS override to break 100vh feedback loop */
  function injectCSS(doc){
    var style = doc.createElement('style');
    style.textContent =
      'html, body {' +
        'height: auto !important;' +
        'min-height: 0 !important;' +
        'overflow-y: hidden !important;' +
      '}';
    doc.head.appendChild(style);
  }

  /* Measure true content height by shrinking first */
  function measure(iframe){
    if (resizing) return 0;
    resizing = true;
    try {
      var doc = iframe.contentWindow.document;
      var body = doc.body;
      if (!body) return 0;

      /* Collapse iframe to force content to shrink-wrap */
      var prev = iframe.style.height;
      iframe.style.height = '0px';

      /* Read the natural content height */
      var h = Math.max(
        body.scrollHeight,
        body.offsetHeight,
        doc.documentElement.scrollHeight
      );

      /* Restore (will be overwritten by caller) */
      iframe.style.height = prev;
      return h;
    } catch(e){
      return 0;
    } finally {
      resizing = false;
    }
  }

  function applyHeight(iframe){
    var h = measure(iframe);
    if (h > 0){
      iframe.style.height = (h + BUFFER) + 'px';
    }
  }

  function debounce(fn, ms){
    var timer;
    return function(){
      clearTimeout(timer);
      timer = setTimeout(fn, ms);
    };
  }

  function setupResizeObserver(iframe){
    try {
      var doc = iframe.contentWindow.document;
      if (!doc || !doc.body) return;

      var debouncedApply = debounce(function(){ applyHeight(iframe); }, DEBOUNCE_MS);

      /* ResizeObserver: fires only on actual size changes, not DOM noise */
      if (typeof ResizeObserver !== 'undefined'){
        var ro = new ResizeObserver(debouncedApply);
        ro.observe(doc.body);
      }

      /* Fallback: also listen inside the iframe for orientation changes */
      iframe.contentWindow.addEventListener('resize', debouncedApply);
    } catch(e){
      /* cross-origin — skip */
    }
  }

  function initIframe(iframe){
    if (managed.has(iframe)) return;
    managed.add(iframe);

    iframe.style.overflow = 'hidden';
    iframe.setAttribute('scrolling', 'no');

    var onReady = function(){
      try {
        var doc = iframe.contentWindow.document;
        injectCSS(doc);
      } catch(e){ return; }

      /* Initial measure after CSS override takes effect */
      requestAnimationFrame(function(){
        applyHeight(iframe);
        setupResizeObserver(iframe);
        /* Delayed pass for SPAs that render async */
        setTimeout(function(){ applyHeight(iframe); }, 600);
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
    for (var i = 0; i < iframes.length; i++){
      initIframe(iframes[i]);
    }
  }

  /* Parent window resize (orientation change, browser resize) */
  window.addEventListener('resize', debounce(function(){
    var iframes = document.querySelectorAll('iframe[src*="/tools/"]');
    for (var i = 0; i < iframes.length; i++){
      applyHeight(iframes[i]);
    }
  }, DEBOUNCE_MS));

  /* Init on DOM ready */
  if (document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', initAll);
  } else {
    initAll();
  }
})();
