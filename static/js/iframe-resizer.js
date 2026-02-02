(function(){
  'use strict';

  var BUFFER = 50;
  var DEBOUNCE_MS = 150;
  var observers = new WeakMap();

  function getContentHeight(iframe){
    try {
      var doc = iframe.contentWindow.document;
      var body = doc.body;
      var html = doc.documentElement;
      if (!body) return 0;
      return Math.max(
        body.scrollHeight, body.offsetHeight,
        html.scrollHeight, html.offsetHeight
      );
    } catch(e){
      /* cross-origin — cannot measure */
      return 0;
    }
  }

  function resize(iframe){
    var h = getContentHeight(iframe);
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

  function setupObserver(iframe){
    if (observers.has(iframe)) return;
    try {
      var doc = iframe.contentWindow.document;
      if (!doc || !doc.body) return;

      var debouncedResize = debounce(function(){ resize(iframe); }, DEBOUNCE_MS);

      var mo = new MutationObserver(debouncedResize);
      mo.observe(doc.body, {
        childList: true,
        subtree: true,
        attributes: true,
        characterData: true
      });
      observers.set(iframe, mo);

      /* Also watch for images/fonts loading inside iframe */
      iframe.contentWindow.addEventListener('load', function(){ resize(iframe); });
      iframe.contentWindow.addEventListener('resize', function(){ resize(iframe); });
    } catch(e){
      /* cross-origin — skip observer */
    }
  }

  function initIframe(iframe){
    /* Remove any hardcoded height from markdown iframes */
    iframe.style.overflow = 'hidden';

    var onReady = function(){
      resize(iframe);
      setupObserver(iframe);
      /* Second pass after short delay for late-rendering SPAs */
      setTimeout(function(){ resize(iframe); }, 500);
      setTimeout(function(){ resize(iframe); }, 2000);
    };

    if (iframe.contentWindow && iframe.contentWindow.document.readyState === 'complete'){
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

  /* Handle window resize / orientation change */
  var globalDebounce = debounce(function(){
    var iframes = document.querySelectorAll('iframe[src*="/tools/"]');
    for (var i = 0; i < iframes.length; i++){
      resize(iframes[i]);
    }
  }, DEBOUNCE_MS);

  window.addEventListener('resize', globalDebounce);

  /* Init on DOM ready */
  if (document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', initAll);
  } else {
    initAll();
  }
})();
