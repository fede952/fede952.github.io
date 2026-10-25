/* Child side of the tool-iframe auto-resize protocol.
   Every self-contained app in static/tools/ and static/games/ loads this.
   It reports the content height to the parent page, which resizes the
   iframe to fit (receiver: /js/iframe-resizer.js) — so the tool never
   shows a scrollbar inside the page's scrollbar on mobile.
   Same-origin only: the message is addressed to location.origin. */
(function () {
  'use strict';
  if (window.parent === window) return; // opened directly, not embedded

  var root = document.documentElement, body = document.body, last = 0, queued = false;
  // Let the document size to its content instead of the iframe viewport.
  root.style.height = 'auto';
  body.style.height = 'auto';
  body.style.minHeight = '0';
  // Wrappers styled min-height:100vh/100% would resolve to the iframe's own
  // height and pin it (the content could grow the frame but never shrink
  // it). Unpin them; fixed `height` (game canvases) is left alone.
  var vh = window.innerHeight;
  Array.prototype.forEach.call(body.querySelectorAll('body > *, body > * > *'), function (el) {
    var mh = parseFloat(getComputedStyle(el).minHeight);
    if (mh && mh >= vh - 1) el.style.minHeight = '0';
  });

  function measure() {
    var cs = getComputedStyle(body);
    return Math.ceil(body.getBoundingClientRect().height +
      parseFloat(cs.marginTop) + parseFloat(cs.marginBottom));
  }
  function send() {
    queued = false;
    var h = measure();
    if (Math.abs(h - last) < 2) return;
    last = h;
    window.parent.postMessage({ type: 'setHeight', height: h }, location.origin);
  }
  function schedule() {
    if (queued) return;
    queued = true;
    requestAnimationFrame(send);
  }

  if ('ResizeObserver' in window) new ResizeObserver(schedule).observe(body);
  else new MutationObserver(schedule).observe(body, { subtree: true, childList: true, attributes: true });
  window.addEventListener('message', function (e) {
    // Parent listener attached after our first report: send it again.
    if (e.source === window.parent && e.origin === location.origin &&
        e.data && e.data.type === 'requestHeight') { last = 0; schedule(); }
  });
  window.addEventListener('load', schedule);
  window.addEventListener('resize', schedule);
  schedule();
})();
