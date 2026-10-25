/* Parent side of the tool-iframe auto-resize protocol (sender:
   /js/embed-resize.js, loaded by every app in static/tools|games/).
   Only same-origin messages from one of this page's own iframes are
   honoured; the iframe is then sized to its content and its inner
   scrollbar disabled (no scroll-in-scroll on mobile).
   An app can finish loading before this script runs, so on start-up we
   also ask every frame to report its height again ('requestHeight').
   data-settle-ms="N" on a frame (front matter tool_settle_ms): for N ms after
   the first report the frame only grows, then takes the last reported
   height. For apps that render a short first frame and then fill in
   (GhostPrint's scan): shrinking and growing back would shift the page. */
(function () {
  'use strict';
  var MIN = 150, MAX = 20000;

  window.addEventListener('message', function (event) {
    if (event.origin !== window.location.origin) return;
    var data = event.data;
    if (!data || data.type !== 'setHeight') return;
    var height = parseInt(data.height, 10);
    if (!height || height < MIN) return;
    if (height > MAX) height = MAX;

    var frames = document.querySelectorAll('iframe');
    for (var i = 0; i < frames.length; i++) {
      if (frames[i].contentWindow === event.source) {
        var f = frames[i];
        // The app reports its content height; the frame's own border (and
        // padding) sit outside it. Without adding them, an app that fills
        // 100vh would report 2 px less on every round and shrink forever.
        var cs = getComputedStyle(f);
        var chrome = cs.boxSizing === 'border-box'
          ? parseFloat(cs.borderTopWidth) + parseFloat(cs.borderBottomWidth) + parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom)
          : 0;
        f._lastHeight = height + chrome;
        f.setAttribute('scrolling', 'no');
        f.style.overflow = 'hidden';
        var settle = parseInt(f.getAttribute('data-settle-ms'), 10);
        if (settle) {
          if (!f._settleUntil) {
            f._settleUntil = Date.now() + settle;
            setTimeout(function (fr) { fr.style.height = fr._lastHeight + 'px'; }, settle, f);
          }
          if (Date.now() < f._settleUntil && f._lastHeight < f.getBoundingClientRect().height) break;
        }
        f.style.height = f._lastHeight + 'px';
        break;
      }
    }
  });

  var frames = document.querySelectorAll('iframe');
  for (var i = 0; i < frames.length; i++) {
    try { frames[i].contentWindow.postMessage({ type: 'requestHeight' }, window.location.origin); } catch (e) {}
  }
})();
