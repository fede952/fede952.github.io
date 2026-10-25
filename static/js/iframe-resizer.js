/* Parent side of the tool-iframe auto-resize protocol (sender:
   /js/embed-resize.js, loaded by every app in static/tools|games/).
   Only same-origin messages from one of this page's own iframes are
   honoured; the iframe is then sized to its content and its inner
   scrollbar disabled (no scroll-in-scroll on mobile).
   An app can finish loading before this script runs, so on start-up we
   also ask every frame to report its height again ('requestHeight'). */
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
        // The app reports its content height; the frame's own border (and
        // padding) sit outside it. Without adding them, an app that fills
        // 100vh would report 2 px less on every round and shrink forever.
        var cs = getComputedStyle(frames[i]);
        var chrome = cs.boxSizing === 'border-box'
          ? parseFloat(cs.borderTopWidth) + parseFloat(cs.borderBottomWidth) + parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom)
          : 0;
        frames[i].style.height = (height + chrome) + 'px';
        frames[i].setAttribute('scrolling', 'no');
        frames[i].style.overflow = 'hidden';
        break;
      }
    }
  });

  var frames = document.querySelectorAll('iframe');
  for (var i = 0; i < frames.length; i++) {
    try { frames[i].contentWindow.postMessage({ type: 'requestHeight' }, window.location.origin); } catch (e) {}
  }
})();
