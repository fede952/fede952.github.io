(function(){
  'use strict';

  window.addEventListener('message', function(event){
    if (!event.data || event.data.type !== 'setHeight') return;
    var height = parseInt(event.data.height, 10);
    if (!height || height < 50) return;

    /* Find the iframe that sent this message */
    var iframes = document.querySelectorAll('iframe[src*="/tools/"]');
    for (var i = 0; i < iframes.length; i++){
      if (iframes[i].contentWindow === event.source){
        iframes[i].style.height = height + 'px';
        iframes[i].style.overflow = 'hidden';
        break;
      }
    }
  });
})();
