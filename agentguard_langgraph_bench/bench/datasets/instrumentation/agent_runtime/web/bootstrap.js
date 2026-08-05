(function () {
  if (window.__AGENTGUARD_LOCAL_CLICK_BOOTSTRAPPED__) {
    return;
  }
  window.__AGENTGUARD_LOCAL_CLICK_BOOTSTRAPPED__ = true;

  function runtimeBase() {
    var current = document.currentScript && document.currentScript.src;
    if (current) {
      return current.replace(/\/bootstrap\.js(?:\?.*)?$/, "");
    }
    return window.location.origin + "/agent_runtime/web";
  }

  function ensureStylesheet(href) {
    if (document.querySelector('link[href="' + href + '"]')) {
      return;
    }
    var link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = href;
    document.head.appendChild(link);
  }

  function ensureScript(src) {
    if (document.querySelector('script[src="' + src + '"]')) {
      return;
    }
    var script = document.createElement("script");
    script.src = src;
    script.defer = true;
    document.head.appendChild(script);
  }

  var base = runtimeBase();
  ensureStylesheet(base + "/local_click_responses.css");
  ensureScript(base + "/local_click_responses.js");
})();
