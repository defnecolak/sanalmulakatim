(() => {
  // NOTE:
  // Bazı sayfalarda "window.__loadPublicConfig()" bekleniyor.
  // Bu dosya hem otomatik DOM güncellemesi yapar, hem de geriye dönük
  // uyumluluk için __loadPublicConfig fonksiyonunu sağlar.

  let _cfgPromise = null;

  function _applyCfg(j) {
    const supportEmail = (j.support_email || "semi.ozgen@sanalmulakatim.com").trim();
    const appName = (j.app_name || "Sanal Mülakatım").trim();
    const baseUrl = (j.public_base_url || "").trim();

    document.querySelectorAll("[data-support-email]").forEach((el) => {
      if (!supportEmail) return;
      if (el.tagName === "A") {
        el.href = "mailto:" + supportEmail;
        if (!el.textContent || el.textContent.includes("@") === false) el.textContent = supportEmail;
      } else {
        el.textContent = supportEmail;
      }
    });

    document.querySelectorAll("[data-app-name]").forEach((el) => {
      el.textContent = appName;
    });

    document.querySelectorAll("[data-base-url]").forEach((el) => {
      el.textContent = baseUrl;
    });
  }

  async function _fetchCfg() {
    const r = await fetch("/api/public_config");
    const j = await r.json();
    window.PUBLIC_CONFIG = j;
    _applyCfg(j);
    return j;
  }

  // Geriye dönük uyumluluk
  window.__loadPublicConfig = async function __loadPublicConfig() {
    if (window.PUBLIC_CONFIG) return window.PUBLIC_CONFIG;
    if (_cfgPromise) return _cfgPromise;
    _cfgPromise = (async () => {
      try {
        return await _fetchCfg();
      } finally {
        // hata olursa bir sonraki denemede tekrar fetch edebilelim
        _cfgPromise = null;
      }
    })();
    return _cfgPromise;
  };

  // Sayfa yüklenince otomatik uygula
  window.__loadPublicConfig().catch(() => {});
})();
