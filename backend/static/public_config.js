(() => {
  let _cfgPromise = null;

  function _company(j) {
    return (j && typeof j.company === "object" && j.company) || {};
  }

  function _formatPrice(v) {
    if (typeof v !== "number" || !Number.isFinite(v)) return "";
    return `${v.toLocaleString("tr-TR", { maximumFractionDigits: 2 })} ₺`;
  }

  function _setTextAttr(attr, value, fallback = "—") {
    document.querySelectorAll(`[${attr}]`).forEach((el) => {
      el.textContent = (value || fallback || "—").toString();
    });
  }

  function _setEmailAttr(value) {
    const email = (value || "").trim();
    document.querySelectorAll("[data-support-email]").forEach((el) => {
      if (!email) {
        el.textContent = "Belirtilecek";
        return;
      }
      if (el.tagName === "A") {
        el.href = "mailto:" + email;
        el.textContent = email;
      } else {
        el.textContent = email;
      }
    });
  }

  function _setPhoneAttr(value) {
    const phone = (value || "").trim();
    const telValue = phone.replace(/[^\d+]/g, "") || "+90";
    document.querySelectorAll("[data-company-phone]").forEach((el) => {
      if (el.tagName === "A") {
        el.href = `tel:${telValue}`;
        el.textContent = phone || "Belirtilecek";
      } else {
        el.textContent = phone || "Belirtilecek";
      }
    });
  }

  function _setUrlAttr(attr, value, fallback = "Belirtilecek") {
    const url = (value || "").trim();
    document.querySelectorAll(`[${attr}]`).forEach((el) => {
      if (el.tagName === "A") {
        el.href = url || "#";
        el.textContent = url || fallback;
      } else {
        el.textContent = url || fallback;
      }
    });
  }

  function _applyCfg(j) {
    const company = _company(j);
    const supportEmail = (j.support_email || "semi.ozgen@sanalmulakatim.com").trim();
    const appName = (j.app_name || "Sanal Mülakatım").trim();
    const baseUrl = (j.public_base_url || "").trim();

    _setEmailAttr(supportEmail);
    _setTextAttr("data-app-name", appName, "Sanal Mülakatım");
    _setTextAttr("data-base-url", baseUrl, "—");
    _setTextAttr("data-company-legal-name", company.legal_name, "Belirtilecek");
    _setTextAttr("data-company-trade-name", company.trade_name, "Belirtilecek");
    _setTextAttr("data-company-mersis-number", company.mersis_number, "Belirtilecek");
    _setTextAttr("data-company-tax-number", company.tax_number, "Belirtilecek");
    _setTextAttr("data-company-address", company.address, "Belirtilecek");
    _setTextAttr("data-company-kep-address", company.kep_address, "Belirtilecek");
    _setTextAttr("data-company-chamber", company.chamber, "Belirtilecek");
    _setTextAttr("data-about-short", company.about_short, "Sanal Mülakatım, adayların iş görüşmelerine yapılandırılmış pratik yaparak hazırlanmasına yardımcı olan dijital bir eğitim aracıdır.");
    _setTextAttr("data-about-long", company.about_long || company.about_short, "Sanal Mülakatım, adayların iş görüşmelerine yapılandırılmış pratik yaparak hazırlanmasına yardımcı olan dijital bir eğitim aracıdır.");
    _setTextAttr("data-pro-title", j.pro_title || "Pro", "Pro");

    const priceText = _formatPrice(j.pro_price_try);
    document.querySelectorAll("[data-pro-price]").forEach((el) => {
      el.textContent = priceText || "Belirtilecek";
    });

    _setPhoneAttr(company.phone);
    _setUrlAttr("data-company-rules-url", company.profession_rules_url, "Belirtilecek");
  }

  async function _fetchCfg() {
    const r = await fetch("/api/public_config");
    const j = await r.json();
    window.PUBLIC_CONFIG = j;
    _applyCfg(j);
    return j;
  }

  window.__loadPublicConfig = async function __loadPublicConfig() {
    if (window.PUBLIC_CONFIG) return window.PUBLIC_CONFIG;
    if (_cfgPromise) return _cfgPromise;
    _cfgPromise = (async () => {
      try {
        return await _fetchCfg();
      } finally {
        _cfgPromise = null;
      }
    })();
    return _cfgPromise;
  };

  window.__loadPublicConfig().catch(() => {});
})();
