(() => {
  const buyBtn = document.getElementById("buyBtn");
  const hint = document.getElementById("buyHint");
  const priceValue = document.getElementById("priceValue");

  // Keep same clientId across pages (rate limits / payment metadata)
  const CLIENT_ID_KEY = "clientId";
  const USER_EMAIL_KEY = "userEmail";

  function makeId() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    return "cid_" + Math.random().toString(16).slice(2) + Date.now().toString(16);
  }

  let clientId = localStorage.getItem(CLIENT_ID_KEY);
  if (!clientId) {
    clientId = makeId();
    localStorage.setItem(CLIENT_ID_KEY, clientId);
  }

  async function getJson(path) {
    const r = await fetch(path, {
      method: "GET",
      headers: { "X-Client-ID": clientId },
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.detail || `HTTP ${r.status}`);
    return j;
  }

  async function postJson(path, body) {
    const r = await fetch(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Client-ID": clientId,
      },
      body: JSON.stringify(body || {}),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.detail || `HTTP ${r.status}`);
    return j;
  }

  function setComingSoon(message) {
    if (buyBtn) {
      buyBtn.disabled = true;
      buyBtn.textContent = "Yakında";
      buyBtn.title = "Ödemeler yakında aktif olacak.";
    }
    if (hint) hint.textContent = message || "Ödemeler yakında aktif olacak.";
  }

  function setPaymentsReady() {
    if (buyBtn) {
      buyBtn.disabled = false;
      buyBtn.textContent = "Pro’ya Geç";
      buyBtn.title = "";
    }
    if (hint) hint.textContent = "";
  }

  async function initBillingUI() {
    if (!buyBtn) return;

    // Safe default: coming soon until we confirm it's configured.
    setComingSoon("Ödemeler yakında aktif olacak.");

    try {
      const cfg = await getJson("/api/public_config");

      // Price display (TRY)
      if (priceValue && cfg && typeof cfg.pro_price_try === "number" && cfg.pro_price_try > 0) {
        priceValue.textContent = `${cfg.pro_price_try} ₺`;
      }

      const provider = (cfg && cfg.payment_provider) || "none";
      const ready = provider !== "none" && !!(cfg && (cfg.iyzico_configured || cfg.stripe_configured));

      if (ready) {
        setPaymentsReady();
      } else {
        // Keep the button disabled, but give a more explicit hint.
        setComingSoon("Ödemeler yakında aktif olacak. Şimdilik ücretsiz deneyebilirsin.");
      }
    } catch (e) {
      // Public config fetch failed; keep the button disabled instead of exposing a broken checkout.
      setComingSoon("Ödemeler yakında aktif olacak.");
    }
  }

  async function tryCheckout() {
    if (!buyBtn || buyBtn.disabled) return;

    if (hint) hint.textContent = "Hazırlanıyor…";
    buyBtn.disabled = true;

    try {
      const email = (localStorage.getItem(USER_EMAIL_KEY) || "").trim();
      const j = await postJson("/api/billing/create_checkout", { email });
      if (j && j.url) {
        window.location.href = j.url;
        return;
      }
      throw new Error("Checkout URL alınamadı.");
    } catch (e) {
      if (hint) hint.textContent = "Ödeme başlatılamadı: " + (e.message || e);
      // If something went wrong, fall back to "coming soon" so users don't get stuck in a loop.
      setComingSoon("Ödemeler yakında aktif olacak.");
      return;
    } finally {
      // Only re-enable if payments are actually ready (otherwise keep it disabled)
      await initBillingUI();
    }
  }

  initBillingUI();
  buyBtn.addEventListener("click", tryCheckout);
})();
