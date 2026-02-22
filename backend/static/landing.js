(() => {
  const buyBtn = document.getElementById("buyBtn");
  const hint = document.getElementById("buyHint");

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

  async function tryCheckout() {
    hint.textContent = "Hazırlanıyor…";
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
      hint.textContent = "Ödeme başlatılamadı: " + (e.message || e);
    } finally {
      buyBtn.disabled = false;
    }
  }

  if (buyBtn) buyBtn.addEventListener("click", tryCheckout);
})();
