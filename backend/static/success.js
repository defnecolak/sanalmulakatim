(() => {
  const tokenBox = document.getElementById("tokenBox");
  const copyBtn = document.getElementById("copyBtn");
  const retryBtn = document.getElementById("retryBtn");
  const alertBox = document.getElementById("globalAlert");

  // More visible success banner
  const okBanner = document.getElementById("okBanner");
  const bannerTitle = document.getElementById("bannerTitle");
  const bannerBody = document.getElementById("bannerBody");

  const redeemLoading = document.getElementById("redeemLoading");
  const redeemTitle = document.getElementById("redeemTitle");
  const redeemHint = document.getElementById("redeemHint");

  // Post-payment modal (ask for email + show key AFTER payment)
  const openPostPayBtn = document.getElementById("openPostPayBtn");
  const postPayOverlay = document.getElementById("postPayOverlay");
  const ppEmail = document.getElementById("ppEmail");
  const ppToken = document.getElementById("ppToken");
  const ppSend = document.getElementById("ppSend");
  const ppCopy = document.getElementById("ppCopy");
  const ppSkip = document.getElementById("ppSkip");
  const ppClose = document.getElementById("ppClose");
  const ppStatus = document.getElementById("ppStatus");

  // Mini checklist (persisted)
  const chkCopied = document.getElementById("chkCopied");
  const chkEmailed = document.getElementById("chkEmailed");

  // Client identity (rate limit)
  const CLIENT_ID_KEY = "clientId";
  const USER_EMAIL_KEY = "userEmail";

  const CHECK_COPIED_KEY = "success_chk_copied";
  const CHECK_EMAILED_KEY = "success_chk_emailed";

  // Polling settings (token sometimes arrives a few seconds after payment)
  const MAX_WAIT_MS = 15000;
  const INITIAL_DELAY_MS = 800;
  const MAX_DELAY_MS = 3200;

  function makeId() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    return "cid_" + Math.random().toString(16).slice(2) + Date.now().toString(16);
  }

  let clientId = localStorage.getItem(CLIENT_ID_KEY);
  if (!clientId) {
    clientId = makeId();
    localStorage.setItem(CLIENT_ID_KEY, clientId);
  }

  function setLoading(on, title, hint) {
    if (!redeemLoading) return;
    if (on) {
      redeemLoading.classList.remove("hidden");
      if (redeemTitle) redeemTitle.textContent = title || "Anahtar hazırlanıyor…";
      if (redeemHint) redeemHint.textContent = hint || "Bu işlem bazen 5–15 saniye sürebilir.";
    } else {
      redeemLoading.classList.add("hidden");
    }
  }

  function showBanner(title, body) {
    if (!okBanner) return;
    okBanner.classList.remove("hidden");
    if (bannerTitle) bannerTitle.textContent = title || "Pro anahtarın hazır";
    if (bannerBody) bannerBody.textContent = body || "";
  }

  function hideBanner() {
    okBanner?.classList.add("hidden");
  }

  function showAlert(msg, kind) {
    // We show errors in the alert box, success in the green banner.
    if (kind === "ok") {
      if (msg) showBanner("E-postana gönderildi ✅", msg);
      if (alertBox) alertBox.classList.add("hidden");
      return;
    }

    hideBanner();
    if (!alertBox) return;
    alertBox.textContent = msg || "";
    alertBox.classList.remove("hidden", "alert-ok", "alert-error");
    if (kind === "error") alertBox.classList.add("alert-error");
    if (!msg) alertBox.classList.add("hidden");
  }

  function setPPStatus(msg) {
    if (!ppStatus) return;
    ppStatus.textContent = msg || "";
  }

  function getQuery(name) {
    const url = new URL(window.location.href);
    return url.searchParams.get(name);
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function setToken(token) {
    const t = (token || "").trim();
    if (!t) return;
    tokenBox.value = t;
    localStorage.setItem("proToken", t);
    copyBtn && (copyBtn.disabled = false);
    if (ppToken) ppToken.value = t;
  }

  function setChecklistFromStorage() {
    if (chkCopied) chkCopied.checked = localStorage.getItem(CHECK_COPIED_KEY) === "1";
    if (chkEmailed) chkEmailed.checked = localStorage.getItem(CHECK_EMAILED_KEY) === "1";
  }

  function markCopied(done) {
    if (!chkCopied) return;
    chkCopied.checked = !!done;
    localStorage.setItem(CHECK_COPIED_KEY, chkCopied.checked ? "1" : "0");
  }

  function markEmailed(done) {
    if (!chkEmailed) return;
    chkEmailed.checked = !!done;
    localStorage.setItem(CHECK_EMAILED_KEY, chkEmailed.checked ? "1" : "0");
  }

  function openPostPayModal({ force } = { force: false }) {
    if (!postPayOverlay) return;
    const token = (tokenBox?.value || "").trim();
    if (!token) return;

    // Prefill email from storage
    const saved = (localStorage.getItem(USER_EMAIL_KEY) || "").trim();
    if (ppEmail && saved && !ppEmail.value) ppEmail.value = saved;

    // Don't nag if the user already handled both
    const alreadyCopied = localStorage.getItem(CHECK_COPIED_KEY) === "1";
    const alreadyEmailed = localStorage.getItem(CHECK_EMAILED_KEY) === "1";
    if (!force && alreadyCopied && alreadyEmailed) return;

    if (ppToken) ppToken.value = token;
    setPPStatus("");

    postPayOverlay.classList.remove("hidden");
    setTimeout(() => ppEmail?.focus(), 0);
  }

  function closePostPayModal() {
    postPayOverlay?.classList.add("hidden");
  }

  function getRedeemParams() {
    const provider = (getQuery("provider") || "").trim().toLowerCase();
    if (provider) {
      const ref = (getQuery("ref") || getQuery("order_id") || "").trim();
      return { provider, ref };
    }
    const session_id = (getQuery("session_id") || "").trim();
    return { session_id };
  }

  async function redeemOnce(params) {
    let url = "";
    if (params.provider) {
      if (!params.ref) {
        return { ok: false, status: 400, detail: "ref bulunamadı. Ödeme dönüş URL'ini kontrol et." };
      }
      url = `/api/billing/redeem?provider=${encodeURIComponent(params.provider)}&ref=${encodeURIComponent(params.ref)}`;
    } else {
      if (!params.session_id) {
        return { ok: false, status: 400, detail: "session_id bulunamadı. Ödeme dönüş URL'ini kontrol et." };
      }
      url = `/api/billing/redeem?session_id=${encodeURIComponent(params.session_id)}`;
    }

    const r = await fetch(url, { headers: { "X-Client-ID": clientId } });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      return { ok: false, status: r.status, detail: j.detail || `HTTP ${r.status}` };
    }
    const token = (j.token || "").trim();
    if (!token) return { ok: false, status: 502, detail: "Token boş döndü." };
    return { ok: true, status: 200, token };
  }

  async function redeemWithPolling(params) {
    let attempt = 0;
    let delay = INITIAL_DELAY_MS;
    const started = Date.now();

    while (Date.now() - started < MAX_WAIT_MS) {
      attempt += 1;
      setLoading(true, attempt === 1 ? "Ödeme doğrulanıyor…" : `Ödeme doğrulanıyor… (deneme ${attempt})`, "Anahtar hazırlanıyor. Bu işlem bazen 5–15 saniye sürebilir.");

      let res;
      try {
        res = await redeemOnce(params);
      } catch (e) {
        res = { ok: false, status: 0, detail: e?.message || String(e) };
      }

      if (res.ok) return res.token;

      // Not ready yet → keep trying
      if (res.status === 404) {
        await sleep(delay);
        delay = Math.min(Math.round(delay * 1.6), MAX_DELAY_MS);
        continue;
      }

      // Rate limit → wait a bit longer
      if (res.status === 429) {
        setLoading(true, "Yoğunluk var…", "Biraz bekleyip tekrar deniyoruz.");
        await sleep(Math.max(delay, 2200));
        delay = Math.min(Math.round(delay * 1.6), MAX_DELAY_MS);
        continue;
      }

      // Hard error
      throw new Error(res.detail || "Token alınamadı.");
    }

    throw new Error("Token henüz hazır değil. Birkaç saniye sonra tekrar dene.");
  }

  let busy = false;
  async function loadToken({ manual } = { manual: false }) {
    if (busy) return;
    busy = true;
    retryBtn?.classList.add("hidden");
    showAlert("", "");

    const params = getRedeemParams();

    try {
      const token = manual ? (await redeemOnce(params)).token : await redeemWithPolling(params);
      if (!token) throw new Error("Token boş döndü.");
      setToken(token);
      setLoading(false);

      // Generic success banner (less noisy than the old alert)
      showBanner("Pro anahtarın hazır", "Anahtarını kopyalayabilir veya e-postana gönderebilirsin.");

      // Ask for email + key after payment
      openPostPayModal({ force: false });

      // If server already emailed the token, show a friendly note
      if ((getQuery("emailed") || "").trim() === "1") {
        showBanner("E-postana gönderildi ✅", "Pro anahtarı e-postana gönderildi. Spam/Junk klasörüne de bak.");
        markEmailed(true);
        setPPStatus("E-postana gönderildi ✅  (Spam/Junk klasörünü de kontrol et.)");
      }
    } catch (e) {
      setLoading(false);
      retryBtn?.classList.remove("hidden");
      showAlert("Pro anahtarı alınamadı: " + (e?.message || e), "error");
    } finally {
      busy = false;
    }
  }

  copyBtn?.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(tokenBox.value || "");
      copyBtn.textContent = "Kopyalandı";
      setTimeout(() => (copyBtn.textContent = "Kopyala"), 900);
      markCopied(true);
    } catch {}
  });

  retryBtn?.addEventListener("click", () => loadToken({ manual: true }));

  async function sendTokenEmail(email, token) {
    const e = (email || "").trim();
    const t = (token || "").trim();
    if (!e) throw new Error("E-posta girmen gerekiyor.");
    if (!t) throw new Error("Token boş. Önce token yüklenmeli.");

    localStorage.setItem(USER_EMAIL_KEY, e);
    const r = await fetch("/api/billing/email_token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Client-ID": clientId,
      },
      body: JSON.stringify({ email: e, token: t }),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.detail || `HTTP ${r.status}`);
    return true;
  }

  async function handleSendFromModal() {
    const email = (ppEmail?.value || "").trim();
    const token = (tokenBox?.value || "").trim();
    setPPStatus("");
    if (ppSend) ppSend.disabled = true;
    try {
      setPPStatus("Gönderiliyor…");
      await sendTokenEmail(email, token);
      setPPStatus("Gönderildi ✅");
      showBanner("E-postana gönderildi ✅", "Pro anahtarını e-postana gönderdik. Spam/Junk klasörüne de bak.");
      markEmailed(true);
    } catch (e) {
      setPPStatus("Gönderilemedi: " + (e?.message || e));
    } finally {
      if (ppSend) ppSend.disabled = false;
    }
  }

  ppSend?.addEventListener("click", handleSendFromModal);
  ppEmail?.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      handleSendFromModal();
    }
  });

  ppCopy?.addEventListener("click", async () => {
    const token = (tokenBox?.value || "").trim();
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token);
      ppCopy.textContent = "Kopyalandı";
      setTimeout(() => (ppCopy.textContent = "Anahtarı Kopyala"), 900);
      markCopied(true);
    } catch {}
  });

  openPostPayBtn?.addEventListener("click", () => openPostPayModal({ force: true }));
  ppSkip?.addEventListener("click", closePostPayModal);
  ppClose?.addEventListener("click", closePostPayModal);

  // Click outside modal closes it
  postPayOverlay?.addEventListener("click", (ev) => {
    if (ev.target === postPayOverlay) closePostPayModal();
  });

  // Checklist persistence
  setChecklistFromStorage();
  chkCopied?.addEventListener("change", () => markCopied(chkCopied.checked));
  chkEmailed?.addEventListener("change", () => markEmailed(chkEmailed.checked));

  // Initial load
  copyBtn && (copyBtn.disabled = true);
  setLoading(true, "Ödeme doğrulanıyor…", "Anahtar hazırlanıyor. Bu işlem bazen 5–15 saniye sürebilir.");
  loadToken({ manual: false });
})();
