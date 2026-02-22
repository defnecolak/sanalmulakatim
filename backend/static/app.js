(() => {
  const $ = (id) => document.getElementById(id);


  // Client identity (for rate limits / daily limits)
  const CLIENT_ID_KEY = "clientId";
  const PRO_TOKEN_KEY = "proToken";

  function makeId() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    return "cid_" + Math.random().toString(16).slice(2) + Date.now().toString(16);
  }

  let clientId = localStorage.getItem(CLIENT_ID_KEY);
  if (!clientId) {
    clientId = makeId();
    localStorage.setItem(CLIENT_ID_KEY, clientId);
  }

  function getProToken() {
    const t = (proTokenEl?.value || localStorage.getItem(PRO_TOKEN_KEY) || "").trim();
    return t;
  }

  function getHeaders(extra) {
    const h = Object.assign({}, extra || {});
    h["X-Client-ID"] = clientId;
    const pt = getProToken();
    if (pt) h["X-Pro-Token"] = pt;
    return h;
  }
  // Elements
  const apiBadge = $("apiBadge");
  const usageBadge = $("usageBadge");
  const globalAlert = $("globalAlert");
  const keyBadge = $("keyBadge");
  const upgradeBtn = $("upgradeBtn");


  const roleEl = $("role");
  const seniorityEl = $("seniority");
  const languageEl = $("language");
  const nQuestionsEl = $("nQuestions");
  const proTokenEl = $("proToken");

  const pdfFileEl = $("pdfFile");
  const pdfStatus = $("pdfStatus");
  const cvTextEl = $("cvText");

  const startBtn = $("startBtn");
  const startStatus = $("startStatus");

  const interviewCard = $("interviewCard");
  const progressText = $("progressText");
  const progressPct = $("progressPct");
  const progressFill = $("progressFill");

  const chipIndex = $("chipIndex");
  const chipType = $("chipType");
  const chipStatus = $("chipStatus");

  const questionText = $("questionText");
  const followupsBox = $("followupsBox");
  const followupsList = $("followupsList");

  const answerEl = $("answer");
  const btnStar = $("btnStar");
  const btnClear = $("btnClear");
  const btnMetric = $("btnMetric");

  const micSelect = $("micSelect");
  const micRefresh = $("micRefresh");
  const meterFill = $("meterFill");
  const meterPct = $("meterPct");

  const recStart = $("recStart");
  const recStop = $("recStop");
  const transcribeStatus = $("transcribeStatus");
  const audioPlayback = $("audioPlayback");

  const evalBtn = $("evalBtn");
  const okNextBtn = $("okNextBtn");

  const feedbackBox = $("feedbackBox");
  const feedbackLoading = $("feedbackLoading");
  const feedbackContent = $("feedbackContent");

  // State
  let sessionId = null;
  let currentIndex = 0;
  let totalQuestions = 0;
  let currentQuestion = null;
  let isEvaluating = false;

  // Audio state
  let mediaRecorder = null;
  let chunks = [];
  let stream = null;
  let audioCtx = null;
  let analyser = null;
  let meterRaf = null;

  // Utils
  function showAlert(msg, kind = "error") {
    globalAlert.classList.remove("hidden");
    globalAlert.classList.toggle("alert-ok", kind === "ok");
    globalAlert.classList.toggle("alert-error", kind !== "ok");
    globalAlert.textContent = msg;
  }
  function clearAlert() {
    globalAlert.classList.add("hidden");
    globalAlert.textContent = "";
  }
  function showMini(el, msg, kind = "muted") {
    el.classList.remove("hidden");
    el.classList.toggle("mini-ok", kind === "ok");
    el.classList.toggle("mini-error", kind === "error");
    el.textContent = msg;
  }
  function hideMini(el) {
    el.classList.add("hidden");
    el.textContent = "";
    el.classList.remove("mini-ok", "mini-error");
  }
  function clampInt(v, min, max, fallback) {
    const n = parseInt(v, 10);
    if (Number.isNaN(n)) return fallback;
    return Math.max(min, Math.min(max, n));
  }
  function pct(done, total) {
    if (!total) return 0;
    return Math.round((done / total) * 100);
  }

  function maskToken(t) {
    const s = String(t || "").trim();
    if (!s) return "—";
    if (s.length <= 8) return "••••";
    return s.slice(0, 4) + "…" + s.slice(-4);
  }

  function renderKeyBadge() {
    if (!keyBadge) return;
    const t = getProToken();
    if (t) {
      keyBadge.textContent = `Anahtar: ${maskToken(t)}`;
      keyBadge.classList.add("badge-ok");
    } else {
      keyBadge.textContent = "Anahtar: —";
      keyBadge.classList.remove("badge-ok");
    }
  }

  function flashKeyBadge(msg, ms = 1200) {
    if (!keyBadge) return;
    const prev = keyBadge.textContent;
    keyBadge.textContent = msg;
    setTimeout(() => {
      keyBadge.textContent = prev;
    }, ms);
  }

  function trTypeLabel(t) {
    const x = (t || "").toLowerCase();
    if (x.includes("tekn")) return "Teknik";
    if (x.includes("davran")) return "Davranışsal";
    if (x.includes("vaka") || x.includes("case")) return "Vaka";
    return t || "—";
  }

  function renderQuestion(q, idx1, total) {
    currentQuestion = q;
    currentIndex = idx1 - 1;
    totalQuestions = total;

    interviewCard.classList.remove("hidden");

    progressText.textContent = `İlerleme: ${currentIndex}/${totalQuestions} tamamlandı`;
    progressPct.textContent = `${pct(currentIndex, totalQuestions)}%`;
    progressFill.style.width = `${pct(currentIndex, totalQuestions)}%`;

    chipIndex.textContent = `Soru ${idx1}/${total}`;
    chipType.textContent = trTypeLabel(q.type);
    chipStatus.textContent = "bekliyor";
    chipStatus.classList.remove("chip-ok");
    chipStatus.classList.add("chip-warn");

    questionText.textContent = q.question || "—";

    // followups
    const fups = Array.isArray(q.followups) ? q.followups.filter(Boolean) : [];
    followupsList.innerHTML = "";
    if (fups.length) {
      followupsBox.classList.remove("hidden");
      fups.forEach((x) => {
        const li = document.createElement("li");
        li.textContent = x;
        followupsList.appendChild(li);
      });
    } else {
      followupsBox.classList.add("hidden");
    }

    // reset answer + feedback
    answerEl.value = "";
    feedbackContent.innerHTML = "";
    feedbackBox.classList.add("hidden");
    okNextBtn.disabled = true;

    updateEvalBtn();
    window.scrollTo({ top: interviewCard.offsetTop - 10, behavior: "smooth" });
  }

  function setLoadingFeedback(on) {
    feedbackBox.classList.remove("hidden");
    feedbackLoading.classList.toggle("hidden", !on);
  }

  function updateEvalBtn() {
    const hasAnswer = (answerEl.value || "").trim().length > 0;
    evalBtn.disabled = isEvaluating || !sessionId || !currentQuestion || !hasAnswer;
  }

  // API
  async function apiGet(path) {
    const r = await fetch(path, { headers: getHeaders() });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      let msg = j.detail || `HTTP ${r.status}`;
      if (j.request_id) msg += ` (rid: ${j.request_id})`;
      throw new Error(msg);
    }
    return j;
  }
  async function apiPost(path, body) {
    const r = await fetch(path, {
      method: "POST",
      headers: getHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(body),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      let msg = j.detail || `HTTP ${r.status}`;
      if (j.request_id) msg += ` (rid: ${j.request_id})`;
      throw new Error(msg);
    }
    return j;
  }

  // Health badge
  async function refreshHealth() {
    if (!apiBadge) return;
    try {
      const h = await apiGet("/api/health");
      apiBadge.textContent = `API: ${h.openai_key ? "Key var" : "Key yok"} • Model: ${h.model || "-"}`;
      apiBadge.classList.toggle("badge-warn", !h.openai_key);
    } catch (e) {
      apiBadge.textContent = "API: erişilemiyor";
      apiBadge.classList.add("badge-warn");
    }
  }

  
  // Usage badge (Free/Pro + remaining)
  function fmtRemaining(v) {
    if (v === null || v === undefined) return "∞";
    return String(v);
  }

  function renderUsage(u) {
    if (!usageBadge) return;
    const plan = (u.plan || "").toUpperCase();
    if (upgradeBtn) {
      upgradeBtn.classList.toggle("hidden", plan === "PRO");
    }
    if (plan === "PRO") {
      usageBadge.innerHTML = `<span class="muted">Paket:</span> <b>PRO</b> <span class="muted">•</span> Limitsiz`;
      return;
    }
    const r = u.remaining || {};
    const lim = u.limits || {};
    usageBadge.innerHTML =
      `<span class="muted">Paket:</span> <b>ÜCRETSİZ</b>` +
      ` <span class="muted">•</span> Deneme <b>${fmtRemaining(r.eval)}</b>/<span class="muted">${fmtRemaining(lim.eval)}</span>` +
      ``;
  }

  async function refreshUsage() {
    try {
      const u = await apiGet("/api/usage");
      renderUsage(u);
    } catch (e) {
      // ignore
    }
  }

  async function startUpgrade() {
    clearAlert();
    if (!upgradeBtn) return;
    upgradeBtn.disabled = true;
    upgradeBtn.textContent = "Yönlendiriliyor…";
    try {
      const resp = await apiPost("/api/billing/create_checkout", {});
      if (resp && resp.url) {
        window.location.href = resp.url;
        return;
      }
      throw new Error("Ödeme bağlantısı alınamadı.");
    } catch (e) {
      showAlert(`Pro'ya geçiş başlatılamadı: ${e.message}`);
    } finally {
      upgradeBtn.disabled = false;
      upgradeBtn.textContent = "Pro'ya Geç";
    }
  }

// PDF auto-parse
  async function parsePdfAuto(file) {
    hideMini(pdfStatus);
    if (!file) return;

    showMini(pdfStatus, "PDF okunuyor…", "muted");
    clearAlert();

    const lang = (languageEl.value || "Türkçe").toLowerCase().includes("türk") ? "tr" : "en";

    const fd = new FormData();
    fd.append("file", file);

    try {
      const r = await fetch(`/api/parse_pdf?language=${encodeURIComponent(lang)}`, { method: "POST", headers: getHeaders(), body: fd });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.detail || `HTTP ${r.status}`);

      cvTextEl.value = (j.text || "").trim();
      showMini(pdfStatus, `PDF okundu (${j.method || "ok"}).`, "ok");
      refreshUsage();
    } catch (e) {
      showMini(pdfStatus, `PDF okunamadı: ${e.message}`, "error");
    }
  }

  // Start interview
  async function startInterview() {
    clearAlert();
    hideMini(startStatus);

    const role = (roleEl.value || "").trim();
    if (!role) {
      showAlert("Meslek boş olamaz.");
      return;
    }

    const n = clampInt(nQuestionsEl.value, 1, 10, 3);
    nQuestionsEl.value = String(n);

    showMini(startStatus, "Başlatılıyor…", "muted");
    startBtn.disabled = true;

    try {
      const resp = await apiPost("/api/start", {
        role,
        seniority: seniorityEl.value,
        language: languageEl.value,
        n_questions: n,
        cv_text: cvTextEl.value || "",
      });

      sessionId = resp.session_id;
      renderQuestion(resp.question, resp.index, resp.total);
      showMini(startStatus, "Başladı. İlk soruyu cevapla.", "ok");
    } catch (e) {
      showAlert(`Başlatılamadı: ${e.message}`);
      hideMini(startStatus);
    } finally {
      startBtn.disabled = false;
      updateEvalBtn();
    }
  }

  // Feedback renderer (clean + less clutter)
  function renderFeedback(fb) {
    const bd = fb.score_breakdown || {};
    const fixes = Array.isArray(fb.top_fixes) ? fb.top_fixes : [];
    const redFlags = Array.isArray(fb.red_flags) ? fb.red_flags : [];
    const ex = fb.example_answers || {};

    const bars = [
      ["Yapı (STAR)", bd.yapi_star],
      ["Uygunluk", bd.uygunluk],
      ["Etki (metrik)", bd.etki_metrik],
      ["Netlik", bd.netlik],
      ["Özgüven", bd.ozguven],
    ];

    const barHtml = bars
      .map(([label, val]) => {
        const v = Math.max(0, Math.min(20, parseInt(val || 0, 10)));
        const w = Math.round((v / 20) * 100);
        return `
          <div class="barRow">
            <div class="barLabel">${label}</div>
            <div class="barTrack"><div class="barFill" style="width:${w}%"></div></div>
            <div class="barVal">${v}/20</div>
          </div>
        `;
      })
      .join("");

    const fixesHtml = fixes
      .map((f) => {
        return `
          <details class="fix">
            <summary><span class="pill">${escapeHtml(f.id || "")}</span> ${escapeHtml(f.title || "")}</summary>
            <div class="fixBody">
              <div class="kv"><div class="k">Neden</div><div class="v">${escapeHtml(f.why || "")}</div></div>
              <div class="kv"><div class="k">Nasıl</div><div class="v">${escapeHtml(f.how || "")}</div></div>
              <div class="kv"><div class="k">Örnek</div><div class="v mono">${escapeHtml(f.example || "")}</div></div>
            </div>
          </details>
        `;
      })
      .join("");

    const redHtml =
      redFlags.length > 0
        ? `<div class="block">
            <div class="blockTitle">Kırmızı Bayraklar</div>
            <ul>${redFlags.map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>
          </div>`
        : "";

    const examplesHtml = `
      <details class="fix">
        <summary><span class="pill">30s</span> Daha güçlü örnek cevap</summary>
        <div class="fixBody"><div class="mono">${escapeHtml(ex.short_30s || "")}</div></div>
      </details>
      <details class="fix">
        <summary><span class="pill">90s</span> Daha güçlü örnek cevap</summary>
        <div class="fixBody"><div class="mono">${escapeHtml(ex.long_90s || "")}</div></div>
      </details>
    `;

    feedbackContent.innerHTML = `
      <div class="scoreHeader">
        <div class="scoreBig">${fb.overall_score || 0}<span class="muted">/100</span></div>
        <div class="scoreMeta">
          <div class="scoreLevel">${escapeHtml(fb.level || "")}</div>
          <div class="muted small">${escapeHtml(fb.one_sentence_goal || "")}</div>
        </div>
      </div>

      <div class="block">
        <div class="blockTitle">Özet</div>
        <div class="blockBody">${escapeHtml(fb.summary || "")}</div>
      </div>

      <div class="block">
        <div class="blockTitle">Puan Dağılımı</div>
        ${barHtml}
      </div>

      <div class="block">
        <div class="blockTitle">Öncelikli 3 Düzeltme</div>
        ${fixesHtml || '<div class="muted small">—</div>'}
      </div>

      ${redHtml}

      <div class="block">
        <div class="blockTitle">Takip Sorusu</div>
        <div class="blockBody">${escapeHtml(fb.followup_question || "")}</div>
      </div>

      <div class="block">
        <div class="blockTitle">Örnek Cevaplar</div>
        ${examplesHtml}
      </div>
    `;

    feedbackBox.classList.remove("hidden");
  }

  function escapeHtml(s) {
    return String(s || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  // Evaluate
  async function evaluateAnswer() {
    clearAlert();
    if (!sessionId || !currentQuestion) return;

    const answer = (answerEl.value || "").trim();
    if (!answer) {
      showAlert("Cevap boş olamaz.");
      return;
    }

    isEvaluating = true;
    updateEvalBtn();
    okNextBtn.disabled = true;

    setLoadingFeedback(true);
    feedbackContent.innerHTML = "";

    try {
      const resp = await apiPost("/api/evaluate", { session_id: sessionId, answer });
      const fb = resp.feedback;

      setLoadingFeedback(false);
      renderFeedback(fb);

      chipStatus.textContent = "cevaplandı";
      chipStatus.classList.remove("chip-warn");
      chipStatus.classList.add("chip-ok");

      okNextBtn.disabled = false;
    } catch (e) {
      setLoadingFeedback(false);
      showAlert(`Değerlendirme yapılamadı: ${e.message}`);
      feedbackBox.classList.add("hidden");
    } finally {
      isEvaluating = false;
      updateEvalBtn();
    }
  }

  // Next question
  async function nextQuestion() {
    clearAlert();
    if (!sessionId) return;

    okNextBtn.disabled = true;
    chipStatus.textContent = "hazırlanıyor";
    chipStatus.classList.remove("chip-ok", "chip-warn");
    chipStatus.classList.add("chip-warn");

    // show a lightweight loader in question area
    questionText.textContent = "Sonraki soru hazırlanıyor…";
    followupsBox.classList.add("hidden");

    try {
      const resp = await apiPost("/api/next", { session_id: sessionId });
      if (resp.done) {
        progressText.textContent = `İlerleme: ${totalQuestions}/${totalQuestions} tamamlandı`;
        progressPct.textContent = "100%";
        progressFill.style.width = "100%";
        questionText.textContent = "Mülakat bitti. Yeni oturum başlatabilirsin.";
        answerEl.value = "";
        feedbackBox.classList.add("hidden");
        evalBtn.disabled = true;
        return;
      }
      renderQuestion(resp.question, resp.index, resp.total);
    } catch (e) {
      showAlert(`Sonraki soru alınamadı: ${e.message}`);
      chipStatus.textContent = "bekliyor";
      chipStatus.classList.remove("chip-warn");
      chipStatus.classList.add("chip-warn");
      updateEvalBtn();
    }
  }

  // Templates
  btnStar.addEventListener("click", () => {
    const tpl =
`STAR (Durum, Görev, Eylem, Sonuç)

Durum:
- (Kısa bağlam: nerede/ne zaman? kimler? sorun neydi?)

Görev:
- (Senin rolün neydi ve senden ne bekleniyordu?)

Eylem:
- (1) ...
- (2) ...
- (3) ...

Sonuç:
- (Ne oldu? Ölçülebilir etki/metrik varsa yaz)
- (Ne öğrendin / bir dahaki sefere neyi farklı yaparsın?)
`;
    if (!answerEl.value.trim()) {
      answerEl.value = tpl;
    } else {
      answerEl.value = answerEl.value.trim() + "\n\n" + tpl;
    }
    updateEvalBtn();
    answerEl.focus();
  });

  btnMetric.addEventListener("click", () => {
    const add =
`\n\nÖlçülebilir etki (metrik) ekle:
- Süre/akış: 25 dk → 10 dk, %20 hızlandı
- Kalite/hata: hata oranı %15 azaldı, yeniden başvuru %10 düştü
- Güvenlik: kritik hata sayısı 3 → 0
- Klinik örnek: SpO2 84 → 92, RR 30 → 20
- Memnuniyet: hasta/ekip memnuniyeti arttı
`;
    answerEl.value = (answerEl.value || "") + add;
    updateEvalBtn();
    answerEl.focus();
  });

  btnClear.addEventListener("click", () => {
    answerEl.value = "";
    updateEvalBtn();
    answerEl.focus();
  });

  answerEl.addEventListener("input", updateEvalBtn);

  // Mic devices
  async function refreshMics() {
    try {
      // Request permission once to get labels
      await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch (_) {}

    const devices = await navigator.mediaDevices.enumerateDevices();
    const mics = devices.filter((d) => d.kind === "audioinput");

    micSelect.innerHTML = "";
    mics.forEach((m, idx) => {
      const opt = document.createElement("option");
      opt.value = m.deviceId;
      opt.textContent = m.label || `Mikrofon ${idx + 1}`;
      micSelect.appendChild(opt);
    });

    if (!mics.length) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "Mikrofon bulunamadı";
      micSelect.appendChild(opt);
    }
  }

  micRefresh.addEventListener("click", refreshMics);

  function startMeter(localStream) {
    try {
      audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const source = audioCtx.createMediaStreamSource(localStream);
      analyser = audioCtx.createAnalyser();
      analyser.fftSize = 2048;
      source.connect(analyser);

      const data = new Uint8Array(analyser.fftSize);

      const tick = () => {
        analyser.getByteTimeDomainData(data);
        // RMS
        let sum = 0;
        for (let i = 0; i < data.length; i++) {
          const v = (data[i] - 128) / 128;
          sum += v * v;
        }
        const rms = Math.sqrt(sum / data.length);
        const pct = Math.min(100, Math.round(rms * 200)); // scaled
        meterFill.style.width = `${pct}%`;
        meterPct.textContent = `${pct}%`;
        meterRaf = requestAnimationFrame(tick);
      };
      tick();
    } catch (_) {}
  }

  function stopMeter() {
    if (meterRaf) cancelAnimationFrame(meterRaf);
    meterRaf = null;
    meterFill.style.width = "0%";
    meterPct.textContent = "0%";
    try {
      if (audioCtx) audioCtx.close();
    } catch (_) {}
    audioCtx = null;
    analyser = null;
  }

  // Recording
  recStart.addEventListener("click", async () => {
    clearAlert();
    hideMini(transcribeStatus);
    audioPlayback.classList.add("hidden");
    audioPlayback.src = "";

    try {
      const deviceId = micSelect.value;
      const constraints = deviceId ? { audio: { deviceId: { exact: deviceId } } } : { audio: true };
      stream = await navigator.mediaDevices.getUserMedia(constraints);

      chunks = [];
      mediaRecorder = new MediaRecorder(stream);
      mediaRecorder.ondataavailable = (e) => {
        if (e.data && e.data.size > 0) chunks.push(e.data);
      };
      mediaRecorder.onstop = async () => {
        try {
          const blob = new Blob(chunks, { type: mediaRecorder.mimeType || "audio/webm" });
          // Playback
          audioPlayback.src = URL.createObjectURL(blob);
          audioPlayback.classList.remove("hidden");

          // Auto transcribe
          showMini(transcribeStatus, "Yazıya çevriliyor…", "muted");
          const fd = new FormData();
          fd.append("file", blob, "audio.webm");
          const lang = (languageEl.value || "Türkçe").toLowerCase().includes("türk") ? "tr" : "en";

          const r = await fetch(`/api/transcribe?language=${encodeURIComponent(lang)}`, { method: "POST", headers: getHeaders(), body: fd });
          const j = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error(j.detail || `HTTP ${r.status}`);

          const text = (j.text || "").trim();
          if (text) {
            if (!answerEl.value.trim()) answerEl.value = text;
            else answerEl.value = answerEl.value.trim() + "\n" + text;
            updateEvalBtn();
            showMini(transcribeStatus, "Yazıya çevirme tamamlandı.", "ok");
    refreshUsage();
          } else {
            showMini(transcribeStatus, j.warning || "Metin çıkarılamadı. Daha net/uzun konuşmayı dene.", "error");
          }
        } catch (e) {
          showMini(transcribeStatus, `Yazıya çevirme hatası: ${e.message}`, "error");
        }
      };

      mediaRecorder.start(250); // timeslice for stability
      startMeter(stream);

      recStart.disabled = true;
      recStop.disabled = false;
    } catch (e) {
      showAlert(`Mikrofon açılamadı: ${e.message || e}`);
    }
  });

  recStop.addEventListener("click", async () => {
    try {
      if (mediaRecorder && mediaRecorder.state !== "inactive") {
        mediaRecorder.stop();
      }
      if (stream) {
        stream.getTracks().forEach((t) => t.stop());
      }
    } catch (_) {}
    stopMeter();

    recStart.disabled = false;
    recStop.disabled = true;
  });

  // Key badge (top-right)
  if (keyBadge) {
    keyBadge.addEventListener("click", async () => {
      const t = getProToken();
      if (t) {
        try {
          await navigator.clipboard.writeText(t);
          flashKeyBadge("Anahtar kopyalandı ✅");
        } catch (e) {
          flashKeyBadge(`Anahtar: ${maskToken(t)}`);
        }
      } else {
        try {
          proTokenEl?.scrollIntoView({ behavior: "smooth", block: "center" });
        } catch (_) {}
        proTokenEl?.focus();
        flashKeyBadge("Anahtar yok — buradan ekleyebilirsin");
      }
    });
  }

  // Buttons
  startBtn.addEventListener("click", startInterview);
  if (upgradeBtn) upgradeBtn.addEventListener("click", startUpgrade);
  evalBtn.addEventListener("click", evaluateAnswer);
  okNextBtn.addEventListener("click", nextQuestion);
  pdfFileEl.addEventListener("change", (e) => parsePdfAuto(e.target.files && e.target.files[0]));


  // Pro token persistence
  if (proTokenEl) {
    proTokenEl.value = localStorage.getItem(PRO_TOKEN_KEY) || "";
    renderKeyBadge();
    proTokenEl.addEventListener("change", () => {
      const v = (proTokenEl.value || "").trim();
      if (v) localStorage.setItem(PRO_TOKEN_KEY, v);
      else localStorage.removeItem(PRO_TOKEN_KEY);
      renderKeyBadge();
      refreshUsage();
      refreshHealth();
    });
  }

  // Init
  renderKeyBadge();
  refreshHealth();
  refreshUsage();
  refreshMics();
})();
