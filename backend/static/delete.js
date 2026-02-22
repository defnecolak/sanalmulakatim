function setLoading(isLoading){
  const b = document.getElementById('cfgBadge');
  if (!b) return;
  b.textContent = isLoading ? 'Yükleniyor…' : 'Hazır';
}


let __captchaToken = '';
let __turnstileLoading = null;

function setCaptchaToken(t){
  __captchaToken = (t || '').trim();
}

function ensureTurnstileLoaded(){
  if (window.turnstile) return Promise.resolve();
  if (__turnstileLoading) return __turnstileLoading;
  __turnstileLoading = new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
    s.async = true;
    s.defer = true;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error('Doğrulama yüklenemedi. Lütfen tekrar dene.'));
    document.head.appendChild(s);
  });
  return __turnstileLoading;
}

function showMsg(type, text){
  const box = document.getElementById('msg');
  if (!box) return;
  box.className = 'msg ' + (type || '');
  box.textContent = text || '';
  box.style.display = text ? 'block' : 'none';
}

async function postJSON(url, data){
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data || {})
  });
  const js = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = (js && (js.detail || js.message)) || res.statusText || 'Hata';
    throw new Error(detail);
  }
  return js;
}

function getCaptchaToken(){
  if (__captchaToken) return __captchaToken;
  // Fallback: Turnstile may still write token into a hidden textarea
  const el = document.querySelector('textarea[name="cf-turnstile-response"]');
  return el && el.value ? el.value : '';
}
async function maybeRenderCaptcha(cfg){
  const row = document.getElementById('captchaRow');
  const widget = document.getElementById('captchaWidget');
  const enabled = !!(cfg && cfg.captcha && cfg.captcha.enabled && cfg.captcha.site_key);
  if (!row || !widget) return;
  if (!enabled){
    row.style.display = 'none';
    widget.innerHTML = '';
    setCaptchaToken('');
    return;
  }

  row.style.display = '';
  widget.innerHTML = '';
  setCaptchaToken('');

  try{
    await ensureTurnstileLoaded();
    if (window.turnstile && typeof window.turnstile.render === 'function'){
      window.turnstile.render(widget, {
        sitekey: cfg.captcha.site_key,
        callback: (t) => setCaptchaToken(t),
      });
    } else {
      // Fallback: auto-render class
      widget.innerHTML = `<div class="cf-turnstile" data-sitekey="${cfg.captcha.site_key}"></div>`;
    }
  }catch(e){
    row.style.display = 'none';
    widget.innerHTML = '';
    setCaptchaToken('');
    throw e;
  }
}

function getTokenFromURL(){
  // Prefer fragment token (#token=...) to avoid proxy/access log leakage.
  try{
    const h = (window.location.hash || '').replace(/^#/, '');
    if (h){
      const hp = new URLSearchParams(h);
      const th = hp.get('token');
      if (th && th.trim()) return th.trim();
    }
  }catch(e){}
  const params = new URLSearchParams(window.location.search);
  const t = params.get('token');
  return t && t.trim() ? t.trim() : '';
}
function setMode(mode){
  const requestBox = document.getElementById('requestBox');
  const confirmBox = document.getElementById('confirmBox');
  if (requestBox) requestBox.style.display = (mode === 'request') ? 'block' : 'none';
  if (confirmBox) confirmBox.style.display = (mode === 'confirm') ? 'block' : 'none';
}

async function init(){
  setLoading(true);
  let cfg = null;
  try{
    cfg = await window.__loadPublicConfig?.();
  }catch(e){
    // non-fatal
  }finally{
    setLoading(false);
  }

  try{ await maybeRenderCaptcha(cfg); }catch(e){ /* non-fatal */ }

  const token = getTokenFromURL();
  setMode(token ? 'confirm' : 'request');

  const btnRequest = document.getElementById('btnRequest');
  const btnConfirm = document.getElementById('btnConfirm');

  if (btnRequest){
    btnRequest.addEventListener('click', async () => {
      showMsg('', '');
      const email = (document.getElementById('email')?.value || '').trim();
      if (!email){
        showMsg('err', 'Lütfen e‑posta adresi girin.');
        return;
      }
      btnRequest.disabled = true;
      try{
        const captcha_token = getCaptchaToken();
        await postJSON('/api/privacy/delete/request', { email, captcha_token });
        showMsg('ok', 'Eğer bu e‑posta ile ilişkili veri varsa, silme onay bağlantısı gönderildi. Lütfen gelen kutunu kontrol et.');
      }catch(e){
        showMsg('err', e.message || 'Hata');
      }finally{
        btnRequest.disabled = false;
      }
    });
  }

  if (btnConfirm){
    btnConfirm.addEventListener('click', async () => {
      showMsg('', '');
      const t = getTokenFromURL();
      if (!t){
        showMsg('err', 'Onay token bulunamadı.');
        return;
      }
      btnConfirm.disabled = true;
      try{
        await postJSON('/api/privacy/delete/confirm', { token: t });
        showMsg('ok', 'Silme işlemi tamamlandı.');
        // remove token from URL to avoid repeated use
        const url = new URL(window.location.href);
        url.searchParams.delete('token');
        url.hash = '';
        window.history.replaceState({}, '', url.toString());
        setMode('request');
      }catch(e){
        showMsg('err', e.message || 'Hata');
      }finally{
        btnConfirm.disabled = false;
      }
    });
  }
}

window.addEventListener('DOMContentLoaded', init);
