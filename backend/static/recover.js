function getToken(){
  // Prefer fragment token (#token=...) to avoid putting tokens into server/proxy logs.
  try{
    const h = (window.location.hash || '').replace(/^#/, '');
    if (h){
      const hp = new URLSearchParams(h);
      const th = hp.get('token');
      if (th && th.trim()) return th.trim();
    }
  }catch(e){}
  const u = new URL(window.location.href);
  const t = u.searchParams.get('token');
  return t && t.trim() ? t.trim() : '';
}

function clearTokenFromURL(){
  const u = new URL(window.location.href);
  u.searchParams.delete('token');
  u.hash = '';
  window.history.replaceState({}, '', u.toString());
}
function showMsg(type, text){
  const el = document.getElementById('msg');
  el.classList.remove('hidden', 'alert-ok', 'alert-warn', 'alert-err');
  if(type === 'ok') el.classList.add('alert-ok');
  else if(type === 'warn') el.classList.add('alert-warn');
  else el.classList.add('alert-err');
  el.textContent = text;
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

function getCaptchaToken(){
  if (__captchaToken) return __captchaToken;
  const el = document.querySelector('textarea[name="cf-turnstile-response"]');
  return el && el.value ? el.value : "";
}
async function maybeRenderCaptcha(cfg){
  const row = document.getElementById('captchaRow');
  const widget = document.getElementById('captchaWidget');
  if(!row || !widget) return;
  const cap = cfg && cfg.captcha ? cfg.captcha : null;
  if(!cap || !cap.enabled || !cap.site_key){
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
        sitekey: cap.site_key,
        callback: (t) => setCaptchaToken(t),
      });
    } else {
      widget.innerHTML = `<div class="cf-turnstile" data-sitekey="${cap.site_key}"></div>`;
    }
  }catch(e){
    row.style.display = 'none';
    widget.innerHTML = '';
    setCaptchaToken('');
    throw e;
  }
}

async function postJSON(url, body){
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('application/json') ? await r.json() : { detail: await r.text() };
  if(!r.ok){
    throw new Error(data.detail || ('HTTP ' + r.status));
  }
  return data;
}

async function getJSON(url){
  const r = await fetch(url);
  const data = await r.json();
  if(!r.ok){
    throw new Error(data.detail || ('HTTP ' + r.status));
  }
  return data;
}

function tokenRow(token){
  const wrap = document.createElement('div');
  wrap.className = 'card';
  wrap.style.marginTop = '12px';
  wrap.style.padding = '14px';

  const code = document.createElement('div');
  code.className = 'code';
  code.textContent = token;

  const btn = document.createElement('button');
  btn.className = 'btn btn-small';
  btn.textContent = 'Kopyala';
  btn.onclick = async () => {
    try{
      await navigator.clipboard.writeText(token);
      btn.textContent = 'Kopyalandı';
      setTimeout(() => (btn.textContent = 'Kopyala'), 1200);
    }catch(e){
      alert('Kopyalama başarısız. Anahtarı manuel kopyalayabilirsin.');
    }
  };

  const row = document.createElement('div');
  row.style.display = 'flex';
  row.style.gap = '10px';
  row.style.alignItems = 'center';
  row.style.justifyContent = 'space-between';
  row.appendChild(code);
  row.appendChild(btn);

  wrap.appendChild(row);
  return wrap;
}

async function init(){
  try{
    const cfg = await window.__loadPublicConfig();
    const badge = document.getElementById('cfgBadge');
    badge.textContent = `${cfg.app_name} • ${cfg.payment_provider}`;
    try{ await maybeRenderCaptcha(cfg); }catch(e){ /* non-fatal */ }
  }catch(e){
    // ignore
  }

  const token = getToken();
  if(token){
    showMsg('warn', 'Link doğrulanıyor…');
    try{
      const data = await postJSON('/api/pro/recovery/consume', { token });
      const list = Array.isArray(data.tokens) ? data.tokens : [];

      if(list.length === 0){
        showMsg('err', 'Bu e-postaya bağlı Pro anahtarı bulunamadı (veya link süresi doldu).');
        return;
      }

      document.getElementById('cardTokens').classList.remove('hidden');
      const container = document.getElementById('tokens');
      container.innerHTML = '';
      list.forEach(t => container.appendChild(tokenRow(t)));
      showMsg('ok', 'Başarılı ✅ Pro anahtarların aşağıda.');
    }catch(e){
      showMsg('err', e.message || 'Link doğrulanamadı.');
    }
  }

  const btnSend = document.getElementById('btnSend');
  btnSend.onclick = async () => {
    const email = (document.getElementById('email').value || '').trim();
    if(!email){
      showMsg('err', 'E-posta gir.');
      return;
    }
    // Optional CAPTCHA
    const captcha_token = getCaptchaToken();
    btnSend.disabled = true;
    btnSend.textContent = 'Gönderiliyor…';
    try{
      await postJSON('/api/pro/recovery/request', { email, captcha_token });
      showMsg('ok', 'Eğer bu e-postaya bağlı Pro anahtarı varsa, kurtarma linki gönderildi.');
    }catch(e){
      showMsg('err', e.message || 'Gönderilemedi.');
    }finally{
      btnSend.disabled = false;
      btnSend.textContent = 'Link Gönder';
    }
  };
}

document.addEventListener('DOMContentLoaded', init);
