(function(){
  const $ = (id) => document.getElementById(id);

  const LS_ADMIN_KEY = 'adminKey';
  const LS_ADMIN_2FA = 'admin2fa';

  function setStatus(text, isError=false){
    const el = $('status');
    if(!el) return;
    el.textContent = text;
    el.style.color = isError ? '#ef4444' : '';
  }

  function getAdminKey(){ return (localStorage.getItem(LS_ADMIN_KEY) || '').trim(); }
  function getAdmin2FA(){ return (localStorage.getItem(LS_ADMIN_2FA) || '').trim(); }

  function setAdminKey(v){
    const val = (v || '').trim();
    if(!val) localStorage.removeItem(LS_ADMIN_KEY);
    else localStorage.setItem(LS_ADMIN_KEY, val);
  }
  function setAdmin2FA(v){
    const val = (v || '').trim();
    if(!val) localStorage.removeItem(LS_ADMIN_2FA);
    else localStorage.setItem(LS_ADMIN_2FA, val);
  }

  function getTotp(){
    return (($('adminTotp')?.value || '').trim());
  }

  function headers(){
    const h = {};
    const k = getAdminKey();
    if(k) h['X-Admin-Key'] = k;
    const k2 = getAdmin2FA();
    if(k2) h['X-Admin-2FA'] = k2;
    const t = getTotp();
    if(t) h['X-Admin-TOTP'] = t;
    return h;
  }

  async function apiGet(path){
    const res = await fetch(path, { headers: headers() });
    if(!res.ok){
      const txt = await res.text().catch(()=> '');
      throw new Error(`${res.status} ${res.statusText}${txt ? ` — ${txt}` : ''}`);
    }
    return res.json();
  }

  async function apiPost(path, body){
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers() },
      body: JSON.stringify(body || {})
    });
    if(!res.ok){
      const txt = await res.text().catch(()=> '');
      throw new Error(`${res.status} ${res.statusText}${txt ? ` — ${txt}` : ''}`);
    }
    return res.json();
  }

  function fmtTop(list){
    if(!Array.isArray(list) || list.length===0) return '—';
    return list.map((x)=> {
      if(Array.isArray(x)) return `${String(x[0]).padEnd(38,' ')}  ${x[1]}`;
      if(x && typeof x === 'object'){
        const key = x.path ?? x.ban_key ?? x.source ?? x.key ?? x.event_type ?? '—';
        const count = x.count ?? x.total ?? '—';
        return `${String(key).padEnd(38,' ')}  ${count}`;
      }
      return String(x);
    }).join('\n');
  }

  function fmtSummary(s){
    if(!s) return '—';
    const byType = Array.isArray(s.by_type) ? s.by_type : [];
    const totalEvents = (s.total_events != null)
      ? s.total_events
      : byType.reduce((acc, row) => acc + (parseInt(row?.count || 0, 10) || 0), 0);

    const lines = [];
    lines.push(`Pencere: son ${s.minutes ?? 60} dk`);
    lines.push(`Kayıt: ${totalEvents}`);
    for(const row of byType){
      lines.push(`- ${row.event_type ?? row.type ?? 'unknown'}: ${row.count ?? 0}`);
    }
    return lines.join('\n');
  }

  function renderEvents(list){
    const body = $('eventsBody');
    if(!body) return;
    body.innerHTML = '';
    if(!Array.isArray(list) || list.length===0){
      const tr = document.createElement('tr');
      tr.innerHTML = `<td class="muted" colspan="5">Kayıt yok</td>`;
      body.appendChild(tr);
      return;
    }
    for(const e of list){
      const tr = document.createElement('tr');
      const rawTs = e.ts || e.created_at || 0;
      const ts = rawTs ? new Date((rawTs > 1e12 ? rawTs : rawTs*1000)).toISOString().replace('T',' ').replace('Z','') : '';
      const details = (typeof e.details === 'string') ? e.details : JSON.stringify(e.details || {});
      tr.innerHTML = `
        <td class="mono">${ts}</td>
        <td>${(e.event_type||e.type||'')}</td>
        <td class="mono">${(e.ip||'')}</td>
        <td class="mono">${(e.path||'')}</td>
        <td class="mono">${details.slice(0,140)}${details.length>140?'…':''}</td>
      `.trim();
      body.appendChild(tr);
    }
  }

  async function refreshAll(){
    try{
      setStatus('Yükleniyor…');
      const minutes = parseInt(($('mins')?.value||'60'),10) || 60;
      const sum = await apiGet(`/api/admin/security/summary?minutes=${encodeURIComponent(minutes)}`);
      $('summary').textContent = fmtSummary(sum);
      $('topPaths').textContent = fmtTop(sum.top_paths);
      $('topSources').textContent = fmtTop(sum.top_sources);

      const events = await apiGet('/api/admin/security/events?limit=200');
      renderEvents(events.events || []);

      const lock = await apiGet('/api/admin/security/lockdown');
      $('lockdownStatus').textContent = lock.active ? 'AÇIK' : 'KAPALI';

      setStatus('OK');
    }catch(err){
      console.error(err);
      setStatus('Hata', true);
      const msg = (err && err.message) ? err.message : String(err);
      $('summary').textContent = `Hata: ${msg}`;
    }
  }

  function bind(){
    $('adminKey').value = getAdminKey();
    $('admin2fa').value = getAdmin2FA();

    $('saveKeyBtn').addEventListener('click', ()=>{
      setAdminKey($('adminKey').value);
      setAdmin2FA($('admin2fa').value);
      setStatus('Kaydedildi');
    });

    $('clearKeyBtn').addEventListener('click', ()=>{
      setAdminKey('');
      setAdmin2FA('');
      $('adminKey').value='';
      $('admin2fa').value='';
      $('adminTotp').value='';
      setStatus('Temizlendi');
    });

    $('refreshBtn').addEventListener('click', refreshAll);

    $('lockdownOnBtn').addEventListener('click', async ()=>{
      try{
        setStatus('Yükleniyor…');
        await apiPost('/api/admin/security/lockdown', { action: 'activate' });
        await refreshAll();
      }catch(e){
        console.error(e);
        setStatus('Hata', true);
      }
    });

    $('lockdownOffBtn').addEventListener('click', async ()=>{
      try{
        setStatus('Yükleniyor…');
        await apiPost('/api/admin/security/lockdown', { action: 'deactivate' });
        await refreshAll();
      }catch(e){
        console.error(e);
        setStatus('Hata', true);
      }
    });

    $('adminTotp').addEventListener('keydown', (ev)=>{
      if(ev.key === 'Enter') refreshAll();
    });
  }

  window.addEventListener('DOMContentLoaded', ()=>{
    bind();
    refreshAll();
  });
})();
