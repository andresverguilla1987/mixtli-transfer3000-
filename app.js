// Mixtli Transfer 3000 — Frontend v3.5 (planes + OTP + paquetes)  ✅

/* ---------- Elementos base (los que ya tenías) ---------- */
const els = {
  backendUrl: document.getElementById('backendUrl'),
  expires:    document.getElementById('expires'),
  btnPick:    document.getElementById('btnPick'),
  fileInput:  document.getElementById('fileInput'),
  dropzone:   document.getElementById('dropzone'),
  btnUpload:  document.getElementById('btnUpload'),
  btnClear:   document.getElementById('btnClear'),
  list:       document.getElementById('list'),
  totalBar:   document.getElementById('totalBar'),
  totalPct:   document.getElementById('totalPct'),
  btnHealth:  document.getElementById('btnHealth'),
  pw:         document.getElementById('pw'),
  pwHint:     document.getElementById('pwHint'), // opcional (no lo usa el backend)
  // Opcionales (si existen en tu HTML, los usamos)
  email:      document.getElementById('email'),
  phone:      document.getElementById('phone'),
  otp:        document.getElementById('otp'),
  btnSend:    document.getElementById('btnSend'),     // Enviar código
  btnVerify:  document.getElementById('btnVerify'),   // Verificar OTP
  planText:   document.getElementById('planText'),
  btnToPro:   document.getElementById('btnToPro'),
  btnToMax:   document.getElementById('btnToMax'),
  btnToFree:  document.getElementById('btnToFree'),
  maxDownloads: document.getElementById('maxDownloads')
};

/* ---------- Config localStorage ---------- */
const LS_BACKEND = 'mixtli_backend_url';
const LS_TOKEN   = 'mixtli_token';

els.backendUrl.value = localStorage.getItem(LS_BACKEND) || '';
els.backendUrl.addEventListener('change', () =>
  localStorage.setItem(LS_BACKEND, els.backendUrl.value.trim())
);

/* ---------- Estado ---------- */
let items = []; // { file, state, pct, links:{key, publicUrl}, uploaded:boolean }
let token  = localStorage.getItem(LS_TOKEN) || '';

/* ---------- Helpers ---------- */
const apiBase = () => (els.backendUrl.value || '').trim().replace(/\/+$/,'');
const authHdr = () => token ? { 'Authorization': 'Bearer ' + token } : {};

function fmtBytes(n){
  if(!Number.isFinite(n)) return '-';
  const u = ['B','KB','MB','GB','TB']; let i=0;
  while(n >= 1024 && i < u.length-1){ n/=1024; i++; }
  return `${n.toFixed(1)} ${u[i]}`;
}

function absoluteUrlLike(urlish){
  if (!urlish) return '';
  if (/^https?:\/\//i.test(urlish)) return urlish;
  return apiBase() + urlish; // para '/share/xxx'
}

/* ---------- Render ---------- */
function render(){
  els.list.innerHTML = '';
  let loaded = 0, total = items.reduce((a,i)=>a + (i.file?.size || 0), 0);

  items.forEach((it) => {
    loaded += (it.file?.size || 0) * (it.pct||0)/100;
    const card = document.createElement('div');
    card.className = 'card';
    const linkPub = it.links?.publicUrl ? `<a class="link-btn" href="${it.links.publicUrl}" target="_blank" rel="noopener">Link público</a>` : '';
    const done    = it.uploaded ? `<span class="ok-badge">OK</span>` : '';
    card.innerHTML = `
      <div class="row">
        <div>
          <div class="name">${it.file.name} ${done}</div>
          <div class="meta">${fmtBytes(it.file.size)} — ${it.file.type || 'application/octet-stream'} — <b>${it.pct||0}%</b> ${it.state||''}</div>
          <div class="progress"><div class="bar" style="width:${it.pct||0}%"></div></div>
        </div>
        <div class="btns">
          ${linkPub}
        </div>
      </div>
    `;
    els.list.appendChild(card);
  });

  const pct = total ? Math.round((loaded/total)*100) : 0;
  els.totalBar.style.width = pct + '%';
  els.totalPct.textContent = pct + '%';
}

/* ---------- Archivos ---------- */
function addFiles(files){
  for(const f of files){
    items.push({ file:f, state:'pendiente', pct:0, links:null, uploaded:false });
  }
  render();
}

els.btnPick?.addEventListener('click', ()=> els.fileInput.click());
els.fileInput?.addEventListener('change', e => addFiles(e.target.files));

['dragenter','dragover'].forEach(ev => els.dropzone?.addEventListener(ev, e=>{
  e.preventDefault(); e.stopPropagation(); els.dropzone.classList.add('drag');
}));
['dragleave','drop'].forEach(ev => els.dropzone?.addEventListener(ev, e=>{
  e.preventDefault(); e.stopPropagation(); els.dropzone.classList.remove('drag');
}));
els.dropzone?.addEventListener('drop', e => addFiles(e.dataTransfer.files));

els.btnClear?.addEventListener('click', ()=>{ items = []; render(); });

/* ---------- XHR PUT con progreso ---------- */
function putWithProgress(putUrl, file, onProgress){
  return new Promise((resolve, reject)=>{
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', putUrl, true);
    xhr.setRequestHeader('Content-Type', file.type || 'application/octet-stream');
    xhr.upload.onprogress = (e)=>{
      if(e.lengthComputable && typeof onProgress === 'function'){
        onProgress(Math.round((e.loaded/e.total)*100));
      }
    };
    xhr.onload = ()=> (xhr.status >=200 && xhr.status<300) ? resolve() : reject(new Error(`PUT ${xhr.status} ${xhr.statusText}`));
    xhr.onerror = ()=> reject(new Error('XHR error'));
    xhr.send(file);
  });
}

/* ---------- OTP (opcional) ---------- */
async function sendOtp(){
  const base = apiBase();
  if (!base) return alert('Configura Backend URL');

  const email = els.email?.value.trim() || '';
  const phone = els.phone?.value.trim() || '';
  if (!email && !phone) return alert('Pon email o teléfono');

  const r = await fetch(base + '/auth/register', {
    method:'POST',
    headers:{ 'Content-Type':'application/json' },
    body: JSON.stringify({ email, phone })
  });
  if (!r.ok) {
    const t = await r.text().catch(()=> '');
    throw new Error(`register ${r.status}: ${t}`);
  }
  return r.json();
}

async function verifyOtp(){
  const base = apiBase();
  if (!base) return alert('Configura Backend URL');

  const email = els.email?.value.trim() || '';
  const phone = els.phone?.value.trim() || '';
  const otp   = els.otp?.value.trim() || '';
  if ((!email && !phone) || !otp) return alert('Falta email/teléfono u OTP');

  const r = await fetch(base + '/auth/verify-otp', {
    method:'POST',
    headers:{ 'Content-Type':'application/json' },
    body: JSON.stringify({ email, phone, otp })
  });
  if (!r.ok) {
    const t = await r.text().catch(()=> '');
    throw new Error(`verify ${r.status}: ${t}`);
  }
  const j = await r.json();
  token = j.token || '';
  localStorage.setItem(LS_TOKEN, token);
  await refreshPlan();
  alert('Autenticado');
}

els.btnSend?.addEventListener('click', async ()=>{ try{ await sendOtp(); alert('Código enviado'); } catch(e){ alert(e.message); } });
els.btnVerify?.addEventListener('click', async ()=>{ try{ await verifyOtp(); } catch(e){ alert(e.message); } });

/* ---------- Planes (opcional) ---------- */
async function refreshPlan(){
  if (!token) { if (els.planText) els.planText.textContent = 'Sin sesión'; return; }
  const base = apiBase(); if (!base) return;
  const r = await fetch(base + '/api/plan', { headers: { ...authHdr() } });
  if (!r.ok) return;
  const j = await r.json();
  if (els.planText) els.planText.textContent = `${j.plan} — ${j.info?.label || ''}`;
}
async function upgradeTo(plan){
  const base = apiBase(); if (!base) return;
  if (!token) return alert('Inicia sesión (OTP)');
  const r = await fetch(base + '/api/plan/upgrade', {
    method:'POST',
    headers:{ 'Content-Type':'application/json', ...authHdr() },
    body: JSON.stringify({ plan })
  });
  const j = await r.json().catch(()=> ({}));
  if (!r.ok) return alert(j.error || 'Error al actualizar plan');
  await refreshPlan();
  alert(j.message || 'Plan actualizado');
}
async function downgradeToFree(){
  const base = apiBase(); if (!base) return;
  if (!token) return alert('Inicia sesión (OTP)');
  const r = await fetch(base + '/api/plan/downgrade', {
    method:'POST',
    headers:{ ...authHdr() }
  });
  const j = await r.json().catch(()=> ({}));
  if (!r.ok) return alert(j.error || 'Error al bajar a FREE');
  await refreshPlan();
  alert('Plan FREE activo');
}

els.btnToPro?.addEventListener('click', ()=> upgradeTo('PRO'));
els.btnToMax?.addEventListener('click', ()=> upgradeTo('PROMAX'));
els.btnToFree?.addEventListener('click', ()=> downgradeToFree());

/* ---------- Presign REAL (v2.15.2-MAX) ---------- */
async function presignOne(file){
  const base = apiBase();
  const r = await fetch(base + '/api/presign', {
    method: 'POST',
    headers: { 'Content-Type':'application/json', ...authHdr() },
    body: JSON.stringify({ filename: file.name, type: file.type || 'application/octet-stream' })
  });
  if (!r.ok) {
    const t = await r.text().catch(()=> '');
    throw new Error(`presign ${r.status}: ${t}`);
  }
  return r.json(); // { method, url, key, publicUrl }
}

/* ---------- Upload + crear paquete ---------- */
async function doUploadAndCreatePackage(){
  const base = apiBase();
  if (!base) return alert('Configura Backend URL');
  if (!token) return alert('Primero inicia sesión (OTP)');

  if (items.length === 0) return alert('Agrega archivos');

  const ttlDays = Number(els.expires?.value || 3);
  const password = (els.pw?.value || '').trim();
  const maxDl = els.maxDownloads ? Number(els.maxDownloads.value || 0) : null;

  // 1) Presign + PUT por archivo
  for (let i=0; i<items.length; i++){
    const it = items[i];
    it.state = 'firmando…'; it.pct = 0; render();
    const j = await presignOne(it.file);
    it.links = { key: j.key, publicUrl: j.publicUrl }; // publicUrl ya viene absoluta o relativa
    it.state = 'subiendo…'; render();

    await putWithProgress(j.url, it.file, pct => { it.pct = pct; render(); });
    it.uploaded = true; it.state = 'completado'; it.pct = 100; render();
  }

  // 2) Crear paquete
  const files = items.map(it => ({
    key: it.links.key,
    name: it.file.name,
    size: it.file.size,
    type: it.file.type || 'application/octet-stream'
  }));

  const body = {
    title: 'Mis archivos',
    ttlDays,
    files,
    password: password || undefined,
    maxDownloads: (Number.isFinite(maxDl) && maxDl>0) ? maxDl : undefined
  };

  const r = await fetch(base + '/api/pack/create', {
    method:'POST',
    headers:{ 'Content-Type':'application/json', ...authHdr() },
    body: JSON.stringify(body)
  });
  const j = await r.json().catch(()=> ({}));
  if (!r.ok) return alert(j.error || 'Error al crear paquete');

  // 3) Mostrar link de compartir (fosforescente)
  const share = absoluteUrlLike(j.url || '');
  const a = document.createElement('a');
  a.href = share; a.target = '_blank'; a.rel = 'noopener';
  a.className = 'share-link';
  a.textContent = 'Abrir enlace de paquete';
  const wrap = document.createElement('div');
  wrap.className = 'share-wrap';
  wrap.appendChild(a);
  els.list.appendChild(wrap);

  alert('Paquete creado ✔️');
}

/* ---------- Botón subir ---------- */
els.btnUpload?.addEventListener('click', async ()=>{
  try{
    await doUploadAndCreatePackage();
  }catch(err){
    console.error(err);
    alert('Error: ' + (err?.message || err));
  }
});

/* ---------- Health ---------- */
els.btnHealth?.addEventListener('click', async ()=>{
  const base = apiBase(); if (!base) return alert('Configura Backend URL');
  try{
    const r = await fetch(base + '/api/health');
    const j = await r.json();
    alert('OK: ' + JSON.stringify(j));
  }catch(e){
    alert('Error health: ' + e.message);
  }
});

/* ---------- Init ---------- */
render();
if (token) refreshPlan().catch(()=>{});
