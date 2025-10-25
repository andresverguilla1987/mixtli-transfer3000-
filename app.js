// Mixtli Transfer 3000 — Frontend v3.0 FIX (compatible v2.5.0 backend)

const els = {
  backendUrl: document.getElementById('backendUrl'),
  expires: document.getElementById('expires'),
  btnPick: document.getElementById('btnPick'),
  fileInput: document.getElementById('fileInput'),
  dropzone: document.getElementById('dropzone'),
  btnUpload: document.getElementById('btnUpload'),
  btnClear: document.getElementById('btnClear'),
  list: document.getElementById('list'),
  totalBar: document.getElementById('totalBar'),
  totalPct: document.getElementById('totalPct'),
  btnHealth: document.getElementById('btnHealth'),
  pw: document.getElementById('pw'),
  pwHint: document.getElementById('pwHint'),
};

const LS_KEY = 'mixtli_backend_url';
els.backendUrl.value = localStorage.getItem(LS_KEY) || '';
els.backendUrl.addEventListener('change', () => localStorage.setItem(LS_KEY, els.backendUrl.value.trim()));

let items = []; // {file, state, pct, links}

function fmtBytes(n){
  if(!Number.isFinite(n)) return '-';
  const u = ['B','KB','MB','GB'];
  let i = 0;
  while(n >= 1024 && i < u.length-1){ n/=1024; i++; }
  return `${n.toFixed(1)} ${u[i]}`;
}

function render(){
  els.list.innerHTML = '';
  let loaded = 0, total = items.reduce((a,i)=>a + (i.file?.size || 0), 0);
  items.forEach((it, idx) => {
    loaded += (it.file?.size || 0) * (it.pct||0)/100;
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `
      <div class="row">
        <div>
          <div class="name">${it.file.name}</div>
          <div class="meta">${fmtBytes(it.file.size)} — ${it.file.type || 'application/octet-stream'} — <b>${it.pct||0}%</b> ${it.state||''}</div>
          <div class="progress"><div class="bar" style="width:${it.pct||0}%"></div></div>
        </div>
        <div class="btns">
          ${it.links?.publicUrl ? `<a class="link-btn" href="${it.links.publicUrl}" target="_blank" rel="noopener">Link público</a>` : ''}
        </div>
      </div>
    `;
    els.list.appendChild(card);
  });
  const pct = total ? Math.round((loaded/total)*100) : 0;
  els.totalBar.style.width = pct + '%';
  els.totalPct.textContent = pct + '%';
}

function addFiles(files){
  for(const f of files){
    items.push({ file: f, state: 'pendiente', pct: 0, links: null });
  }
  render();
}

els.btnPick.addEventListener('click', ()=> els.fileInput.click());
els.fileInput.addEventListener('change', e => addFiles(e.target.files));

// Drag & drop
['dragenter','dragover'].forEach(ev => els.dropzone.addEventListener(ev, e=>{
  e.preventDefault(); e.stopPropagation(); els.dropzone.classList.add('drag');
}));
['dragleave','drop'].forEach(ev => els.dropzone.addEventListener(ev, e=>{
  e.preventDefault(); e.stopPropagation(); els.dropzone.classList.remove('drag');
}));
els.dropzone.addEventListener('drop', e => addFiles(e.dataTransfer.files));

els.btnClear.addEventListener('click', ()=>{ items = []; render(); });

// Presign REAL compatible con backend v2.5.0
async function presignOne(backendUrl, file, days, password, hint){
  const body = {
    filename: file.name,
    contentType: file.type,
    contentLength: file.size,
    durationDays: days,
    linkPassword: password || undefined,
    linkPasswordHint: hint || undefined
  };

  const resp = await fetch(new URL('/api/presign', backendUrl), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  if(!resp.ok){
    throw new Error(`presign ${resp.status}: ${await resp.text().catch(()=> '')}`);
  }
  return await resp.json();
}

// Upload con XHR para progreso real
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
    xhr.onload = ()=>{
      if(xhr.status >= 200 && xhr.status < 300) resolve();
      else reject(new Error(`PUT ${xhr.status} ${xhr.statusText}`));
    };
    xhr.onerror = ()=> reject(new Error('XHR error'));
    xhr.send(file);
  });
}

els.btnUpload.addEventListener('click', async ()=>{
  try{
    const backend = els.backendUrl.value.trim();
    if(!backend) return alert('Configura el Backend URL');
    const files = items.map(i => i.file);
    if(files.length === 0) return alert('Agrega archivos');

    const days = Number(els.expires.value || 3);
    const password = els.pw.value.trim() || null;
    const hint = els.pwHint.value.trim() || null;

    // Paso 1: obtener presign por archivo
    for(let i = 0; i < items.length; i++){
      const it = items[i];
      it.state = 'firmando…'; it.pct = 0; render();

      const j = await presignOne(backend, it.file, days, password, hint);

      it.links = {
        uploadUrl: j.uploadUrl,
        publicUrl: backend + j.publicUrl
      };
      it.state = 'subiendo…'; render();

      // Paso 2: subir
      await putWithProgress(j.uploadUrl, it.file, pct => { it.pct = pct; render(); });

      it.state = 'ok'; it.pct = 100; render();
    }
  }catch(err){
    console.error(err);
    alert('Error: ' + err.message);
  }
});

// Health
els.btnHealth.addEventListener('click', async ()=>{
  const backend = els.backendUrl.value.trim();
  if(!backend) return alert('Configura el Backend URL');
  try{
    const r = await fetch(new URL('/api/health', backend));
    const j = await r.json();
    alert('OK: ' + JSON.stringify(j));
  }catch(e){
    alert('Error health: ' + e.message);
  }
});

render();
