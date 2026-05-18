'use strict';
const CHUNK_THRESHOLD = 5  * 1024 * 1024;
const CHUNK_SIZE      = 10 * 1024 * 1024;
const MAX_FILE_SIZE   = 5  * 1024 * 1024 * 1024;
const BLOCKED_EXTS = new Set([
  'exe','bat','cmd','com','msi','ps1','psm1',
  'sh','bash','zsh','fish','command',
  'php','php3','php4','php5','php7','php8','phtml','phar',
  'asp','aspx','cshtml','jsp','jspx',
  'py','pyc','pyw','rb','pl','cgi','lua',
  'js','mjs','cjs','ts','tsx','jsx',
  'html','htm','xhtml','svg','xml',
  'htaccess','htpasswd','dll','so','dylib','sys',
  'vbs','vbe','wsf','wsh','hta','jar','war','class',
  'scr','pif','reg','lnk','app','dmg','pkg','deb','rpm','apk',
]);
let loginLocked   = false;
let uploadPending = [];
let _signupData   = {};
const _sliceCache = new WeakMap();
function precacheSlices(file) {
  if (file.size <= CHUNK_THRESHOLD) return;
  if (_sliceCache.has(file)) return;
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  const slices = Array.from({ length: totalChunks }, (_, i) => {
    const start = i * CHUNK_SIZE;
    return file.slice(start, Math.min(start + CHUNK_SIZE, file.size));
  });
  _sliceCache.set(file, slices);
}
(async () => {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    if (!d.ready) {
      document.getElementById('login-screen').innerHTML =
        '<div class="auth-card svc-unconfigured">' +
        '<h2>Service Not Configured</h2>' +
        '<p>The operator has not set the required environment variables.<br>Refer to the README for setup instructions.</p>' +
        '</div>';
      showScreen('login'); return;
    }
  } catch {}
  try {
    const r = await fetch('/api/me', { credentials:'same-origin' });
    if (r.ok) { bootApp(await r.json()); return; }
  } catch {}
  showScreen('login');
})();
function showScreen(name) {
  document.querySelectorAll('.screen').forEach(el => el.classList.remove('active'));
  document.getElementById('app-screen').classList.remove('active');
  if (name === 'app') document.getElementById('app-screen').classList.add('active');
  else { const el = document.getElementById(`${name}-screen`); if (el) el.classList.add('active'); }
}
document.getElementById('login-username').addEventListener('keydown', e => { if (e.key==='Enter') document.getElementById('login-password').focus(); });
document.getElementById('login-password').addEventListener('keydown', e => { if (e.key==='Enter') doLogin(); });
async function doLogin() {
  if (loginLocked) return;
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const errEl    = document.getElementById('login-error');
  const btn      = document.getElementById('login-btn');
  errEl.textContent = '';
  if (!username || !password) { errEl.textContent = 'Please enter your username and password.'; return; }
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await fetch('/api/auth', {
      method:'POST', credentials:'same-origin',
      headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify({ username, password }),
    });
    document.getElementById('login-password').value = '';
    if (r.ok) {
      const d = await r.json();
      bootApp({ display: d.display || username, username });
    } else if (r.status === 429) {
      startLockout(15 * 60);
    } else {
      errEl.textContent = 'Incorrect username or password.';
      document.getElementById('login-password').focus();
    }
  } catch { errEl.textContent = 'Connection error. Please try again.'; }
  btn.disabled = false; btn.textContent = 'Sign In';
}
function startLockout(secs) {
  loginLocked = true;
  const btn = document.getElementById('login-btn');
  const el  = document.getElementById('login-lockout');
  btn.disabled = true;
  const tick = () => {
    const m = Math.floor(secs/60), s = secs%60;
    el.textContent = `Too many attempts. Try again in ${m}:${String(s).padStart(2,'0')}.`;
    if (secs-- <= 0) { loginLocked=false; btn.disabled=false; el.textContent=''; clearInterval(t); }
  };
  tick(); const t = setInterval(tick, 1000);
}
function bootApp(me) {
  const chip = document.getElementById('user-chip');
  chip.textContent = me.display || me.username;
  chip.title = me.display || me.username;
  showScreen('app'); loadMeta(); loadFiles();
}
async function loadMeta() {
  try {
    const r = await fetch('/api/me', { credentials:'same-origin' });
    if (r.ok) { const d = await r.json(); document.getElementById('repo-label').textContent = d.repo||''; }
  } catch {}
}
async function doLogout() {
  if (!confirm('Sign out of StoreGit?')) return;
  try { await fetch('/api/logout',{method:'POST',credentials:'same-origin'}); } catch {}
  uploadPending=[]; clearQueue(); showScreen('login');
}
function goToStep(n) {
  [1,2,3].forEach(i => {
    document.getElementById(`step-${i}`).classList.toggle('active', i===n);
    const d = document.getElementById(`sdot-${i}`);
    d.className = 'step-dot' + (i<n?' done':i===n?' active':'');
  });
  document.getElementById('signup-footer-note').style.display = n===3?'none':'';
}
function updateStrength(pw) {
  const wrap=document.getElementById('pw-strength'), fill=document.getElementById('pw-strength-fill'), label=document.getElementById('pw-strength-label');
  if (!pw){wrap.style.display='none';return;} wrap.style.display='block';
  let s=0; if(pw.length>=8)s++; if(pw.length>=12)s++; if(/[A-Z]/.test(pw)&&/[a-z]/.test(pw))s++; if(/[0-9]/.test(pw))s++; if(/[^a-zA-Z0-9]/.test(pw))s++;
  const L=[{pct:10,color:'#c0392b',text:'Very weak'},{pct:30,color:'#e67e22',text:'Weak'},{pct:55,color:'#f1c40f',text:'Fair'},{pct:80,color:'#2ecc71',text:'Strong'},{pct:100,color:'#34a853',text:'Very strong'}];
  const lv=L[Math.min(s,L.length-1)]; fill.style.width=lv.pct+'%'; fill.style.background=lv.color; label.textContent=lv.text;
}
function step1Next() {
  const u=document.getElementById('s-username').value.trim(), p=document.getElementById('s-password').value, p2=document.getElementById('s-password2').value, e=document.getElementById('step1-error');
  e.textContent='';
  if(!u){e.textContent='Please enter a username.';return;}
  if(!/^[a-zA-Z0-9_\-]{3,32}$/.test(u)){e.textContent='Username must be 3–32 characters: letters, numbers, hyphens, underscores.';return;}
  if(p.length<8){e.textContent='Password must be at least 8 characters.';return;}
  if(p!==p2){e.textContent='Passwords do not match.';return;}
  _signupData.username=u; _signupData.password=p; goToStep(2);
}
async function step2Next() {
  const t=document.getElementById('s-gh-token').value.trim(), o=document.getElementById('s-gh-owner').value.trim(), r=document.getElementById('s-gh-repo').value.trim();
  const err=document.getElementById('step2-error'), btn=document.getElementById('step2-btn');
  err.textContent='';
  if(!t||!o||!r){err.textContent='Please fill in all fields.';return;}
  if(!t.startsWith('ghp_')&&!t.startsWith('github_pat_')){err.textContent='Token should start with ghp_ or github_pat_';return;}
  btn.disabled=true; btn.innerHTML='<span class="spinner"></span> Verifying…';
  try {
    const gr = await fetch(`https://api.github.com/repos/${encodeURIComponent(o)}/${encodeURIComponent(r)}`,
      {headers:{Authorization:`token ${t}`,Accept:'application/vnd.github.v3+json','User-Agent':'StoreGit-Setup'}});
    if(gr.status===401){err.textContent='Invalid GitHub token.';return;}
    if(gr.status===404){err.textContent='Repository not found.';return;}
    if(!gr.ok){err.textContent=`GitHub error (${gr.status}).`;return;}
    const repo=await gr.json();
    if(!repo.permissions?.push&&!repo.permissions?.admin){err.textContent='Token needs write access to this repository.';return;}
    const sr=await fetch('/api/signup',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:_signupData.username,password:_signupData.password,ghToken:t,ghOwner:o,ghRepo:r,ghBranch:'main',folder:'uploads'})});
    const sd=await sr.json();
    if(sr.ok){
      _signupData={}; document.getElementById('s-password').value=''; document.getElementById('s-password2').value=''; document.getElementById('s-gh-token').value='';
      goToStep(3);
    } else if(sr.status===409){err.textContent='That username is already taken.';}
    else{err.textContent=sd.error||'Signup failed.';}
  } catch{err.textContent='Connection error. Please try again.';}
  finally{btn.disabled=false;btn.textContent='Verify & Continue';}
}
async function loadFiles() {
  const el=document.getElementById('file-list');
  el.innerHTML='<div class="loading-row"><span class="spinner"></span> Loading files…</div>';
  try {
    const r=await fetch('/api/files',{credentials:'same-origin'});
    if(r.status===401){doLogout();return;}
    if(!r.ok) throw new Error('Failed to load files.');
    renderFiles(await r.json());
  } catch(e){el.innerHTML='';el.appendChild(emptyState(e.message));}
}
function renderFiles(files) {
  const el=document.getElementById('file-list');
  el.innerHTML='';
  const visible=files.filter(f=>f.name!=='.storegit');
  if(!visible.length){el.appendChild(emptyState('No files uploaded yet.'));return;}
  for(const f of visible){
    const row  = elem('div','file-row');
    const badge = elem('div','file-type-badge');
    badge.textContent = fileExt(f.name);
    const info = elem('div','file-info');
    const nm   = elem('div','file-name'); nm.textContent=f.name; nm.title=f.name;
    const mt   = elem('div','file-meta'); mt.textContent=fmtSize(f.size);
    info.append(nm,mt);
    const chevron = elem('div','file-chevron');
    chevron.innerHTML=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><polyline points="9 18 15 12 9 6"/></svg>`;
    row.append(badge,info,chevron);
    row.onclick = () => openFileDetail(f);
    el.appendChild(row);
  }
}
async function deleteFile(name, sha, chunked) {
  if (!confirm(`Permanently delete "${name}"?\n\nThis cannot be undone.`)) return;
  try {
    const body = chunked ? { name, chunked:true } : { name, sha };
    const r=await fetch('/api/delete',{method:'DELETE',credentials:'same-origin',
      headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(r.status===401){doLogout();return;}
    if(r.ok){toast('File deleted.','ok');loadFiles();}
    else toast('Delete failed.','error');
  } catch{toast('Delete failed.','error');}
}
async function downloadFile(name, size) {
  const bar=document.getElementById('dl-bar'), fill=document.getElementById('dl-fill'),
        lbl=document.getElementById('dl-label'), fnEl=document.getElementById('dl-filename');
  const url=`/api/download?name=${encodeURIComponent(name)}`;
  try {
    const r=await fetch(url,{credentials:'same-origin'});
    if(r.status===401){doLogout();return;}
    if(!r.ok){toast('Download failed.','error');return;}
    const contentLen=parseInt(r.headers.get('Content-Length')||'0',10);
    const knownSize=contentLen||size||0;
    const showBar=knownSize>2*1024*1024&&typeof ReadableStream!=='undefined'&&r.body;
    if(showBar){
      fnEl.textContent=name; fill.style.width='0%'; lbl.textContent='Starting…'; bar.style.display='block';
      const reader=r.body.getReader(), chunks=[];
      let received=0;
      while(true){
        const{done,value}=await reader.read(); if(done)break;
        chunks.push(value); received+=value.length;
        if(knownSize>0){
          const pct=Math.min(100,Math.round(received/knownSize*100));
          fill.style.width=pct+'%'; lbl.textContent=`${fmtSize(received)} of ${fmtSize(knownSize)}`;
        } else { lbl.textContent=`${fmtSize(received)} downloaded…`; }
      }
      bar.style.display='none'; triggerSave(new Blob(chunks),name);
    } else { triggerSave(await r.blob(),name); }
    toast('Saved to Downloads.','ok');
  } catch{ document.getElementById('dl-bar').style.display='none'; toast('Download failed.','error'); }
}
function triggerSave(blob, filename) {
  const url=URL.createObjectURL(blob), a=document.createElement('a');
  a.href=url; a.download=filename; a.style.display='none';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(()=>URL.revokeObjectURL(url),60000);
}
const dropZone=document.getElementById('drop-zone');
dropZone.addEventListener('dragover',e=>{e.preventDefault();dropZone.classList.add('dragging');});
dropZone.addEventListener('dragleave',()=>dropZone.classList.remove('dragging'));
dropZone.addEventListener('drop',e=>{e.preventDefault();dropZone.classList.remove('dragging');onFilePicked(e.dataTransfer.files);});
function onFilePicked(fileList) {
  const rejected=[];
  for(const f of fileList){
    if(f.size>MAX_FILE_SIZE){rejected.push(`"${f.name}" exceeds the size limit.`);continue;}
    const ext=f.name.split('.').pop()?.toLowerCase()||'';
    if(BLOCKED_EXTS.has(ext)){rejected.push(`"${f.name}" — file type not permitted.`);continue;}
    if(!uploadPending.find(p=>p.file.name===f.name&&p.file.size===f.size)){
      uploadPending.push({file:f,status:'wait'});
      precacheSlices(f);
    }
  }
  if(rejected.length) toast(rejected[0],'error');
  renderQueue();
}
function renderQueue() {
  const qEl=document.getElementById('upload-queue'), aEl=document.getElementById('upload-actions');
  if(!uploadPending.length){qEl.style.display='none';aEl.style.display='none';return;}
  qEl.style.display='block'; aEl.style.display='flex'; qEl.innerHTML='';
  uploadPending.forEach((it,i)=>{
    const item=elem('div','queue-item');
    const badge=elem('div','queue-file-icon'); badge.textContent=fileExt(it.file.name);
    const info=elem('div','queue-info');
    const nm=elem('div','queue-name'); nm.textContent=it.file.name;
    const sz=elem('div','queue-size');
    sz.textContent=fmtSize(it.file.size);
    const bar=elem('div','queue-bar'), fill=elem('div','queue-fill');
    fill.id=`qfill-${i}`; bar.appendChild(fill);
    info.append(nm,sz,bar);
    const st=elem('span',`queue-status ${it.status}`); st.id=`qstat-${i}`; st.textContent=statusLabel(it.status);
    item.append(badge,info,st); qEl.appendChild(item);
  });
}
function clearQueue(){
  uploadPending=[];
  document.getElementById('file-input').value='';
  renderQueue();
}
async function startUpload() {
  if(!uploadPending.length) return;
  const btn=document.getElementById('upload-btn');
  btn.disabled=true; btn.textContent='Uploading…';
  for(let i=0;i<uploadPending.length;i++){
    if(uploadPending[i].status==='ok') continue;
    setQ(i,'go',0);
    try{
      if(uploadPending[i].file.size > CHUNK_THRESHOLD){
        await chunkedUpload(uploadPending[i].file, i);
      } else {
        await xhrUpload(uploadPending[i].file, i);
      }
      setQ(i,'ok',100);
    } catch(e){ setQ(i,'fail',0); toast(e.message,'error'); }
  }
  btn.disabled=false; btn.textContent='Upload Files';
  const failed=uploadPending.filter(p=>p.status==='fail').length;
  if(!failed){toast('All files uploaded.','ok');clearQueue();}
  else toast(`${failed} file${failed>1?'s':''} failed.`,'error');
  loadFiles();
}
function blobToBase64(blob) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload  = () => res(r.result.slice(r.result.indexOf(',') + 1));
    r.onerror = () => rej(new Error('Read failed'));
    r.readAsDataURL(blob);
  });
}
async function xhrUpload(file, idx) {
  setQ(idx, 'go', 5);
  const b64 = await blobToBase64(file);
  setQ(idx, 'go', 30);
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload');
    xhr.withCredentials = true;
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.upload.onprogress = e => {
      if (e.lengthComputable) setQ(idx, 'go', 30 + Math.round(e.loaded / e.total * 65));
    };
    xhr.onload = () => {
      if (xhr.status === 200) { resolve(); return; }
      if (xhr.status === 401) { doLogout(); reject(new Error('Session expired.')); return; }
      let msg = 'Upload failed.'; try { msg = JSON.parse(xhr.responseText).error || msg; } catch {}
      reject(new Error(msg));
    };
    xhr.onerror   = () => reject(new Error('Network error.'));
    xhr.ontimeout = () => reject(new Error('Upload timed out.'));
    xhr.timeout   = 10 * 60 * 1000;
    xhr.send(JSON.stringify({ name: file.name, content: b64 }));
  });
}
const UPLOAD_CONCURRENCY = 5;
async function chunkedUpload(file, idx) {
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  setQ(idx, 'go', 2);
  const slices = _sliceCache.get(file) || Array.from({ length: totalChunks }, (_, i) => {
    const start = i * CHUNK_SIZE;
    return file.slice(start, Math.min(start + CHUNK_SIZE, file.size));
  });
  if (!_sliceCache.has(file)) _sliceCache.set(file, slices);
  const encoded = await Promise.all(slices.map(s => blobToBase64(s)));
  setQ(idx, 'go', 18);
  const blobs      = new Array(totalChunks);
  let  doneCount   = 0;
  const indexQueue = Array.from({ length: totalChunks }, (_, i) => i);
  const runWorker = async () => {
    while (indexQueue.length > 0) {
      const i = indexQueue.shift();
      const result = await xhrChunkWithRetry(
        encoded[i], slices[i].size, file.name, i, totalChunks, idx
      );
      blobs[i] = { index: i, blobSha: result.blobSha, blobToken: result.blobToken, size: slices[i].size };
      doneCount++;
      setQ(idx, 'go', 18 + Math.round((doneCount / totalChunks) * 74));
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(UPLOAD_CONCURRENCY, totalChunks) }, runWorker)
  );
  setQ(idx, 'go', 93);
  const fr = await fetch('/api/finalize-upload', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: file.name, totalSize: file.size,
      totalChunks, chunkSize: CHUNK_SIZE, blobs,
    }),
  });
  if (fr.status === 401) { doLogout(); throw new Error('Session expired.'); }
  if (!fr.ok) {
    const d = await fr.json().catch(() => ({}));
    throw new Error(d.error || 'Finalize failed.');
  }
  setQ(idx, 'go', 99);
}
const CHUNK_MAX_RETRIES = 2;
const CHUNK_BACKOFF_MS  = 800;
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
async function xhrChunkWithRetry(b64, rawSize, name, chunkIndex, totalChunks, queueIdx) {
  let lastErr;
  for (let attempt = 0; attempt <= CHUNK_MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      await sleep(CHUNK_BACKOFF_MS * Math.pow(2, attempt - 1));
    }
    try {
      return await xhrChunkEncoded(b64, rawSize, name, chunkIndex, totalChunks, queueIdx);
    } catch (err) {
      if (err.message === 'Session expired.') throw err;
      lastErr = err;
    }
  }
  throw lastErr;
}
async function xhrChunkEncoded(b64, rawSize, name, chunkIndex, totalChunks, queueIdx) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload-chunk');
    xhr.withCredentials = true;
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.timeout   = 5 * 60 * 1000;
    xhr.onload = () => {
      if (xhr.status === 200) { resolve(JSON.parse(xhr.responseText)); return; }
      if (xhr.status === 401) { doLogout(); reject(new Error('Session expired.')); return; }
      let msg = `Upload error on segment ${chunkIndex + 1}.`;
      try { msg = JSON.parse(xhr.responseText).error || msg; } catch {}
      reject(new Error(msg));
    };
    xhr.onerror   = () => reject(new Error(`Network error.`));
    xhr.ontimeout = () => reject(new Error(`Upload segment timed out.`));
    xhr.send(JSON.stringify({ name, chunkIndex, totalChunks, content: b64 }));
  });
}
function setQ(i, status, pct) {
  uploadPending[i].status = status;
  const st   = document.getElementById(`qstat-${i}`);
  const fill = document.getElementById(`qfill-${i}`);
  if (st) { st.className = `queue-status ${status}`; st.textContent = statusLabel(status); }
  if (fill) {
    fill.style.width = pct + '%';
    if (status === 'go') { fill.classList.add('wave'); } else { fill.classList.remove('wave'); }
  }
}
function statusLabel(s){return{wait:'Ready',go:'Uploading…',ok:'Done',fail:'Failed'}[s]||s;}
function fmtSize(b){
  if(b==null||isNaN(b))return'—';
  if(b<1024)return`${b} B`;
  if(b<1048576)return`${(b/1024).toFixed(1)} KB`;
  if(b<1073741824)return`${(b/1048576).toFixed(1)} MB`;
  return`${(b/1073741824).toFixed(2)} GB`;
}
function fileExt(name){const e=(name||'').split('.').pop();return e&&e!==name?e.slice(0,5).toUpperCase():'FILE';}
function elem(tag,cls){const el=document.createElement(tag);if(cls)el.className=cls;return el;}
function emptyState(msg){
  const d=elem('div','empty-state'),ic=elem('div','empty-state-icon');
  ic.innerHTML=`<svg viewBox="0 0 40 40" fill="none"><rect x="8" y="6" width="24" height="28" rx="3" stroke="#bbb" stroke-width="1.5"/><path d="M14 15h12M14 20h12M14 25h8" stroke="#bbb" stroke-width="1.5" stroke-linecap="round"/></svg>`;
  const p=elem('p');p.textContent=msg;d.append(ic,p);return d;
}
function toast(msg,type=''){
  const el=document.getElementById('toast');
  el.textContent=String(msg).slice(0,100);
  el.className=`toast show${type?' '+type:''}`;
  clearTimeout(el._t); el._t=setTimeout(()=>{el.className='toast';},3500);
}

/* ── File detail sheet ── */
const FD_IMG   = new Set(['jpg','jpeg','png','gif','webp','bmp','ico','tiff','tif','avif']);
const FD_AUDIO = new Set(['mp3','wav','ogg','m4a','flac','aac','opus']);
const FD_VIDEO = new Set(['mp4','webm','mov','m4v']);
const FD_TEXT  = new Set(['txt','md','markdown','csv','json','log','ini','cfg','conf','yaml','yml','toml','nfo','diff','patch']);

function openFileDetail(f) {
  document.getElementById('fd-icon').textContent = fileExt(f.name);
  document.getElementById('fd-name').textContent = f.name;
  document.getElementById('fd-meta').textContent = fmtSize(f.size);
  document.getElementById('fd-dl-btn').onclick  = () => downloadFile(f.name, f.size);
  document.getElementById('fd-del-btn').onclick = () => {
    closeFileDetail();
    setTimeout(() => deleteFile(f.name, f.sha, f.chunked || false), 250);
  };
  document.getElementById('fd-preview').innerHTML =
    '<div class="fd-preview-loading"><span class="spinner"></span> Loading preview…</div>';
  document.getElementById('fd-overlay').classList.add('open');
  loadFilePreview(f);
}

function closeFileDetail() {
  document.getElementById('fd-overlay').classList.remove('open');
}

async function loadFilePreview(f) {
  const el  = document.getElementById('fd-preview');
  const ext = (f.name.split('.').pop() || '').toLowerCase();

  function noPreview(msg) {
    // Fix: use DOM APIs instead of innerHTML so msg can never cause XSS.
    // msg may contain '<br>' for line-breaks — handle that without trusting arbitrary HTML.
    const wrap = document.createElement('div');
    wrap.className = 'fd-preview-none';
    const icon = document.createElement('div');
    icon.className = 'fd-preview-none-icon';
    // SVG is static and controlled — safe to set via innerHTML
    icon.innerHTML = '<svg viewBox="0 0 40 40" fill="none"><rect x="8" y="6" width="24" height="28" rx="3" stroke="currentColor" stroke-width="1.5"/><path d="M14 15h12M14 20h12M14 25h8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>';
    const textEl = document.createElement('div');
    // Split on literal '<br>' to preserve intended line breaks without allowing arbitrary HTML
    msg.split('<br>').forEach((line, i) => {
      if (i > 0) textEl.appendChild(document.createElement('br'));
      textEl.appendChild(document.createTextNode(line));
    });
    wrap.append(icon, textEl);
    el.replaceChildren(wrap);
  }

  async function fetchAsDataURL() {
    const r = await fetch(`/api/download?name=${encodeURIComponent(f.name)}`, {
      credentials: 'same-origin'
    });
    if (!r.ok) throw new Error('fetch_failed');
    const blob = await r.blob();
    return new Promise((res, rej) => {
      const reader = new FileReader();
      reader.onload  = e => res(e.target.result);
      reader.onerror = () => rej(new Error('read_failed'));
      reader.readAsDataURL(blob);
    });
  }

  if (FD_IMG.has(ext)) {
    if (f.size > 8 * 1024 * 1024) { noPreview('Image too large to preview.<br>Download to view.'); return; }
    try {
      const dataUrl = await fetchAsDataURL();
      const _img = document.createElement('img'); _img.className = 'fd-preview-img'; _img.src = dataUrl; _img.alt = f.name; el.replaceChildren(_img);
    } catch { noPreview('Could not load image preview.'); }
    return;
  }

  if (FD_AUDIO.has(ext)) {
    if (f.size > 8 * 1024 * 1024) { noPreview('Audio file is large.<br>Download to listen.'); return; }
    try {
      const dataUrl = await fetchAsDataURL();
      const _aud = document.createElement('audio'); _aud.className = 'fd-preview-audio'; _aud.controls = true; _aud.src = dataUrl; el.replaceChildren(_aud);
    } catch { noPreview('Could not load audio preview.'); }
    return;
  }

  if (FD_VIDEO.has(ext)) {
    if (f.size > 15 * 1024 * 1024) { noPreview('Video too large to preview here.<br>Download to watch.'); return; }
    try {
      const dataUrl = await fetchAsDataURL();
      const _vid = document.createElement('video'); _vid.className = 'fd-preview-video'; _vid.controls = true; _vid.src = dataUrl; el.replaceChildren(_vid);
    } catch { noPreview('Could not load video preview.'); }
    return;
  }

  if (FD_TEXT.has(ext) || f.size <= 200 * 1024) {
    if (f.size > 500 * 1024) { noPreview('File too large to preview as text.<br>Download to open.'); return; }
    try {
      const r = await fetch(`/api/download?name=${encodeURIComponent(f.name)}`, {
        credentials: 'same-origin'
      });
      if (!r.ok) throw new Error();
      const text    = await r.text();
      const preview = text.slice(0, 6000);
      const pre     = document.createElement('pre');
      pre.className   = 'fd-preview-code';
      pre.textContent = preview + (text.length > 6000 ? '\n\n… (truncated)' : '');
      el.innerHTML = '';
      el.appendChild(pre);
    } catch { noPreview('Could not load text preview.'); }
    return;
  }

  noPreview('No preview available.<br>Download to open this file.');
}
