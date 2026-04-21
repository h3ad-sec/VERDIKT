document.addEventListener('DOMContentLoaded', async () => {
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeModal();
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      const btn = document.getElementById('scan-btn');
      if (!btn.disabled) startScan();
    }
  });
  await detectMode();
  if (typeof updateVTPaidBadge === 'function') updateVTPaidBadge();
});

async function detectMode() {
  try {
    const resp = await fetch('/api/status', { signal: AbortSignal.timeout(3000) });
    if (resp.ok) {
      const status = await resp.json();
      if (status.mode === 'server') {
        SERVER_MODE = true;
        window._serverVTPaid = status.vt_paid === true;
        setMode('server');
        setServerStatusDots(status);
        document.getElementById('server-mode-badge').style.display = '';
        const rn = document.getElementById('rate-note-text');
        if (rn) rn.textContent = status.vt_paid ? 'Server mode · VT Paid — fully parallel' : 'Server mode · VT Free — token bucket (4 req/min)';
        const active = ['vt','abuseipdb','otx'].filter(k => status[k]).length;
        showToast(`Server mode — ${active}/3 keys configured`, active > 0 ? 'success' : 'warning');
        return;
      }
    }
  } catch(e) { /* not on Vercel */ }

  SERVER_MODE = false;
  setMode('input');
  loadSavedKeys();
  updateStatusDots();
  ['vt-key','ab-key','otx-key'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', updateStatusDots);
  });
  const vtPaid = document.getElementById('vt-paid');
  if (vtPaid) vtPaid.addEventListener('change', () => { updateVTPaidUI(); updateVTPaidBadge(); });
}

function handleDragOver(e)  { e.preventDefault(); document.getElementById('upload-zone').classList.add('dragover'); }
function handleDragLeave()  { document.getElementById('upload-zone').classList.remove('dragover'); }
function handleDrop(e) { e.preventDefault(); document.getElementById('upload-zone').classList.remove('dragover'); const f=e.dataTransfer.files[0]; if(f) processFile(f); }
function handleFileUpload(e) { const f=e.target.files[0]; if(f) processFile(f); e.target.value=''; }

function processFile(file) {
  const ext = file.name.toLowerCase().split('.').pop();
  const badge = document.getElementById('upload-badge');
  badge.textContent = file.name; badge.style.display = '';
  if (ext==='xlsx'||ext==='xls') readXLSX(file);
  else if (ext==='json') readText(file,'json');
  else readText(file, ext);
}

function readText(file, ext) {
  const r = new FileReader();
  r.onload = e => loadIOCsToInput(parseFromFileContent(e.target.result, ext));
  r.readAsText(file);
}

function readXLSX(file) {
  const r = new FileReader();
  r.onload = e => {
    const wb = XLSX.read(new Uint8Array(e.target.result), { type:'array' });
    const sheet = wb.Sheets[wb.SheetNames[0]];
    const rows = XLSX.utils.sheet_to_json(sheet, { header:1 });
    const iocFields = ['ioc','indicator','value','ip','domain','url','hash','md5','sha1','sha256','sha512','email','observable'];
    let values = [];
    if (rows.length > 0) {
      const header = rows[0].map(h => String(h||'').toLowerCase().trim());
      const cols = header.reduce((a,h,i) => { if(iocFields.some(f=>h.includes(f))) a.push(i); return a; }, []);
      if (cols.length > 0) { for (let row=1; row<rows.length; row++) cols.forEach(c => { const v=rows[row][c]; if(v) values.push(String(v).trim()); }); }
      else values = rows.flat().filter(Boolean).map(v=>String(v).trim());
    }
    loadIOCsToInput(values.join('\n'));
  };
  r.readAsArrayBuffer(file);
}

function loadIOCsToInput(text) {
  const firstTab = document.querySelector('.input-tab');
  if (firstTab) switchInputTab('text', firstTab);
  document.getElementById('ioc-input').value = text;
  parseIOCsRealtime();
  showToast('File loaded — IOCs extracted', 'success');
}
