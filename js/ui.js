
let currentVerdictFilter = 'all';
let currentTypeFilter    = 'all';
let currentActionFilter  = 'all';
let currentSearch        = '';

function setMode(mode) {
  const show = id => { const el=document.getElementById(id); if(el) el.style.display=''; };
  const hide = id => { const el=document.getElementById(id); if(el) el.style.display='none'; };

  if (mode === 'server') {
    hide('api-panel'); show('server-banner'); hide('browser-banner');
    const btn=document.getElementById('mode-toggle-btn');
    if (btn) { btn.textContent='INPUT KEY MODE'; btn.dataset.mode='server'; }
    const badge=document.getElementById('mode-badge');
    if (badge) { badge.textContent='SERVER KEYS'; badge.className='mode-badge mode-server'; }
    const el=document.getElementById('footer-key-note'); if(el) el.textContent='Keys in Vercel env vars';
  } else {
    show('api-panel'); hide('server-banner'); show('browser-banner');
    const btn=document.getElementById('mode-toggle-btn');
    if (btn) { btn.textContent='SERVER KEY MODE'; btn.dataset.mode='input'; }
    const badge=document.getElementById('mode-badge');
    if (badge) { badge.textContent='INPUT KEYS'; badge.className='mode-badge mode-input'; }
    const el=document.getElementById('footer-key-note'); if(el) el.textContent='Keys in localStorage';
    loadSavedKeys(); updateStatusDots();
  }
}
function toggleMode() {
  const btn=document.getElementById('mode-toggle-btn');
  setMode((btn?.dataset.mode||'input')==='server'?'input':'server');
}

function scanSingleIOC() {
  const input = document.getElementById('single-ioc-input');
  const val = input?.value.trim();
  if (!val) return;
  document.getElementById('ioc-input').value = val;
  parseIOCsRealtime();
  startScan();
  input.value = '';
}

function renderResultRows(results) {
  document.getElementById('results-body').innerHTML = results.map((e,i) => buildRow(e,i)).join('');
  applyFilters();
}

function buildRow(entry, i) {
  const { ioc, verdict, action, score, confidence, reasons, indicators, firstSeen, lastSeen, done } = entry;
  const privateNote = ioc.isPrivate ? '<div class="ioc-private-badge">PRIVATE</div>' : '';
  const defangNote  = ioc.defanged  ? `<div class="ioc-defang-note" title="Defanged from: ${escapeAttr(ioc.defanged)}">defanged</div>` : '';
  const logNote     = ioc.fromLog   ? '<div class="ioc-log-badge">LOG</div>' : '';

  return `<tr data-row="${i}" data-verdict="${verdict||'pending'}" data-type="${ioc.baseType||''}" data-action="${action||''}" data-ioc="${escapeAttr(ioc.value.toLowerCase())}">
    <td class="td-ioc">
      <div class="ioc-val-wrap">
        <span class="ioc-val">${escapeHtml(truncate(ioc.value,52))}</span>
        <button class="ioc-copy-btn" onclick="copyToClipboard('${escapeAttr(ioc.value)}')" title="Copy">⎘</button>
      </div>
      ${privateNote}${defangNote}${logNote}
    </td>
    <td><span class="type-badge type-${ioc.baseType}">${ioc.label}</span></td>
    <td id="v-${i}">${buildVerdictCell(verdict, action, score, confidence, done)}</td>
    <td id="dec-${i}">${buildDecisionCell(action, reasons, done)}</td>
    <td id="ind-${i}">${buildIndicatorsCell(indicators, done)}</td>
    <td id="dates-${i}">${buildDatesCell(firstSeen, lastSeen, done)}</td>
    <td>${done?`<button class="btn-detail" onclick="openModal(${i})">DETAIL</button>`:'<span class="src-loading">…</span>'}</td>
  </tr>`;
}

function buildVerdictCell(verdict, action, score, confidence, done) {
  if (!done) return `<div class="verdict-pending-cell"><div class="vc-spinner"></div><span>Scanning…</span></div>`;
  const vMap = {
    malicious: { icon:'🔴', label:'MALICIOUS',  cls:'verdict-malicious' },
    suspicious:{ icon:'🟡', label:'SUSPICIOUS', cls:'verdict-suspicious' },
    clean:     { icon:'🟢', label:'CLEAN',      cls:'verdict-clean' },
    unknown:   { icon:'⚪', label:'UNKNOWN',    cls:'verdict-unknown' },
    error:     { icon:'⚫', label:'ERROR',      cls:'verdict-error' },
  };
  const v = vMap[verdict] || vMap.unknown;
  const confColor = { high:'var(--accent)', medium:'var(--yellow)', low:'var(--muted)' }[confidence] || 'var(--muted)';
  return `<div class="verdict-cell">
    <span class="verdict-badge ${v.cls}">${v.icon} ${v.label}</span>
    <div class="vc-meta">
      <span class="vc-score" title="Risk score 0–100">${score!=null?score:'—'}<span class="vc-score-unit">/100</span></span>
      <span class="vc-conf" style="color:${confColor}">${(confidence||'—').toUpperCase()}</span>
    </div>
  </div>`;
}

function buildDecisionCell(action, reasons, done) {
  if (!done) return '<span class="src-loading">…</span>';
  const aMap = {
    block:       { icon:'🚫', label:'BLOCK IMMEDIATELY', cls:'action-block' },
    investigate: { icon:'🔍', label:'INVESTIGATE',       cls:'action-investigate' },
    allow:       { icon:'✅', label:'ALLOW',             cls:'action-allow' },
    monitor:     { icon:'⏳', label:'MONITOR',           cls:'action-monitor' },
  };
  const a = aMap[action] || aMap.monitor;
  const reason = reasons?.[0] ? escapeHtml(reasons[0]) : '—';
  return `<div class="decision-cell">
    <span class="action-badge ${a.cls}">${a.icon} ${a.label}</span>
    <div class="dc-reason" title="${escapeAttr(reasons?.[0]||'')}">${reason}</div>
  </div>`;
}

function buildIndicatorsCell(indicators, done) {
  if (!done) return '<span class="src-loading">…</span>';
  let html = '';
  if (indicators?.length) {
    html += indicators.map(ind => `<span class="indicator-chip">${escapeHtml(ind)}</span>`).join('');
  }
  return html ? `<div class="indicators-cell">${html}</div>` : '<span class="src-na">No signals</span>';
}

function buildDatesCell(firstSeen, lastSeen, done) {
  if (!done) return '<span class="src-loading">…</span>';
  if (!firstSeen && !lastSeen) return '<span class="src-na">—</span>';
  let html = '';
  if (firstSeen) html += `<div class="date-row"><span class="date-lbl">FIRST</span><span class="date-val">${escapeHtml(firstSeen)}</span></div>`;
  if (lastSeen)  html += `<div class="date-row"><span class="date-lbl">LAST</span><span class="date-val">${escapeHtml(lastSeen)}</span></div>`;
  return `<div class="dates-cell">${html}</div>`;
}

function updateRow(i, entry) {
  const row = document.querySelector(`tr[data-row="${i}"]`); if(!row) return;
  row.dataset.verdict = entry.verdict||'pending';
  row.dataset.action  = entry.action||'';
  const $ = (id, html) => { const el=document.getElementById(id); if(el) el.innerHTML=html; };
  $(`v-${i}`,     buildVerdictCell(entry.verdict,entry.action,entry.score,entry.confidence,true));
  $(`dec-${i}`,   buildDecisionCell(entry.action,entry.reasons,true));
  $(`ind-${i}`,   buildIndicatorsCell(entry.indicators,true));
  $(`dates-${i}`, buildDatesCell(entry.firstSeen,entry.lastSeen,true));
  const tds = row.querySelectorAll('td');
  if (tds[6]) tds[6].innerHTML = `<button class="btn-detail" onclick="openModal(${i})">DETAIL</button>`;
  applyFilters();
}
function updateRowLoading(i) {
  const row=document.querySelector(`tr[data-row="${i}"]`); if(!row) return;
  row.style.background='rgba(0,255,159,0.025)';
  setTimeout(()=>{ if(row) row.style.background=''; },400);
}

function renderDecisionPanel(results) {
  const done = results.filter(r=>r.done);
  const cnt = { block:0, investigate:0, allow:0, monitor:0 };
  done.forEach(r => { if(cnt[r.action]!==undefined) cnt[r.action]++; });

  const el = document.getElementById('decision-panel');
  if (!el) return;

  if (!done.length) { el.style.display='none'; return; }
  el.style.display='';
  el.innerHTML = `
    <div class="dp-title">QUICK DECISION PANEL</div>
    <div class="dp-actions">
      <button class="dp-action dp-block ${currentActionFilter==='block'?'active':''}" onclick="filterByAction('block',this)">
        <span class="dp-icon">🚫</span>
        <span class="dp-num">${cnt.block}</span>
        <span class="dp-lbl">BLOCK</span>
      </button>
      <button class="dp-action dp-investigate ${currentActionFilter==='investigate'?'active':''}" onclick="filterByAction('investigate',this)">
        <span class="dp-icon">🔍</span>
        <span class="dp-num">${cnt.investigate}</span>
        <span class="dp-lbl">INVESTIGATE</span>
      </button>
      <button class="dp-action dp-allow ${currentActionFilter==='allow'?'active':''}" onclick="filterByAction('allow',this)">
        <span class="dp-icon">✅</span>
        <span class="dp-num">${cnt.allow}</span>
        <span class="dp-lbl">ALLOW</span>
      </button>
      <button class="dp-action dp-monitor ${currentActionFilter==='monitor'?'active':''}" onclick="filterByAction('monitor',this)">
        <span class="dp-icon">⏳</span>
        <span class="dp-num">${cnt.monitor}</span>
        <span class="dp-lbl">MONITOR</span>
      </button>
      ${currentActionFilter!=='all'?`<button class="dp-clear" onclick="filterByAction('all',this)">✕ SHOW ALL</button>`:''}
    </div>`;
}

function renderSummary(results) {
  const done=results.filter(r=>r.done);
  const cnt={malicious:0,suspicious:0,clean:0,unknown:0};
  const scores=[];
  done.forEach(r=>{ if(cnt[r.verdict]!==undefined)cnt[r.verdict]++; if(r.score!=null)scores.push(r.score); });
  const avg=scores.length?Math.round(scores.reduce((a,b)=>a+b,0)/scores.length):null;

  document.getElementById('summary-strip').innerHTML=`
    <div class="summary-card sc-total"><div class="sc-icon">📊</div><div><div class="summary-num">${results.length}</div><div class="summary-lbl">TOTAL</div></div></div>
    <div class="summary-card sc-malicious"><div class="sc-icon">🔴</div><div><div class="summary-num">${cnt.malicious}</div><div class="summary-lbl">MALICIOUS</div></div></div>
    <div class="summary-card sc-suspicious"><div class="sc-icon">🟡</div><div><div class="summary-num">${cnt.suspicious}</div><div class="summary-lbl">SUSPICIOUS</div></div></div>
    <div class="summary-card sc-clean"><div class="sc-icon">🟢</div><div><div class="summary-num">${cnt.clean}</div><div class="summary-lbl">CLEAN</div></div></div>
    <div class="summary-card sc-unknown"><div class="sc-icon">⚪</div><div><div class="summary-num">${cnt.unknown}</div><div class="summary-lbl">UNKNOWN</div></div></div>
    <div class="summary-card sc-score"><div class="sc-icon">⚡</div><div><div class="summary-num">${avg!=null?avg:'—'}</div><div class="summary-lbl">AVG RISK</div></div></div>`;

  renderDecisionPanel(results);
}

function updateResultsMeta(results) {
  const done=results.filter(r=>r.done).length;
  document.getElementById('results-meta').innerHTML=`<span>${done}</span> / ${results.length} analyzed`;
}

function filterResults(v,btn) { currentVerdictFilter=v; document.querySelectorAll('[data-filter]').forEach(b=>b.classList.remove('active')); btn.classList.add('active'); applyFilters(); }
function filterByType(t,btn)  { currentTypeFilter=t; document.querySelectorAll('[data-type-filter]').forEach(b=>b.classList.remove('active')); btn.classList.add('active'); applyFilters(); }
function filterByAction(a,btn){ currentActionFilter=a; applyFilters(); renderDecisionPanel(scanResults); }
function searchResults(val)   { currentSearch=val.toLowerCase(); applyFilters(); }

function applyFilters() {
  document.querySelectorAll('#results-body tr').forEach(row => {
    const ok = (currentVerdictFilter==='all'||row.dataset.verdict===currentVerdictFilter)
            && (currentTypeFilter==='all'||row.dataset.type===currentTypeFilter)
            && (currentActionFilter==='all'||row.dataset.action===currentActionFilter)
            && (!currentSearch||(row.dataset.ioc||'').includes(currentSearch));
    row.classList.toggle('hidden',!ok);
  });
}

function openModal(i) {
  const e=scanResults[i]; if(!e) return;
  document.getElementById('modal-title').innerHTML=`
    <span style="color:var(--muted);font-size:10px;letter-spacing:1px">VERDIKT DETAIL</span>
    <span style="margin:0 8px;color:var(--border)">·</span>
    <span style="color:var(--accent2)">${e.ioc.label}</span>`;
  document.getElementById('modal-body').innerHTML = buildModalContent(e);
  document.getElementById('modal-overlay').classList.add('open');
}
function closeModal() { document.getElementById('modal-overlay').classList.remove('open'); }

function buildModalContent(entry) {
  const { ioc, verdict, action, score, confidence, reasons, indicators, firstSeen, lastSeen, vt, ab, otx, mb, uh, shodan } = entry;

  const vMap = { malicious:{icon:'🔴',cls:'verdict-malicious'}, suspicious:{icon:'🟡',cls:'verdict-suspicious'}, clean:{icon:'🟢',cls:'verdict-clean'}, unknown:{icon:'⚪',cls:'verdict-unknown'} };
  const aMap = { block:{icon:'🚫',cls:'action-block'}, investigate:{icon:'🔍',cls:'action-investigate'}, allow:{icon:'✅',cls:'action-allow'}, monitor:{icon:'⏳',cls:'action-monitor'} };
  const v=vMap[verdict]||vMap.unknown, a=aMap[action]||aMap.monitor;

  const privateNote = ioc.isPrivate ? `<div class="modal-private-note">⚠ Private IP address — external source queries were skipped</div>` : '';
  const defangNote  = ioc.defanged  ? `<div class="modal-defang-note">Defanged from: <code>${escapeHtml(ioc.defanged)}</code></div>` : '';
  const logNote     = ioc.fromLog   ? `<div class="modal-log-note">Extracted from log/raw text</div>` : '';

  let html = `
    <div class="modal-ioc">
      <span class="modal-ioc-val">${escapeHtml(ioc.value)}</span>
      <button class="modal-copy-btn" onclick="copyToClipboard('${escapeAttr(ioc.value)}')" title="Copy">⎘ Copy</button>
    </div>
    ${privateNote}${defangNote}${logNote}

    <div class="modal-verdict-card">
      <div class="mvc-left">
        <div class="mvc-verdict"><span class="verdict-badge ${v.cls}">${v.icon} ${(verdict||'unknown').toUpperCase()}</span></div>
        <div class="mvc-action"><span class="action-badge ${a.cls}">${a.icon} ${(action||'monitor').toUpperCase()}</span></div>
      </div>
      <div class="mvc-center">
        <div class="mvc-score-block">
          <div class="mvc-score-num">${score!=null?score:'—'}</div>
          <div class="mvc-score-bar"><div class="mvc-score-fill" style="width:${score||0}%;background:${scoreColor(score)}"></div></div>
          <div class="mvc-score-label">RISK SCORE / 100</div>
        </div>
      </div>
      <div class="mvc-right">
        <div class="mvc-conf-block">
          <div class="mvc-conf-val" style="color:${confColor(confidence)}">${(confidence||'—').toUpperCase()}</div>
          <div class="mvc-conf-label">CONFIDENCE</div>
        </div>
        ${firstSeen||lastSeen ? `<div class="mvc-dates">
          ${firstSeen?`<div class="mvc-date-item"><span class="mvc-date-label">First seen</span><span class="mvc-date-val">${firstSeen}</span></div>`:''}
          ${lastSeen?`<div class="mvc-date-item"><span class="mvc-date-label">Last seen</span><span class="mvc-date-val">${lastSeen}</span></div>`:''}
        </div>` : ''}
      </div>
    </div>

    <div class="modal-evidence-row">
      <div class="modal-reasons-block">
        <div class="modal-section-label">REASON SUMMARY</div>
        ${reasons?.map(r=>`<div class="modal-reason-line">• ${escapeHtml(r)}</div>`).join('')||'<div class="modal-reason-line" style="color:var(--muted)">No signals detected</div>'}
      </div>
      <div class="modal-indicators-block">
        <div class="modal-section-label">KEY INDICATORS</div>
        <div class="modal-indicators-grid">
          ${indicators?.length?indicators.map(ind=>`<span class="indicator-chip">${escapeHtml(ind)}</span>`).join(''):'<span style="color:var(--muted);font-size:13px">—</span>'}
        </div>
      </div>
    </div>

    <div class="modal-sources-divider"></div>`;

  if (vt)     html += modalSource('VIRUSTOTAL',       'var(--vt)',  vt,  vtRows(vt),     vt.tags,  vt.link,    '↗ VT');
  if (ab)     html += modalSource('ABUSEIPDB',        'var(--ab)',  ab,  abRows(ab),     [],        ab.link,    '↗ AbuseIPDB');
  if (otx)    html += modalSource('ALIENVAULT OTX',   'var(--otx)', otx, otxRows(otx),  otx.tags,  otx.link,   '↗ OTX');
  if (mb)     html += modalSource('MALWAREBAZAAR', 'var(--mb)', mb, mbRows(mb), mb.tags, mb.link, '↗ Bazaar');
  if (uh)     html += modalSource('URLHAUS',       'var(--uh)', uh, uhRows(uh), uh.tags, uh.link, '↗ URLhaus');
  if (shodan) html += modalSource('SHODAN INTERNETDB','var(--sh)',  shodan, shRows(shodan), [], shodan.link, '↗ Shodan');

  return html;
}

function scoreColor(s) {
  if (!s) return 'var(--muted)';
  if (s>=60) return 'var(--red)'; if (s>=25) return 'var(--yellow)'; return 'var(--green)';
}
function confColor(c) { return {high:'var(--accent)',medium:'var(--yellow)',low:'var(--muted)'}[c]||'var(--muted)'; }

function modalSource(title, color, r, bodyRows, tags, link, linkLabel) {
  if (!r) return '';
  if (r.skipped) return `<div class="modal-source-block">
    <div class="modal-source-title" style="color:${color}">${escapeHtml(title)}<span class="mst-skip"> — ${escapeHtml(r.reason||'Skipped')}</span></div></div>`;
  const tagsHtml = tags?.length?`<div class="modal-tags">${tags.map(t=>`<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>`:'';
  const linkHtml = link?`<a class="modal-link" href="${link}" target="_blank" rel="noopener">${linkLabel}</a>`:'';
  return `<div class="modal-source-block">
    <div class="modal-source-title" style="color:${color}"><span>${escapeHtml(title)}</span>${linkHtml}</div>
    <div class="modal-kv-grid">${r.error?kv('Error',r.error,'val-malicious'):bodyRows}</div>${tagsHtml}
  </div>`;
}

function vtRows(r) {
  if (!r||r.skipped||r.error) return '';
  let s=kv('Detection',r.score,vc(r.verdict));
  s+=kv('Malicious engines',r.malicious); s+=kv('Total engines',r.total);
  if (r.reputation!=null) s+=kv('Reputation',r.reputation);
  if (r.country) s+=kv('Country',r.country);
  if (r.asn) s+=kv('ASN',`${r.asn}${r.as_owner?' — '+r.as_owner:''}`);
  if (r.file_type) s+=kv('File type',r.file_type);
  if (r.file_name) s+=kv('File name',r.file_name);
  if (r.file_size) s+=kv('File size',formatBytes(r.file_size));
  if (r.last_analysis_date) s+=kv('Last scan',r.last_analysis_date);
  if (r.threat_names?.length) s+=kv('Threats',r.threat_names.join(', '));
  return s;
}
function abRows(r) {
  if (!r||r.skipped||r.error) return '';
  let s=kv('Abuse score',`${r.score}%`,vc(r.verdict));
  s+=kv('Total reports',r.totalReports); s+=kv('Distinct users',r.numDistinctUsers);
  if (r.lastReportedAt) s+=kv('Last reported',r.lastReportedAt?.split('T')[0]);
  if (r.isp) s+=kv('ISP',r.isp); if (r.usageType) s+=kv('Usage type',r.usageType);
  if (r.country) s+=kv('Country',r.country);
  s+=kv('TOR exit node',r.isTor?'Yes':'No',r.isTor?'val-malicious':'');
  return s;
}
function otxRows(r) {
  if (!r||r.skipped||r.error) return '';
  let s=kv('Pulse count',r.pulseCount,vc(r.verdict));
  if (r.country) s+=kv('Country',r.country); if (r.asn) s+=kv('ASN',r.asn);
  if (r.recentPulse) s+=kv('Latest pulse',truncate(r.recentPulse,60));
  if (r.malwareFamilies?.length) s+=kv('Malware families',r.malwareFamilies.join(', '));
  if (r.adversaries?.length) s+=kv('Adversaries',r.adversaries.join(', '));
  return s;
}
function mbRows(r) {
  if (!r||r.skipped||r.error) return '';
  if (r.notFound) return kv('Status','Not in database');
  let s='';
  if (r.fileName) s+=kv('File name',r.fileName);
  if (r.fileType) s+=kv('File type',r.fileType);
  if (r.fileSize) s+=kv('File size',formatBytes(r.fileSize));
  if (r.firstSeen||r.dateAdded) s+=kv('First seen',r.firstSeen||r.dateAdded);
  if (r.lastSeen) s+=kv('Last seen',r.lastSeen);
  if (r.signature) s+=kv('Signature',r.signature,'val-malicious');
  if (r.reporter) s+=kv('Reporter',r.reporter);
  if (r.clamav?.length) s+=kv('ClamAV',r.clamav.join(', '));
  return s;
}
function uhRows(r) {
  if (!r||r.skipped||r.error) return '';
  if (r.notFound) return kv('Status','Not in database');
  let s='';
  if (r.urlStatus) s+=kv('URL status',r.urlStatus,r.urlStatus==='online'?'val-malicious':'');
  if (r.threat) s+=kv('Threat',r.threat,'val-malicious');
  if (r.host) s+=kv('Host',r.host);
  if (r.dateAdded||r.firstSeen) s+=kv('First seen',r.dateAdded||r.firstSeen);
  if (r.lastSeen) s+=kv('Last seen',r.lastSeen);
  if (r.fileType) s+=kv('File type',r.fileType);
  if (r.fileSize) s+=kv('File size',formatBytes(r.fileSize));
  if (r.urlCount) s+=kv('URLs with hash',r.urlCount);
  if (r.signature) s+=kv('Signature',r.signature,'val-malicious');
  if (r.reporter) s+=kv('Reporter',r.reporter);
  return s;
}
function shRows(r) {
  if (!r||r.skipped||r.error) return '';
  if (!r.ports?.length&&!r.cves?.length) return kv('Status','Not indexed');
  let s='';
  if (r.isp) s+=kv('ISP',r.isp);
  if (r.hostnames?.length) s+=kv('Hostnames',r.hostnames.slice(0,3).join(', '));
  if (r.ports?.length) s+=kv('Open ports',r.ports.join(', '));
  if (r.tags?.length) s+=kv('Tags',r.tags.join(', '),r.tags.some(t=>['malware','honeypot','tor'].includes(t))?'val-malicious':'');
  if (r.cves?.length) s+=kv(`CVEs (${r.cves.length})`,r.cves.slice(0,8).join(', '),'val-malicious');
  return s;
}
function kv(k,v,cls='') { return `<div class="modal-k">${escapeHtml(k)}</div><div class="modal-v ${cls}">${escapeHtml(String(v??'—'))}</div>`; }
function vc(v) { return {malicious:'val-malicious',suspicious:'val-suspicious',clean:'val-clean'}[v]||''; }

function renderBreakdown(iocs) {
  if (!iocs.length) {
    document.getElementById('ioc-breakdown').style.display='none';
    document.getElementById('ioc-parsed-info').innerHTML='';
    document.getElementById('scan-count').innerHTML='';
    document.getElementById('scan-btn').disabled=true;
    return;
  }
  const { logDetected } = parseIOCsWithMeta(document.getElementById('ioc-input').value);
  const breakdown=getIOCBreakdown(iocs);
  document.getElementById('ioc-breakdown').style.display='';

  const logBadge = logDetected ? '<span class="log-extract-badge">LOG DETECTED — auto-extracting IOCs</span>' : '';
  const privateCount = iocs.filter(i=>i.isPrivate).length;
  const privateBadge = privateCount>0 ? `<span class="private-warn-badge">⚠ ${privateCount} private IP${privateCount>1?'s':''}</span>` : '';
  const defangedCount = iocs.filter(i=>i.defanged).length;
  const defangBadge = defangedCount>0 ? `<span class="defang-badge">🔧 ${defangedCount} defanged</span>` : '';

  document.getElementById('breakdown-chips').innerHTML =
    Object.entries(breakdown).map(([t,c])=>`<div class="bc-chip"><span class="bc-type">${t.toUpperCase()}</span><span class="bc-count">${c}</span></div>`).join('')
    + logBadge + privateBadge + defangBadge;

  document.getElementById('ioc-parsed-info').innerHTML=`Detected: <span>${iocs.length}</span> IOCs`;
  document.getElementById('scan-count').innerHTML=`<span>${iocs.length}</span> queued`;
  document.getElementById('scan-btn').disabled=false;
}

function togglePanel(id) {
  const body=document.getElementById(`${id}-body`), chev=document.getElementById(`${id}-chevron`);
  const hidden=body.style.display==='none'; body.style.display=hidden?'':'none';
  if(chev) chev.classList.toggle('closed',!hidden);
}
function switchInputTab(tab,btn) {
  document.querySelectorAll('.input-tab').forEach(b=>b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));
  btn.classList.add('active'); document.getElementById(`tab-${tab}`).classList.add('active');
}

function toggleKey(id) {
  const inp=document.getElementById(id);
  inp.type=inp.type==='password'?'text':'password';
  inp.nextElementSibling.textContent=inp.type==='password'?'SHOW':'HIDE';
}
function saveKeys() {
  ['vt','ab','otx','abch'].forEach(s=>{ const v=document.getElementById(`${s}-key`)?.value.trim(); if(v) localStorage.setItem(`tg_${s}_key`,v); });
  localStorage.setItem('tg_vt_paid',document.getElementById('vt-paid')?.checked?'1':'0');
  const proxy=document.getElementById('cors-proxy-url')?.value.trim();
  if(proxy) localStorage.setItem('tg_cors_proxy',proxy); else localStorage.removeItem('tg_cors_proxy');
  updateStatusDots();
  const msg=document.getElementById('key-saved-msg');
  msg.textContent='✓ Saved'; msg.classList.add('show');
  setTimeout(()=>msg.classList.remove('show'),3000);
}
function clearKeys() {
  ['tg_vt_key','tg_ab_key','tg_otx_key','tg_abch_key','tg_vt_paid','tg_cors_proxy'].forEach(k=>localStorage.removeItem(k));
  ['vt','ab','otx','abch'].forEach(s=>{ const el=document.getElementById(`${s}-key`); if(el) el.value=''; });
  const proxyEl=document.getElementById('cors-proxy-url'); if(proxyEl) proxyEl.value='';
  const paid=document.getElementById('vt-paid'); if(paid) paid.checked=false;
  updateVTPaidUI(); updateStatusDots();
  const msg=document.getElementById('key-saved-msg');
  msg.textContent='Cleared'; msg.classList.add('show');
  setTimeout(()=>msg.classList.remove('show'),2000);
}
function loadSavedKeys() {
  ['vt','ab','otx','abch'].forEach(s=>{ const v=localStorage.getItem(`tg_${s}_key`); const el=document.getElementById(`${s}-key`); if(v&&el) el.value=v; });
  const paid=document.getElementById('vt-paid'); if(paid) paid.checked=localStorage.getItem('tg_vt_paid')==='1';
  const proxy=localStorage.getItem('tg_cors_proxy'); const proxyEl=document.getElementById('cors-proxy-url'); if(proxy&&proxyEl) proxyEl.value=proxy;
  updateVTPaidUI(); updateStatusDots();
}
function updateVTPaidUI() {
  const paid=document.getElementById('vt-paid')?.checked;
  const note=document.getElementById('vt-tier-note'); if(note) note.textContent=paid?'Paid: ~500 req/min · no daily cap':'Free: 4 req/min · 500/day';
  const rn=document.getElementById('rate-note-text'); if(rn&&!isScanning) rn.textContent=paid?'VT Paid — fully parallel, no rate limit':'Parallel · VT Free — token bucket (4 req/min)';
}
function updateStatusDots() {
  if(SERVER_MODE) return;
  ['vt','ab','otx'].forEach(s=>{
    const has=!!getKey(s);
    const dot=document.querySelector(`#${s}-status .hstatus-dot`); if(!dot) return;
    dot.className='hstatus-dot '+(has?'on':'off');
    dot.style.background=has?`var(--${s})`:''; dot.style.boxShadow=has?`0 0 5px var(--${s})`:'';
  });
  const hasAbch=!!getKey('abch');
  ['mb','uh'].forEach(s=>{
    const dot=document.querySelector(`#${s}-status .hstatus-dot`); if(!dot) return;
    dot.className='hstatus-dot '+(hasAbch?'on':'off');
    dot.style.background=hasAbch?`var(--${s})`:''; dot.style.boxShadow=hasAbch?`0 0 5px var(--${s})`:'';
  });
}
function setServerStatusDots(status) {
  ['vt','ab','otx'].forEach(s=>{
    const has=!!status[s==='ab'?'abuseipdb':s];
    const dot=document.querySelector(`#${s}-status .hstatus-dot`); if(!dot) return;
    dot.className='hstatus-dot '+(has?'on':'off');
    dot.style.background=has?`var(--${s})`:''; dot.style.boxShadow=has?`0 0 5px var(--${s})`:'';
  });
  const hasAbch=!!status.abusech;
  ['mb','uh'].forEach(s=>{
    const dot=document.querySelector(`#${s}-status .hstatus-dot`); if(!dot) return;
    dot.className='hstatus-dot '+(hasAbch?'on':'off');
    dot.style.background=hasAbch?`var(--${s})`:''; dot.style.boxShadow=hasAbch?`0 0 5px var(--${s})`:'';
  });
}

function parseIOCsRealtime() { renderBreakdown(parseIOCs(document.getElementById('ioc-input').value)); }
function getInputText() { return document.getElementById('ioc-input').value; }

function clearAll() {
  document.getElementById('ioc-input').value='';
  document.getElementById('ioc-breakdown').style.display='none';
  document.getElementById('ioc-parsed-info').innerHTML='';
  document.getElementById('scan-count').innerHTML='';
  document.getElementById('scan-btn').disabled=true;
  document.getElementById('results-panel').style.display='none';
  const dp=document.getElementById('decision-panel'); if(dp) dp.style.display='none';
  scanResults=[]; currentVerdictFilter='all'; currentTypeFilter='all'; currentActionFilter='all'; currentSearch='';
}

let toastTO;
function showToast(msg,type='info') {
  let el=document.getElementById('toast');
  if(!el){el=document.createElement('div');el.id='toast';el.style.cssText='position:fixed;bottom:22px;right:22px;z-index:9999;padding:12px 20px;font-family:var(--mono);font-size:13px;border:1px solid;transition:opacity 0.3s;max-width:400px;background:var(--panel);border-radius:4px;';document.body.appendChild(el);}
  const c={success:'var(--accent)',error:'var(--red)',warning:'var(--yellow)',info:'var(--accent2)'};
  el.style.color=c[type]||c.info;el.style.borderColor=c[type]||c.info;
  el.textContent=msg;el.style.opacity='1';
  clearTimeout(toastTO);toastTO=setTimeout(()=>el.style.opacity='0',4500);
}

function escapeHtml(s){if(s==null)return'';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escapeAttr(s){if(s==null)return'';return String(s).replace(/'/g,"\\'").replace(/"/g,'&quot;');}
function truncate(s,n){if(!s)return'';return s.length>n?s.slice(0,n)+'…':s;}
function formatBytes(b){if(!b)return'—';const u=['B','KB','MB','GB'];const i=Math.floor(Math.log(b)/Math.log(1024));return`${(b/Math.pow(1024,i)).toFixed(1)} ${u[i]}`;}
function copyToClipboard(t){navigator.clipboard.writeText(t).then(()=>showToast('Copied','success'));}
