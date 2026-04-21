
let scanResults   = [];
let isScanning    = false;
let stopRequested = false;
let totalScanned  = 0;

const VtBucket = {
  tokens: 4, max: 4, refillRate: 4,
  lastRefill: Date.now(), paid: false,
  async acquire() {
    if (this.paid) return;
    const now = Date.now();
    this.tokens = Math.min(this.max, this.tokens + ((now - this.lastRefill) / 60000) * this.refillRate);
    this.lastRefill = now;
    if (this.tokens >= 1) { this.tokens--; return; }
    const waitMs = ((1 - this.tokens) / this.refillRate) * 60000;
    updateProgressSub(`VT rate limit — waiting ${Math.ceil(waitMs/1000)}s…`);
    await sleep(waitMs);
    this.tokens = 0; this.lastRefill = Date.now();
  }
};

async function fetchWithRetry(fn, retries=2, ms=8000) {
  for (let i=0; i<=retries; i++) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), ms);
      const r = await fn(ctrl.signal);
      clearTimeout(t); return r;
    } catch(e) {
      if (i === retries) throw e;
      if (e.name === 'AbortError') throw new Error('Timeout');
      await sleep(1000*(i+1));
    }
  }
}

async function startScan() {
  const raw = getInputText();
  if (!raw?.trim()) return;

  const { iocs, logDetected } = parseIOCsWithMeta(raw);
  if (!iocs.length) { showToast('No valid IOCs detected', 'error'); return; }

  if (logDetected) showToast(`Log detected — extracted ${iocs.length} IOCs`, 'info');

  const privateCount = iocs.filter(i => i.isPrivate).length;
  if (privateCount > 0) showToast(`${privateCount} private IP${privateCount>1?'s':''} detected — will skip external queries`, 'warning');

  const paid = SERVER_MODE ? (window._serverVTPaid === true) : isVTPaid();
  VtBucket.paid = paid; VtBucket.tokens = 4; VtBucket.lastRefill = Date.now();

  isScanning = true; stopRequested = false; scanResults = []; totalScanned = 0;

  for (const ioc of iocs) {
    scanResults.push({ ioc, vt:null, ab:null, otx:null, mb:null, uh:null, shodan:null,
      verdict:null, confidence:null, action:null, score:null,
      reasons:[], indicators:[], firstSeen:null, lastSeen:null, done:false });
  }

  document.getElementById('results-panel').style.display = '';
  document.getElementById('progress-container').style.display = '';
  setScanBtnState('scanning');

  document.getElementById('rate-note-text').textContent = paid
    ? 'Parallel · VT Paid — no rate limit'
    : 'Parallel · VT Free — token bucket (4 req/min)';

  renderResultRows(scanResults);
  renderSummary(scanResults);
  updateResultsMeta(scanResults);

  for (let i=0; i<iocs.length; i++) {
    if (stopRequested) break;
    const ioc = iocs[i], entry = scanResults[i];
    updateProgress(i, iocs.length, ioc.value);
    updateRowLoading(i);
    await runParallelScan(entry);
    const scored = scoreEntry(entry);
    Object.assign(entry, scored, { done:true });
    totalScanned++;
    updateRow(i, entry);
    renderSummary(scanResults);
    updateResultsMeta(scanResults);
    updateHeaderCount();
  }

  isScanning = false;
  updateProgress(totalScanned, iocs.length, stopRequested ? 'Stopped' : 'Complete');
  setScanBtnState('idle');
  setTimeout(() => { document.getElementById('progress-container').style.display='none'; }, 2000);
  showToast(stopRequested ? `Stopped — ${totalScanned} IOCs analyzed` : `VERDIKT complete — ${iocs.length} IOCs analyzed`, 'success');
}

async function runParallelScan(entry) {
  const { ioc } = entry;

  if (ioc.isPrivate) {
    const skip = s => ({ source:s, skipped:true, reason:'Private IP — skipped' });
    entry.vt     = skip('virustotal');
    entry.ab     = skip('abuseipdb');
    entry.otx    = skip('otx');
    entry.mb     = skip('malwarebazaar');
    entry.shodan = skip('shodan');
    return;
  }

  const vtP = (async () => {
    if (!SERVER_MODE && !getKey('vt')) return { source:'virustotal', skipped:true, reason:'No API key' };
    await VtBucket.acquire();
    return fetchWithRetry(sig => API.virusTotal(ioc, sig)).catch(e => ({ source:'virustotal', error:e.message }));
  })();

  const abP = (async () => {
    if (!SERVER_MODE && !getKey('ab')) return { source:'abuseipdb', skipped:true, reason:'No API key' };
    if (ioc.baseType !== 'ip') return { source:'abuseipdb', skipped:true, reason:'IPv4/IPv6 only' };
    return fetchWithRetry(sig => API.abuseIPDB(ioc, sig)).catch(e => ({ source:'abuseipdb', error:e.message }));
  })();

  const otxP = (async () => {
    if (!SERVER_MODE && !getKey('otx')) return { source:'otx', skipped:true, reason:'No API key' };
    return fetchWithRetry(sig => API.otx(ioc, sig)).catch(e => ({ source:'otx', error:e.message }));
  })();

  const mbP = (() => {
    if (!ioc.type.startsWith('hash') || ioc.type === 'hash_sha512')
      return Promise.resolve({ source:'malwarebazaar', skipped:true, reason:`N/A for ${ioc.label}` });
    return fetchWithRetry(sig => API.malwareBazaar(ioc, sig)).catch(e => ({ source:'malwarebazaar', error:e.message }));
  })();

  const uhP = (() => {
    if (ioc.type !== 'url' && ioc.type !== 'hash_sha256')
      return Promise.resolve({ source:'urlhaus', skipped:true, reason:'URLs & SHA256 only' });
    return fetchWithRetry(sig => API.urlhaus(ioc, sig)).catch(e => ({ source:'urlhaus', error:e.message }));
  })();

  const shP = ioc.baseType === 'ip'
    ? fetchWithRetry(sig => API.shodan(ioc, sig)).catch(e => ({ source:'shodan', error:e.message }))
    : Promise.resolve({ source:'shodan', skipped:true, reason:'IPv4 only' });

  const [vt, ab, otx, mb, uh, shodan] = await Promise.all([vtP, abP, otxP, mbP, uhP, shP]);
  entry.vt=vt; entry.ab=ab; entry.otx=otx; entry.mb=mb; entry.uh=uh; entry.shodan=shodan;

  entry.firstSeen = extractFirstSeen(mb, uh);
  entry.lastSeen  = extractLastSeen(vt, ab, mb, uh);
}

function extractFirstSeen(mb, uh) {
  const dates = [];
  if (mb?.firstSeen) dates.push(mb.firstSeen);
  if (mb?.dateAdded) dates.push(mb.dateAdded);
  if (uh?.firstSeen) dates.push(uh.firstSeen);
  if (uh?.dateAdded) dates.push(uh.dateAdded);
  return dates.sort()[0] || null;
}
function extractLastSeen(vt, ab, mb, uh) {
  const dates = [];
  if (vt?.last_analysis_date) dates.push(vt.last_analysis_date);
  if (ab?.lastReportedAt) dates.push(ab.lastReportedAt?.split('T')[0]);
  if (mb?.lastSeen) dates.push(mb.lastSeen);
  if (uh?.lastSeen) dates.push(uh.lastSeen);
  return dates.sort().reverse()[0] || null;
}

function maxScoreForType(type) {
  let max = 15;
  if (type !== 'email') max += 40;
  if (type === 'ip' || type === 'ipv6') max += 30;
  if (type === 'hash_md5' || type === 'hash_sha1' || type === 'hash_sha256') max += 10;
  if (type === 'url' || type === 'hash_sha256') max += 10;
  if (type === 'ip') max += 8;
  return max;
}

function scoreEntry(entry) {
  const { vt, ab, otx, mb, uh, shodan } = entry;
  let score = 0;
  const reasons = [], indicators = [];
  let sourcesChecked=0, sourcesMalicious=0, sourcesSuspicious=0;

  if (vt && !vt.skipped && !vt.error) {
    const mal=vt.malicious||0, tot=vt.total||0;
    if (tot > 0) {
      sourcesChecked++;
      score += Math.round((mal/tot)*40);
      indicators.push(`VT: ${mal}/${tot} engines`);
      if (mal>0) { sourcesMalicious++; reasons.push(`Detected by ${mal} engine${mal>1?'s':''} on VirusTotal`); }
    }
    if (vt.reputation != null && vt.reputation < -10) score += Math.min(10, Math.abs(vt.reputation)/5);
  }

  if (ab && !ab.skipped && !ab.error) {
    sourcesChecked++;
    const s = ab.score||0;
    score += Math.round((s/100)*30);
    indicators.push(`AbuseIPDB: ${s}% abuse score`);
    if (s>=75) { sourcesMalicious++; reasons.push(`High abuse score (${s}%) from AbuseIPDB`); }
    else if (s>=25) { sourcesSuspicious++; reasons.push(`Moderate abuse score (${s}%) on AbuseIPDB`); }
  }

  if (otx && !otx.skipped && !otx.error) {
    sourcesChecked++;
    const p=otx.pulseCount||0;
    score += Math.min(15, Math.round((p/10)*15));
    if (p>0) {
      indicators.push(`OTX: ${p} pulse${p>1?'s':''}`);
      if (p>=5) { sourcesMalicious++; reasons.push(`Listed in ${p} OTX threat pulses`); }
      else { sourcesSuspicious++; reasons.push(`Found in ${p} OTX threat feed${p>1?'s':''}`); }
    }
  }

  const mbHit = mb && !mb.skipped && !mb.error && !mb.notFound;
  const uhHit = uh && !uh.skipped && !uh.error && !uh.notFound;
  if (mbHit) {
    sourcesChecked++; score += 10; sourcesMalicious++;
    indicators.push('MalwareBazaar: found');
    reasons.push(`Listed in MalwareBazaar${mb.signature?` as ${mb.signature}`:mb.fileType?` (${mb.fileType})`:''}`);
  }
  if (uhHit) {
    sourcesChecked++; score += 10; sourcesMalicious++;
    indicators.push('URLhaus: found');
    reasons.push(`Listed in URLhaus${uh.threat?` (${uh.threat})`:uh.urlStatus?` — ${uh.urlStatus}`:''}`);
  }

  if (shodan && !shodan.skipped && !shodan.error) {
    const cves=shodan.cves?.length||0;
    const ports=shodan.ports?.length||0;
    const threatTag=shodan.tags?.find(t=>['tor','honeypot','malware'].includes(t));
    if (cves>0||ports>0||threatTag) {
      sourcesChecked++;
      if (cves>0) { score+=Math.min(5,cves); indicators.push(`Shodan: ${cves} CVE${cves>1?'s':''}`); reasons.push(`${cves} known CVE${cves>1?'s':''} on Shodan`); }
      if (threatTag) { score+=3; reasons.push(`Flagged as ${threatTag} on Shodan`); }
      if (ports>0) indicators.push(`Shodan: ${shodan.ports.slice(0,4).join(',')} open`);
    }
  }

  const maxPossible = maxScoreForType(entry.ioc.type);
  score = Math.min(100, Math.round((score / maxPossible) * 100));

  const abScore=(ab&&!ab.skipped&&!ab.error)?(ab.score||0):0;
  const vtMal=(vt&&!vt.skipped&&!vt.error)?(vt.malicious||0):0;
  const anyFreeHit=(mb&&!mb.skipped&&!mb.error&&!mb.notFound)||(uh&&!uh.skipped&&!uh.error&&!uh.notFound);

  let verdict, action;
  if (abScore>=75||vtMal>=5||anyFreeHit||score>=60||sourcesMalicious>=2) { verdict='malicious'; action='block'; }
  else if (score>=25||sourcesSuspicious>=1||sourcesMalicious>=1||vtMal>=1||abScore>=25)  { verdict='suspicious'; action='investigate'; }
  else if (sourcesChecked>=1) { verdict='clean'; action='allow'; }
  else { verdict='unknown'; action='monitor'; }

  const keySourcesRan = (vt&&!vt.skipped&&!vt.error) || (ab&&!ab.skipped&&!ab.error) || (otx&&!otx.skipped&&!otx.error);
  const freeSourceHit = anyFreeHit;
  if (!keySourcesRan && !freeSourceHit && verdict==='clean') { verdict='unknown'; action='monitor'; }

  let confidence;
  if (sourcesChecked===0) confidence='low';
  else if (sourcesMalicious>=2||sourcesChecked>=3) confidence='high';
  else if (sourcesChecked>=2||sourcesMalicious>=1) confidence='medium';
  else confidence='low';

  const finalReasons=reasons.slice(0,2);
  if (!finalReasons.length) {
    if (!keySourcesRan && !freeSourceHit) {
      finalReasons.push('No API keys configured — add VT, AbuseIPDB or OTX keys to get verdicts');
    } else if (sourcesChecked>0) {
      finalReasons.push('No threat signals detected across checked sources');
    } else {
      finalReasons.push('No sources returned usable data');
    }
  }

  return { score, verdict, action, confidence, reasons:finalReasons, indicators };
}

function stopScan() { stopRequested=true; showToast('Stopping after current IOC…','warning'); }

function setScanBtnState(state) {
  const btn=document.getElementById('scan-btn'), stop=document.getElementById('stop-btn');
  if (state==='scanning') { btn.disabled=true; btn.style.display='none'; stop.style.display=''; }
  else {
    btn.disabled=false; btn.style.display=''; stop.style.display='none';
    btn.innerHTML=`<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="7" r="5" stroke="currentColor" stroke-width="1.5"/><path d="M7 4.5v2.5l1.8 1.8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg> ANALYZE`;
  }
}

function updateProgress(done, total, label) {
  const pct=total>0?Math.round((done/total)*100):0;
  document.getElementById('progress-fill').style.width=pct+'%';
  document.getElementById('progress-stats').textContent=`${done} / ${total}`;
  const complete=label==='Complete'||label==='Stopped'||done>=total;
  document.getElementById('progress-label').textContent=complete?'VERDIKT COMPLETE':'ANALYZING…';
  document.getElementById('progress-sub').innerHTML=complete
    ?`<span style="color:var(--accent)">✓ ${totalScanned} IOCs analyzed</span><span style="color:var(--muted)">${pct}%</span>`
    :`<span style="color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:70%">${escapeHtml(label)}</span><span style="color:var(--muted)">${pct}%</span>`;
}
function updateProgressSub(msg) { const el=document.getElementById('progress-sub'); if(el) el.innerHTML=`<span style="color:var(--yellow)">${escapeHtml(msg)}</span>`; }
function updateHeaderCount() { const el=document.getElementById('session-count'); if(el) el.textContent=totalScanned; }
function sleep(ms) { return new Promise(r=>setTimeout(r,ms)); }
