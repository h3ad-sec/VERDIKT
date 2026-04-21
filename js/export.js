
function exportResults(format) {
  if (!scanResults?.length) { showToast('No results', 'error'); return; }
  const done = scanResults.filter(r => r.done);
  if (!done.length) { showToast('Scan not complete', 'error'); return; }
  const ts = new Date().toISOString().slice(0,19).replace(/:/g,'-');
  const fn = `verdikt-${ts}`;
  if (format==='json') exportJSON(done, fn);
  else if (format==='csv') exportCSV(done, fn);
  else if (format==='xlsx') exportXLSX(done, fn);
}

function exportJSON(results, fn) {
  downloadBlob(new Blob([JSON.stringify(results.map(r=>buildExportRow(r,true)),null,2)],{type:'application/json'}),`${fn}.json`);
  showToast('JSON exported','success');
}

function exportCSV(results, fn) {
  const H = headers();
  const rows = results.map(r => { const row=buildExportRow(r,false); return H.map(h=>csvCell(row[h])); });
  downloadBlob(new Blob(['\ufeff'+[H.join(','),...rows.map(r=>r.join(','))].join('\n')],{type:'text/csv;charset=utf-8'}),`${fn}.csv`);
  showToast('CSV exported','success');
}

function exportXLSX(results, fn) {
  if (typeof XLSX==='undefined'){showToast('XLSX library not loaded','error');return;}
  const wb = XLSX.utils.book_new();

  const H = headers();
  const rows = results.map(r => { const row=buildExportRow(r,false); return H.map(h=>row[h]??''); });
  const wsData = XLSX.utils.aoa_to_sheet([H,...rows]);
  wsData['!cols'] = [42,10,12,6,10,9, 40,40,30, 15,10,8,10,10, 15,10,28, 8,36,36, 14,28, 14,28,40, 40,40,40,40,40].map(w=>({wch:w}));

  const range = XLSX.utils.decode_range(wsData['!ref']||'A1');
  for (let c=range.s.c; c<=range.e.c; c++) {
    const addr = XLSX.utils.encode_cell({r:0,c});
    if (!wsData[addr]) continue;
    wsData[addr].s = { font:{bold:true}, fill:{fgColor:{rgb:'0F1520'}} };
  }
  XLSX.utils.book_append_sheet(wb, wsData, 'IOC Results');

  const done = results.filter(r=>r.done);
  const cnt={malicious:0,suspicious:0,benign:0,unknown:0};
  const actionCnt={block:0,investigate:0,allow:0,monitor:0};
  const scores=[];
  done.forEach(r=>{
    if(cnt[r.verdict]!==undefined)cnt[r.verdict]++;
    if(actionCnt[r.action]!==undefined)actionCnt[r.action]++;
    if(r.score!=null)scores.push(r.score);
  });
  const avg=scores.length?Math.round(scores.reduce((a,b)=>a+b,0)/scores.length):0;
  const malList = done.filter(r=>r.verdict==='malicious').map(r=>r.ioc.value).slice(0,20);
  const invList = done.filter(r=>r.action==='investigate').map(r=>r.ioc.value).slice(0,20);

  const report = [
    ['VERDIKT — Analyst Report'],
    ['Generated', new Date().toLocaleString()],
    ['Mode', SERVER_MODE?'Server (Vercel env vars)':'Browser (localStorage)'],
    [],
    ['━━ EXECUTIVE SUMMARY ━━'],
    ['Total IOCs Analyzed', results.length],
    ['Average Risk Score', `${avg}/100`],
    [],
    ['━━ VERDICT BREAKDOWN ━━'],
    ['🔴 Malicious', cnt.malicious],
    ['🟡 Suspicious', cnt.suspicious],
    ['🟢 Benign', cnt.benign],
    ['⚪ Unknown', cnt.unknown],
    [],
    ['━━ ACTION SUMMARY ━━'],
    ['🚫 Block Immediately', actionCnt.block],
    ['🔍 Investigate Further', actionCnt.investigate],
    ['✅ Allow', actionCnt.allow],
    ['⏳ Monitor', actionCnt.monitor],
    [],
    ['━━ SOURCES USED ━━'],
    ['VirusTotal',       results.some(r=>r.vt&&!r.vt.skipped)?'✓ Active':'— No key'],
    ['AbuseIPDB',        results.some(r=>r.ab&&!r.ab.skipped)?'✓ Active':'— No key'],
    ['AlienVault OTX',   results.some(r=>r.otx&&!r.otx.skipped)?'✓ Active':'— No key'],
    ['MalwareBazaar',    '✓ Active (free)'],
    ['URLhaus',          '✓ Active (free)'],
    ['Shodan InternetDB','✓ Active (free)'],
    [],
    ['━━ BLOCK LIST (Top 20 Malicious IOCs) ━━'],
    ...malList.map(ioc=>['🚫', ioc]),
    malList.length===0?['No malicious IOCs detected']:null,
    [],
    ['━━ INVESTIGATE LIST (Top 20 Suspicious IOCs) ━━'],
    ...invList.map(ioc=>['🔍', ioc]),
    invList.length===0?['No IOCs requiring investigation']:null,
  ].filter(Boolean);

  const wsReport = XLSX.utils.aoa_to_sheet(report);
  wsReport['!cols'] = [{wch:35},{wch:45}];
  XLSX.utils.book_append_sheet(wb, wsReport, 'Analyst Report');

  const blockSheet = XLSX.utils.aoa_to_sheet([
    ['IOC','Type','Score','Reason'],
    ...done.filter(r=>r.action==='block').map(r=>[r.ioc.value,r.ioc.label,r.score,r.reasons?.[0]||''])
  ]);
  blockSheet['!cols'] = [{wch:48},{wch:10},{wch:8},{wch:60}];
  XLSX.utils.book_append_sheet(wb, blockSheet, 'Block List');

  XLSX.writeFile(wb, `${fn}.xlsx`);
  showToast('XLSX with analyst report exported','success');
}

function headers() {
  return [
    'IOC','Type','Verdict','Score','Confidence','Action',
    'Reason_1','Reason_2','Key_Indicators',
    'VT_Detection','VT_Malicious','VT_Total','VT_Country','VT_Reputation',
    'AIPDB_Score','AIPDB_Reports','AIPDB_ISP',
    'OTX_Pulses','OTX_Malware','OTX_Tags',
    'MB_Verdict','MB_Detail',
    'UH_Verdict','UH_Detail',
    'Shodan_Verdict','Shodan_CVEs',
    'First_Seen','Last_Seen',
    'VT_Link','AIPDB_Link','OTX_Link','MB_Link','UH_Link','Shodan_Link',
  ];
}

function buildExportRow(r, includeRaw) {
  const {ioc,verdict,score,confidence,action,reasons,indicators,firstSeen,lastSeen,vt,ab,otx,mb,uh,shodan}=r;
  const row = {
    IOC:ioc.value, Type:ioc.label,
    Verdict:(verdict||'').toUpperCase(), Score:score!=null?score:'', Confidence:(confidence||'').toUpperCase(), Action:(action||'').toUpperCase(),
    Reason_1:reasons?.[0]||'', Reason_2:reasons?.[1]||'', Key_Indicators:indicators?.join(' | ')||'',
    VT_Detection:vt?.error?`ERR:${vt.error}`:vt?.skipped?'N/A':(vt?.score||''),
    VT_Malicious:vt?.malicious??'', VT_Total:vt?.total??'', VT_Country:vt?.country||'', VT_Reputation:vt?.reputation??'',
    AIPDB_Score:ab?.error?`ERR:${ab.error}`:ab?.skipped?'N/A':`${ab?.score||0}%`,
    AIPDB_Reports:ab?.totalReports??'', AIPDB_ISP:ab?.isp||'',
    OTX_Pulses:otx?.error?`ERR:${otx.error}`:otx?.skipped?'N/A':(otx?.pulseCount??''),
    OTX_Malware:otx?.malwareFamilies?.join('; ')||'', OTX_Tags:otx?.tags?.join('; ')||'',
    MB_Verdict:mb?.error?`ERR:${mb.error}`:mb?.skipped?'N/A':mb?.notFound?'Not in DB':(mb?.verdict||'').toUpperCase(),
    MB_Detail:mb?.signature||mb?.fileType||'',
    UH_Verdict:uh?.error?`ERR:${uh.error}`:uh?.skipped?'N/A':uh?.notFound?'Not in DB':(uh?.verdict||'').toUpperCase(),
    UH_Detail:uh?.threat||uh?.urlStatus||uh?.signature||'',
    Shodan_Verdict:shodan?.error?`ERR:${shodan.error}`:shodan?.skipped?'N/A':(shodan?.verdict||'').toUpperCase(),
    Shodan_CVEs:Array.isArray(shodan?.cves)?shodan.cves.join(', '):'',
    First_Seen:firstSeen||'', Last_Seen:lastSeen||'',
    VT_Link:vt?.link||'', AIPDB_Link:ab?.link||'', OTX_Link:otx?.link||'', MB_Link:mb?.link||'', UH_Link:uh?.link||'', Shodan_Link:shodan?.link||'',
  };
  if (includeRaw) row._raw={vt:vt?.raw||null,ab:ab?.raw||null,otx:otx?.raw||null,mb:mb?.raw||null,shodan:shodan?.raw||null};
  return row;
}

function csvCell(v){if(v==null)return'';const s=String(v);return(s.includes(',')||s.includes('"')||s.includes('\n'))?'"'+s.replace(/"/g,'""')+'"':s;}
function downloadBlob(blob,filename){const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=filename;document.body.appendChild(a);a.click();document.body.removeChild(a);setTimeout(()=>URL.revokeObjectURL(url),1000);}
