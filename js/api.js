let SERVER_MODE = false;
let SERVER_BASE = '';

const API = {

  async virusTotal(ioc, signal) {
    const t = ioc.type;
    let vtPath = '';
    if      (t === 'ip' || t === 'ipv6') vtPath = `/api/v3/ip_addresses/${encodeURIComponent(ioc.value)}`;
    else if (t === 'domain')              vtPath = `/api/v3/domains/${encodeURIComponent(ioc.value)}`;
    else if (t === 'url')                 vtPath = `/api/v3/urls/${btoa(ioc.value).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}`;
    else if (t.startsWith('hash'))        vtPath = `/api/v3/files/${ioc.value.toLowerCase()}`;
    else if (t === 'email')               return { source:'virustotal', skipped:true, reason:'Not supported' };
    else                                  return { source:'virustotal', skipped:true, reason:'Unknown type' };

    try {
      const resp = SERVER_MODE
        ? await fetch(`${SERVER_BASE}/api/vt?path=${encodeURIComponent(vtPath)}`, { signal })
        : await fetch(`https://www.virustotal.com${vtPath}`, { headers:{ 'x-apikey': getKey('vt') }, signal });
      if (!resp.ok) return vtHttpErr(resp.status);
      return parseVTResponse(await resp.json(), t);
    } catch(e) { return { source:'virustotal', error: fmtErr(e) }; }
  },

  async abuseIPDB(ioc, signal) {
    if (ioc.baseType !== 'ip') return { source:'abuseipdb', skipped:true, reason:'IPv4/IPv6 only' };
    try {
      const resp = SERVER_MODE
        ? await fetch(`${SERVER_BASE}/api/abuseipdb?ip=${encodeURIComponent(ioc.value)}`, { signal })
        : await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ioc.value)}&maxAgeInDays=90&verbose`, {
            headers:{ 'Key': getKey('ab'), 'Accept':'application/json' }, signal
          });
      if (!resp.ok) return abHttpErr(resp.status);
      return parseAbuseIPDBResponse(await resp.json());
    } catch(e) { return { source:'abuseipdb', error: fmtErr(e) }; }
  },

  async otx(ioc, signal) {
    const t = ioc.type;
    let path = '';
    if      (t==='ip'||t==='ipv6') path = `/api/v1/indicators/IPv4/${ioc.value}/general`;
    else if (t==='domain')          path = `/api/v1/indicators/domain/${ioc.value}/general`;
    else if (t==='url')             path = `/api/v1/indicators/url/${encodeURIComponent(ioc.value)}/general`;
    else if (t.startsWith('hash'))  path = `/api/v1/indicators/file/${ioc.value}/general`;
    else if (t==='email') {
      const domain = ioc.value.split('@')[1];
      path = `/api/v1/indicators/domain/${domain}/general`;
    } else return { source:'otx', skipped:true, reason:'Unsupported type' };
    try {
      const resp = SERVER_MODE
        ? await fetch(`${SERVER_BASE}/api/otx?path=${encodeURIComponent(path)}`, { signal })
        : await fetch(`https://otx.alienvault.com${path}`, { headers:{ 'X-OTX-API-KEY': getKey('otx') }, signal });
      if (!resp.ok) return otxHttpErr(resp.status);
      return parseOTXResponse(await resp.json(), t);
    } catch(e) { return { source:'otx', error: fmtErr(e) }; }
  },

  async malwareBazaar(ioc, signal) {
    const t = ioc.type;
    if (!t.startsWith('hash'))    return { source:'malwarebazaar', skipped:true, reason:'Hashes only' };
    if (t === 'hash_sha512')      return { source:'malwarebazaar', skipped:true, reason:'SHA512 not supported' };
    try {
      let resp;
      if (SERVER_MODE) {
        resp = await fetch(`${SERVER_BASE}/api/malwarebazaar?hash=${encodeURIComponent(ioc.value.toLowerCase())}`, { signal });
      } else {
        const body = new URLSearchParams({ query:'get_info', hash: ioc.value.toLowerCase() });
        const headers = { 'Content-Type':'application/x-www-form-urlencoded' };
        const abchKey = getKey('abch');
        if (abchKey) headers['Auth-Key'] = abchKey;
        resp = await fetch('https://mb-api.abuse.ch/api/v1/', { method:'POST', body, headers, signal });
      }
      if (!resp.ok) return { source:'malwarebazaar', error:`HTTP ${resp.status}` };
      return parseMalwareBazaarResponse(await resp.json());
    } catch(e) {
      if (!SERVER_MODE && e?.message?.match(/fetch|network|load/i))
        return { source:'malwarebazaar', skipped:true, reason:'CORS blocked — use managed deployment' };
      return { source:'malwarebazaar', error: fmtErr(e) };
    }
  },

  async urlhaus(ioc, signal) {
    const t = ioc.type;
    const isUrl = t === 'url', isSha256 = t === 'hash_sha256';
    if (!isUrl && !isSha256) return { source:'urlhaus', skipped:true, reason:'URLs & SHA256 only' };
    try {
      let resp;
      if (SERVER_MODE) {
        const param = isUrl
          ? `url=${encodeURIComponent(ioc.value)}`
          : `sha256=${encodeURIComponent(ioc.value.toLowerCase())}`;
        resp = await fetch(`${SERVER_BASE}/api/urlhaus?${param}`, { signal });
      } else {
        const endpoint = isUrl ? 'https://urlhaus-api.abuse.ch/v1/url/' : 'https://urlhaus-api.abuse.ch/v1/payload/';
        const body = new URLSearchParams(isUrl ? { url: ioc.value } : { sha256_hash: ioc.value.toLowerCase() });
        const headers = { 'Content-Type':'application/x-www-form-urlencoded' };
        const abchKey = getKey('abch');
        if (abchKey) headers['Auth-Key'] = abchKey;
        resp = await fetch(endpoint, { method:'POST', body, headers, signal });
      }
      if (!resp.ok) return { source:'urlhaus', error:`HTTP ${resp.status}` };
      return parseURLhausResponse(await resp.json(), isUrl ? 'url' : 'hash');
    } catch(e) {
      if (!SERVER_MODE && e?.message?.match(/fetch|network|load/i))
        return { source:'urlhaus', skipped:true, reason:'CORS blocked — use managed deployment' };
      return { source:'urlhaus', error: fmtErr(e) };
    }
  },

  async shodan(ioc, signal) {
    if (ioc.type !== 'ip') return { source:'shodan', skipped:true, reason:'IPv4 only' };
    if (ioc.isPrivate)     return { source:'shodan', skipped:true, reason:'Private IP' };
    try {
      const resp = await fetch(`https://internetdb.shodan.io/${ioc.value}`, { signal });
      if (resp.status === 404) return { source:'shodan', verdict:'benign', score:0, scoreLabel:'Not indexed', ports:[], cves:[], tags:[], raw:null };
      if (!resp.ok) return { source:'shodan', error:`HTTP ${resp.status}` };
      return parseShodanResponse(await resp.json());
    } catch(e) { return { source:'shodan', error: fmtErr(e) }; }
  }
};


function parseVTResponse(data, type) {
  const attrs = data?.data?.attributes || {};
  const stats = attrs?.last_analysis_stats || {};
  const mal = stats.malicious || 0, sus = stats.suspicious || 0;
  const harm = stats.harmless || 0, undet = stats.undetected || 0;
  const total = mal + sus + harm + undet;
  const verdict = mal > 0 ? 'malicious' : sus > 0 ? 'suspicious' : 'benign';
  const r = {
    source:'virustotal', verdict, malicious:mal, suspicious:sus,
    harmless:harm, undetected:undet, total,
    score: total > 0 ? `${mal}/${total}` : 'N/A',
    reputation: attrs.reputation, country: attrs.country,
    asn: attrs.asn, as_owner: attrs.as_owner,
    tags: attrs.tags || [], threat_names: attrs.threat_names || [],
    last_analysis_date: attrs.last_analysis_date ? new Date(attrs.last_analysis_date*1000).toISOString().split('T')[0] : null,
    link: buildVTLink(data?.data?.id, type), raw: data,
  };
  if (type?.startsWith('hash')) {
    r.file_name = attrs.meaningful_name || attrs.name;
    r.file_type = attrs.type_description;
    r.file_size = attrs.size;
    r.ssdeep    = attrs.ssdeep;
  }
  return r;
}

function parseAbuseIPDBResponse(data) {
  const d = data?.data || {};
  const score = d.abuseConfidenceScore || 0;
  const verdict = score >= 75 ? 'malicious' : score >= 25 ? 'suspicious' : 'benign';
  return {
    source:'abuseipdb', verdict, score, scoreLabel:`${score}%`,
    totalReports: d.totalReports || 0, numDistinctUsers: d.numDistinctUsers || 0,
    lastReportedAt: d.lastReportedAt, isp: d.isp, usageType: d.usageType,
    domain: d.domain, country: d.countryCode, isTor: d.isTor, isWhitelisted: d.isWhitelisted,
    link: `https://www.abuseipdb.com/check/${d.ipAddress}`, raw: data,
  };
}

function parseOTXResponse(data, type) {
  const pulseCount = data?.pulse_info?.count || 0;
  const pulses = data?.pulse_info?.pulses || [];
  const verdict = pulseCount >= 5 ? 'malicious' : pulseCount >= 1 ? 'suspicious' : 'benign';
  const malwareFamilies=[], tags=[], adversaries=[];
  for (const p of pulses.slice(0,5)) {
    if (p.malware_families) malwareFamilies.push(...p.malware_families.map(f=>f.display_name||f));
    if (p.tags) tags.push(...p.tags.slice(0,3));
    if (p.adversary) adversaries.push(p.adversary);
  }
  return {
    source:'otx', verdict, pulseCount,
    scoreLabel: `${pulseCount} pulse${pulseCount!==1?'s':''}`,
    malwareFamilies: [...new Set(malwareFamilies)].slice(0,5),
    tags: [...new Set(tags)].slice(0,8),
    adversaries: [...new Set(adversaries)].slice(0,3),
    country: data?.country_name, asn: data?.asn,
    recentPulse: pulses[0]?.name || null,
    link: buildOTXLink(data, type), raw: data,
  };
}

function parseMalwareBazaarResponse(data) {
  if (data?.query_status === 'hash_not_found' || !data?.data?.length)
    return { source:'malwarebazaar', verdict:'benign', notFound:true, link:'https://bazaar.abuse.ch/', raw:data };
  if (data?.query_status !== 'ok') return { source:'malwarebazaar', error:data?.query_status||'Error', raw:data };
  const d = data.data[0];
  return {
    source:'malwarebazaar', verdict:'malicious',
    scoreLabel:'In DB', fileName:d.file_name, fileType:d.file_type, fileSize:d.file_size,
    firstSeen:d.first_seen?.split(' ')[0], lastSeen:d.last_seen?.split(' ')[0],
    reporter:d.reporter, tags:d.tags||[], signature:d.signature||null,
    deliveryMethod:d.delivery_method||null,
    clamav:d.vendor_intel?.ClamAV?.map(v=>v.result).filter(Boolean).slice(0,3)||[],
    link:`https://bazaar.abuse.ch/sample/${d.sha256_hash}/`, raw:data,
  };
}

function parseURLhausResponse(data, mode) {
  const notFound = ['no_results','hash_not_found','url_not_found'].includes(data?.query_status);
  if (notFound) return { source:'urlhaus', verdict:'benign', notFound:true, link:'https://urlhaus.abuse.ch/', raw:data };
  if (data?.query_status !== 'ok') return { source:'urlhaus', error:data?.query_status||'Error', raw:data };
  if (mode === 'url') {
    return {
      source:'urlhaus', verdict:'malicious', scoreLabel:data.url_status||'In DB',
      urlStatus:data.url_status, threat:data.threat, tags:data.tags||[],
      dateAdded:data.date_added?.split(' ')[0], host:data.host, reporter:data.reporter,
      link:data.urlhaus_reference||'https://urlhaus.abuse.ch/', raw:data,
    };
  }
  return {
    source:'urlhaus', verdict:'malicious', scoreLabel:'Payload in DB',
    fileType:data.file_type, fileSize:data.file_size,
    firstSeen:data.firstseen?.split(' ')[0], lastSeen:data.lastseen?.split(' ')[0],
    urlCount:data.urls?.length||0, signature:data.signature||null, tags:data.tags||[],
    link:data.urlhaus_reference||'https://urlhaus.abuse.ch/', raw:data,
  };
}

function parseShodanResponse(data) {
  const cves = data?.vulns || [], ports = data?.ports || [], tags = data?.tags || [];
  const cveArr = Array.isArray(cves) ? cves : Object.keys(cves);
  let verdict = 'benign';
  if (cveArr.length > 0) verdict = 'suspicious';
  if (tags.includes('honeypot')||tags.includes('malware')||tags.includes('tor')) verdict = 'malicious';
  return {
    source:'shodan', verdict, ports, cves:cveArr, tags, hostnames:data?.hostnames||[],
    scoreLabel: cveArr.length > 0 ? `${cveArr.length} CVE${cveArr.length>1?'s':''}` : ports.length ? `${ports.length} ports` : 'No data',
    isp:data?.isp||null, link:`https://www.shodan.io/host/${data?.ip||''}`, raw:data,
  };
}

function vtHttpErr(s)  { return { source:'virustotal',  error:{404:'Not found',401:'Invalid API key',429:'Rate limited — check VT tier'}[s]||`HTTP ${s}` }; }
function abHttpErr(s)  { return { source:'abuseipdb',   error:{401:'Invalid API key',429:'Rate limited'}[s]||`HTTP ${s}` }; }
function otxHttpErr(s) { return { source:'otx',         error:{401:'Invalid API key',404:'Not found',429:'Rate limited'}[s]||`HTTP ${s}` }; }
function fmtErr(e)     { return e?.name==='AbortError' ? 'Timeout (8s)' : e?.message?.match(/fetch|network/i) ? 'Network error' : (e.message||'Unknown error'); }

function buildVTLink(id, type) {
  if (!id) return null;
  if (type==='ip'||type==='ipv6')  return `https://www.virustotal.com/gui/ip-address/${id}`;
  if (type==='domain')              return `https://www.virustotal.com/gui/domain/${id}`;
  if (type==='url')                 return `https://www.virustotal.com/gui/url/${id}`;
  if (type?.startsWith('hash'))     return `https://www.virustotal.com/gui/file/${id}`;
  return `https://www.virustotal.com/gui/search/${id}`;
}
function buildOTXLink(data, type) {
  if (type==='ip'||type==='ipv6')  return `https://otx.alienvault.com/indicator/ip/${data?.indicator||''}`;
  if (type==='domain')              return `https://otx.alienvault.com/indicator/domain/${data?.indicator||''}`;
  if (type==='url')                 return `https://otx.alienvault.com/indicator/url/${encodeURIComponent(data?.indicator||'')}`;
  if (type?.startsWith('hash'))     return `https://otx.alienvault.com/indicator/file/${data?.indicator||''}`;
  return 'https://otx.alienvault.com';
}


function getKey(service) {
  const el = document.getElementById(`${service}-key`);
  if (el?.value.trim()) return el.value.trim();
  return localStorage.getItem(`tg_${service}_key`) || '';
}
function isVTPaid() {
  return document.getElementById('vt-paid')?.checked || localStorage.getItem('tg_vt_paid') === '1';
}
