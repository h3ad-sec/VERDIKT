const IOCPatterns = {
  ipv4:   /^(\d{1,3}\.){3}\d{1,3}$/,
  ipv6:   /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4})?$/,
  url:    /^https?:\/\/([\w\-\.]+)(:\d+)?(\/[^\s]*)?$/i,
  email:  /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/,
  md5:    /^[a-fA-F0-9]{32}$/,
  sha1:   /^[a-fA-F0-9]{40}$/,
  sha256: /^[a-fA-F0-9]{64}$/,
  sha512: /^[a-fA-F0-9]{128}$/,
  domain: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,
};

const PRIVATE_RANGES = [
  /^10\./, /^192\.168\./, /^172\.(1[6-9]|2[0-9]|3[01])\./, /^127\./,
  /^0\.0\.0\.0$/, /^255\.255\.255\.255$/, /^169\.254\./, /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
];

const LOG_EXTRACT = {
  // URLs (before IP to avoid partial matches)
  url:    /https?:\/\/(?:[\[\(]?\.\]?\)?)?[\w\-\.]+(?::\d+)?(?:\/[^\s"',;>)\]]*)?/gi,
  // IPv4 — including defanged: 1[.]2[.]3[.]4  1(.)2(.)3(.)4
  ipv4:   /\b(\d{1,3})[\[\(]?\.[\]\)]?(\d{1,3})[\[\(]?\.[\]\)]?(\d{1,3})[\[\(]?\.[\]\)]?(\d{1,3})\b/g,
  // Hashes by length
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  sha1:   /\b[a-fA-F0-9]{40}\b/g,
  md5:    /\b[a-fA-F0-9]{32}\b/g,
  // Email
  email:  /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
  // Domain (conservative — after email/URL to avoid false positives)
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|int|co|uk|de|fr|ru|cn|jp|br|au|nl|se|no|fi|dk|pl|it|es|pt|be|ch|at|nz|za|in|sg|hk|tw|kr|mx|ar|cl|ph|th|id|vn|pk|bd|ng|ke|gh|tz|ug|zw|biz|info|mobi|name|museum|coop|aero|pro|tel|cat|xxx|travel|jobs|app|dev|cloud|tech|online|site|web|store|shop|blog|news|media|digital|ai)\b/gi,
};

const FIELD_LABELS = [
  // Common firewall formats
  /src[\s=:]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/gi,
  /dst[\s=:]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/gi,
  /source[\s=:]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/gi,
  /destination[\s=:]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/gi,
  /srcip[\s=:]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/gi,
  /dstip[\s=:]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/gi,
  /client_ip[\s=:]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/gi,
  /remote_addr[\s=:]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/gi,
  // Email header fields
  /X-Originating-IP[\s:]+\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?/gi,
  /Received:.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/gi,
  /X-Forwarded-For[\s:]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/gi,
  // File hash fields
  /hash[\s=:"]+([a-fA-F0-9]{32,128})/gi,
  /md5[\s=:"]+([a-fA-F0-9]{32})/gi,
  /sha256[\s=:"]+([a-fA-F0-9]{64})/gi,
  /sha1[\s=:"]+([a-fA-F0-9]{40})/gi,
  /checksum[\s=:"]+([a-fA-F0-9]{32,64})/gi,
  // URL fields
  /url[\s=:"']+([^\s"',;>\]]+)/gi,
  /request[\s=:"']+([^\s"',;>\]]+)/gi,
  /hostname[\s=:"']+([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})/gi,
  /domain[\s=:"']+([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})/gi,
];

function looksLikeLog(text) {
  const logIndicators = [
    /\b(src|dst|srcip|dstip|proto|port|action|permit|deny|drop|alert|blocked)\s*[=:]/i,
    /\bReceived:\s+from\b/i,
    /\bX-Originating-IP\b/i,
    /\bX-Forwarded-For\b/i,
    /\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/,
    /\b(TRAFFIC|THREAT|SYSTEM|CONFIG|HIPMATCH)\b/,  // Palo Alto
    /\bFortiGate\b|\bFortiOS\b/i,
    /\bEventCode=|\bSignatureID=/i,  // SIEM
    /\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/,  // ISO timestamp
    /\bSEVERITY=|\bPRIORITY=|\bFACILITY=/i,
    /\bsyslog\b|\bsyslogd\b/i,
    /\[.*?\]\s+\[.*?\]/,  // bracketed fields
    /<\d+>/,  // syslog priority
  ];
  return logIndicators.some(p => p.test(text));
}

function extractFromLog(text) {
  const found = new Set();
  const results = [];

  // First pass: field label extractions (highest confidence)
  for (const pattern of FIELD_LABELS) {
    let m;
    pattern.lastIndex = 0;
    while ((m = pattern.exec(text)) !== null) {
      const val = m[1]?.trim();
      if (val) found.add(val.toLowerCase()) && results.push(val);
    }
  }

  // Second pass: freeform regex extraction
  // URLs first
  let m;
  LOG_EXTRACT.url.lastIndex = 0;
  while ((m = LOG_EXTRACT.url.exec(text)) !== null) {
    const raw = m[0].replace(/[\[\(]?\.\]?\)?/g, '.').replace(/hxxp/gi, 'http').replace(/\[:\]/g, ':');
    if (!found.has(raw.toLowerCase())) { found.add(raw.toLowerCase()); results.push(raw); }
  }

  // IPv4 (including defanged)
  LOG_EXTRACT.ipv4.lastIndex = 0;
  while ((m = LOG_EXTRACT.ipv4.exec(text)) !== null) {
    const ip = `${m[1]}.${m[2]}.${m[3]}.${m[4]}`;
    if (isValidIPv4(ip) && !found.has(ip)) { found.add(ip); results.push(ip); }
  }

  // Hashes (longest first to avoid subset matches)
  for (const key of ['sha256','sha1','md5']) {
    LOG_EXTRACT[key].lastIndex = 0;
    while ((m = LOG_EXTRACT[key].exec(text)) !== null) {
      const h = m[0].toLowerCase();
      if (!found.has(h)) { found.add(h); results.push(m[0]); }
    }
  }

  // Emails
  LOG_EXTRACT.email.lastIndex = 0;
  while ((m = LOG_EXTRACT.email.exec(text)) !== null) {
    const e = m[0].toLowerCase();
    if (!found.has(e)) { found.add(e); results.push(m[0]); }
  }

  // Domains (last — most false-positive prone)
  LOG_EXTRACT.domain.lastIndex = 0;
  while ((m = LOG_EXTRACT.domain.exec(text)) !== null) {
    const d = m[0].toLowerCase();
    // Skip if already captured as part of a URL or email
    if (!found.has(d) && !results.some(r => r.toLowerCase().includes(d))) {
      found.add(d); results.push(m[0]);
    }
  }

  return results.join('\n');
}

function defang(token) {
  return token
    .replace(/hxxps?/gi, m => m.replace(/xx/i, 'tt'))
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\\\./g, '.')
    .replace(/^http\\:\/\//i, 'http://');
}

function wasDefanged(original, normalized) {
  return original !== normalized;
}

function parseIOCs(raw) {
  if (!raw?.trim()) return [];

  // Auto-detect log vs clean IOC list
  const isLog = looksLikeLog(raw);
  const textToProcess = isLog ? extractFromLog(raw) : raw;

  const seen = new Set();
  const result = [];
  const defangedMap = {};

  const tokens = textToProcess
    .split(/[\n\r,;\t]+/)
    .flatMap(line => line.split(/\s{2,}/))   // also split on 2+ spaces
    .map(t => t.trim())
    .filter(t => t.length >= 4 && !t.startsWith('#') && !t.startsWith('//') && !t.startsWith(';'));

  for (const raw_token of tokens) {
    const token = defang(raw_token);
    const lower = token.toLowerCase();
    if (seen.has(lower)) continue;
    seen.add(lower);

    const type = detectIOCType(token);
    if (!type) continue;

    const isPrivate = (type === 'ip') ? isPrivateIP(token) : false;
    const defangedNote = wasDefanged(raw_token, token) ? raw_token : null;

    result.push({
      value:       token,
      type,
      baseType:    getBaseType(type),
      label:       getTypeLabel(type),
      isPrivate,
      defanged:    defangedNote,
      fromLog:     isLog,
    });
  }

  return result;
}

function parseIOCsWithMeta(raw) {
  if (!raw?.trim()) return { iocs: [], logDetected: false, extractedCount: 0 };
  const isLog = looksLikeLog(raw);
  const iocs = parseIOCs(raw);
  return { iocs, logDetected: isLog, extractedCount: iocs.length };
}

function getIOCBreakdown(iocs) {
  const counts = {};
  for (const ioc of iocs) {
    const t = ioc.baseType || 'unknown';
    counts[t] = (counts[t] || 0) + 1;
  }
  return counts;
}

function parseFromFileContent(content, ext) {
  if (ext === 'json') {
    try {
      const data = JSON.parse(content);
      const extract = obj => {
        if (typeof obj === 'string') return obj;
        if (typeof obj === 'number') return String(obj);
        if (Array.isArray(obj)) return obj.map(extract).filter(Boolean).join('\n');
        if (obj && typeof obj === 'object') {
          const iocFields = ['ioc','indicator','value','ip','domain','url','hash',
                             'md5','sha1','sha256','sha512','email','observable','IOC'];
          for (const f of iocFields) { if (typeof obj[f] === 'string' && obj[f]) return obj[f]; }
          return Object.values(obj).map(extract).filter(Boolean).join('\n');
        }
        return '';
      };
      return extract(data);
    } catch(e) { /* fall through */ }
  }
  return content;
}

function detectIOCType(v) {
  if (!v || v.length < 4) return null;
  if (IOCPatterns.url.test(v))    return 'url';
  if (IOCPatterns.email.test(v))  return 'email';
  if (IOCPatterns.sha512.test(v)) return 'hash_sha512';
  if (IOCPatterns.sha256.test(v)) return 'hash_sha256';
  if (IOCPatterns.sha1.test(v))   return 'hash_sha1';
  if (IOCPatterns.md5.test(v))    return 'hash_md5';
  if (IOCPatterns.ipv6.test(v))   return 'ipv6';
  if (IOCPatterns.ipv4.test(v) && isValidIPv4(v)) return 'ip';
  if (IOCPatterns.domain.test(v)) return 'domain';
  return null;
}
function isValidIPv4(ip) {
  const parts = ip.split('.');
  return parts.length === 4 && parts.every(o => { const n = parseInt(o, 10); return n >= 0 && n <= 255 && String(n) === o; });
}
function isPrivateIP(ip) { return PRIVATE_RANGES.some(r => r.test(ip)); }
function getBaseType(t) { if (!t) return null; if (t.startsWith('hash')) return 'hash'; if (t === 'ipv6') return 'ip'; return t; }
function getTypeLabel(t) {
  return { ip:'IPv4', ipv6:'IPv6', url:'URL', domain:'Domain', email:'Email',
           hash_md5:'MD5', hash_sha1:'SHA1', hash_sha256:'SHA256', hash_sha512:'SHA512' }[t] || t;
}
