# VERDIKT

Every IOC. One verdict.

Bulk IOC intelligence checker — 6 sources, instant verdicts, built for SOC analysts and detection engineers. Runs entirely in the browser.  
**API keys stored in Vercel environment variables** — never exposed to the client.

---

## Key Architecture Change — Server vs Browser Mode

| Mode | How keys are stored | When it activates |
|------|--------------------|--------------------|
| **Server Mode** | Vercel environment variables | Deployed to Vercel with env vars set |
| **Browser Mode** | Browser localStorage | GitHub Pages / Netlify / local dev |

On startup, the app hits `/api/status`. If Vercel serverless functions are running, it enters **Server Mode** and hides the API key panel entirely. Keys never reach the browser. If `/api/status` returns a network error (static host), it falls back to **Browser Mode** with localStorage keys.

---

## Deploy to Vercel (Server Mode — Recommended)

### Step 1 — Push to GitHub

```bash
cd verdikt
git init
git add .
git commit -m "VERDIKT v1.0"
git remote add origin https://github.com/YOUR_USERNAME/verdikt.git
git push -u origin main
```

### Step 2 — Import to Vercel

1. Go to [vercel.com/new](https://vercel.com/new)
2. Click **"Import Git Repository"**
3. Select your `verdikt` repo
4. Framework Preset: **Other** (it's a static site + serverless functions)
5. Click **Deploy**

### Step 3 — Add Environment Variables

In your Vercel project dashboard:  
**Settings → Environment Variables**

Add these variables:

| Variable | Required | Get it from | Notes |
|----------|----------|-------------|-------|
| `VT_API_KEY` | Recommended | [virustotal.com](https://www.virustotal.com) → Sign up → API Key | Free: 4 req/min, 500/day. Paid: unlimited |
| `ABUSEIPDB_API_KEY` | Recommended | [abuseipdb.com](https://www.abuseipdb.com) → Account → API | Free: 1,000 req/day. IPs only |
| `OTX_API_KEY` | Recommended | [otx.alienvault.com](https://otx.alienvault.com) → Settings → API Key | Free, generous limits. Covers all IOC types |
| `ABUSECH_AUTH_KEY` | Recommended | [abuse.ch](https://abuse.ch/api) → Register free | Required for MalwareBazaar + URLhaus since late 2024 |
| `VT_PAID` | Optional | — | Set to `true` if you have a paid VT subscription. Removes rate limiting |

**What happens without each key:**
- No `VT_API_KEY` → VirusTotal skipped for all IOCs
- No `ABUSEIPDB_API_KEY` → AbuseIPDB skipped for all IPs
- No `OTX_API_KEY` → OTX skipped for all IOCs
- No `ABUSECH_AUTH_KEY` → MalwareBazaar and URLhaus return 401, shown as error
- No `VT_PAID` → defaults to free-tier rate limiting (4 req/min token bucket)

At minimum, add `VT_API_KEY` — VirusTotal covers the widest range of IOC types and carries the most scoring weight.

Set each variable for **Production**, **Preview**, and **Development** environments.

### Step 4 — Redeploy

After adding env vars, go to **Deployments → Redeploy** (or push a new commit).

The app will detect server mode automatically. The API key panel disappears and a **SERVER KEYS** badge appears in the header.

### Using Vercel CLI instead

```bash
npm i -g vercel
vercel                          # Deploy + follow prompts
vercel env add VT_API_KEY       # Add each key interactively
vercel env add ABUSEIPDB_API_KEY
vercel env add OTX_API_KEY
vercel env add VT_PAID
vercel env add ABUSECH_AUTH_KEY
vercel --prod                   # Redeploy to production
```

---

## Alternative Deploys (Browser Mode)

These hosts don't run serverless functions. The app falls back to localStorage keys automatically.

### Netlify

```bash
npm i -g netlify-cli
netlify deploy --dir . --prod
```

Or drag-and-drop at [app.netlify.com/drop](https://app.netlify.com/drop).

### GitHub Pages

The `.github/workflows/deploy.yml` included auto-deploys on every push:

```bash
git push origin main   # triggers GitHub Actions → deploys to Pages
```

Enable Pages: **Settings → Pages → Branch: main → Save**

---

## Themes

Click the **DARK·G / DARK·B / DARK·R / LIGHT** button in the header to cycle through 4 themes. Selection is persisted in localStorage.

| Theme | Description |
|-------|-------------|
| **DARK·G** | Terminal green — default SOC aesthetic |
| **DARK·B** | Cyber blue — cooler palette |
| **DARK·R** | Red ops — high-contrast red accent |
| **LIGHT** | Day mode — light background for bright environments |

---

## Sources

| Source | Key Required | IOC Types | Free Limits |
|--------|-------------|-----------|-------------|
| VirusTotal | ✅ | IP · Domain · URL · MD5/SHA1/SHA256/SHA512 | 4 req/min · 500/day (free) |
| AbuseIPDB | ✅ | IPv4 · IPv6 | 1,000 req/day |
| AlienVault OTX | ✅ | All types incl. Email | Generous |
| MalwareBazaar | ✅ Free (abuse.ch) | MD5 · SHA1 · SHA256 | No limit |
| URLhaus | ✅ Free (abuse.ch) | URLs · SHA256 | No limit |
| Shodan InternetDB | ❌ Free | IPv4 | No limit |

**Why AbuseIPDB doesn't check hashes:**  
AbuseIPDB is an IP reputation database by design — no hash API exists. Hashes are automatically routed to MalwareBazaar (MD5/SHA1/SHA256) and URLhaus (SHA256 + URLs).

---

## IOC Type Routing

| Type | VT | AbuseIPDB | OTX | MalwareBazaar | URLhaus | Shodan |
|------|----|-----------|-----|---------------|---------|--------|
| IPv4 | ✅ | ✅ | ✅ | — | — | ✅ |
| IPv6 | ✅ | ✅ | ✅ | — | — | — |
| Domain | ✅ | — | ✅ | — | — | — |
| URL | ✅ | — | ✅ | — | ✅ | — |
| MD5 | ✅ | — | ✅ | ✅ | — | — |
| SHA1 | ✅ | — | ✅ | ✅ | — | — |
| SHA256 | ✅ | — | ✅ | ✅ | ✅ | — |
| SHA512 | ✅ | — | ✅ | — | — | — |
| Email | — | — | ✅* | — | — | — |

*OTX checks the email's domain

---

## File Structure

```
verdikt/
├── index.html                      # Main single-page app
├── vercel.json                     # Vercel routing + headers config
├── css/
│   └── style.css                   # 4 themes via CSS variables
├── js/
│   ├── ioc-parser.js               # IOC detection, defang support
│   ├── api.js                      # 6 sources — server/browser routing
│   ├── scanner.js                  # Orchestration, rate limiting, stop
│   ├── ui.js                       # Render, theme system, modal, filters
│   ├── export.js                   # JSON / CSV / XLSX
│   └── app.js                      # Init, mode detection, file upload
├── api/                            # Vercel serverless functions (Node.js)
│   ├── vt.js                       # VirusTotal proxy
│   ├── abuseipdb.js                # AbuseIPDB proxy
│   ├── otx.js                      # AlienVault OTX proxy
│   └── status.js                   # Key health check (no values exposed)
└── .github/
    └── workflows/deploy.yml        # GitHub Pages auto-deploy
```

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl / Cmd + Enter` | Run scan |
| `Esc` | Close detail modal |

---

## Scoring Logic

Each IOC is scored 0–100 and assigned a verdict. The score is normalized against the maximum possible for that IOC type — so a domain (max 55 raw points from VT + OTX) is scored fairly against an IP (max 93 raw points from all sources).

### Source weights

| Source | Max contribution | Notes |
|--------|-----------------|-------|
| VirusTotal | 40 pts | `(malicious engines / total engines) × 40` — only counts if `total > 0` |
| AbuseIPDB | 30 pts | `(abuse score / 100) × 30` — IPs only |
| AlienVault OTX | 15 pts | `(pulse count / 10) × 15`, capped at 15 |
| MalwareBazaar | 10 pts | Binary — found in DB = 10, not found = 0 |
| URLhaus | 10 pts | Binary — found in DB = 10, not found = 0 |
| Shodan CVEs | up to 5 pts | 1 pt per CVE, capped at 5 |
| Shodan threat tag | +3 pts | Flat bonus for TOR/honeypot/malware tags |

### Maximum score per IOC type

| Type | VT | AbuseIPDB | OTX | MB | URLhaus | Shodan | Max |
|------|----|-----------|-----|----|---------|--------|-----|
| IPv4 | 40 | 30 | 15 | — | — | 8 | **93** |
| IPv6 | 40 | 30 | 15 | — | — | — | **85** |
| Domain | 40 | — | 15 | — | — | — | **55** |
| URL | 40 | — | 15 | — | 10 | — | **65** |
| Email | — | — | 15 | — | — | — | **15** |
| MD5 / SHA1 | 40 | — | 15 | 10 | — | — | **65** |
| SHA256 | 40 | — | 15 | 10 | 10 | — | **75** |
| SHA512 | 40 | — | 15 | — | — | — | **55** |

### Verdict thresholds

Verdicts use both the normalized score and direct signal flags — whichever triggers first wins:

| Verdict | Triggers when… |
|---------|----------------|
| 🔴 **MALICIOUS / BLOCK** | Score ≥ 60, or VT ≥ 5 engines, or AbuseIPDB ≥ 75%, or any MB/URLhaus hit, or 2+ independent malicious sources |
| 🟡 **SUSPICIOUS / INVESTIGATE** | Score ≥ 25, or any VT detection, or AbuseIPDB ≥ 25%, or OTX 1–4 pulses, or OTX 5+ pulses (single source) |
| 🟢 **CLEAN / ALLOW** | At least 1 source checked, no threat signals found |
| ⚪ **UNKNOWN / MONITOR** | No key-based sources ran and no free-source hit |

### Confidence

| Level | Condition |
|-------|-----------|
| **High** | 2+ malicious sources, or 3+ sources checked |
| **Medium** | 2+ sources checked, or 1 malicious source confirmed |
| **Low** | 0–1 source checked with no malicious signals |

---

## Security Notes

- In **Server Mode**, API keys exist only in Vercel's encrypted environment variable store. `/api/status` only returns `true/false` per key — never the key value itself.
- In **Browser Mode**, keys are in localStorage — only your browser can read them.
- MalwareBazaar, URLhaus, and Shodan are called directly from the browser — they require no keys and have permissive CORS.
- No analytics, no telemetry, no third-party scripts beyond Google Fonts and the XLSX library.

---

## License

MIT
