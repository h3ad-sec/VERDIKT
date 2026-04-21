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

| Variable Name | Value | Required |
|---------------|-------|----------|
| `VT_API_KEY` | Your VirusTotal API key | For VT source |
| `ABUSEIPDB_API_KEY` | Your AbuseIPDB API key | For AbuseIPDB source |
| `OTX_API_KEY` | Your AlienVault OTX API key | For OTX source |
| `VT_PAID` | `true` or `false` | Controls rate limiting |

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
| MalwareBazaar | ❌ Free | MD5 · SHA1 · SHA256 | No limit |
| URLhaus | ❌ Free | URLs · SHA256 | No limit |
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

## Security Notes

- In **Server Mode**, API keys exist only in Vercel's encrypted environment variable store. `/api/status` only returns `true/false` per key — never the key value itself.
- In **Browser Mode**, keys are in localStorage — only your browser can read them.
- MalwareBazaar, URLhaus, and Shodan are called directly from the browser — they require no keys and have permissive CORS.
- No analytics, no telemetry, no third-party scripts beyond Google Fonts and the XLSX library.

---

## License

MIT
