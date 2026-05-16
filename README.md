# VERDIKT

**Every IOC. One Verdict.**

Bulk IOC intelligence checker built for SOC analysts and detection engineers. Paste a list of IPs, domains, URLs, or file hashes — get a consolidated threat verdict powered by six intelligence sources in parallel.

Live: [h3ad-sec.github.io/VERDIKT](https://h3ad-sec.github.io/VERDIKT/)

---

## What it does

- Accepts IPv4, IPv6, domains, URLs, email addresses, and MD5 / SHA-1 / SHA-256 / SHA-512 hashes
- Auto-detects IOC types and handles defanged indicators (`hxxp://`, `1[.]2[.]3[.]4`, `[dot]`)
- Extracts IOCs from raw SIEM log lines and firewall exports
- Deduplicates input automatically and skips private / RFC1918 IPs
- Runs all sources in parallel — no waiting for one before the next starts

---

## Intelligence sources

| Source | IOC types |
|--------|-----------|
| VirusTotal | IP, Domain, URL, Hash |
| AbuseIPDB | IPv4, IPv6 |
| AlienVault OTX | IP, Domain, URL, Hash |
| MalwareBazaar | MD5, SHA-1, SHA-256 |
| URLhaus | URL, SHA-256 |
| Shodan InternetDB | IPv4 — ports, CVEs, threat tags |

---

## Output per IOC

Each IOC produces six components:

- **Verdict** — MALICIOUS / SUSPICIOUS / BENIGN / UNKNOWN
- **Risk score** — 0–100 normalized across sources
- **Confidence** — HIGH / MEDIUM / LOW / INFORMATIONAL
- **Action** — BLOCK / INVESTIGATE / ALLOW / MONITOR
- **Reason summary** — auto-generated from source data
- **Score breakdown** — per-source table in the detail modal

---

## Modes

**BYOK** — enter your own API keys in the browser. Keys are stored in localStorage and never sent anywhere except the upstream APIs.

**Managed** — API keys configured server-side. The frontend detects the backend on load and switches modes automatically. No key setup needed on the client.

---

## Features

- Bulk textarea input and file upload (.txt, .csv, .json, .xlsx)
- Quick single-IOC lookup bar
- Verdict filter (Malicious / Suspicious / Benign / Unknown) and type filter
- Detail modal with per-source raw data and scoring breakdown
- Export: CSV, JSON, Excel (full results + analyst report + block list)
- Dark / light theme with matrix background

---

## Stack

- Vanilla JS, HTML, CSS — no framework, no build step
- GitHub Pages (static frontend)
- Vercel serverless functions (managed mode backend)

---

## File structure

```
VERDIKT/
├── index.html
├── css/style.css
├── js/
│   ├── ioc-parser.js   — IOC detection, defang, log extraction
│   ├── api.js          — 6 source integrations, BYOK + managed routing
│   ├── scanner.js      — parallel engine, rate limiting, scoring
│   ├── ui.js           — table, modal, verdict rendering
│   ├── export.js       — CSV / JSON / Excel export
│   └── app.js          — init, mode detection, file upload
└── api/                — Vercel serverless proxies (managed mode)
    ├── vt.js
    ├── abuseipdb.js
    ├── otx.js
    ├── malwarebazaar.js
    ├── urlhaus.js
    └── status.js
```

---

## Part of H3AD-SEC

VERDIKT is a sub-tool under [H3AD-X](https://h3ad-sec.github.io/H3AD-X/) — Threat Intelligence hub of the [H3AD-SEC](https://h3ad-sec.github.io) platform.

Related tools: [X-VERDIKT](https://h3ad-sec.github.io/X-VERDIKT/) · [PARSE-X](https://h3ad-sec.github.io/PARSE-X/)
