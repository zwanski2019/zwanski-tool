# Zwanski Security Scanner v2

Aggressive 403/401 ACL bypass scanner with AI-powered triage and HackerOne report generation.

## Features

- **100+ bypass techniques**: path mutations, header injection, method overrides, port variants
- **Robots.txt & sitemap.xml harvesting** with automatic ACL bypass attempts
- **Force Bypass mode**: hammer a single URL with the full arsenal
- **AI analysis** via OpenRouter: triage, H1 report generation, advanced bypass suggestions
- **Curl command export**: every successful bypass comes with a copy-paste reproducer
- **Threaded scanning** with configurable concurrency
- **JSON report export** with full scan data

## Quick Start

```bash
pip install -r requirements.txt
streamlit run zwanski_scanner.py
```

## Deploy to Railway

1. Push this repo to GitHub
2. Create a new project on railway.app → Deploy from GitHub
3. Railway auto-detects `nixpacks.toml` + `Procfile` + `requirements.txt`
4. In the Variables tab, add:
   - `OPENROUTER_API_KEY` = your OpenRouter key (optional, for AI features)
5. Deploy. Railway will expose a public URL.

## Deploy to Streamlit Community Cloud

1. Push to GitHub (make sure `.streamlit/secrets.toml` is in `.gitignore`)
2. Go to share.streamlit.io, connect your repo
3. App settings → Secrets → add:
   ```toml
   OPENROUTER_API_KEY = "sk-or-v1-..."
   ```
4. Force Python 3.11 in app settings

## API Key Setup

Priority order:
1. Environment variable `OPENROUTER_API_KEY`
2. `st.secrets["OPENROUTER_API_KEY"]` (from `.streamlit/secrets.toml`)
3. Manual input in the sidebar (for local dev only)

**Never commit API keys to git.** The `.gitignore` excludes `secrets.toml` by default.

Get a free key at https://openrouter.ai/keys — the `:free` model suffixes cost $0 but have rate limits.

## Legal

**Authorized targets only.** Use on systems you own or have explicit written permission to test. Bug bounty targets count only within their defined scope. The author assumes no liability for misuse.

## Troubleshooting

- **"Fatal error" / blank page on Streamlit Cloud**: check the Manage app → logs panel. Usually a Python version issue or missing dep.
- **"0 Unknown Error" during scanning**: target is unreachable from the hosting environment's network (common on Streamlit Cloud for internal/VPN targets). Run locally or deploy to Railway which has more permissive egress.
- **All techniques fail**: the target is probably behind Cloudflare or a modern WAF. Use the AI Bypass Suggester for custom techniques.

## File Structure

```
.
├── zwanski_scanner.py          # main app
├── requirements.txt
├── Procfile                    # Railway/Heroku
├── nixpacks.toml               # Railway build config
├── railway.json                # Railway deploy config
├── runtime.txt                 # Python version pin
├── .gitignore
└── .streamlit/
    ├── config.toml             # Streamlit server config
    └── secrets.toml.example    # secrets template
```
