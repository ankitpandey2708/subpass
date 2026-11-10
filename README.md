[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/ankitpandey2708/subpass)

# Subpass

Advanced subdomain enumeration tool built with Next.js, aggregating 11 keyless OSINT sources (up to 15 with free API keys) for comprehensive reconnaissance.

## Features

- **11 keyless OSINT sources**: crt.sh, subdomain.center, RapidDNS, HackerTarget, Anubis, CertSpotter, DNSRepo, Wayback Archive, CommonCrawl (latest indices auto-discovered), URLScan, HudsonRock
- **4 opt-in sources** (free API keys): AlienVault OTX, VirusTotal, SecurityTrails, Chaos
- **Parallel Scanning**: All sources queried simultaneously for maximum speed
- **Real-time Status Verification**: DNS + HTTP/HTTPS checks for discovered subdomains
- **Cyberpunk UI**: Modern, responsive terminal-style interface
- **Smart Batching**: Adaptive batch processing for large result sets

## Setup

```bash
npm install
npm run dev
```

### API keys (optional)

Each keyed source turns on automatically when its env var is set (e.g. in `.env.local` or your Vercel project). The "Sources Online" badge counts only active sources.

| Env var | Source | Free key |
|---|---|---|
| `OTX_API_KEY` | AlienVault OTX | https://otx.alienvault.com |
| `VIRUSTOTAL_API_KEY` | VirusTotal | https://www.virustotal.com |
| `SECURITYTRAILS_API_KEY` | SecurityTrails | https://securitytrails.com |
| `CHAOS_API_KEY` | ProjectDiscovery Chaos | https://chaos.projectdiscovery.io |

## Usage

Enter a domain to scan for subdomains. The tool will:
1. Query all active sources in parallel
2. Aggregate and deduplicate results
3. Optionally verify subdomain status (DNS + HTTP checks)

## API

- `GET /api/subdomains/scan?domain=example.com` — streams NDJSON as each source finishes (`start`, one `source` line per source, then `done` with the full result). Cacheable: browser 5 min, CDN 1 h. Whole scan is capped at 25 s; sources still running are reported as `timeout`.
- `POST /api/subdomains/scan` `{ "domain": "example.com" }` — same final result as a single JSON response.
- `PUT /api/subdomains/status` `{ "subdomains": [...] }` — DNS + HTTP/HTTPS liveness per subdomain.

## Adding or fixing a source

All sources live in [`app/lib/sources.ts`](app/lib/sources.ts) — one entry each. A source that throws is reported as `status: "failed"` in the scan response's `progress` array (and logged server-side), so dead sources are easy to spot.

## Commands

```bash
npm run dev      # Start development server
npm run build    # Build for production
npm run start    # Run production server
npm run lint     # Run ESLint
npm run knip     # Check for unused code
```
