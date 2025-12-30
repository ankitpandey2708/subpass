[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/ankitpandey2708/subpass)

# Subpass

Advanced subdomain enumeration tool built with Next.js, utilizing 19 OSINT data sources for comprehensive reconnaissance.

## Features

- **19 OSINT Data Sources**: Aggregates results from crt.sh, RapidDNS, AlienVault OTX, HackerTarget, Anubis, CommonCrawl, ThreatCrowd, WaybackArchive, Sublist3r, CertSpotter, BeVigil, Riddler.io, LeakIX, DNSRepo, FullHunt, Hunter.io, Censys, BinaryEdge, and ZoomEye
- **Parallel Scanning**: All sources queried simultaneously for maximum speed
- **Real-time Status Verification**: DNS + HTTP/HTTPS checks for discovered subdomains
- **Cyberpunk UI**: Modern, responsive terminal-style interface
- **Smart Batching**: Adaptive batch processing for large result sets

## Setup

```bash
npm install
npm run dev
```

## Usage

Enter a domain to scan for subdomains using 19 OSINT sources. The tool will:
1. Query all data sources in parallel
2. Aggregate and deduplicate results
3. Optionally verify subdomain status (DNS + HTTP checks)

## Commands

```bash
npm run dev      # Start development server
npm run build    # Build for production
npm run start    # Run production server
npm run lint     # Run ESLint
npm run knip     # Check for unused code
```
