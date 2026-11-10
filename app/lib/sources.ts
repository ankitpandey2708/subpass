// OSINT source registry — the single place to add, remove, or fix a source.
//
// Each source returns a Set of hostnames (unfiltered; processSubdomains() cleans
// them) or throws. A throw is reported as `status: 'failed'` in the scan
// progress, so dead sources are visible instead of looking like "0 results".
//
// Sources with `env` are opt-in: they run only when that env var holds an API
// key (all listed ones have a free tier). See README "API keys".
//
// Last verified live: 2026-11 (removed: ThreatCrowd, Riddler, Sublist3r,
// BinaryEdge, BeVigil, Censys, ZoomEye, LeakIX, FullHunt, Hunter).

import { extractHostFromUrl, fetchSource } from './subdomain-scanner';

interface Source {
    name: string;
    /** Env var holding an API key. Omitted = keyless. */
    env?: string;
    fetch: (domain: string, apiKey: string) => Promise<Set<string>>;
}

// Retry a flaky source with linear backoff (2s, 4s, …). Keep total wait under the scan deadline.
async function withRetry<T>(fn: () => Promise<T>, tries = 4, baseDelayMs = 2000): Promise<T> {
    for (let attempt = 1; ; attempt++) {
        try {
            return await fn();
        } catch (err) {
            if (attempt >= tries) throw err;
            await new Promise(resolve => setTimeout(resolve, baseDelayMs * attempt));
        }
    }
}

const lower = (xs: unknown[]) =>
    new Set(xs.filter((x): x is string => typeof x === 'string').map(x => x.toLowerCase()));

const SOURCES: Source[] = [
    // ---- keyless ----
    {
        name: 'crt.sh', // Certificate Transparency
        fetch: d => fetchSource(`https://crt.sh/?q=%25.${d}&output=json`, 60000, async res => {
            const out = new Set<string>();
            for (const entry of await res.json()) {
                for (const name of String(entry.name_value ?? '').split('\n')) out.add(name.trim().toLowerCase());
            }
            return out;
        }),
    },
    {
        name: 'SubdomainCenter', // largest keyless source; often 503 "server busy" — retried
        fetch: d => withRetry(() => fetchSource(`https://api.subdomain.center/?domain=${encodeURIComponent(d)}`, 15000,
            async res => lower(await res.json()))),
    },
    {
        name: 'RapidDNS',
        fetch: d => fetchSource(`https://rapiddns.io/subdomain/${d}?full=1`, 30000, async res => {
            const re = new RegExp(`<td>([a-zA-Z0-9.\\-]+\\.${d.replace(/\./g, '\\.')})</td>`, 'gi');
            return lower([...(await res.text()).matchAll(re)].map(m => m[1]));
        }),
    },
    {
        name: 'HackerTarget',
        fetch: d => fetchSource(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(d)}`, 30000,
            async res => lower((await res.text()).split('\n').map(line => line.split(',')[0].trim()))),
    },
    {
        name: 'Anubis',
        fetch: d => fetchSource(`https://anubisdb.com/anubis/subdomains/${d}`, 30000, async res => {
            const data = await res.json();
            return Array.isArray(data) ? lower(data) : new Set();
        }),
    },
    {
        name: 'CertSpotter',
        fetch: d => fetchSource(
            `https://api.certspotter.com/v1/issuances?domain=${d}&include_subdomains=true&expand=dns_names`, 30000,
            async res => lower((await res.json()).flatMap((e: { dns_names?: string[] }) => e.dns_names ?? []))),
    },
    {
        name: 'DNSRepo',
        fetch: d => fetchSource(`https://dnsrepo.noc.org/?domain=${encodeURIComponent(d)}`, 30000, async res => {
            const re = new RegExp(`([a-zA-Z0-9.\\-]+\\.${d.replace(/\./g, '\\.')})`, 'gi');
            return lower([...(await res.text()).matchAll(re)].map(m => m[1]));
        }),
    },
    {
        name: 'WaybackArchive',
        fetch: d => fetchSource(
            `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(d)}&output=json&fl=original&collapse=urlkey&limit=10000`,
            40000,
            async res => new Set((await res.json()).slice(1).map((row: string[]) => extractHostFromUrl(row[0])))),
    },
    {
        name: 'CommonCrawl',
        fetch: async d => {
            // Index names rotate monthly; discover the newest instead of hardcoding.
            const indices = await fetchSource('https://index.commoncrawl.org/collinfo.json', 10000, async res =>
                new Set((await res.json()).slice(0, 3).map((c: { id: string }) => c.id)));
            let lastError: unknown;
            let anyOk = false;
            for (const idx of indices) {
                const url = `https://index.commoncrawl.org/${idx}-index?url=*.${encodeURIComponent(d)}&output=json&fl=url`;
                try {
                    const hosts = await fetchSource(url, 30000, async res => {
                        const out = new Set<string>();
                        for (const line of (await res.text()).split('\n')) {
                            try { out.add(extractHostFromUrl(JSON.parse(line).url)); } catch { /* skip bad line */ }
                        }
                        return out;
                    });
                    anyOk = true;
                    if (hosts.size > 0) return hosts;
                } catch (err) {
                    lastError = err; // index servers are often overloaded; try the next
                }
            }
            if (!anyOk) throw lastError;
            return new Set();
        },
    },
    {
        name: 'URLScan',
        fetch: d => fetchSource(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(d)}&size=100`, 30000,
            async res => {
                const { results = [] } = await res.json();
                return lower(results.flatMap((r: { page?: { domain?: string }; task?: { domain?: string } }) =>
                    [r.page?.domain, r.task?.domain]));
            }),
    },
    {
        name: 'HudsonRock', // URLs seen in infostealer logs
        fetch: d => fetchSource(
            `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain=${encodeURIComponent(d)}`, 30000,
            async res => {
                const { data = {} } = await res.json();
                const urls = [...(data.employees_urls ?? []), ...(data.clients_urls ?? [])];
                return new Set(urls.map((u: { url: string }) => extractHostFromUrl(String(u.url))));
            }),
    },

    // ---- opt-in (free API key) ----
    {
        name: 'AlienVault',
        env: 'OTX_API_KEY', // https://otx.alienvault.com — anonymous access is now rate-limited to ~0
        fetch: (d, key) => fetchSource(`https://otx.alienvault.com/api/v1/indicators/domain/${d}/passive_dns`, 30000,
            async res => lower(((await res.json()).passive_dns ?? []).map((e: { hostname: string }) => e.hostname)),
            { 'X-OTX-API-KEY': key }),
    },
    {
        name: 'VirusTotal',
        env: 'VIRUSTOTAL_API_KEY', // https://www.virustotal.com — free: 4 req/min
        fetch: async (d, key) => {
            const out = new Set<string>();
            let url: string | undefined = `https://www.virustotal.com/api/v3/domains/${d}/subdomains?limit=40`;
            for (let page = 0; url && page < 3; page++) {
                const { data = [], links = {} }: { data?: { id: string }[]; links?: { next?: string } } =
                    await fetchSource(url, 30000, res => res.json(), { 'x-apikey': key });
                for (const item of data) out.add(String(item.id).toLowerCase());
                url = links.next;
            }
            return out;
        },
    },
    {
        name: 'SecurityTrails',
        env: 'SECURITYTRAILS_API_KEY', // https://securitytrails.com — free: 50 req/month
        fetch: (d, key) => fetchSource(`https://api.securitytrails.com/v1/domain/${d}/subdomains?children_only=false`, 30000,
            async res => new Set(((await res.json()).subdomains ?? []).map((s: string) => `${s}.${d}`.toLowerCase())),
            { APIKEY: key }),
    },
    {
        name: 'Chaos',
        env: 'CHAOS_API_KEY', // https://chaos.projectdiscovery.io — free key
        fetch: (d, key) => fetchSource(`https://dns.projectdiscovery.io/dns/${d}/subdomains`, 30000,
            async res => new Set(((await res.json()).subdomains ?? []).map((s: string) => `${s}.${d}`.toLowerCase())),
            { Authorization: key }),
    },
];

/** Sources that will actually run: keyless ones plus keyed ones whose env var is set. Server-only. */
export function activeSources(): (Source & { apiKey: string })[] {
    return SOURCES.flatMap(s => {
        const apiKey = s.env ? process.env[s.env]?.trim() ?? '' : '';
        return s.env && !apiKey ? [] : [{ ...s, apiKey }];
    });
}
