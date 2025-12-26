import { NextRequest, NextResponse } from 'next/server';
import { processSubdomains, ScanProgress, normalizeDomain, fetchSource, extractHostFromUrl, createErrorResponse } from '@/app/lib/subdomain-scanner';

// Define all sources matching subdomain.py
const sources = {
    'crt.sh': 'crt.sh',
    'RapidDNS': 'RapidDNS',
    'AlienVault': 'AlienVault',
    'HackerTarget': 'HackerTarget',
    'Anubis': 'Anubis',
    'CommonCrawl': 'CommonCrawl',
    'ThreatCrowd': 'ThreatCrowd',
    'WaybackArchive': 'WaybackArchive',
    'Sublist3rAPI': 'Sublist3rAPI',
    'CertSpotter': 'CertSpotter',
    'BeVigil': 'BeVigil',
    'Riddler': 'Riddler',
    'LeakIX': 'LeakIX',
    'DNSRepo': 'DNSRepo',
    'FullHunt': 'FullHunt',
    'Hunter': 'Hunter',
    'Censys': 'Censys',
    'BinaryEdge': 'BinaryEdge',
    'ZoomEye': 'ZoomEye',
};

// Export the count of sources for the UI
export const SOURCES_COUNT = Object.keys(sources).length;

// Fetch from crt.sh - Certificate Transparency logs
async function fetchCrtsh(domain: string): Promise<Set<string>> {
    const url = `https://crt.sh/?q=%25.${domain}&output=json`;
    return fetchSource(url, 60000, async (response) => {
        const data = await response.json();
        const subdomains = new Set<string>();

        for (const entry of data) {
            const nameValue = entry.name_value;
            if (nameValue) {
                for (const sub of nameValue.split('\n')) {
                    const cleaned = sub.trim().toLowerCase();
                    if (cleaned.endsWith(domain) && !cleaned.startsWith('*')) {
                        subdomains.add(cleaned);
                    }
                }
            }
        }
        return subdomains;
    });
}

// Fetch from RapidDNS
async function fetchRapiddns(domain: string): Promise<Set<string>> {
    const url = `https://rapiddns.io/subdomain/${domain}?full=1`;
    return fetchSource(url, 30000, async (response) => {
        const text = await response.text();
        const regex = new RegExp(`<td>([a-zA-Z0-9\\.\\-]+\\.${domain.replace(/\./g, '\\.')})</td>`, 'gi');
        const matches = text.matchAll(regex);
        const subdomains = new Set<string>();

        for (const match of matches) {
            const sub = match[1].toLowerCase();
            if (!sub.startsWith('*')) {
                subdomains.add(sub);
            }
        }
        return subdomains;
    });
}

// Fetch from AlienVault OTX
async function fetchAlienvault(domain: string): Promise<Set<string>> {
    const url = `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`;
    return fetchSource(url, 30000, async (response) => {
        const data = await response.json();
        const subdomains = new Set<string>();

        for (const entry of data.passive_dns || []) {
            const hostname = entry.hostname;
            if (hostname && hostname.endsWith(domain) && !hostname.startsWith('*')) {
                subdomains.add(hostname.toLowerCase());
            }
        }
        return subdomains;
    });
}

// Fetch from HackerTarget
async function fetchHackertarget(domain: string): Promise<Set<string>> {
    const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
    return fetchSource(url, 30000, async (response) => {
        const text = await response.text();
        const subdomains = new Set<string>();

        for (const line of text.split('\n')) {
            const parts = line.split(',');
            if (parts.length > 0) {
                const sub = parts[0].toLowerCase().trim();
                if (sub.endsWith(domain) && !sub.startsWith('*')) {
                    subdomains.add(sub);
                }
            }
        }
        return subdomains;
    });
}

// Fetch from Anubis
async function fetchAnubis(domain: string): Promise<Set<string>> {
    const url = `https://jldc.me/anubis/subdomains/${domain}`;
    return fetchSource(url, 30000, async (response) => {
        const data = await response.json();
        if (Array.isArray(data)) {
            return new Set(data.map(h => h.toLowerCase()).filter(h => h.endsWith(domain) && !h.startsWith('*')));
        }
        return new Set();
    });
}

// Fetch from ThreatCrowd
async function fetchThreatcrowd(domain: string): Promise<Set<string>> {
    const url = `https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${encodeURIComponent(domain)}`;
    return fetchSource(url, 30000, async (response) => {
        const data = await response.json();
        const subs = data.subdomains || [];
        return new Set(subs.map((s: string) => s.toLowerCase()).filter((s: string) => s.endsWith(domain) && !s.startsWith('*')));
    });
}

// Fetch from Wayback Archive
async function fetchWaybackarchive(domain: string): Promise<Set<string>> {
    const url = `http://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}&output=json&fl=original&collapse=urlkey&limit=10000`;
    return fetchSource(url, 40000, async (response) => {
        const data = await response.json();
        const hosts = new Set<string>();

        for (const row of data.slice(1)) {
            const original = row[0];
            try {
                const host = extractHostFromUrl(original);
                if (host && host.endsWith(domain) && !host.startsWith('*')) {
                    hosts.add(host);
                }
            } catch {
                continue;
            }
        }
        return hosts;
    });
}

// Fetch from CommonCrawl
async function fetchCommoncrawl(domain: string): Promise<Set<string>> {
    const indices = ['CC-MAIN-2024-51-index', 'CC-MAIN-2024-46-index', 'CC-MAIN-2024-38-index'];
    const found = new Set<string>();

    for (const idx of indices) {
        const url = `https://index.commoncrawl.org/${idx}?url=*.${encodeURIComponent(domain)}&output=json`;
        const result = await fetchSource(url, 30000, async (response) => {
            const text = await response.text();
            const hosts = new Set<string>();

            for (const line of text.split('\n')) {
                try {
                    const obj = JSON.parse(line.trim());
                    if (obj && obj.url) {
                        const host = extractHostFromUrl(obj.url);
                        if (host && host.endsWith(domain) && !host.startsWith('*')) {
                            hosts.add(host);
                        }
                    }
                } catch {
                    continue;
                }
            }
            return hosts;
        });

        result.forEach(host => found.add(host));
        if (found.size > 0) break;
    }
    return found;
}

// Fetch from CertSpotter
async function fetchCertspotter(domain: string): Promise<Set<string>> {
    const url = `https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names`;
    return fetchSource(url, 30000, async (response) => {
        const data = await response.json();
        const subs = new Set<string>();

        for (const entry of data) {
            const dnsNames = entry.dns_names || [];
            for (const name of dnsNames) {
                if (name.endsWith(domain) && !name.startsWith('*')) {
                    subs.add(name.toLowerCase());
                }
            }
        }
        return subs;
    });
}

// Fetch from Sublist3r API
async function fetchSublist3rApi(domain: string): Promise<Set<string>> {
    const url = `https://api.sublist3r.com/search.php?domain=${domain}`;
    return fetchSource(url, 30000, async (response) => {
        const data = await response.json();
        return new Set(data.map((s: string) => s.toLowerCase()).filter((s: string) => s.endsWith(domain) && !s.startsWith('*')));
    });
}

// Fetch from BeVigil
async function fetchBevigil(domain: string): Promise<Set<string>> {
    const url = `https://bevigil.com/api/${domain}/subdomains/`;
    return fetchSource(url, 30000, async (response) => {
        const data = await response.json();
        return new Set((data.subdomains || []).map((s: string) => s.toLowerCase()).filter((s: string) => s.endsWith(domain)));
    });
}

// Fetch from Riddler.io - CSV export endpoint (no auth required)
async function fetchRiddler(domain: string): Promise<Set<string>> {
    const url = `https://riddler.io/search/exportcsv?q=pld:${encodeURIComponent(domain)}`;
    return fetchSource(url, 30000, async (response) => {
        const text = await response.text();
        const subdomains = new Set<string>();

        for (const line of text.split('\n').slice(1)) { // Skip CSV header
            const parts = line.split(',');
            if (parts.length > 0) {
                const host = parts[0].trim().toLowerCase();
                if (host && host.endsWith(domain) && !host.startsWith('*')) {
                    subdomains.add(host);
                }
            }
        }
        return subdomains;
    });
}

// Fetch from LeakIX - Free tier (limited results without API key)
async function fetchLeakix(domain: string): Promise<Set<string>> {
    const url = `https://leakix.net/api/subdomains/${encodeURIComponent(domain)}`;
    return fetchSource(url, 30000, async (response) => {
        const data = await response.json();
        const subdomains = new Set<string>();

        if (Array.isArray(data)) {
            for (const entry of data) {
                const subdomain = entry.subdomain || entry;
                if (typeof subdomain === 'string' && subdomain.endsWith(domain) && !subdomain.startsWith('*')) {
                    subdomains.add(subdomain.toLowerCase());
                }
            }
        }
        return subdomains;
    });
}

// Fetch from DNSRepo
async function fetchDnsrepo(domain: string): Promise<Set<string>> {
    const url = `https://dnsrepo.noc.org/?domain=${encodeURIComponent(domain)}`;
    return fetchSource(url, 30000, async (response) => {
        const text = await response.text();
        const subdomains = new Set<string>();

        // Parse JSON-LD or text output
        const regex = new RegExp(`([a-zA-Z0-9\\.\\-]+\\.${domain.replace(/\./g, '\\.')})`, 'gi');
        const matches = text.matchAll(regex);

        for (const match of matches) {
            const sub = match[1].toLowerCase();
            if (!sub.startsWith('*')) {
                subdomains.add(sub);
            }
        }
        return subdomains;
    });
}

// Fetch from FullHunt.io
async function fetchFullhunt(domain: string): Promise<Set<string>> {
    const url = `https://fullhunt.io/api/v1/domain/${encodeURIComponent(domain)}/subdomains`;
    return fetchSource(url, 30000, async (response) => {
        const data = await response.json();
        const subdomains = new Set<string>();

        const hosts = data.hosts || data.subdomains || [];
        for (const host of hosts) {
            const hostname = typeof host === 'string' ? host : host.domain || host.host;
            if (hostname && hostname.endsWith(domain) && !hostname.startsWith('*')) {
                subdomains.add(hostname.toLowerCase());
            }
        }
        return subdomains;
    });
}

// Fetch from Hunter.io - Email search can reveal subdomains
async function fetchHunter(domain: string): Promise<Set<string>> {
    const url = `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}`;
    return fetchSource(url, 30000, async (response) => {
        const data = await response.json();
        const subdomains = new Set<string>();

        if (data.data && data.data.emails) {
            for (const email of data.data.emails) {
                if (email.sources) {
                    for (const source of email.sources) {
                        if (source.domain && source.domain.endsWith(domain)) {
                            subdomains.add(source.domain.toLowerCase());
                        }
                        if (source.uri) {
                            try {
                                const host = extractHostFromUrl(source.uri);
                                if (host && host.endsWith(domain) && !host.startsWith('*')) {
                                    subdomains.add(host);
                                }
                            } catch {
                                continue;
                            }
                        }
                    }
                }
            }
        }
        return subdomains;
    });
}

// Fetch from Censys
async function fetchCensys(domain: string): Promise<Set<string>> {
    const url = `https://search.censys.io/api/v2/certificates?q=${encodeURIComponent(domain)}`;
    return fetchSource(url, 30000, async (response) => {
        const data = await response.json();
        const subdomains = new Set<string>();

        if (data.results) {
            for (const cert of data.results) {
                const names = cert.names || cert.parsed?.names || [];
                for (const name of names) {
                    if (name.endsWith(domain) && !name.startsWith('*')) {
                        subdomains.add(name.toLowerCase());
                    }
                }
            }
        }
        return subdomains;
    });
}

// Fetch from BinaryEdge
async function fetchBinaryedge(domain: string): Promise<Set<string>> {
    const url = `https://api.binaryedge.io/v2/query/domains/subdomain/${encodeURIComponent(domain)}`;
    return fetchSource(url, 30000, async (response) => {
        const data = await response.json();
        const subdomains = new Set<string>();

        const events = data.events || [];
        for (const subdomain of events) {
            if (typeof subdomain === 'string' && subdomain.endsWith(domain) && !subdomain.startsWith('*')) {
                subdomains.add(subdomain.toLowerCase());
            }
        }
        return subdomains;
    });
}

// Fetch from ZoomEye
async function fetchZoomeye(domain: string): Promise<Set<string>> {
    const url = `https://api.zoomeye.org/domain/search?q=${encodeURIComponent(domain)}`;
    return fetchSource(url, 30000, async (response) => {
        const data = await response.json();
        const subdomains = new Set<string>();

        if (data.list) {
            for (const item of data.list) {
                const name = item.name || item.domain;
                if (name && name.endsWith(domain) && !name.startsWith('*')) {
                    subdomains.add(name.toLowerCase());
                }
            }
        }
        return subdomains;
    });
}

// Main POST handler
export async function POST(request: NextRequest) {
    try {
        const { domain } = await request.json();

        if (!domain) {
            return NextResponse.json({ error: 'Domain is required' }, { status: 400 });
        }

        const cleanDomain = normalizeDomain(domain);
        const allSubdomains = new Set<string>();
        const progress: ScanProgress[] = [];

        // Map source names to fetch functions
        const sourceFunctions = {
            'crt.sh': fetchCrtsh,
            'RapidDNS': fetchRapiddns,
            'AlienVault': fetchAlienvault,
            'HackerTarget': fetchHackertarget,
            'Anubis': fetchAnubis,
            'CommonCrawl': fetchCommoncrawl,
            'ThreatCrowd': fetchThreatcrowd,
            'WaybackArchive': fetchWaybackarchive,
            'Sublist3rAPI': fetchSublist3rApi,
            'CertSpotter': fetchCertspotter,
            'BeVigil': fetchBevigil,
            'Riddler': fetchRiddler,
            'LeakIX': fetchLeakix,
            'DNSRepo': fetchDnsrepo,
            'FullHunt': fetchFullhunt,
            'Hunter': fetchHunter,
            'Censys': fetchCensys,
            'BinaryEdge': fetchBinaryedge,
            'ZoomEye': fetchZoomeye,
        };

        // Fetch from all sources in parallel
        const results = await Promise.allSettled(
            Object.entries(sourceFunctions).map(async ([name, func]) => {
                const subs = await func(cleanDomain);
                return { name, subs };
            })
        );

        // Process results
        for (const result of results) {
            if (result.status === 'fulfilled') {
                const { name, subs } = result.value;
                const count = subs.size;
                // Correctly add subdomains to the main set
                subs.forEach(sub => allSubdomains.add(sub));
                progress.push({
                    source: name,
                    count,
                    status: 'success'
                });
            } else {
                // Find which source failed
                const index = results.indexOf(result);
                const name = Object.keys(sourceFunctions)[index];
                progress.push({
                    source: name,
                    count: 0,
                    status: 'failed'
                });
            }
        }

        // Process and clean subdomains
        const finalSubdomains = processSubdomains(allSubdomains, cleanDomain);

        return NextResponse.json({
            domain: cleanDomain,
            subdomains: finalSubdomains,
            progress,
            total: finalSubdomains.length
        });

    } catch (error) {
        console.error('Scan error:', error);
        return createErrorResponse('Failed to scan subdomains');
    }
}
