import { NextRequest, NextResponse } from 'next/server';
import { HEADERS, processSubdomains, ScanProgress } from '@/app/lib/subdomain-scanner';

// Fetch from crt.sh - Certificate Transparency logs
async function fetchCrtsh(domain: string): Promise<Set<string>> {
    const url = `https://crt.sh/?q=%25.${domain}&output=json`;
    try {
        const response = await fetch(url, {
            headers: HEADERS,
            signal: AbortSignal.timeout(60000),
            cache: 'no-store'
        });
        if (!response.ok) return new Set();

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
    } catch {
        return new Set();
    }
}

// Fetch from RapidDNS
async function fetchRapiddns(domain: string): Promise<Set<string>> {
    const url = `https://rapiddns.io/subdomain/${domain}?full=1`;
    try {
        const response = await fetch(url, {
            headers: HEADERS,
            signal: AbortSignal.timeout(30000),
            cache: 'no-store'
        });
        if (!response.ok) return new Set();

        const text = await response.text();
        // More inclusive regex to capture all subdomains in the table
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
    } catch {
        return new Set();
    }
}

// Fetch from AlienVault OTX
async function fetchAlienvault(domain: string): Promise<Set<string>> {
    const url = `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`;
    try {
        const response = await fetch(url, {
            headers: HEADERS,
            signal: AbortSignal.timeout(30000),
            cache: 'no-store'
        });
        if (!response.ok) return new Set();

        const data = await response.json();
        const subdomains = new Set<string>();

        for (const entry of data.passive_dns || []) {
            const hostname = entry.hostname;
            if (hostname && hostname.endsWith(domain) && !hostname.startsWith('*')) {
                subdomains.add(hostname.toLowerCase());
            }
        }
        return subdomains;
    } catch {
        return new Set();
    }
}

// Fetch from HackerTarget
async function fetchHackertarget(domain: string): Promise<Set<string>> {
    const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
    try {
        const response = await fetch(url, {
            headers: HEADERS,
            signal: AbortSignal.timeout(30000),
            cache: 'no-store'
        });
        if (!response.ok) return new Set();

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
    } catch {
        return new Set();
    }
}

// Fetch from Anubis
async function fetchAnubis(domain: string): Promise<Set<string>> {
    const url = `https://jldc.me/anubis/subdomains/${domain}`;
    try {
        const response = await fetch(url, {
            headers: HEADERS,
            signal: AbortSignal.timeout(30000),
            cache: 'no-store'
        });
        if (!response.ok) return new Set();

        const data = await response.json();
        if (Array.isArray(data)) {
            return new Set(data.map(h => h.toLowerCase()).filter(h => h.endsWith(domain) && !h.startsWith('*')));
        }
        return new Set();
    } catch {
        return new Set();
    }
}

// Fetch from ThreatCrowd
async function fetchThreatcrowd(domain: string): Promise<Set<string>> {
    const url = `https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${encodeURIComponent(domain)}`;
    try {
        const response = await fetch(url, {
            headers: HEADERS,
            signal: AbortSignal.timeout(30000),
            cache: 'no-store'
        });
        if (!response.ok) return new Set();

        const data = await response.json();
        const subs = data.subdomains || [];
        return new Set(subs.map((s: string) => s.toLowerCase()).filter((s: string) => s.endsWith(domain) && !s.startsWith('*')));
    } catch {
        return new Set();
    }
}

// Fetch from Wayback Archive
async function fetchWaybackarchive(domain: string): Promise<Set<string>> {
    const url = `http://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}&output=json&fl=original&collapse=urlkey&limit=10000`;
    try {
        const response = await fetch(url, {
            headers: HEADERS,
            signal: AbortSignal.timeout(40000),
            cache: 'no-store'
        });
        if (!response.ok) return new Set();

        const data = await response.json();
        const hosts = new Set<string>();

        for (const row of data.slice(1)) {
            const original = row[0];
            try {
                // More robust extraction than new URL() which identifies protocol-less strings
                let host = original;
                if (host.includes('://')) {
                    host = host.split('://')[1];
                }
                host = host.split('/')[0].split(':')[0].toLowerCase();

                if (host && host.endsWith(domain) && !host.startsWith('*')) {
                    hosts.add(host);
                }
            } catch {
                continue;
            }
        }
        return hosts;
    } catch {
        return new Set();
    }
}

// Fetch from CommonCrawl
async function fetchCommoncrawl(domain: string): Promise<Set<string>> {
    const indices = ['CC-MAIN-2024-51-index', 'CC-MAIN-2024-46-index', 'CC-MAIN-2024-38-index'];
    const found = new Set<string>();

    for (const idx of indices) {
        try {
            const url = `https://index.commoncrawl.org/${idx}?url=*.${encodeURIComponent(domain)}&output=json`;
            const response = await fetch(url, {
                headers: HEADERS,
                signal: AbortSignal.timeout(30000),
                cache: 'no-store'
            });
            if (!response.ok) continue;

            const text = await response.text();
            for (const line of text.split('\n')) {
                try {
                    const obj = JSON.parse(line.trim());
                    if (obj && obj.url) {
                        let host = obj.url;
                        if (host.includes('://')) {
                            host = host.split('://')[1];
                        }
                        host = host.split('/')[0].split(':')[0].toLowerCase();

                        if (host && host.endsWith(domain) && !host.startsWith('*')) {
                            found.add(host);
                        }
                    }
                } catch {
                    continue;
                }
            }
            if (found.size > 0) break;
        } catch {
            continue;
        }
    }
    return found;
}

// Fetch from CertSpotter
async function fetchCertspotter(domain: string): Promise<Set<string>> {
    const url = `https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names`;
    try {
        const response = await fetch(url, {
            headers: HEADERS,
            signal: AbortSignal.timeout(30000),
            cache: 'no-store'
        });
        if (!response.ok) return new Set();

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
    } catch {
        return new Set();
    }
}

// Fetch from Sublist3r API
async function fetchSublist3rApi(domain: string): Promise<Set<string>> {
    const url = `https://api.sublist3r.com/search.php?domain=${domain}`;
    try {
        const response = await fetch(url, {
            headers: HEADERS,
            signal: AbortSignal.timeout(30000),
            cache: 'no-store'
        });
        if (!response.ok) return new Set();

        const data = await response.json();
        return new Set(data.map((s: string) => s.toLowerCase()).filter((s: string) => s.endsWith(domain) && !s.startsWith('*')));
    } catch {
        return new Set();
    }
}

// Fetch from BeVigil
async function fetchBevigil(domain: string): Promise<Set<string>> {
    const url = `https://bevigil.com/api/${domain}/subdomains/`;
    try {
        const response = await fetch(url, {
            headers: HEADERS,
            signal: AbortSignal.timeout(30000),
            cache: 'no-store'
        });
        if (!response.ok) return new Set();

        const data = await response.json();
        return new Set((data.subdomains || []).map((s: string) => s.toLowerCase()).filter((s: string) => s.endsWith(domain)));
    } catch {
        return new Set();
    }
}

// Main POST handler
export async function POST(request: NextRequest) {
    try {
        const { domain } = await request.json();

        if (!domain) {
            return NextResponse.json({ error: 'Domain is required' }, { status: 400 });
        }

        const cleanDomain = domain.toLowerCase().trim();
        const allSubdomains = new Set<string>();
        const progress: ScanProgress[] = [];

        // Define all sources matching subdomain.py
        const sources = {
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
        };

        // Fetch from all sources in parallel
        const results = await Promise.allSettled(
            Object.entries(sources).map(async ([name, func]) => {
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
                const name = Object.keys(sources)[index];
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
        return NextResponse.json({ error: 'Failed to scan subdomains' }, { status: 500 });
    }
}
