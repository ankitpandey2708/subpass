// Type definitions and utilities for subdomain scanning
export interface SubdomainResult {
    subdomain: string;
    working: boolean;
    protocol?: string;
    source?: string;
}

export interface ScanProgress {
    source: string;
    count: number;
    status: 'success' | 'failed';
}

export interface ScanResult {
    domain: string;
    subdomains: string[];
    progress: ScanProgress[];
    total: number;
}

// Headers that replicate Python script
export const HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
};

// Validate domain format
export function isValidDomain(domain: string): boolean {
    const domainRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;
    return domainRegex.test(domain);
}

// Clean and validate subdomain
export function cleanSubdomain(subdomain: string, baseDomain: string): string | null {
    const cleaned = subdomain.trim().toLowerCase();

    // Must end with base domain and not start with wildcard
    if (!cleaned.endsWith(baseDomain) || cleaned.startsWith('*')) {
        return null;
    }

    // Validate format
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/.test(cleaned)) {
        return null;
    }

    return cleaned;
}

// Deduplicate and filter subdomains
export function processSubdomains(subdomains: Set<string>, baseDomain: string): string[] {
    const cleaned = new Set<string>();
    const domainRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

    for (const sub of subdomains) {
        const s = sub.trim().toLowerCase();
        // Must end with base domain, not be the base domain itself, and not start with wildcard
        if (s.endsWith(baseDomain) && s !== baseDomain && !s.startsWith('*')) {
            // Regex validation matching Python script
            if (domainRegex.test(s)) {
                cleaned.add(s);
            }
        }
    }

    return Array.from(cleaned).sort();
}
