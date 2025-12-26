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

// Domain validation regex constant
const DOMAIN_REGEX = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

// Normalize domain input to extract clean domain
// Handles: https://www.npci.org.in/, www.npci.org.in/, npci.org.in/abc
export function normalizeDomain(input: string): string {
    let domain = input.trim().toLowerCase();

    // Remove protocol (http://, https://)
    domain = domain.replace(/^https?:\/\//, '');

    // Remove www. prefix
    domain = domain.replace(/^www\./, '');

    // Remove path, query params, and fragment
    domain = domain.split('/')[0].split('?')[0].split('#')[0];

    // Remove port if present
    domain = domain.split(':')[0];

    return domain;
}

// Deduplicate and filter subdomains
export function processSubdomains(subdomains: Set<string>, baseDomain: string): string[] {
    const cleaned = new Set<string>();

    for (const sub of subdomains) {
        const s = sub.trim().toLowerCase();
        // Must end with base domain, not be the base domain itself, and not start with wildcard
        if (s.endsWith(baseDomain) && s !== baseDomain && !s.startsWith('*')) {
            // Regex validation matching Python script
            if (DOMAIN_REGEX.test(s)) {
                cleaned.add(s);
            }
        }
    }

    return Array.from(cleaned).sort();
}

// Extract host from URL string (handles URLs with/without protocol)
export function extractHostFromUrl(url: string): string {
    let host = url;
    if (host.includes('://')) {
        host = host.split('://')[1];
    }
    return host.split('/')[0].split(':')[0].toLowerCase();
}

// Generic fetch wrapper for all OSINT sources
export async function fetchSource(
    url: string,
    timeout: number,
    parser: (response: Response) => Promise<Set<string>>
): Promise<Set<string>> {
    try {
        const response = await fetch(url, {
            headers: HEADERS,
            signal: AbortSignal.timeout(timeout),
            cache: 'no-store'
        });
        if (!response.ok) return new Set();
        return await parser(response);
    } catch {
        return new Set();
    }
}

// Helper function for creating consistent error responses
export function createErrorResponse(message: string, status = 500) {
    if (typeof window === 'undefined') {
        // Server-side only - import NextResponse dynamically
        const { NextResponse } = require('next/server');
        return NextResponse.json({ error: message }, { status });
    }
    throw new Error('createErrorResponse should only be used server-side');
}
