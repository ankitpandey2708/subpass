import { NextRequest, NextResponse } from 'next/server';
import { SubdomainResult, HEADERS, createErrorResponse } from '@/app/lib/subdomain-scanner';
import dns from 'dns/promises';
import https from 'https';
import http from 'http';

// Resolve DNS for a subdomain
async function resolveDns(subdomain: string): Promise<boolean> {
    try {
        await dns.lookup(subdomain);
        return true;
    } catch {
        return false;
    }
}

// Custom fetch function that ignores SSL certificate errors (matching Python's verify=False)
async function fetchWithoutSSLVerification(url: string, timeout: number): Promise<{ status: number }> {
    return new Promise((resolve, reject) => {
        const urlObj = new URL(url);
        const isHttps = urlObj.protocol === 'https:';
        const module = isHttps ? https : http;

        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || (isHttps ? 443 : 80),
            path: urlObj.pathname + urlObj.search,
            method: 'GET',
            headers: {
                'User-Agent': HEADERS['User-Agent'],
            },
            rejectUnauthorized: false, // Ignore SSL certificate errors
            timeout,
        };

        const req = module.request(options, (res) => {
            // Drain the response to prevent memory leaks
            res.resume();
            resolve({ status: res.statusCode || 0 });
        });

        req.on('error', reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });

        req.end();
    });
}

// Check subdomain status (DNS + HTTP)
async function checkSubdomainStatus(subdomain: string): Promise<SubdomainResult> {
    // First check DNS resolution
    const dnsResolved = await resolveDns(subdomain);

    if (!dnsResolved) {
        return {
            subdomain,
            working: false,
            protocol: undefined,
        };
    }

    // Try HTTPS and HTTP in parallel for faster results
    const protocols = ['https://', 'http://'];

    const results = await Promise.allSettled(
        protocols.map(async (protocol) => {
            const url = `${protocol}${subdomain}`;
            const response = await fetchWithoutSSLVerification(url, 10000);

            // Consider 2xx and 3xx status codes as "working"
            if (response.status >= 200 && response.status < 400) {
                return { protocol, status: response.status };
            }
            throw new Error('Not successful');
        })
    );

    // Return first successful result (prefer HTTPS over HTTP)
    for (let i = 0; i < results.length; i++) {
        if (results[i].status === 'fulfilled') {
            const value = (results[i] as PromiseFulfilledResult<{ protocol: string; status: number }>).value;
            return {
                subdomain,
                working: true,
                protocol: value.protocol,
            };
        }
    }

    // DNS resolved but no HTTP/HTTPS response
    return {
        subdomain,
        working: false,
        protocol: undefined,
    };
}

// PUT handler for checking multiple subdomains
export async function PUT(request: NextRequest) {
    try {
        const { subdomains } = await request.json();

        if (!subdomains || !Array.isArray(subdomains)) {
            return createErrorResponse('Subdomains array is required', 400);
        }

        // Check all subdomains in parallel
        const results = await Promise.all(
            subdomains.map((subdomain: string) => checkSubdomainStatus(subdomain))
        );

        const workingCount = results.filter(r => r.working).length;

        return NextResponse.json({
            results,
            total: results.length,
            working: workingCount,
            notWorking: results.length - workingCount,
        });

    } catch (error) {
        console.error('Status check error:', error);
        return createErrorResponse('Failed to check subdomain statuses');
    }
}
