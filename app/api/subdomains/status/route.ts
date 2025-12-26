import { NextRequest, NextResponse } from 'next/server';
import { SubdomainResult } from '@/app/lib/subdomain-scanner';
import dns from 'dns/promises';

// Resolve DNS for a subdomain
async function resolveDns(subdomain: string): Promise<boolean> {
    try {
        await dns.lookup(subdomain);
        return true;
    } catch {
        return false;
    }
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

    // Try HTTPS first, then HTTP
    const protocols = ['https://', 'http://'];

    for (const protocol of protocols) {
        try {
            const url = `${protocol}${subdomain}`;
            const response = await fetch(url, {
                method: 'GET',
                redirect: 'follow',
                signal: AbortSignal.timeout(10000), // 10 second timeout
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                },
            });

            // Consider 2xx and 3xx status codes as "working"
            if (response.status >= 200 && response.status < 400) {
                return {
                    subdomain,
                    working: true,
                    protocol,
                };
            }
        } catch {
            // If fetch fails, try the next protocol
            continue;
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
            return NextResponse.json(
                { error: 'Subdomains array is required' },
                { status: 400 }
            );
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
        return NextResponse.json(
            { error: 'Failed to check subdomain statuses' },
            { status: 500 }
        );
    }
}
