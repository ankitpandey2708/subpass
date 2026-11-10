import { NextRequest, NextResponse } from 'next/server';
import { normalizeDomain, createErrorResponse } from '@/app/lib/subdomain-scanner';
import { runScan, sourceNames } from '@/app/lib/run-scan';

// Results change slowly; let the browser reuse a scan for 5 min and the CDN for
// 1 h (serving stale up to a day while it refreshes in the background).
const CACHE_CONTROL = 'public, max-age=300, s-maxage=3600, stale-while-revalidate=86400';

/**
 * GET /api/subdomains/scan?domain=example.com — streaming, cacheable.
 * Responds with NDJSON, one JSON object per line:
 *   {"type":"start","domain":"example.com","sources":["crt.sh", ...]}
 *   {"type":"source","source":"crt.sh","status":"success","count":17,"subdomains":[...]}   (one per source, as each settles)
 *   {"type":"done","result":{domain, subdomains, progress, total}}                        (same shape as POST)
 */
export async function GET(request: NextRequest) {
    const domain = normalizeDomain(request.nextUrl.searchParams.get('domain') ?? '');
    if (!domain) {
        return NextResponse.json({ error: 'Domain is required' }, { status: 400 });
    }

    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
        async start(controller) {
            const send = (msg: object) => controller.enqueue(encoder.encode(JSON.stringify(msg) + '\n'));
            try {
                send({ type: 'start', domain, sources: sourceNames() });
                const result = await runScan(domain, (progress, subdomains) =>
                    send({ type: 'source', ...progress, subdomains }));
                send({ type: 'done', result });
            } catch (error) {
                console.error('Scan error:', error);
                send({ type: 'error', error: 'Failed to scan subdomains' });
            } finally {
                controller.close();
            }
        },
    });

    return new Response(stream, {
        headers: {
            'Content-Type': 'application/x-ndjson; charset=utf-8',
            'Cache-Control': CACHE_CONTROL,
        },
    });
}

/** POST { domain } — single JSON response (kept for API compatibility). */
export async function POST(request: NextRequest) {
    try {
        const { domain } = await request.json();

        if (!domain) {
            return NextResponse.json({ error: 'Domain is required' }, { status: 400 });
        }

        return NextResponse.json(await runScan(normalizeDomain(domain)));
    } catch (error) {
        console.error('Scan error:', error);
        return createErrorResponse('Failed to scan subdomains');
    }
}
