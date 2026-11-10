// Server-only scan runner shared by the JSON (POST) and streaming (GET) endpoints.

import { activeSources } from './sources';
import { processSubdomains, type ScanProgress, type ScanResult } from './subdomain-scanner';

/** Whole-scan deadline. Sources still running then are reported as 'timeout'. */
const SCAN_DEADLINE_MS = 25_000;

const TIMED_OUT = Symbol('timeout');

/**
 * Query every active source in parallel. `onSource` fires as each one settles
 * (success, failure, or deadline), with that source's cleaned subdomains.
 */
export async function runScan(
    domain: string,
    onSource?: (progress: ScanProgress, subdomains: string[]) => void
): Promise<ScanResult> {
    const sources = activeSources();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<typeof TIMED_OUT>(resolve => {
        timer = setTimeout(() => resolve(TIMED_OUT), SCAN_DEADLINE_MS);
    });

    const all = new Set<string>();
    const progress: ScanProgress[] = [];

    await Promise.all(sources.map(async ({ name, fetch, apiKey }) => {
        let entry: ScanProgress;
        let subs: string[] = [];
        try {
            const result = await Promise.race([fetch(domain, apiKey), deadline]);
            if (result === TIMED_OUT) {
                entry = { source: name, count: 0, status: 'timeout' };
            } else {
                subs = processSubdomains(result, domain);
                subs.forEach(s => all.add(s));
                entry = { source: name, count: result.size, status: 'success' };
            }
        } catch (err) {
            console.warn(`[scan] ${name} failed:`, err instanceof Error ? err.message : err);
            entry = { source: name, count: 0, status: 'failed' };
        }
        progress.push(entry);
        onSource?.(entry, subs);
    }));
    clearTimeout(timer);

    // Keep progress in registry order regardless of completion order.
    const order = new Map(sources.map((s, i) => [s.name, i]));
    progress.sort((a, b) => order.get(a.source)! - order.get(b.source)!);

    const subdomains = Array.from(all).sort();
    return { domain, subdomains, progress, total: subdomains.length };
}

export const sourceNames = () => activeSources().map(s => s.name);
