'use client';

// Side-effect layer for scan-machine.ts: performs fetches and dispatches events.
// All state transitions live in the reducer; this hook only drives them.

import { useCallback, useEffect, useReducer, useRef } from 'react';
import { initialScanState, scanReducer } from './scan-machine';
import type { ScanProgress, ScanResult, SubdomainResult } from './subdomain-scanner';

/** Status-check batches allowed in flight at once. */
const VERIFY_CONCURRENCY = 3;

type StreamMessage =
  | { type: 'start'; sources: string[] }
  | ({ type: 'source'; subdomains: string[] } & ScanProgress)
  | { type: 'done'; result: ScanResult }
  | { type: 'error'; error: string };

// Yield one parsed object per NDJSON line as bytes arrive.
async function* readNdjson(body: ReadableStream<Uint8Array>): AsyncGenerator<StreamMessage> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let newline;
    while ((newline = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (line) yield JSON.parse(line);
    }
  }
  if (buffer.trim()) yield JSON.parse(buffer);
}

// Small lists go in one request; large ones are split into ~10 batches
// (30–100 each) so the UI shows progress without overwhelming the server.
function toBatches(subdomains: string[]): string[][] {
  if (subdomains.length <= 50) return [subdomains];
  const size = Math.min(Math.max(30, Math.ceil(subdomains.length / 10)), 100);
  const batches: string[][] = [];
  for (let i = 0; i < subdomains.length; i += size) batches.push(subdomains.slice(i, i + size));
  return batches;
}

const isAbort = (err: unknown) => err instanceof Error && err.name === 'AbortError';

export function useScan() {
  const [state, dispatch] = useReducer(scanReducer, initialScanState);
  const nextId = useRef(0);
  const abortRef = useRef<AbortController | null>(null);

  // Cancel in-flight work on unmount.
  useEffect(() => () => abortRef.current?.abort(), []);

  const replaceController = () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    return controller;
  };

  const scan = useCallback(async (domain: string) => {
    const scanId = ++nextId.current;
    const { signal } = replaceController(); // also aborts any running verify
    dispatch({ type: 'SCAN_STARTED', scanId, domain });

    try {
      // GET so the browser/CDN can cache it; NDJSON so results render as each source lands.
      const response = await fetch(`/api/subdomains/scan?domain=${encodeURIComponent(domain)}`, { signal });
      if (!response.ok || !response.body) throw new Error('Connection failed. Check target and retry.');

      let result: ScanResult | undefined;
      for await (const msg of readNdjson(response.body)) {
        if (msg.type === 'start') {
          dispatch({ type: 'SOURCES_ANNOUNCED', scanId, sources: msg.sources });
        } else if (msg.type === 'source') {
          const { subdomains, source, count, status } = msg;
          dispatch({ type: 'SOURCE_REPORTED', scanId, progress: { source, count, status }, subdomains });
        } else if (msg.type === 'done') {
          result = msg.result;
        } else {
          throw new Error(msg.error);
        }
      }
      if (!result) throw new Error('Scan interrupted. Check connection and retry.');
      dispatch({ type: 'SCAN_SUCCEEDED', scanId, result, completedAt: Date.now() });
    } catch (err) {
      if (isAbort(err)) return;
      dispatch({ type: 'SCAN_FAILED', scanId, error: err instanceof Error ? err.message : 'System error occurred' });
    }
  }, []);

  const verify = useCallback(async (subdomains: string[]) => {
    if (subdomains.length === 0) return;
    const runId = ++nextId.current;
    const { signal } = replaceController();
    dispatch({ type: 'VERIFY_STARTED', runId });

    const queue = toBatches(subdomains);
    // Small worker pool: up to VERIFY_CONCURRENCY batches in flight, in list order.
    const worker = async () => {
      for (let batch = queue.shift(); batch; batch = queue.shift()) {
        if (signal.aborted) return;
        dispatch({ type: 'BATCH_STARTED', runId, batch });
        try {
          const response = await fetch('/api/subdomains/status', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ subdomains: batch }),
            signal,
          });
          if (!response.ok) throw new Error(`Status check failed (${response.status})`);
          const data: { results: SubdomainResult[] } = await response.json();
          dispatch({ type: 'BATCH_SUCCEEDED', runId, batch, results: data.results });
        } catch (err) {
          if (isAbort(err)) return;
          console.error('Status check failed:', err);
          dispatch({ type: 'BATCH_FAILED', runId, batch });
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(VERIFY_CONCURRENCY, queue.length) }, worker));
    if (!signal.aborted) dispatch({ type: 'VERIFY_FINISHED', runId });
  }, []);

  return { state, scan, verify };
}
