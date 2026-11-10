// Explicit state machines for the scan page. Pure: no React, no fetch.
//
//  Scan
//    idle ─┐
//    failed┼─SCAN_STARTED──▶ scanning ⟲ SOURCES_ANNOUNCED | SOURCE_REPORTED (results stream in)
//    done ─┘                    ├──SCAN_SUCCEEDED──▶ done
//                               └──SCAN_FAILED─────▶ failed
//
//  Verify (lives inside scan `done`; a new scan discards it)
//    idle ─┐
//    done ─┴─VERIFY_STARTED──▶ running ⟲ BATCH_STARTED | BATCH_SUCCEEDED | BATCH_FAILED
//                                 └──VERIFY_FINISHED──▶ done
//    Batches may overlap: `inFlight` is the union of all batches currently out.
//
//  Subdomain (derived via `subdomainStatus`, never stored)
//    unchecked ──▶ checking ──▶ active | down
//
// Async events carry the scanId/runId they belong to. Events whose id does not
// match the current state are dropped, so responses from an aborted or
// superseded run can never leak into the UI.

import type { ScanProgress, ScanResult, SubdomainResult } from './subdomain-scanner';

export type SubdomainStatus = 'unchecked' | 'checking' | 'active' | 'down';

type VerifyState =
  | { phase: 'idle' }
  | {
      phase: 'running';
      runId: number;
      results: ReadonlyMap<string, SubdomainResult>;
      inFlight: ReadonlySet<string>;
      failedCount: number;
    }
  | { phase: 'done'; results: ReadonlyMap<string, SubdomainResult>; failedCount: number };

type ScanState =
  | { phase: 'idle' }
  | {
      phase: 'scanning';
      scanId: number;
      domain: string;
      /** Source names the server announced (empty until it does). */
      sources: string[];
      /** One entry per source that has reported so far. */
      progress: ScanProgress[];
      /** Sorted, deduped partial results. */
      subdomains: string[];
    }
  | { phase: 'failed'; error: string }
  | { phase: 'done'; result: ScanResult; completedAt: number; verify: VerifyState };

type ScanEvent =
  | { type: 'SCAN_STARTED'; scanId: number; domain: string }
  | { type: 'SOURCES_ANNOUNCED'; scanId: number; sources: string[] }
  | { type: 'SOURCE_REPORTED'; scanId: number; progress: ScanProgress; subdomains: string[] }
  | { type: 'SCAN_SUCCEEDED'; scanId: number; result: ScanResult; completedAt: number }
  | { type: 'SCAN_FAILED'; scanId: number; error: string }
  | { type: 'VERIFY_STARTED'; runId: number }
  | { type: 'BATCH_STARTED'; runId: number; batch: string[] }
  | { type: 'BATCH_SUCCEEDED'; runId: number; batch: string[]; results: SubdomainResult[] }
  | { type: 'BATCH_FAILED'; runId: number; batch: string[] }
  | { type: 'VERIFY_FINISHED'; runId: number };

export const initialScanState: ScanState = { phase: 'idle' };

const EMPTY_RESULTS: ReadonlyMap<string, SubdomainResult> = new Map();
const EMPTY_SET: ReadonlySet<string> = new Set();

function verifyReducer(state: VerifyState, event: ScanEvent): VerifyState {
  if (event.type === 'VERIFY_STARTED') {
    if (state.phase === 'running') return state; // one run at a time
    return { phase: 'running', runId: event.runId, results: EMPTY_RESULTS, inFlight: EMPTY_SET, failedCount: 0 };
  }

  if (state.phase !== 'running' || !('runId' in event) || event.runId !== state.runId) return state;

  const without = (batch: string[]) => {
    const inFlight = new Set(state.inFlight);
    for (const s of batch) inFlight.delete(s);
    return inFlight;
  };

  switch (event.type) {
    case 'BATCH_STARTED':
      return { ...state, inFlight: new Set([...state.inFlight, ...event.batch]) };
    case 'BATCH_SUCCEEDED': {
      const results = new Map(state.results);
      for (const r of event.results) results.set(r.subdomain, r);
      return { ...state, results, inFlight: without(event.batch) };
    }
    case 'BATCH_FAILED':
      return { ...state, inFlight: without(event.batch), failedCount: state.failedCount + event.batch.length };
    case 'VERIFY_FINISHED':
      return { phase: 'done', results: state.results, failedCount: state.failedCount };
    default:
      return state;
  }
}

export function scanReducer(state: ScanState, event: ScanEvent): ScanState {
  switch (event.type) {
    case 'SCAN_STARTED':
      if (state.phase === 'scanning') return state; // one scan at a time
      return { phase: 'scanning', scanId: event.scanId, domain: event.domain, sources: [], progress: [], subdomains: [] };
    case 'SOURCES_ANNOUNCED':
      if (state.phase !== 'scanning' || state.scanId !== event.scanId) return state;
      return { ...state, sources: event.sources };
    case 'SOURCE_REPORTED': {
      if (state.phase !== 'scanning' || state.scanId !== event.scanId) return state;
      const merged = new Set(state.subdomains);
      for (const s of event.subdomains) merged.add(s);
      const subdomains = merged.size === state.subdomains.length ? state.subdomains : Array.from(merged).sort();
      return { ...state, progress: [...state.progress, event.progress], subdomains };
    }
    case 'SCAN_SUCCEEDED':
      if (state.phase !== 'scanning' || state.scanId !== event.scanId) return state;
      return { phase: 'done', result: event.result, completedAt: event.completedAt, verify: { phase: 'idle' } };
    case 'SCAN_FAILED':
      if (state.phase !== 'scanning' || state.scanId !== event.scanId) return state;
      return { phase: 'failed', error: event.error };
    default: {
      if (state.phase !== 'done') return state;
      const verify = verifyReducer(state.verify, event);
      return verify === state.verify ? state : { ...state, verify };
    }
  }
}

// ---- Selectors ----

export function verifyResults(verify: VerifyState): ReadonlyMap<string, SubdomainResult> {
  return verify.phase === 'idle' ? EMPTY_RESULTS : verify.results;
}

export function subdomainStatus(verify: VerifyState, subdomain: string): SubdomainStatus {
  if (verify.phase === 'running' && verify.inFlight.has(subdomain)) return 'checking';
  const result = verifyResults(verify).get(subdomain);
  if (!result) return 'unchecked';
  return result.working ? 'active' : 'down';
}

export function verifySummary(verify: VerifyState) {
  const results = verifyResults(verify);
  let active = 0;
  for (const r of results.values()) if (r.working) active++;
  return { checked: results.size, active, down: results.size - active };
}
