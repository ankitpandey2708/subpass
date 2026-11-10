'use client';

import { useState, useSyncExternalStore } from 'react';
import { SubdomainResult, normalizeDomain } from '@/app/lib/subdomain-scanner';
import { SubdomainStatus, subdomainStatus, verifyResults, verifySummary } from '@/app/lib/scan-machine';
import { useScan } from '@/app/lib/use-scan';

const noopSubscribe = () => () => {};

const GROUPS:{ status: SubdomainStatus; label: string; icon: string; color: string }[] = [
  { status: 'active', label: 'Active', icon: '◆', color: '#39ff14' },
  { status: 'down', label: 'Down', icon: '◇', color: '#ff3d00' },
  { status: 'unchecked', label: 'Unchecked', icon: '○', color: '#555566' },
];

function StatusIcon({ status }: { status: SubdomainStatus }) {
  switch (status) {
    case 'checking':
      return <span className="text-[#00f0ff] text-base animate-pulse">&#x25CF;</span>;
    case 'active':
      return <span className="status-working text-base">&#x25C6;</span>;
    case 'down':
      return <span className="status-failed text-base">&#x25C7;</span>;
    default:
      return <span className="status-pending text-xs">&#x25CB;</span>;
  }
}

function SubdomainRow({
  subdomain,
  status,
  result,
  index,
}: {
  subdomain: string;
  status: SubdomainStatus;
  result?: SubdomainResult;
  index: number;
}) {
  const protocol = status === 'active' ? result?.protocol : undefined;
  return (
    <div
      className="subdomain-item flex items-center justify-between p-3 slide-in"
      style={{ animationDelay: `${Math.min(index * 0.02, 0.5)}s` }}
      data-status={status}
    >
      <div className="flex items-center gap-3 min-w-0">
        <span className="w-5 text-center flex-shrink-0">
          <StatusIcon status={status} />
        </span>
        <a
          href={`${protocol ?? 'https://'}${subdomain}`}
          target="_blank"
          rel="noopener noreferrer"
          className="subdomain-text font-mono text-sm text-[#8888a0] truncate hover:text-[#00f0ff] transition-colors"
          title={subdomain}
        >
          {subdomain}
        </a>
      </div>
      {protocol && (
        <span className="protocol-badge px-2 py-0.5 flex-shrink-0 ml-2">
          {protocol.replace('://', '').toUpperCase()}
        </span>
      )}
    </div>
  );
}

export default function Scanner({ sourcesCount }: { sourcesCount: number }) {
  const [domain, setDomain] = useState('');
  const [inputError, setInputError] = useState('');
  // false during SSR + hydration, true afterwards (gates the entrance animation)
  const mounted = useSyncExternalStore(noopSubscribe, () => true, () => false);
  const { state, scan, verify } = useScan();

  const scanning = state.phase === 'scanning';
  const error = inputError || (state.phase === 'failed' ? state.error : '');
  const done = state.phase === 'done' ? state : null;
  const live = state.phase === 'scanning' ? state : null;
  // What the results card shows: final results, or partial ones while sources stream in
  const view = done
    ? { domain: done.result.domain, subdomains: done.result.subdomains }
    : live && live.subdomains.length > 0
      ? { domain: live.domain, subdomains: live.subdomains }
      : null;
  const sourcesTotal = live?.sources.length || sourcesCount;
  const sourcesReported = live?.progress.length ?? 0;
  const unhealthySources = done?.result.progress.filter(p => p.status !== 'success') ?? [];
  const verifyState = done?.verify ?? { phase: 'idle' as const };
  const verifying = verifyState.phase === 'running';
  const results = verifyResults(verifyState);
  const { checked: checkedCount, active: workingCount, down: downCount } = verifySummary(verifyState);
  const failedProbes = verifyState.phase === 'idle' ? 0 : verifyState.failedCount;

  const handleScan = () => {
    if (scanning) return;
    if (!domain.trim()) {
      setInputError('ERROR: No target specified');
      return;
    }
    setInputError('');
    const normalizedDomain = normalizeDomain(domain.trim());
    if (normalizedDomain !== domain.trim()) setDomain(normalizedDomain);
    scan(normalizedDomain);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') handleScan();
  };

  const renderList = () => {
    if (!view) return null;
    const { subdomains } = view;

    if (subdomains.length === 0) {
      return (
        <div className="text-center py-16 font-mono">
          <div className="text-[#555566] text-lg mb-2">NO TARGETS FOUND</div>
          <div className="text-[#8888a0] text-sm">
            Domain returned empty results from all sources
          </div>
        </div>
      );
    }

    // Flat list for < 10 subdomains or before any status has come back
    if (subdomains.length < 10 || checkedCount === 0) {
      return (
        <div className="space-y-1 max-h-[500px] overflow-y-auto custom-scrollbar pr-2">
          {subdomains.map((subdomain, index) => (
            <SubdomainRow
              key={subdomain}
              subdomain={subdomain}
              status={subdomainStatus(verifyState, subdomain)}
              result={results.get(subdomain)}
              index={index}
            />
          ))}
        </div>
      );
    }

    // Grouped by status; in-flight rows stay in the "unchecked" group
    const grouped: Record<string, string[]> = { active: [], down: [], unchecked: [] };
    for (const subdomain of subdomains) {
      const s = subdomainStatus(verifyState, subdomain);
      grouped[s === 'checking' ? 'unchecked' : s].push(subdomain);
    }

    return (
      <div className="space-y-4 max-h-[500px] overflow-y-auto custom-scrollbar pr-2">
        {GROUPS.map(({ status, label, icon, color }) => {
          const items = grouped[status];
          if (items.length === 0) return null;
          return (
            <div key={status} data-group={status}>
              <div className="flex items-center gap-2 mb-2 pb-2 border-b border-[#1a1a2e]">
                <span className="text-sm" style={{ color }}>{icon}</span>
                <span className="font-mono text-xs tracking-wider uppercase" style={{ color }}>
                  {status === 'unchecked' && verifying ? 'Checking' : label}
                </span>
                <span className="text-[#555566] text-xs font-mono">({items.length})</span>
              </div>
              <div className="space-y-1">
                {items.map((subdomain, index) => (
                  <SubdomainRow
                    key={subdomain}
                    subdomain={subdomain}
                    status={subdomainStatus(verifyState, subdomain)}
                    result={results.get(subdomain)}
                    index={index}
                  />
                ))}
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <div className="scanlines noise" data-scan-phase={state.phase} data-verify-phase={verifyState.phase}>
      <div className="min-h-screen cyber-grid relative overflow-hidden">
        {/* Ambient glow effects */}
        <div className="fixed top-0 left-1/4 w-96 h-96 bg-[#00f0ff] opacity-5 blur-[150px] pointer-events-none" />
        <div className="fixed bottom-0 right-1/4 w-96 h-96 bg-[#ff00a8] opacity-5 blur-[150px] pointer-events-none" />

        {/* Scanning line effect when active */}
        {scanning && <div className="scanning-line" />}

        <div className="relative z-10 min-h-screen flex flex-col px-4 py-8 md:px-8 md:py-12">
          {/* Header Section */}
          <header className={`text-center mb-12 md:mb-16 ${mounted ? 'fade-in-up' : 'opacity-0'}`}>
            {/* ASCII Art Logo */}
            <div className="mb-6 font-mono text-[#00f0ff] text-xs md:text-sm opacity-60 select-none hidden md:block">
              <pre className="inline-block text-left">
{`╔═══════════════════════════════════════════════════════════╗
║  ███████╗██╗   ██╗██████╗ ██████╗  █████╗ ███████╗███████╗ ║
║  ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝ ║
║  ███████╗██║   ██║██████╔╝██████╔╝███████║███████╗███████╗ ║
║  ╚════██║██║   ██║██╔══██╗██╔═══╝ ██╔══██║╚════██║╚════██║ ║
║  ███████║╚██████╔╝██████╔╝██║     ██║  ██║███████║███████║ ║
║  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ║
╚═══════════════════════════════════════════════════════════╝`}
              </pre>
            </div>

            {/* Mobile Logo */}
            <h1
              className="md:hidden text-4xl font-bold tracking-wider mb-4 glow-cyan"
              style={{ fontFamily: "'Orbitron', sans-serif" }}
            >
              <span className="text-[#00f0ff]">SUB</span>
              <span className="text-[#ff00a8]">PASS</span>
            </h1>

            {/* Subtitle */}
            <div className="flex items-center justify-center gap-3 text-[#8888a0] text-sm md:text-base">
              <span className="w-12 h-px bg-gradient-to-r from-transparent to-[#00f0ff]" />
              <span className="tracking-[0.2em] uppercase" style={{ fontFamily: "'Orbitron', sans-serif" }}>
                Subdomain Reconnaissance System
              </span>
              <span className="w-12 h-px bg-gradient-to-l from-transparent to-[#ff00a8]" />
            </div>

            {/* Source count badge */}
            <div className="mt-4 inline-flex items-center gap-2 px-4 py-2 border border-[#1a1a2e] bg-[#030308]">
              <span className="w-2 h-2 rounded-full bg-[#39ff14] shadow-[0_0_8px_rgba(57,255,20,0.5)]" />
              <span className="text-xs tracking-wider text-[#8888a0] uppercase" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                {sourcesCount} OSINT Sources Online
              </span>
            </div>
          </header>

          {/* Main Content */}
          <main className="flex-1 max-w-4xl w-full mx-auto">
            {/* Input Terminal Card */}
            <div
              className={`cyber-card neon-box mb-8 ${mounted ? 'fade-in-up' : 'opacity-0'}`}
              style={{ animationDelay: '0.1s' }}
            >
              {/* Card Header */}
              <div className="cyber-header">
                <span className={`cyber-header-dot ${!scanning && !error ? 'active' : ''}`} />
                <span className="cyber-header-dot" />
                <span className="cyber-header-dot" />
                <span className="ml-2">target_acquisition.exe</span>
              </div>

              {/* Card Content */}
              <div className="p-6 md:p-8">
                <div className="flex flex-col md:flex-row gap-4">
                  {/* Terminal Input */}
                  <div className="flex-1 relative">
                    <div className="absolute left-4 top-1/2 -translate-y-1/2 text-[#00f0ff] font-mono text-sm opacity-70">
                      $&gt;
                    </div>
                    <input
                      type="text"
                      value={domain}
                      onChange={(e) => {
                        setDomain(e.target.value);
                        if (inputError) setInputError('');
                      }}
                      onKeyDown={handleKeyDown}
                      placeholder="example.com"
                      aria-label="Target domain"
                      aria-invalid={!!error}
                      className="terminal-input w-full pl-12 pr-4 py-4 text-[#e8e8f0] font-mono text-base md:text-lg placeholder:text-[#555566]"
                      disabled={scanning}
                      autoComplete="off"
                      spellCheck="false"
                      autoFocus
                    />
                  </div>

                  {/* Scan Button */}
                  <button
                    onClick={handleScan}
                    disabled={scanning}
                    aria-busy={scanning}
                    className="cyber-btn px-8 py-4 text-sm md:text-base"
                    style={{ fontFamily: "'Orbitron', sans-serif" }}
                  >
                    {scanning ? (
                      <span className="flex items-center justify-center gap-3">
                        <span className="cyber-spinner" />
                        <span>Scanning</span>
                      </span>
                    ) : (
                      <>
                        <span className="mr-2">[</span>
                        Execute
                        <span className="ml-2">]</span>
                      </>
                    )}
                  </button>
                </div>

                {/* Error Display */}
                {error && (
                  <div role="alert" className="mt-4 p-4 border border-[#ff3d00] bg-[rgba(255,61,0,0.1)] font-mono text-sm">
                    <span className="text-[#ff3d00]">{'>'} {error}</span>
                  </div>
                )}

                {/* Scanning Progress Indicator */}
                {scanning && (
                  <div className="mt-6 font-mono text-sm text-[#8888a0]">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-[#00f0ff]">[</span>
                      <span className="flex-1 h-1 bg-[#1a1a2e] overflow-hidden">
                        <span className="block h-full w-1/3 bg-gradient-to-r from-[#00f0ff] to-[#ff00a8] animate-pulse"
                              style={{ animation: 'pulse 1s ease-in-out infinite' }} />
                      </span>
                      <span className="text-[#ff00a8]">]</span>
                    </div>
                    <p className="text-center text-xs tracking-wider animate-pulse" role="status">
                      QUERYING OSINT SOURCES... {sourcesReported}/{sourcesTotal}
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Results Section */}
            {view && (
              <div
                className="cyber-card neon-box fade-in-up"
                style={{ animationDelay: '0.2s' }}
              >
                {/* Results Header */}
                <div className="cyber-header justify-between">
                  <div className="flex items-center gap-2">
                    <span className="cyber-header-dot active" />
                    <span>scan_results.log</span>
                  </div>
                  <span className="text-[#00f0ff]">{view.domain}</span>
                </div>

                {/* Stats Bar */}
                <div className="p-4 border-b border-[#1a1a2e] bg-[#030308]">
                  <div className="flex flex-wrap items-center justify-between gap-4">
                    {/* Stats */}
                    <div className="flex items-center gap-6 font-mono text-sm" aria-live="polite">
                      <div className="flex items-center gap-2">
                        <span className="text-[#555566]">FOUND:</span>
                        <span className="text-[#00f0ff] glow-cyan text-lg font-bold" style={{ fontFamily: "'Orbitron', sans-serif" }}>
                          {view.subdomains.length}
                        </span>
                      </div>
                      {checkedCount > 0 && (
                        <>
                          <span className="text-[#1a1a2e]">|</span>
                          <div className="flex items-center gap-2">
                            <span className="text-[#555566]">ACTIVE:</span>
                            <span className="text-[#39ff14] glow-acid text-lg font-bold" style={{ fontFamily: "'Orbitron', sans-serif" }}>
                              {workingCount}
                            </span>
                          </div>
                          <span className="text-[#1a1a2e]">|</span>
                          <div className="flex items-center gap-2">
                            <span className="text-[#555566]">DOWN:</span>
                            <span className="text-[#ff3d00] text-lg font-bold" style={{ fontFamily: "'Orbitron', sans-serif" }}>
                              {downCount}
                            </span>
                          </div>
                        </>
                      )}
                      {failedProbes > 0 && !verifying && (
                        <>
                          <span className="text-[#1a1a2e]">|</span>
                          <span className="text-[#ff3d00] text-xs" role="alert">
                            {failedProbes} PROBE{failedProbes === 1 ? '' : 'S'} FAILED — RETRY
                          </span>
                        </>
                      )}
                    </div>

                    {/* Status Check Button */}
                    <button
                      onClick={() => done && verify(done.result.subdomains)}
                      disabled={!done || verifying || view.subdomains.length === 0}
                      aria-busy={verifying}
                      className="cyber-btn cyber-btn-secondary px-6 py-2 text-xs"
                      style={{ fontFamily: "'Orbitron', sans-serif" }}
                    >
                      {verifying ? (
                        <span className="flex items-center gap-2">
                          <span className="cyber-spinner" />
                          Probing {checkedCount}/{view.subdomains.length}
                        </span>
                      ) : (
                        'Verify Status'
                      )}
                    </button>
                  </div>
                </div>

                {/* Subdomain List */}
                <div className="p-4">{renderList()}</div>

                {/* Footer */}
                <div className="px-4 py-3 border-t border-[#1a1a2e] bg-[#030308] font-mono text-xs text-[#555566]">
                  <div className="flex items-center justify-between">
                    <span>
                      {done ? (
                        <>
                          Scan completed at {new Date(done.completedAt).toLocaleTimeString('en-US', { hour12: false })}
                          {unhealthySources.length > 0 && (
                            <span title={unhealthySources.map(p => `${p.source}: ${p.status}`).join('\n')}>
                              {' '}· {unhealthySources.length}/{done.result.progress.length} sources unavailable
                            </span>
                          )}
                        </>
                      ) : (
                        <span className="animate-pulse">
                          Receiving results… {sourcesReported}/{sourcesTotal} sources reported
                        </span>
                      )}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </main>

          {/* Footer */}
          <footer className={`mt-12 text-center ${mounted ? 'fade-in-up' : 'opacity-0'}`} style={{ animationDelay: '0.3s' }}>
            <div className="font-mono text-xs text-[#555566] tracking-wider">
              <span className="text-[#00f0ff]">&lt;</span>
              SUBPASS
              <span className="text-[#ff00a8]">/&gt;</span>
              <span className="mx-2 opacity-50">|</span>
              <span className="opacity-50">Reconnaissance Framework v1.0</span>
            </div>
          </footer>
        </div>
      </div>
    </div>
  );
}
