'use client';

import { useState, useEffect } from 'react';
import { ScanResult, ScanProgress, SubdomainResult, normalizeDomain } from '@/app/lib/subdomain-scanner';
import { SOURCES_COUNT } from '@/app/api/subdomains/scan/route';

export default function Home() {
  const [domain, setDomain] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [progress, setProgress] = useState<ScanProgress[]>([]);
  const [error, setError] = useState('');
  const [checkingStatus, setCheckingStatus] = useState(false);
  const [subdomainStatuses, setSubdomainStatuses] = useState<Map<string, SubdomainResult>>(new Map());
  const [checkingSubdomains, setCheckingSubdomains] = useState<Set<string>>(new Set());
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const handleScan = async () => {
    if (!domain.trim()) {
      setError('ERROR: No target specified');
      return;
    }

    setScanning(true);
    setError('');
    setScanResult(null);
    setProgress([]);
    setSubdomainStatuses(new Map());

    try {
      // Normalize domain to extract clean domain from URLs
      const normalizedDomain = normalizeDomain(domain.trim());

      // Update input field if normalized domain is different
      if (normalizedDomain !== domain.trim()) {
        setDomain(normalizedDomain);
      }

      const response = await fetch('/api/subdomains/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: normalizedDomain }),
      });

      if (!response.ok) {
        throw new Error('Connection failed. Check target and retry.');
      }

      const data: ScanResult = await response.json();
      setScanResult(data);
      setProgress(data.progress);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'System error occurred');
    } finally {
      setScanning(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleScan();
    }
  };

  const checkAllStatuses = async () => {
    if (!scanResult || scanResult.subdomains.length === 0) return;

    setCheckingStatus(true);
    setCheckingSubdomains(new Set()); // Clear checking set at start
    const newStatuses = new Map<string, SubdomainResult>();

    try {
      const subdomains = scanResult.subdomains;
      const batchSize = 5; // Process 5 subdomains at a time for real-time updates

      // Process subdomains in batches
      for (let i = 0; i < subdomains.length; i += batchSize) {
        const batch = subdomains.slice(i, i + batchSize);

        // Mark current batch as being checked
        setCheckingSubdomains(new Set(batch));

        const response = await fetch('/api/subdomains/status', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ subdomains: batch }),
        });

        if (response.ok) {
          const data = await response.json();
          data.results.forEach((result: SubdomainResult) => {
            newStatuses.set(result.subdomain, result);
          });
          // Update UI after each batch completes
          setSubdomainStatuses(new Map(newStatuses));
        }

        // Clear checking state for this batch
        setCheckingSubdomains(new Set());
      }
    } catch (err) {
      console.error('Status check failed:', err);
    } finally {
      setCheckingStatus(false);
      setCheckingSubdomains(new Set());
    }
  };

  const workingCount = Array.from(subdomainStatuses.values()).filter(s => s.working).length;
  const checkedCount = subdomainStatuses.size;

  return (
    <div className="scanlines noise">
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
                {SOURCES_COUNT} OSINT Sources Online
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
                      onChange={(e) => setDomain(e.target.value)}
                      onKeyPress={handleKeyPress}
                      placeholder="example.com"
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
                  <div className="mt-4 p-4 border border-[#ff3d00] bg-[rgba(255,61,0,0.1)] font-mono text-sm">
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
                    <p className="text-center text-xs tracking-wider animate-pulse">
                      QUERYING OSINT SOURCES...
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Results Section */}
            {scanResult && (
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
                  <span className="text-[#00f0ff]">{scanResult.domain}</span>
                </div>

                {/* Stats Bar */}
                <div className="p-4 border-b border-[#1a1a2e] bg-[#030308]">
                  <div className="flex flex-wrap items-center justify-between gap-4">
                    {/* Stats */}
                    <div className="flex items-center gap-6 font-mono text-sm">
                      <div className="flex items-center gap-2">
                        <span className="text-[#555566]">FOUND:</span>
                        <span className="text-[#00f0ff] glow-cyan text-lg font-bold" style={{ fontFamily: "'Orbitron', sans-serif" }}>
                          {scanResult.total}
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
                              {checkedCount - workingCount}
                            </span>
                          </div>
                        </>
                      )}
                    </div>

                    {/* Status Check Button */}
                    <button
                      onClick={checkAllStatuses}
                      disabled={checkingStatus}
                      className="cyber-btn cyber-btn-secondary px-6 py-2 text-xs"
                      style={{ fontFamily: "'Orbitron', sans-serif" }}
                    >
                      {checkingStatus ? (
                        <span className="flex items-center gap-2">
                          <span className="cyber-spinner" />
                          Probing {checkedCount}/{scanResult.total}
                        </span>
                      ) : (
                        'Verify Status'
                      )}
                    </button>
                  </div>
                </div>

                {/* Subdomain List */}
                <div className="p-4">
                  {scanResult.subdomains.length === 0 ? (
                    <div className="text-center py-16 font-mono">
                      <div className="text-[#555566] text-lg mb-2">NO TARGETS FOUND</div>
                      <div className="text-[#8888a0] text-sm">
                        Domain returned empty results from all sources
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-1 max-h-[500px] overflow-y-auto custom-scrollbar pr-2">
                      {scanResult.subdomains.map((subdomain, index) => {
                        const status = subdomainStatuses.get(subdomain);
                        const isChecking = checkingSubdomains.has(subdomain);
                        return (
                          <div
                            key={subdomain}
                            className="subdomain-item flex items-center justify-between p-3 slide-in"
                            style={{ animationDelay: `${Math.min(index * 0.02, 0.5)}s` }}
                          >
                            <div className="flex items-center gap-3 min-w-0">
                              {/* Status Indicator */}
                              <span className="w-5 text-center flex-shrink-0">
                                {isChecking ? (
                                  <span className="text-[#00f0ff] text-base animate-pulse">&#x25CF;</span>
                                ) : status ? (
                                  status.working ? (
                                    <span className="status-working text-base">&#x25C6;</span>
                                  ) : (
                                    <span className="status-failed text-base">&#x25C7;</span>
                                  )
                                ) : (
                                  <span className="status-pending text-xs">&#x25CB;</span>
                                )}
                              </span>

                              {/* Subdomain Name */}
                              <span
                                className="subdomain-text font-mono text-sm text-[#8888a0] truncate"
                                title={subdomain}
                              >
                                {subdomain}
                              </span>
                            </div>

                            {/* Protocol Badge */}
                            {status?.working && status.protocol && (
                              <span className="protocol-badge px-2 py-0.5 flex-shrink-0 ml-2">
                                {status.protocol.replace('://', '').toUpperCase()}
                              </span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Footer */}
                <div className="px-4 py-3 border-t border-[#1a1a2e] bg-[#030308] font-mono text-xs text-[#555566]">
                  <div className="flex items-center justify-between">
                    <span>
                      Scan completed at {new Date().toLocaleTimeString('en-US', { hour12: false })}
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
