'use client';

import { useState } from 'react';
import { ScanResult, ScanProgress, SubdomainResult } from '@/app/lib/subdomain-scanner';

export default function Home() {
  const [domain, setDomain] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [progress, setProgress] = useState<ScanProgress[]>([]);
  const [error, setError] = useState('');
  const [checkingStatus, setCheckingStatus] = useState(false);
  const [subdomainStatuses, setSubdomainStatuses] = useState<Map<string, SubdomainResult>>(new Map());

  const handleScan = async () => {
    if (!domain.trim()) {
      setError('Please enter a domain');
      return;
    }

    setScanning(true);
    setError('');
    setScanResult(null);
    setProgress([]);
    setSubdomainStatuses(new Map());

    try {
      const response = await fetch('/api/subdomains/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim() }),
      });

      if (!response.ok) {
        throw new Error('Failed to scan domain');
      }

      const data: ScanResult = await response.json();
      setScanResult(data);
      setProgress(data.progress);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
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
    const newStatuses = new Map<string, SubdomainResult>();

    try {
      const response = await fetch('/api/subdomains/status', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subdomains: scanResult.subdomains }),
      });

      if (response.ok) {
        const data = await response.json();
        data.results.forEach((result: SubdomainResult) => {
          newStatuses.set(result.subdomain, result);
        });
        setSubdomainStatuses(newStatuses);
      }
    } catch (err) {
      console.error('Failed to check statuses:', err);
    } finally {
      setCheckingStatus(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 text-white p-8">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-5xl font-bold mb-4 bg-gradient-to-r from-blue-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">
            Subdomain Scanner
          </h1>
          <p className="text-gray-300 text-lg">
            Discover subdomains using 11 powerful OSINT data sources
          </p>
        </div>

        {/* Input Section */}
        <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-8 mb-8 border border-white/20 shadow-2xl">
          <div className="flex gap-4">
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Enter domain (e.g., example.com)"
              className="flex-1 px-6 py-4 bg-white/5 border border-white/10 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent text-white placeholder-gray-400 text-lg transition-all"
              disabled={scanning}
            />
            <button
              onClick={handleScan}
              disabled={scanning}
              className="px-8 py-4 bg-gradient-to-r from-purple-500 to-pink-500 rounded-xl font-semibold text-lg hover:from-purple-600 hover:to-pink-600 disabled:opacity-50 disabled:cursor-not-allowed transition-all transform hover:scale-105 shadow-lg"
            >
              {scanning ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Scanning...
                </span>
              ) : (
                'Scan'
              )}
            </button>
          </div>

          {error && (
            <div className="mt-4 p-4 bg-red-500/20 border border-red-500/50 rounded-lg text-red-200">
              {error}
            </div>
          )}
        </div>


        {/* Results Section */}
        {scanResult && (
          <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-8 border border-white/20 shadow-2xl">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-2xl font-bold flex items-center gap-2">
                <span className="text-green-400">✓</span>
                Found {scanResult.total} Subdomains for {scanResult.domain}
              </h2>
              <button
                onClick={checkAllStatuses}
                disabled={checkingStatus}
                className="px-6 py-3 bg-gradient-to-r from-blue-500 to-cyan-500 rounded-lg font-semibold hover:from-blue-600 hover:to-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg"
              >
                {checkingStatus ? 'Checking...' : 'Check Status'}
              </button>
            </div>

            {scanResult.subdomains.length === 0 ? (
              <div className="text-center py-12 text-gray-400">
                <p className="text-xl">No subdomains found for this domain</p>
              </div>
            ) : (
              <div className="space-y-2 max-h-[600px] overflow-y-auto custom-scrollbar">
                {scanResult.subdomains.map((subdomain) => {
                  const status = subdomainStatuses.get(subdomain);
                  return (
                    <div
                      key={subdomain}
                      className="flex items-center justify-between p-4 bg-white/5 hover:bg-white/10 rounded-lg border border-white/10 transition-all group"
                    >
                      <div className="flex items-center gap-3">
                        {status ? (
                          status.working ? (
                            <span className="text-green-400 text-xl" title="Working">✓</span>
                          ) : (
                            <span className="text-red-400 text-xl" title="Not Working">✗</span>
                          )
                        ) : (
                          <span className="text-gray-500 text-xl">○</span>
                        )}
                        <span className="font-mono text-gray-200 group-hover:text-white transition-colors">
                          {subdomain}
                        </span>
                      </div>
                      {status?.working && status.protocol && (
                        <span className="text-xs px-3 py-1 bg-purple-500/30 border border-purple-500/50 rounded-full text-purple-200">
                          {status.protocol.replace('://', '').toUpperCase()}
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

          </div>
        )}
      </div>
    </div>
  );
}
