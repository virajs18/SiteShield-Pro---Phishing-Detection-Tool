import React, { useState } from 'react';
import { Shield, Search, CheckCircle, AlertTriangle, Loader2, Globe, Lock } from 'lucide-react';

interface ScanResult {
  safe: boolean;
  maliciousCount: number;
  totalScans: number;
  details: string;
  normalizedUrl: string;
}

function App() {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const API_KEY = '790c9d74b4f7f516fc512500c4cb0d45937d040266f8fad9bdfad72bac4f0531';

  const normalizeUrl = (urlString: string) => {
    let normalized = urlString.trim().toLowerCase();
    
    // Add protocol if missing
    if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
      normalized = 'https://' + normalized;
    }
    
    try {
      const urlObj = new URL(normalized);
      
      // Remove trailing slash
      if (urlObj.pathname === '/') {
        urlObj.pathname = '';
      }
      
      // Sort query parameters for consistency
      const params = new URLSearchParams(urlObj.search);
      const sortedParams = new URLSearchParams();
      Array.from(params.keys()).sort().forEach(key => {
        sortedParams.append(key, params.get(key) || '');
      });
      urlObj.search = sortedParams.toString();
      
      return urlObj.toString();
    } catch {
      return normalized;
    }
  };

  const isValidUrl = (urlString: string) => {
    try {
      const normalized = normalizeUrl(urlString);
      const url = new URL(normalized);
      return url.protocol === 'http:' || url.protocol === 'https:';
    } catch {
      return false;
    }
  };

  const base64UrlEncode = (str: string) => {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };

  const scanUrl = async () => {
    if (!url.trim()) {
      setError('Please enter a URL to scan');
      return;
    }

    if (!isValidUrl(url)) {
      setError('Please enter a valid URL (e.g., example.com or https://example.com)');
      return;
    }

    const normalizedUrl = normalizeUrl(url);
    
    setIsScanning(true);
    setError(null);
    setResult(null);

    try {
      // First, submit the URL for scanning
      const submitResponse = await fetch('/vtapi/urls', {
        method: 'POST',
        headers: {
          'x-apikey': API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `url=${encodeURIComponent(normalizedUrl)}`,
      });

      if (!submitResponse.ok) {
        throw new Error(`HTTP error! status: ${submitResponse.status}`);
      }

      // Wait a moment for the scan to process
      await new Promise(resolve => setTimeout(resolve, 3000));

      // Get the results using the encoded URL as ID
      const encodedUrl = base64UrlEncode(normalizedUrl);
      const resultResponse = await fetch(`/vtapi/urls/${encodedUrl}`, {
        headers: {
          'x-apikey': API_KEY,
        },
      });

      if (!resultResponse.ok) {
        throw new Error(`HTTP error! status: ${resultResponse.status}`);
      }

      const data = await resultResponse.json();
      const stats = data.data.attributes.last_analysis_stats;
      
      const maliciousCount = stats.malicious || 0;
      const suspiciousCount = stats.suspicious || 0;
      const totalScans = Object.values(stats).reduce((a: number, b: number) => a + b, 0);
      
      const isSafe = maliciousCount === 0 && suspiciousCount === 0;
      
      setResult({
        safe: isSafe,
        maliciousCount: maliciousCount + suspiciousCount,
        totalScans,
        normalizedUrl,
        details: isSafe 
          ? 'This website appears to be safe based on our security analysis.'
          : 'This website has been flagged as potentially dangerous by our security analysis.'
      });

    } catch (err) {
      console.error('Error scanning URL:', err);
      setError('Unable to scan URL. Please try again or check if the URL is accessible.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    scanUrl();
  };

  const handleUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const inputUrl = e.target.value;
    setUrl(inputUrl);
    
    // Clear previous results when URL changes
    if (result) {
      setResult(null);
    }
    if (error) {
      setError(null);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Animated background elements */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-purple-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse"></div>
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-blue-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse animation-delay-2000"></div>
      </div>

      {/* Header */}
      <header className="relative z-10 bg-white/5 backdrop-blur-md border-b border-white/10">
        <div className="max-w-6xl mx-auto px-6 py-8">
          <div className="flex items-center justify-center space-x-4">
            <div className="relative">
              <div className="absolute inset-0 bg-gradient-to-r from-blue-400 to-purple-400 rounded-full blur-sm opacity-75"></div>
              <div className="relative bg-gradient-to-r from-blue-500 to-purple-500 p-3 rounded-full">
                <Shield className="w-8 h-8 text-white" />
              </div>
            </div>
            <div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">
                SiteShield Pro
              </h1>
              <p className="text-slate-300 text-lg mt-1">
                Advanced Phishing Detection & URL Security Scanner
              </p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="relative z-10 max-w-6xl mx-auto px-6 py-16">
        {/* Scanner Card */}
        <div className="bg-white/10 backdrop-blur-md rounded-3xl border border-white/20 shadow-2xl overflow-hidden">
          <div className="bg-gradient-to-r from-blue-600/80 to-purple-600/80 backdrop-blur-sm px-8 py-8">
            <div className="flex items-center space-x-3 mb-2">
              <Globe className="w-7 h-7 text-white" />
              <h2 className="text-3xl font-bold text-white">URL Security Scanner</h2>
            </div>
            <p className="text-blue-100 text-lg">
              Enter any URL to check for phishing, malware, and other security threats
            </p>
          </div>

          <div className="p-8">
            <form onSubmit={handleSubmit} className="space-y-8">
              <div>
                <label htmlFor="url" className="block text-lg font-semibold text-slate-200 mb-3">
                  Website URL
                </label>
                <div className="relative">
                  <Globe className="absolute left-4 top-1/2 transform -translate-y-1/2 w-6 h-6 text-slate-400" />
                  <input
                    id="url"
                    type="text"
                    value={url}
                    onChange={handleUrlChange}
                    placeholder="example.com or https://www.example.com"
                    className="w-full pl-14 pr-6 py-5 text-xl bg-white/10 backdrop-blur-sm border border-white/20 rounded-2xl focus:ring-2 focus:ring-purple-400 focus:border-transparent transition-all duration-300 text-white placeholder-slate-400 hover:bg-white/15"
                    disabled={isScanning}
                  />
                </div>
                {url && (
                  <p className="mt-3 text-slate-300">
                    Will scan: <span className="font-mono text-purple-300 bg-white/10 px-3 py-1 rounded-lg">{normalizeUrl(url)}</span>
                  </p>
                )}
              </div>

              <button
                type="submit"
                disabled={isScanning || !url.trim()}
                className="w-full bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 disabled:from-slate-600 disabled:to-slate-700 text-white font-bold py-5 px-8 rounded-2xl transition-all duration-300 flex items-center justify-center space-x-3 text-xl shadow-lg hover:shadow-purple-500/25 disabled:cursor-not-allowed transform hover:scale-[1.02] disabled:hover:scale-100"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-6 h-6 animate-spin" />
                    <span>Scanning...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-6 h-6" />
                    <span>Scan Now</span>
                  </>
                )}
              </button>
            </form>

            {/* Error Display */}
            {error && (
              <div className="mt-8 p-6 bg-red-500/20 border border-red-400/30 rounded-2xl backdrop-blur-sm">
                <div className="flex items-center space-x-3">
                  <AlertTriangle className="w-6 h-6 text-red-400" />
                  <p className="text-red-300 font-semibold text-lg">Error</p>
                </div>
                <p className="text-red-200 mt-2 text-lg">{error}</p>
              </div>
            )}

            {/* Loading Display */}
            {isScanning && (
              <div className="mt-8 p-8 bg-blue-500/20 border border-blue-400/30 rounded-2xl backdrop-blur-sm">
                <div className="flex items-center justify-center space-x-4">
                  <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
                  <div>
                    <p className="text-blue-300 font-semibold text-xl">Analyzing URL Security</p>
                    <p className="text-blue-200 text-lg mt-1">Checking against threat databases...</p>
                  </div>
                </div>
              </div>
            )}

            {/* Results Display */}
            {result && !isScanning && (
              <div className={`mt-8 p-8 rounded-2xl border-2 backdrop-blur-sm ${
                result.safe 
                  ? 'bg-green-500/20 border-green-400/40' 
                  : 'bg-red-500/20 border-red-400/40'
              }`}>
                <div className="flex items-start space-x-4">
                  {result.safe ? (
                    <CheckCircle className="w-10 h-10 text-green-400 flex-shrink-0 mt-1" />
                  ) : (
                    <AlertTriangle className="w-10 h-10 text-red-400 flex-shrink-0 mt-1" />
                  )}
                  <div className="flex-1">
                    <h3 className={`text-2xl font-bold ${
                      result.safe ? 'text-green-300' : 'text-red-300'
                    }`}>
                      {result.safe ? '✅ This site appears safe' : '⚠️ Potential threat detected'}
                    </h3>
                    <p className={`mt-2 text-lg font-mono ${
                      result.safe ? 'text-green-200' : 'text-red-200'
                    } bg-white/10 px-3 py-2 rounded-lg inline-block`}>
                      {result.normalizedUrl}
                    </p>
                    <p className={`mt-4 text-lg ${
                      result.safe ? 'text-green-200' : 'text-red-200'
                    }`}>
                      {result.details}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Info Cards */}
        <div className="grid lg:grid-cols-2 gap-8 mt-12">
          <div className="bg-white/10 backdrop-blur-md rounded-2xl border border-white/20 p-8 hover:bg-white/15 transition-all duration-300">
            <div className="flex items-center space-x-4 mb-6">
              <div className="bg-gradient-to-r from-blue-500 to-purple-500 p-3 rounded-xl">
                <Shield className="w-7 h-7 text-white" />
              </div>
              <h3 className="text-2xl font-bold text-slate-200">How It Works</h3>
            </div>
            <ul className="space-y-4 text-slate-300">
              <li className="flex items-start space-x-3">
                <span className="w-2 h-2 bg-gradient-to-r from-blue-400 to-purple-400 rounded-full mt-3 flex-shrink-0"></span>
                <span className="text-lg">Normalizes URLs to detect unique websites</span>
              </li>
              <li className="flex items-start space-x-3">
                <span className="w-2 h-2 bg-gradient-to-r from-blue-400 to-purple-400 rounded-full mt-3 flex-shrink-0"></span>
                <span className="text-lg">Submits URL to VirusTotal's threat database</span>
              </li>
              <li className="flex items-start space-x-3">
                <span className="w-2 h-2 bg-gradient-to-r from-blue-400 to-purple-400 rounded-full mt-3 flex-shrink-0"></span>
                <span className="text-lg">Analyzes against multiple security engines</span>
              </li>
              <li className="flex items-start space-x-3">
                <span className="w-2 h-2 bg-gradient-to-r from-blue-400 to-purple-400 rounded-full mt-3 flex-shrink-0"></span>
                <span className="text-lg">Provides real-time security verdict</span>
              </li>
            </ul>
          </div>

          <div className="bg-white/10 backdrop-blur-md rounded-2xl border border-white/20 p-8 hover:bg-white/15 transition-all duration-300">
            <div className="flex items-center space-x-4 mb-6">
              <div className="bg-gradient-to-r from-purple-500 to-pink-500 p-3 rounded-xl">
                <Lock className="w-7 h-7 text-white" />
              </div>
              <h3 className="text-2xl font-bold text-slate-200">Threat Detection</h3>
            </div>
            <ul className="space-y-4 text-slate-300">
              <li className="flex items-start space-x-3">
                <span className="w-2 h-2 bg-gradient-to-r from-purple-400 to-pink-400 rounded-full mt-3 flex-shrink-0"></span>
                <span className="text-lg">Detects suspicious banking site clones</span>
              </li>
              <li className="flex items-start space-x-3">
                <span className="w-2 h-2 bg-gradient-to-r from-purple-400 to-pink-400 rounded-full mt-3 flex-shrink-0"></span>
                <span className="text-lg">Identifies fake social media login pages</span>
              </li>
              <li className="flex items-start space-x-3">
                <span className="w-2 h-2 bg-gradient-to-r from-purple-400 to-pink-400 rounded-full mt-3 flex-shrink-0"></span>
                <span className="text-lg">Catches malicious email attachments</span>
              </li>
              <li className="flex items-start space-x-3">
                <span className="w-2 h-2 bg-gradient-to-r from-purple-400 to-pink-400 rounded-full mt-3 flex-shrink-0"></span>
                <span className="text-lg">Protects against credential theft attempts</span>
              </li>
            </ul>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="relative z-10 bg-white/5 backdrop-blur-md border-t border-white/10 mt-20">
        <div className="max-w-6xl mx-auto px-6 py-8">
          <div className="text-center">
            <p className="text-slate-300 text-lg">
              Powered by VirusTotal API • Built for educational and security research purposes
            </p>
            <p className="text-slate-400 mt-2">
              Always exercise caution when visiting unknown websites
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;