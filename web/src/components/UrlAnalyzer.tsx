"use client";

/**
 * URL Analyzer component - Redesigned for a typography-focused, icon-free theme.
 * Uses ASCII/text symbols and follows a strict monochromatic aesthetic.
 */

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { analyzeUrl, type WebSecurityAnalysis } from "@/lib/api";
import { Map, MapMarker, MarkerContent } from "@/components/ui/map";

// --- Sub-components for better modularity ---

interface DataItemProps {
  label: string;
  value: string | number | null | undefined;
}

const DataItem = ({ label, value }: DataItemProps) => {
  if (!value) return null;
  return (
    <div className="flex flex-col gap-1 py-2 border-b border-white/5 last:border-0 font-mono">
      <span className="text-[9px] uppercase tracking-[0.2em] text-white/40 font-bold">
        {label}
      </span>
      <span className="text-sm text-white truncate uppercase">{value}</span>
    </div>
  );
};

interface SectionProps {
  title: string;
  symbol: string;
  children: React.ReactNode;
  className?: string;
  hasData?: boolean;
  helpText?: string;
}

const Section = ({
  title,
  symbol,
  children,
  className = "",
  hasData = true,
  helpText,
}: SectionProps) => {
  const [showHelp, setShowHelp] = useState(false);
  if (!hasData) return null;
  return (
    <div
      className={`rounded-none border border-white/10 bg-black transition-colors relative group ${className}`}
    >
      <div className="px-4 py-2 border-b border-white/10 flex items-center justify-between bg-white/5">
        <h3 className="text-[10px] font-bold uppercase tracking-[0.3em] flex items-center gap-2 text-white">
          <span className="text-white/40">[{symbol}]</span>
          {title}
        </h3>
        {helpText && (
          <button
            onClick={() => setShowHelp(!showHelp)}
            className="text-[10px] text-white/20 hover:text-white font-bold transition-colors"
          >
            [?]
          </button>
        )}
      </div>
      {showHelp && helpText && (
        <div className="absolute inset-x-0 top-[37px] z-20 bg-white text-black p-4 text-[10px] font-bold leading-relaxed uppercase animate-in fade-in slide-in-from-top-1 duration-200">
          <div className="flex justify-between items-start mb-2 border-b border-black/10 pb-1">
            <span>METHODOLOGY_INFO</span>
            <button
              onClick={() => setShowHelp(false)}
              className="hover:opacity-60"
            >
              [X]
            </button>
          </div>
          {helpText}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
};

// --- Threat Level Utilities ---

/**
 * Gets the normalized threat level from a string (case-insensitive).
 * 
 * @param threatLevel - The threat level string (e.g., "LOW", "high", "Critical")
 * @returns Normalized uppercase threat level or null
 */
const normalizeThreatLevel = (
  threatLevel: string | null | undefined
): string | null => {
  if (!threatLevel) return null;
  return threatLevel.toUpperCase().trim();
};

/**
 * Gets the threat level based on score if level is missing.
 * 
 * @param threatLevel - The threat level string
 * @param threatScore - The numeric threat score
 * @returns Normalized threat level
 */
const getThreatLevel = (
  threatLevel: string | null | undefined,
  threatScore: number | null | undefined
): string | null => {
  const normalized = normalizeThreatLevel(threatLevel);
  if (normalized) return normalized;
  
  // Fallback to score-based classification
  const score = threatScore ?? 0;
  if (score >= 50) return "CRITICAL";
  if (score >= 30) return "HIGH";
  if (score >= 15) return "MEDIUM";
  return "LOW";
};

/**
 * Gets the status message and styling for a threat level.
 * 
 * @param threatLevel - The threat level string
 * @param threatScore - The numeric threat score
 * @returns Object with message and className
 */
const getThreatStatusInfo = (
  threatLevel: string | null | undefined,
  threatScore: number | null | undefined
): { message: string; className: string } | null => {
  const level = getThreatLevel(threatLevel, threatScore);
  
  switch (level) {
    case "LOW":
      return {
        message: "✓ SAFE - GOOD SECURITY POSTURE",
        className: "text-white/60"
      };
    case "MEDIUM":
      return {
        message: "⚠ MODERATE RISK - REVIEW RECOMMENDED",
        className: "text-cyan-400"
      };
    case "HIGH":
      return {
        message: "⚠ HIGH RISK - ACTION REQUIRED",
        className: "text-yellow-400"
      };
    case "CRITICAL":
      return {
        message: "✗ CRITICAL RISK - URGENT ACTION REQUIRED",
        className: "text-red-400"
      };
    default:
      return null;
  }
};

// --- Main Component ---

export default function UrlAnalyzer() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<WebSecurityAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showInfo, setShowInfo] = useState(false);
  const [showThreatScoreInfo, setShowThreatScoreInfo] = useState(false);

  const handleAnalyze = async () => {
    if (!url.trim()) {
      setError("ERROR: TARGET_UNDEFINED");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    setProgress(0);

    const progressInterval = setInterval(() => {
      setProgress((prev) => (prev >= 90 ? prev : prev + 10));
    }, 200);

    try {
      const analysis = await analyzeUrl(url);
      clearInterval(progressInterval);
      setProgress(100);
      setResult(analysis);
      if (analysis.status === "error")
        setError(`ANALYSIS_FAILED: ${analysis.error || "UNKNOWN_ERROR"}`);
    } catch (err) {
      clearInterval(progressInterval);
      setError(
        `CRITICAL_FAILURE: ${err instanceof Error ? err.message : "NETWORK_ERROR"}`,
      );
    } finally {
      setLoading(false);
      setTimeout(() => setProgress(0), 1000);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && !loading) handleAnalyze();
  };

  const formatDate = (dateStr: string | null | undefined) => {
    if (!dateStr) return "N/A";
    try {
      return new Date(dateStr).toISOString().split("T")[0];
    } catch {
      return dateStr;
    }
  };

  const getSubjectName = (
    subject: Record<string, string> | string | undefined,
  ): string => {
    if (!subject) return "---";
    if (typeof subject === "string") return subject;
    return subject.commonName || subject.CN || JSON.stringify(subject);
  };

  return (
    <div className="min-h-screen bg-black text-white font-mono selection:bg-white selection:text-black">
      {/* Top Banner Area */}
      <div className="sticky top-0 z-50 bg-black border-b border-white/10">
        <div className="container mx-auto px-6 max-w-[1600px]">
          <div className="flex items-center justify-between h-20 gap-8">
            <div className="flex-1 relative group flex items-center gap-4">
              <div className="relative flex-1">
                <span className="absolute left-4 top-1/2 -translate-y-1/2 text-white/40 font-bold">
                  $
                </span>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="ENTER_TARGET_URL..."
                  className="w-full pl-10 pr-4 py-3 bg-black border border-white/10 text-sm focus:outline-none focus:border-white transition-all font-mono uppercase placeholder:text-white/20"
                  disabled={loading}
                />
                {loading && (
                  <div className="absolute right-4 top-1/2 -translate-y-1/2 text-[10px] font-bold animate-pulse text-white/40">
                    RUNNING...
                  </div>
                )}
              </div>
              <button
                onClick={() => setShowInfo(true)}
                className="text-white/40 hover:text-white border border-white/10 hover:border-white px-3 py-3 transition-all text-xs font-bold shrink-0"
                title="How it works"
              >
                [i]
              </button>
            </div>

            <button
              type="button"
              onClick={handleAnalyze}
              disabled={loading || !url.trim()}
              className="bg-white text-black px-10 py-3 text-xs font-black uppercase tracking-widest hover:bg-white/80 transition-all disabled:opacity-10 shrink-0"
            >
              EXECUTE_SCAN
            </button>
          </div>
          {loading && (
            <div className="px-4 pb-4">
              <Progress value={progress} />
            </div>
          )}
        </div>
      </div>

      <div className="container mx-auto px-6 py-12 max-w-[1600px]">
        {error && (
          <div className="mb-12 p-6 border border-white bg-white/5 flex flex-col gap-2">
            <span className="text-[10px] font-black uppercase tracking-[0.4em] text-white">
              ! CRITICAL_NOTICE
            </span>
            <span className="text-sm font-bold tracking-tight uppercase">
              {error}
            </span>
          </div>
        )}

        {result && result.status === "success" && (
          <div className="space-y-12 animate-in fade-in duration-700">
            {/* Summary Bar */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-6 border border-white/10 bg-black flex flex-col gap-3 relative">
                <span className="text-[9px] font-bold text-white/40 uppercase tracking-[0.3em]">
                  [01] STATUS_LEVEL
                </span>
                <div className="flex items-baseline justify-between">
                  <span className="text-xl font-black uppercase">
                    {result.threat_level || "UNKNOWN"}
                  </span>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono border border-white/20 px-2 py-0.5">
                      SCORE: {result.threat_score ?? 0}
                    </span>
                    <button
                      onClick={() => setShowThreatScoreInfo(!showThreatScoreInfo)}
                      className="text-white/40 hover:text-white text-[10px] font-bold transition-colors border border-white/10 hover:border-white px-1.5 py-0.5"
                      title="Threat Score Information"
                    >
                      [i]
                    </button>
                  </div>
                </div>
                {(() => {
                  const statusInfo = getThreatStatusInfo(
                    result.threat_level,
                    result.threat_score
                  );
                  if (!statusInfo) return null;
                  
                  return (
                    <div className="mt-2 pt-2 border-t border-white/10">
                      <span className={`text-[9px] font-bold uppercase tracking-widest ${statusInfo.className}`}>
                        {statusInfo.message}
                      </span>
                    </div>
                  );
                })()}
                {showThreatScoreInfo && (
                  <div className="absolute inset-x-0 top-[calc(100%+8px)] z-30 bg-white text-black p-4 text-[10px] font-bold leading-relaxed uppercase animate-in fade-in slide-in-from-top-1 duration-200 border border-white/20 shadow-2xl">
                    <div className="flex justify-between items-start mb-3 border-b border-black/10 pb-2">
                      <span className="font-black">THREAT_SCORE_METHODOLOGY</span>
                      <button
                        onClick={() => setShowThreatScoreInfo(false)}
                        className="hover:opacity-60 text-xs"
                      >
                        [X]
                      </button>
                    </div>
                    <div className="space-y-3 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
                      <div>
                        <span className="font-black block mb-1">SCORING_FACTORS:</span>
                        <div className="space-y-1 text-[9px] text-black/80">
                          <div>• SUSPICIOUS_URL_DETECTION: +25 POINTS</div>
                          <div>• SUSPICIOUS_PATH_PATTERNS: +10 POINTS EACH</div>
                          <div>• MISSING_SECURITY_HEADERS: +5 POINTS EACH</div>
                          <div className="pl-4">- STRICT-TRANSPORT-SECURITY</div>
                          <div className="pl-4">- X-FRAME-OPTIONS</div>
                          <div className="pl-4">- CONTENT-SECURITY-POLICY</div>
                          <div>• SSL_CERTIFICATE_ISSUES: +30 POINTS</div>
                        </div>
                      </div>
                      <div className="border-t border-black/10 pt-2">
                        <span className="font-black block mb-1">THREAT_LEVEL_SCALE:</span>
                        <div className="space-y-1 text-[9px] text-black/80">
                          <div className="flex items-center gap-2">
                            <span className="w-16 font-black">CRITICAL:</span>
                            <span>50+ POINTS (RED) - URGENT ACTION REQUIRED</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="w-16 font-black">HIGH:</span>
                            <span>30-49 POINTS (YELLOW) - SIGNIFICANT RISKS DETECTED</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="w-16 font-black">MEDIUM:</span>
                            <span>15-29 POINTS (CYAN) - MODERATE CONCERNS</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="w-16 font-black">LOW:</span>
                            <span>0-14 POINTS (WHITE) - SAFE, GOOD SECURITY POSTURE</span>
                          </div>
                        </div>
                      </div>
                      <div className="border-t border-black/10 pt-2 bg-green-50/50 p-2 rounded">
                        <span className="font-black block mb-1 text-green-900">SAFETY_INDICATOR:</span>
                        <div className="text-[9px] text-black/80 leading-relaxed">
                          A LOW THREAT SCORE (0-14 POINTS) INDICATES THE SITE IS SAFE AND SECURE. THIS MEANS: VALID SSL CERTIFICATE, PROPER SECURITY HEADERS PRESENT, NO SUSPICIOUS URL PATTERNS, AND OVERALL GOOD SECURITY HYGIENE. YOU CAN PROCEED WITH CONFIDENCE.
                        </div>
                      </div>
                      <div className="border-t border-black/10 pt-2">
                        <span className="font-black block mb-1">CALCULATION:</span>
                        <div className="text-[9px] text-black/80 leading-relaxed">
                          THREAT_SCORE IS CALCULATED BY SUMMING ALL DETECTED SECURITY ISSUES. HIGHER SCORES INDICATE GREATER SECURITY RISK. THE SYSTEM ANALYZES SSL CERTIFICATES, HTTP HEADERS, URL PATTERNS, AND PATH STRUCTURE TO DETERMINE THE FINAL THREAT LEVEL.
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
              <div className="p-6 border border-white/10 bg-black flex flex-col gap-3">
                <span className="text-[9px] font-bold text-white/40 uppercase tracking-[0.3em]">
                  [02] TARGET_IP
                </span>
                <span className="text-lg font-bold truncate">
                  {result.ip_address || "---"}
                </span>
              </div>
              <div className="p-6 border border-white/10 bg-black flex flex-col gap-3">
                <span className="text-[9px] font-bold text-white/40 uppercase tracking-[0.3em]">
                  [03] INFRASTRUCTURE
                </span>
                <span className="text-lg font-bold uppercase">
                  {result.technologies?.server || "UNKNOWN"}
                </span>
              </div>
              <div className="p-6 border border-white/10 bg-black flex flex-col gap-3">
                <span className="text-[9px] font-bold text-white/40 uppercase tracking-[0.3em]">
                  [04] SSL_AUTH
                </span>
                <div className="flex items-center gap-2">
                  <span
                    className={`text-lg font-black uppercase ${result.ssl_certificate?.valid ? "text-white" : "text-white/20"}`}
                  >
                    {result.ssl_certificate?.valid ? "VALID" : "INVALID"}
                  </span>
                </div>
                {result.ssl_certificate?.expiration_warning && (
                  <div className="mt-2 pt-2 border-t border-white/10">
                    <span
                      className={`text-[9px] font-bold uppercase tracking-widest ${
                        result.ssl_certificate.expiration_warning === "critical"
                          ? "text-red-400"
                          : result.ssl_certificate.expiration_warning === "warning"
                            ? "text-yellow-400"
                            : "text-cyan-400"
                      }`}
                    >
                      {result.ssl_certificate.expiration_warning === "critical"
                        ? "⚠ EXPIRES SOON"
                        : result.ssl_certificate.expiration_warning === "warning"
                          ? "⚠ EXPIRING"
                          : "ℹ EXPIRES IN "}
                      {result.ssl_certificate.days_until_expiry !== null &&
                        result.ssl_certificate.days_until_expiry !== undefined &&
                        ` ${result.ssl_certificate.days_until_expiry} DAYS`}
                    </span>
                  </div>
                )}
                {result.http_headers?.response_time_ms !== null &&
                  result.http_headers?.response_time_ms !== undefined && (
                    <div className="mt-2 pt-2 border-t border-white/10">
                      <span className="text-[9px] font-bold text-white/60 uppercase tracking-widest">
                        RESPONSE: {result.http_headers.response_time_ms}MS
                      </span>
                    </div>
                  )}
              </div>
            </div>

            {/* Content Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
              <Section
                title="GEO_INTEL"
                symbol="G"
                className="xl:col-span-2"
                hasData={
                  !!result.server_location && !!result.server_location.org
                }
                helpText="RESOLVES TARGET IP TO PHYSICAL SERVER LOCATION, ISP, AND AUTONOMOUS SYSTEM (ASN) DATA VIA EXTERNAL INTEL PROVIDERS."
              >
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                  <div className="space-y-1">
                    <DataItem
                      label="PROVIDER"
                      value={result.server_location?.org}
                    />
                    <DataItem
                      label="LOCATION"
                      value={
                        result.server_location?.city
                          ? `${result.server_location.city}, ${result.server_location.region}`
                          : undefined
                      }
                    />
                    <DataItem
                      label="TIMEZONE"
                      value={result.server_location?.timezone}
                    />
                    <DataItem
                      label="COORDINATES"
                      value={
                        result.server_location?.coordinates
                          ? `${result.server_location.coordinates.latitude}, ${result.server_location.coordinates.longitude}`
                          : undefined
                      }
                    />
                  </div>
                  <div className="h-[240px] border border-white/10 bg-black relative">
                    {result.server_location?.coordinates && (
                      <Map
                        center={[
                          result.server_location.coordinates.longitude,
                          result.server_location.coordinates.latitude,
                        ]}
                        zoom={4}
                        styles={{
                          dark: "https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json",
                          light:
                            "https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json",
                        }}
                      >
                        <MapMarker
                          longitude={
                            result.server_location.coordinates.longitude
                          }
                          latitude={result.server_location.coordinates.latitude}
                        >
                          <MarkerContent>
                            <div className="w-4 h-4 bg-white rounded-full animate-pulse border-2 border-black" />
                          </MarkerContent>
                        </MapMarker>
                      </Map>
                    )}
                  </div>
                </div>
              </Section>

              <Section
                title="HARDENING"
                symbol="H"
                hasData={
                  !!result.security_headers_analysis &&
                  result.security_headers_analysis.percentage > 0
                }
                helpText="EVALUATES HTTP SECURITY HEADERS (CSP, HSTS, X-FRAME-OPTIONS) TO MEASURE PROACTIVE DEFENSE AGAINST COMMON WEB ATTACK VECTORS."
              >
                <div className="flex flex-col gap-6">
                  <div className="flex flex-col items-center justify-center py-6 border border-white/5 bg-white/[0.02]">
                    <span className="text-4xl font-black">
                      {result.security_headers_analysis?.percentage ?? 0}%
                    </span>
                    <span className="text-[9px] text-white/40 font-bold uppercase tracking-widest mt-2">
                      SECURED
                    </span>
                  </div>
                  <div className="space-y-2">
                    {Object.entries(
                      result.security_headers_analysis?.headers || {},
                    )
                      .slice(0, 6)
                      .map(([header, data]) => (
                        <div
                          key={header}
                          className="flex items-center justify-between text-[10px] uppercase"
                        >
                          <span className="text-white/40 truncate mr-4">
                            {header}
                          </span>
                          <span
                            className={
                              data.present ? "text-white" : "text-white/20"
                            }
                          >
                            {data.present ? "[+]" : "[-]"}
                          </span>
                        </div>
                      ))}
                  </div>
                  {result.csp_analysis &&
                    (result.csp_analysis.unsafe_inline ||
                      result.csp_analysis.unsafe_eval ||
                      result.csp_analysis.issues.length > 0) && (
                      <div className="mt-4 pt-4 border-t border-white/10">
                        <span className="text-[9px] font-bold text-white/40 uppercase block mb-2 tracking-widest">
                          CSP_ISSUES
                        </span>
                        <div className="space-y-1">
                          {result.csp_analysis.issues.map((issue, i) => (
                            <div
                              key={i}
                              className="text-[9px] text-yellow-400 font-bold"
                            >
                              • {issue.toUpperCase()}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                </div>
              </Section>

              <Section
                title="TECH_STACK"
                symbol="T"
                hasData={
                  !!result.technologies &&
                  (!!result.technologies.server ||
                    !!result.technologies.cms ||
                    (result.technologies.languages?.length ?? 0) > 0)
                }
                helpText="FINGERPRINTS UNDERLYING SERVER SOFTWARE, CONTENT MANAGEMENT SYSTEMS, AND BACKEND LANGUAGES VIA HTTP RESPONSE PATTERNS."
              >
                <div className="space-y-4">
                  <DataItem
                    label="SERVER"
                    value={result.technologies?.server}
                  />
                  <DataItem label="CMS" value={result.technologies?.cms} />
                  <DataItem label="CDN" value={result.technologies?.cdn} />
                  {result.http_headers?.protocol_version && (
                    <DataItem
                      label="PROTOCOL"
                      value={result.http_headers.protocol_version.toUpperCase()}
                    />
                  )}
                  {(result.technologies?.languages?.length ?? 0) > 0 && (
                    <div className="mt-4">
                      <span className="text-[9px] uppercase tracking-[0.2em] text-white/40 font-bold mb-2 block">
                        LANGUAGES
                      </span>
                      <div className="flex flex-wrap gap-2">
                        {result.technologies?.languages.map((l) => (
                          <span
                            key={l}
                            className="text-[10px] border border-white/20 px-2 py-1 uppercase font-bold"
                          >
                            {l}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </Section>

              <Section
                title="NET_PORTS"
                symbol="P"
                hasData={
                  !!result.port_scan &&
                  (result.port_scan.open_ports?.length ?? 0) > 0
                }
                helpText="SCANS COMMON INFRASTRUCTURE PORTS (SSH, HTTP, SQL) TO IDENTIFY EXPOSED SERVICES AND POTENTIAL NETWORK ENTRY POINTS."
              >
                <div className="grid grid-cols-4 gap-2">
                  {[80, 443, 22, 21, 25, 53, 3306, 8080].map((port) => {
                    const isOpen =
                      result.port_scan?.open_ports?.includes(port) ?? false;
                    return (
                      <div
                        key={port}
                        className={`flex flex-col items-center justify-center p-2 border ${isOpen ? "border-white bg-white/10" : "border-white/5 opacity-20"}`}
                      >
                        <span className="text-[10px] font-bold">{port}</span>
                        <span className="text-[8px] mt-1">
                          {isOpen ? "ON" : "OFF"}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </Section>

              <Section
                title="ENCRYPTION"
                symbol="E"
                hasData={
                  !!result.ssl_certificate && !!result.ssl_certificate.subject
                }
                helpText="VALIDATES SSL/TLS CERTIFICATE AUTHENTICITY, ISSUER TRUST, AND EXPIRATION DATA VIA SECURE SOCKET HANDSHAKES."
              >
                <div className="space-y-1">
                  <DataItem
                    label="SUBJECT"
                    value={getSubjectName(result.ssl_certificate?.subject)}
                  />
                  <DataItem
                    label="ISSUER"
                    value={getSubjectName(result.ssl_certificate?.issuer)}
                  />
                  <DataItem
                    label="EXPIRES"
                    value={formatDate(result.ssl_certificate?.expires)}
                  />
                  {result.ssl_certificate?.tls_version && (
                    <DataItem
                      label="TLS_VERSION"
                      value={result.ssl_certificate.tls_version}
                    />
                  )}
                  {result.ssl_certificate?.cipher_suite && (
                    <DataItem
                      label="CIPHER_SUITE"
                      value={result.ssl_certificate.cipher_suite}
                    />
                  )}
                  {result.ssl_certificate?.days_until_expiry !== null &&
                    result.ssl_certificate?.days_until_expiry !== undefined && (
                      <DataItem
                        label="DAYS_UNTIL_EXPIRY"
                        value={`${result.ssl_certificate.days_until_expiry} days`}
                      />
                    )}
                  <div className="mt-4 pt-4 border-t border-white/5">
                    <span className="text-[10px] font-bold text-white/40 uppercase tracking-widest block text-center">
                      SSL_VERIFIED_NODE
                    </span>
                  </div>
                </div>
              </Section>

              <Section
                title="REDIRECTS"
                symbol="R"
                hasData={
                  !!result.redirects &&
                  (result.redirects.chain?.length ?? 0) > 0
                }
                helpText="TRACKS HTTP STATUS CODES (301, 302) TO MAP THE FULL REQUEST PATH FROM SOURCE TO FINAL DESTINATION."
              >
                <div className="space-y-3">
                  <div className="text-[10px] flex items-center gap-2">
                    <span className="text-white/40 font-bold">[SRC]</span>
                    <span className="truncate">{url}</span>
                  </div>
                  {result.redirects?.chain.map((step, i) => (
                    <div
                      key={i}
                      className="pl-4 border-l border-white/10 flex flex-col gap-1"
                    >
                      <div className="text-[10px] flex items-center gap-2">
                        <span className="text-white font-bold">
                          [{step.status_code}]
                        </span>
                        <span className="truncate text-white/60">
                          {step.url}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </Section>

              <Section
                title="DNS_MAP"
                symbol="D"
                hasData={
                  !!result.dns_records &&
                  ((result.dns_records.a?.length ?? 0) > 0 ||
                    (result.dns_records.ns?.length ?? 0) > 0 ||
                    !!result.dns_records.email_security ||
                    !!result.dnssec ||
                    (result.subdomains?.discovered?.length ?? 0) > 0)
                }
                helpText="QUERIES AUTHORITATIVE NAME SERVERS FOR A, MX, AND TXT RECORDS TO UNCOVER DOMAIN ARCHITECTURE AND MAIL CONFIGURATION."
              >
                <div className="space-y-6">
                  {(result.dns_records?.a?.length ?? 0) > 0 && (
                    <div>
                      <span className="text-[9px] font-bold text-white/40 uppercase block mb-2 tracking-widest">
                        A_RECORDS
                      </span>
                      <div className="flex flex-col gap-1">
                        {result.dns_records?.a.map((ip) => (
                          <span
                            key={ip}
                            className="text-[10px] font-bold bg-white/5 px-2 py-1"
                          >
                            {ip}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {(result.dns_records?.ns?.length ?? 0) > 0 && (
                    <div>
                      <span className="text-[9px] font-bold text-white/40 uppercase block mb-2 tracking-widest">
                        NS_RECORDS
                      </span>
                      <div className="flex flex-col gap-1">
                        {result.dns_records?.ns.map((ns) => (
                          <span
                            key={ns}
                            className="text-[10px] font-bold bg-white/5 px-2 py-1 truncate"
                          >
                            {ns}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {result.dns_records?.email_security && (
                    <div>
                      <span className="text-[9px] font-bold text-white/40 uppercase block mb-2 tracking-widest">
                        EMAIL_SECURITY
                      </span>
                      <div className="space-y-2">
                        <div className="flex items-center justify-between text-[10px]">
                          <span className="text-white/60">SPF</span>
                          <span
                            className={
                              result.dns_records.email_security.spf_present
                                ? "text-white"
                                : "text-red-400"
                            }
                          >
                            {result.dns_records.email_security.spf_present
                              ? "[+]"
                              : "[-]"}
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-[10px]">
                          <span className="text-white/60">DMARC</span>
                          <span
                            className={
                              result.dns_records.email_security.dmarc_present
                                ? "text-white"
                                : "text-red-400"
                            }
                          >
                            {result.dns_records.email_security.dmarc_present
                              ? "[+]"
                              : "[-]"}
                          </span>
                        </div>
                        {(result.dns_records.email_security.dkim_selectors?.length ??
                          0) > 0 && (
                          <div className="text-[10px] text-white/60">
                            DKIM:{" "}
                            {result.dns_records.email_security.dkim_selectors.join(
                              ", ",
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                  {result.dnssec && (
                    <div>
                      <span className="text-[9px] font-bold text-white/40 uppercase block mb-2 tracking-widest">
                        DNSSEC
                      </span>
                      <div className="flex items-center justify-between text-[10px]">
                        <span className="text-white/60">ENABLED</span>
                        <span
                          className={
                            result.dnssec.enabled ? "text-white" : "text-white/20"
                          }
                        >
                          {result.dnssec.enabled ? "[+]" : "[-]"}
                        </span>
                      </div>
                      {result.dnssec.enabled && (
                        <div className="flex items-center justify-between text-[10px] mt-1">
                          <span className="text-white/60">VALID</span>
                          <span
                            className={
                              result.dnssec.valid ? "text-white" : "text-yellow-400"
                            }
                          >
                            {result.dnssec.valid ? "[+]" : "[!]"}
                          </span>
                        </div>
                      )}
                    </div>
                  )}
                  {(result.subdomains?.discovered?.length ?? 0) > 0 && result.subdomains && (
                    <div>
                      <span className="text-[9px] font-bold text-white/40 uppercase block mb-2 tracking-widest">
                        SUBDOMAINS ({result.subdomains.discovered.length})
                      </span>
                      <div className="flex flex-col gap-1 max-h-32 overflow-y-auto">
                        {result.subdomains.discovered.map((subdomain) => (
                          <span
                            key={subdomain}
                            className="text-[10px] font-bold bg-white/5 px-2 py-1 truncate"
                          >
                            {subdomain}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </Section>

              <Section
                title="COOKIE_SECURITY"
                symbol="C"
                hasData={
                  !!result.cookies &&
                  (result.cookies.total_cookies ?? 0) > 0
                }
                helpText="ANALYZES COOKIE SECURITY ATTRIBUTES INCLUDING SECURE, HTTPONLY, AND SAMESITE FLAGS TO IDENTIFY INSECURE COOKIE CONFIGURATIONS."
              >
                <div className="space-y-4">
                  {result.cookies?.total_cookies !== undefined && (
                    <div className="flex items-center justify-between py-2 border-b border-white/10">
                      <span className="text-[9px] text-white/40 font-bold uppercase tracking-widest">
                        TOTAL_COOKIES
                      </span>
                      <span className="text-sm font-black">
                        {result.cookies.total_cookies}
                      </span>
                    </div>
                  )}
                  {result.cookies?.security_score !== undefined && (
                    <div className="flex items-center justify-between py-2 border-b border-white/10">
                      <span className="text-[9px] text-white/40 font-bold uppercase tracking-widest">
                        SECURITY_SCORE
                      </span>
                      <span
                        className={`text-sm font-black ${
                          result.cookies.security_score >= 80
                            ? "text-white"
                            : result.cookies.security_score >= 50
                              ? "text-yellow-400"
                              : "text-red-400"
                        }`}
                      >
                        {result.cookies.security_score}%
                      </span>
                    </div>
                  )}
                  {result.cookies?.insecure_count !== undefined &&
                    result.cookies.insecure_count > 0 && (
                      <div className="p-3 bg-red-500/10 border border-red-500/20">
                        <span className="text-[10px] text-red-400 font-bold uppercase">
                          {result.cookies.insecure_count} INSECURE COOKIE(S)
                        </span>
                      </div>
                    )}
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {result.cookies?.cookies.map((cookie, i) => (
                      <div
                        key={i}
                        className="p-2 border border-white/10 bg-white/5"
                      >
                        <div className="text-[10px] font-bold text-white mb-1">
                          {cookie.name}
                        </div>
                        <div className="flex flex-wrap gap-2 text-[9px]">
                          <span
                            className={
                              cookie.secure ? "text-white/60" : "text-red-400"
                            }
                          >
                            {cookie.secure ? "[SECURE]" : "[!SECURE]"}
                          </span>
                          <span
                            className={
                              cookie.httponly ? "text-white/60" : "text-red-400"
                            }
                          >
                            {cookie.httponly ? "[HTTPONLY]" : "[!HTTPONLY]"}
                          </span>
                          {cookie.samesite && (
                            <span className="text-white/60">
                              [SAMESITE: {cookie.samesite.toUpperCase()}]
                            </span>
                          )}
                        </div>
                        {cookie.security_issues &&
                          cookie.security_issues.length > 0 && (
                            <div className="mt-1 text-[9px] text-red-400">
                              {cookie.security_issues.join(", ")}
                            </div>
                          )}
                      </div>
                    ))}
                  </div>
                </div>
              </Section>

              <Section
                title="ROBOTS_TXT"
                symbol="R"
                hasData={
                  result.robots_txt?.present ||
                  (result.robots_txt?.disallowed_paths.length ?? 0) > 0 ||
                  (result.robots_txt?.sitemaps.length ?? 0) > 0
                }
                helpText="PARSES ROBOTS.TXT FILE TO IDENTIFY DISALLOWED PATHS AND SITEMAP REFERENCES THAT MAY REVEAL SENSITIVE INFORMATION."
              >
                <div className="space-y-4">
                  {result.robots_txt?.present ? (
                    <>
                      {(result.robots_txt.disallowed_paths.length ?? 0) > 0 && (
                        <div>
                          <span className="text-[9px] font-bold text-white/40 uppercase block mb-2 tracking-widest">
                            DISALLOWED_PATHS ({result.robots_txt.disallowed_paths.length})
                          </span>
                          <div className="space-y-1 max-h-32 overflow-y-auto">
                            {result.robots_txt.disallowed_paths.map((path, i) => (
                              <div
                                key={i}
                                className="text-[10px] font-bold bg-white/5 px-2 py-1"
                              >
                                {path}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {(result.robots_txt.sitemaps.length ?? 0) > 0 && (
                        <div>
                          <span className="text-[9px] font-bold text-white/40 uppercase block mb-2 tracking-widest">
                            SITEMAPS
                          </span>
                          <div className="space-y-1">
                            {result.robots_txt.sitemaps.map((sitemap, i) => (
                              <div
                                key={i}
                                className="text-[10px] font-bold bg-white/5 px-2 py-1 truncate"
                              >
                                {sitemap}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="text-[10px] text-white/40 font-bold uppercase">
                      NOT_FOUND
                    </div>
                  )}
                </div>
              </Section>

              <Section
                title="THREAT_VECTORS"
                symbol="!"
                hasData={
                  (!!result.threats && result.threats.length > 0) ||
                  (result.mixed_content?.present ?? false) ||
                  (result.open_redirects?.vulnerable ?? false)
                }
                helpText="IDENTIFIES POTENTIAL SECURITY VULNERABILITIES BASED ON MISSING DEFENSIVE HEADERS, SUSPICIOUS PATH PATTERNS, AND SSL WEAKNESSES."
                className="border-white/20"
              >
                <div className="space-y-3">
                  {result.threats?.map((threat, i) => (
                    <div
                      key={i}
                      className="flex items-start gap-3 p-3 bg-white/5 border border-white/10"
                    >
                      <span className="text-white font-bold text-xs mt-0.5">
                        !
                      </span>
                      <span className="text-[11px] uppercase font-bold tracking-tight text-white/80 leading-relaxed">
                        {threat}
                      </span>
                    </div>
                  ))}
                  {result.mixed_content?.present && (
                    <div className="flex items-start gap-3 p-3 bg-red-500/10 border border-red-500/20">
                      <span className="text-red-400 font-bold text-xs mt-0.5">
                        !
                      </span>
                      <div className="flex-1">
                        <span className="text-[11px] uppercase font-bold tracking-tight text-red-400 block mb-1">
                          MIXED_CONTENT_DETECTED
                        </span>
                        <div className="text-[10px] text-white/60 space-y-1">
                          {result.mixed_content.resources
                            .slice(0, 3)
                            .map((resource, i) => (
                              <div key={i} className="truncate">
                                {resource.type.toUpperCase()}: {resource.url}
                              </div>
                            ))}
                          {(result.mixed_content.resources.length ?? 0) > 3 && (
                            <div className="text-white/40">
                              +{result.mixed_content.resources.length - 3} MORE
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                  {result.open_redirects?.vulnerable && (
                    <div className="flex items-start gap-3 p-3 bg-yellow-500/10 border border-yellow-500/20">
                      <span className="text-yellow-400 font-bold text-xs mt-0.5">
                        !
                      </span>
                      <div className="flex-1">
                        <span className="text-[11px] uppercase font-bold tracking-tight text-yellow-400 block mb-1">
                          OPEN_REDIRECT_VULNERABILITY
                        </span>
                        <div className="text-[10px] text-white/60 space-y-1">
                          {result.open_redirects.vulnerabilities
                            .slice(0, 3)
                            .map((vuln, i) => (
                              <div key={i}>
                                PARAM: {vuln.parameter.toUpperCase()} →{" "}
                                {vuln.redirect_to}
                              </div>
                            ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </Section>
            </div>
          </div>
        )}
      </div>

      {showInfo && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/90 backdrop-blur-sm p-6 animate-in fade-in duration-300">
          <div className="max-w-2xl w-full border border-white/20 bg-black p-8 relative">
            <button
              onClick={() => setShowInfo(false)}
              className="absolute top-4 right-4 text-white/40 hover:text-white text-xs font-bold tracking-widest"
            >
              [CLOSE_X]
            </button>

            <div className="mb-8">
              <div className="text-[10px] font-bold text-white/40 tracking-[0.4em] mb-2 uppercase">
                [SYSTEM_OPERATIONS_01]
              </div>
              <h2 className="text-3xl font-black tracking-tighter uppercase">
                SCAN_METHODOLOGY
              </h2>
            </div>

            <div className="space-y-6 max-h-[60vh] overflow-y-auto pr-4 custom-scrollbar">
              <div className="space-y-2">
                <h4 className="text-xs font-black tracking-widest uppercase text-white">
                  [01] SSL_VALIDATION
                </h4>
                <p className="text-[11px] text-white/60 leading-relaxed uppercase">
                  VERIFIES CERTIFICATE CHAIN, EXPIRATION, ISSUER AUTHENTICITY,
                  AND ENCRYPTION STRENGTH VIA SSL/TLS HANDSHAKE.
                </p>
              </div>

              <div className="space-y-2">
                <h4 className="text-xs font-black tracking-widest uppercase text-white">
                  [02] DNS_RECON
                </h4>
                <p className="text-[11px] text-white/60 leading-relaxed uppercase">
                  PERFORMS DEEP QUERIES FOR A, AAAA, MX, NS, AND TXT RECORDS TO
                  MAP THE DOMAIN'S ARCHITECTURE.
                </p>
              </div>

              <div className="space-y-2">
                <h4 className="text-xs font-black tracking-widest uppercase text-white">
                  [03] HEADER_ANALYSIS
                </h4>
                <p className="text-[11px] text-white/60 leading-relaxed uppercase">
                  EVALUATES SECURITY POLICIES (CSP, HSTS, XSS-PROTECTION) TO
                  MEASURE FRONT-END HARDENING LEVELS.
                </p>
              </div>

              <div className="space-y-2">
                <h4 className="text-xs font-black tracking-widest uppercase text-white">
                  [04] GEO_INTELLIGENCE
                </h4>
                <p className="text-[11px] text-white/60 leading-relaxed uppercase">
                  RESOLVES TARGET IP TO PHYSICAL SERVER LOCATION, ISP, AND
                  AUTONOMOUS SYSTEM (ASN) INFORMATION.
                </p>
              </div>

              <div className="space-y-2">
                <h4 className="text-xs font-black tracking-widest uppercase text-white">
                  [05] TECH_STACK_ID
                </h4>
                <p className="text-[11px] text-white/60 leading-relaxed uppercase">
                  FINGERPRINTS SERVER SOFTWARE, CMS, CDNS, AND BACKEND LANGUAGES
                  VIA HTTP FINGERPRINTING.
                </p>
              </div>

              <div className="space-y-2">
                <h4 className="text-xs font-black tracking-widest uppercase text-white">
                  [06] PORT_SURVEY
                </h4>
                <p className="text-[11px] text-white/60 leading-relaxed uppercase">
                  SCANS COMMON SERVICE PORTS (80, 443, 22, ETC.) TO IDENTIFY
                  EXPOSED INFRASTRUCTURE COMPONENTS.
                </p>
              </div>

              <div className="space-y-2">
                <h4 className="text-xs font-black tracking-widest uppercase text-white">
                  [07] THREAT_SCORING
                </h4>
                <p className="text-[11px] text-white/60 leading-relaxed uppercase">
                  USES MONIX CORE ANALYZERS TO CALCULATE RISK BASED ON ENDPOINT
                  SUSPICION AND PATH PATTERNS.
                </p>
              </div>
            </div>

            <div className="mt-10 pt-6 border-t border-white/10 flex justify-between items-center">
              <span className="text-[9px] font-bold text-white/20 tracking-widest uppercase italic">
                ! AUTONOMOUS_SCANNER_v2.0
              </span>
              <button
                onClick={() => setShowInfo(false)}
                className="bg-white text-black px-6 py-2 text-[10px] font-black uppercase tracking-widest hover:bg-white/80 transition-all"
              >
                UNDERSTOOD
              </button>
            </div>
          </div>
        </div>
      )}

      <style jsx global>{`
        .custom-scrollbar::-webkit-scrollbar { width: 2px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: #000; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #333; }
      `}</style>
    </div>
  );
}
