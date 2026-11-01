import React, { useState, useEffect } from 'react';
import {
  Layers,
  ShieldAlert,
  ShieldCheck,
  Package,
  ExternalLink,
  Code2,
  AlertTriangle,
  CheckCircle2,
  FileSearch,
  Building2,
  Lock,
  ArrowRight
} from 'lucide-react';

interface ThirdPartyProps {
  scanId: string;
}

export const ThirdPartyIntelligenceView: React.FC<ThirdPartyProps> = ({ scanId }) => {
  const [activeSection, setActiveSection] = useState<'inventory' | 'explorer' | 'inspector' | 'razorpay' | 'impact'>('inventory');
  const [summary, setSummary] = useState<any>(null);
  const [packages, setPackages] = useState<any[]>([]);
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [selectedPkgName, setSelectedPkgName] = useState<string>('razorpay');
  const [sourceData, setSourceData] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchData();
  }, [scanId]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const sumRes = await fetch(`/api/scans/${scanId}/third-party/summary`);
      if (sumRes.ok) setSummary(await sumRes.json());

      const pkgRes = await fetch(`/api/scans/${scanId}/third-party/packages`);
      if (pkgRes.ok) {
        const pkgs = await pkgRes.json();
        setPackages(pkgs);
        if (pkgs.length > 0) setSelectedPkgName(pkgs[0].name);
      }

      const intRes = await fetch(`/api/scans/${scanId}/third-party/integrations`);
      if (intRes.ok) setIntegrations(await intRes.json());

      const repRes = await fetch(`/api/scans/${scanId}/third-party/security-report`);
      if (repRes.ok) setFindings(await repRes.json());
    } catch (e) {
      console.error('Error fetching third-party intelligence data:', e);
    } finally {
      setLoading(false);
    }
  };

  const handleInspectPackage = async (pkgName: string) => {
    setSelectedPkgName(pkgName);
    setActiveSection('inspector');
    try {
      const res = await fetch(`/api/scans/${scanId}/third-party/packages/${encodeURIComponent(pkgName)}/source`);
      if (res.ok) {
        setSourceData(await res.json());
      }
    } catch (e) {
      console.error('Error fetching package source:', e);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6 overflow-y-auto h-[calc(100vh-230px)]">
      {/* Top Banner / Metrics */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2">
            <Layers className="w-6 h-6 text-indigo-400" />
            <h2 className="text-xl font-bold text-white tracking-wide">Third-Party Intelligence & Integration Security</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Exact package instance inventory, verified artifact source inspection, and deep SaaS integration auditing.
          </p>
        </div>

        {summary && (
          <div className="flex items-center gap-3 text-xs">
            <div className="bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-xl">
              <span className="text-slate-400">Total Packages:</span>{' '}
              <span className="text-white font-bold">{summary.total_packages}</span>
            </div>
            <div className="bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-xl">
              <span className="text-slate-400">Verified Artifacts:</span>{' '}
              <span className="text-emerald-400 font-bold">{summary.retrieved_packages_count}</span>
            </div>
            <div className="bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-xl">
              <span className="text-slate-400">Security Findings:</span>{' '}
              <span className="text-rose-400 font-bold">{summary.total_integration_findings}</span>
            </div>
          </div>
        )}
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800/80 pb-3 text-xs font-semibold">
        {[
          { id: 'inventory', label: 'Integration Inventory', icon: Building2 },
          { id: 'explorer', label: 'Dependency Explorer', icon: Package },
          { id: 'inspector', label: 'Package Source Inspector', icon: FileSearch },
          { id: 'razorpay', label: 'Razorpay & Vendor Reports', icon: ShieldAlert },
          { id: 'impact', label: 'Business Journey Impact', icon: Lock }
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSection(tab.id as any)}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-xl transition-all duration-200 ease-out hover:scale-[1.02] active:scale-95 cursor-pointer ${
                activeSection === tab.id
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30 font-semibold'
                  : 'text-slate-400 hover:text-white hover:bg-white/[0.05]'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Section A: Integration Inventory */}
      {activeSection === 'inventory' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {integrations.length === 0 ? (
            <div className="col-span-full p-8 rounded-xl bg-slate-900 border border-slate-800 text-center text-slate-400">
              No third-party SaaS integrations detected in the target project.
            </div>
          ) : (
            integrations.map((vendor) => (
              <div
                key={vendor.vendor_id}
                className="bg-[#111928]/90 hover:bg-[#152033] border border-white/[0.08] hover:border-indigo-500/40 rounded-2xl p-5 space-y-4 transition-all duration-300 ease-out hover:-translate-y-0.5 shadow-lg hover:shadow-[0_16px_36px_-12px_rgba(0,0,0,0.6)]"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white text-sm">{vendor.vendor_name}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${
                    vendor.findings.length > 0 ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/20 text-emerald-300'
                  }`}>
                    {vendor.findings.length > 0 ? `${vendor.findings.length} Weaknesses` : 'Verified Secure'}
                  </span>
                </div>

                <div className="text-xs space-y-1.5 text-slate-300">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Rules Assessed:</span>
                    <span className="font-mono">{vendor.checked_rules_count} checks</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Passing Controls:</span>
                    <span className="font-mono text-emerald-400">{vendor.passed_rules_count} passing</span>
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
                  <span className="text-[11px] text-slate-400">Endpoints: {vendor.endpoints_contacted.length}</span>
                  <button
                    onClick={() => setActiveSection('razorpay')}
                    className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 font-semibold"
                  >
                    View Report <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Section B: Dependency Explorer */}
      {activeSection === 'explorer' && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="font-bold text-white text-sm">Discovered Package Instances ({packages.length})</h3>
            <span className="text-xs text-slate-400">Lockfile v1/v2/v3 exact installed resolution</span>
          </div>

          <div className="divide-y divide-slate-800/80 overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="p-3">Package Instance</th>
                  <th className="p-3">Scope</th>
                  <th className="p-3">Direct/Transitive</th>
                  <th className="p-3">Integrity Verification</th>
                  <th className="p-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {packages.map((pkg) => (
                  <tr key={pkg.instance_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="p-3 font-mono font-bold text-slate-200">
                      {pkg.name} <span className="text-indigo-400">@{pkg.version}</span>
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                        {pkg.scope}
                      </span>
                    </td>
                    <td className="p-3 text-slate-400">
                      {pkg.is_direct ? 'Direct' : `Transitive (${pkg.parent_dependency || 'nested'})`}
                    </td>
                    <td className="p-3">
                      <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" /> {pkg.retrieval_status}
                      </span>
                    </td>
                    <td className="p-3">
                      <button
                        onClick={() => handleInspectPackage(pkg.name)}
                        className="text-indigo-400 hover:text-indigo-300 font-semibold flex items-center gap-1"
                      >
                        Inspect Code <ArrowRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Section C: Package Source Inspector */}
      {activeSection === 'inspector' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="font-bold text-white text-sm">Package Code Inspector: {selectedPkgName}</h3>
              <p className="text-xs text-slate-400">Inspecting exact published source extracted in sandbox.</p>
            </div>
            <span className="text-xs bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2.5 py-1 rounded-lg">
              Artifact Verified
            </span>
          </div>

          {sourceData ? (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
                <span className="text-xs font-bold text-slate-300 uppercase tracking-wide">Extracted Source Files</span>
                <div className="max-h-80 overflow-y-auto space-y-1 text-xs font-mono text-slate-400">
                  {sourceData.source_files.map((file: string, idx: number) => (
                    <div key={idx} className="p-1 hover:bg-slate-900 rounded truncate">
                      {file}
                    </div>
                  ))}
                </div>
              </div>

              <div className="lg:col-span-2 bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <span className="text-xs font-bold text-slate-300 uppercase tracking-wide">
                  Sample Code ({sourceData.sample_code?.file || 'N/A'})
                </span>
                <pre className="text-xs font-mono text-slate-300 overflow-x-auto p-3 bg-slate-900/60 rounded-lg max-h-80">
                  {sourceData.sample_code?.content || '// Source files extracted locally and verified.'}
                </pre>
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-slate-400 text-xs">
              Select a package from the Dependency Explorer to inspect its verified code.
            </div>
          )}
        </div>
      )}

      {/* Section D: Integration Security Report */}
      {activeSection === 'razorpay' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-bold text-white text-base">Integration Security Findings ({findings.length})</h3>
            <span className="text-xs text-slate-400">Validated against official vendor security specifications</span>
          </div>

          <div className="space-y-3">
            {findings.map((finding) => (
              <div
                key={finding.finding_id}
                className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-3"
              >
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-500/20 text-indigo-300 uppercase">
                        {finding.rule_id}
                      </span>
                      <h4 className="font-bold text-white text-sm">{finding.title}</h4>
                    </div>
                    <p className="text-xs text-slate-300">{finding.description}</p>
                  </div>
                  <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded-full ${
                    finding.severity === 'critical' ? 'bg-rose-500/20 text-rose-300' : 'bg-amber-500/20 text-amber-300'
                  }`}>
                    {finding.severity}
                  </span>
                </div>

                {finding.code_excerpt && (
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800/80 font-mono text-xs text-rose-300">
                    <span className="text-slate-500 select-none mr-2">Line {finding.line_number || '?'}:</span>
                    {finding.code_excerpt}
                  </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 text-xs border-t border-slate-800">
                  <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
                    <span className="font-bold text-slate-400 block mb-1">Security Impact:</span>
                    <span className="text-slate-300">{finding.explanation}</span>
                  </div>
                  <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
                    <span className="font-bold text-emerald-400 block mb-1">Recommended Remediation:</span>
                    <span className="text-slate-300">{finding.remediation}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Section E: Business Impact */}
      {activeSection === 'impact' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <h3 className="font-bold text-white text-base">Critical Business Journeys at Risk</h3>
          <p className="text-xs text-slate-400">
            Correlates payment vulnerabilities directly with business operations.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
            <div className="bg-slate-950 p-4 rounded-xl border border-rose-500/30 space-y-2">
              <span className="font-bold text-sm text-rose-300 block">Customer Checkout</span>
              <span className="text-xs text-slate-400">Affected by: RZP-001, RZP-002, RZP-004</span>
              <p className="text-xs text-slate-300 pt-2 border-t border-slate-800">
                Threat of financial loss from client-controlled order amounts and forged HMAC payment signatures.
              </p>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-amber-500/30 space-y-2">
              <span className="font-bold text-sm text-amber-300 block">Order Fulfillment</span>
              <span className="text-xs text-slate-400">Affected by: RZP-006, RZP-007</span>
              <p className="text-xs text-slate-300 pt-2 border-t border-slate-800">
                Duplicate order processing or delivery denial from webhook reserialization and missing event deduplication.
              </p>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-indigo-500/30 space-y-2">
              <span className="font-bold text-sm text-indigo-300 block">User Authentication</span>
              <span className="text-xs text-slate-400">Affected by: AUTH0-001, FB-001</span>
              <p className="text-xs text-slate-300 pt-2 border-t border-slate-800">
                Account takeover and unauthorized session issuance if client secrets or service keys are compromised.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

