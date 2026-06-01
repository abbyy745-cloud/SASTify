import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth, API } from '../context/AuthContext.jsx';
import { useDashboard } from '../hooks/useDashboard.jsx';
import SeverityBadge from '../components/SeverityBadge.jsx';

/* ── Keyframe Animations ────────────────────────── */
const scansKeyframes = `
@keyframes scansSevBoxPulse {
  0%, 100% { filter: brightness(1); }
  50%      { filter: brightness(1.15); }
}
`;

export default function ScansPage() {
    const { scanId } = useParams();
    return scanId ? <ScanDetail scanId={scanId} /> : <ScanList />;
}

function ScanList() {
    const { scans, loading } = useDashboard();
    const navigate = useNavigate();
    const [search, setSearch] = useState('');
    const [filter, setFilter] = useState('all');
    const [searchFocused, setSearchFocused] = useState(false);

    const filtered = scans.filter(sc => {
        const matchSearch = !search ||
            sc.filename?.toLowerCase().includes(search.toLowerCase()) ||
            sc.language?.toLowerCase().includes(search.toLowerCase());
        const matchFilter = filter === 'all' ||
            (filter === 'critical' && sc.critical_count > 0) ||
            (filter === 'high' && sc.high_count > 0);
        return matchSearch && matchFilter;
    });

    if (loading) return <Spinner />;

    return (
        <div style={s.page} className="animate-fade-in">
            <style>{scansKeyframes}</style>
            {/* Header */}
            <div style={s.header}>
                <div>
                    <h1 style={s.h1}>Scan History</h1>
                    <p style={s.sub}>{scans.length} total scans recorded</p>
                </div>
                <div style={s.headerRight}>
                    <div style={{
                        ...s.searchWrap,
                        ...(searchFocused ? {
                            borderColor: 'rgba(0,240,255,0.4)',
                            boxShadow: '0 0 0 3px rgba(0,240,255,0.08), 0 0 20px rgba(0,240,255,0.08)',
                            background: 'rgba(0,240,255,0.03)',
                        } : {})
                    }}>
                        <svg style={s.searchIcon} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
                        </svg>
                        <input style={s.search} placeholder="Search filename or language…"
                            value={search} onChange={e => setSearch(e.target.value)}
                            onFocus={() => setSearchFocused(true)}
                            onBlur={() => setSearchFocused(false)} />
                    </div>
                    <div style={s.filterGroup}>
                        {['all', 'critical', 'high'].map(f => (
                            <button key={f} style={{ ...s.filterBtn, ...(filter === f ? s.filterActive : {}) }}
                                onClick={() => setFilter(f)}>
                                {f.charAt(0).toUpperCase() + f.slice(1)}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            {/* Stats bar */}
            <div style={s.statsBar}>
                <div style={s.statBarItem}>
                    <span style={{ ...s.statBarDot, background: '#00f0ff' }} />
                    <span style={s.statBarLabel}>Total Scans</span>
                    <span style={s.statBarValue}>{scans.length}</span>
                </div>
                <div style={s.statBarDivider} />
                <div style={s.statBarItem}>
                    <span style={{ ...s.statBarDot, background: '#ef4444' }} />
                    <span style={s.statBarLabel}>With Critical</span>
                    <span style={s.statBarValue}>{scans.filter(s => s.critical_count > 0).length}</span>
                </div>
                <div style={s.statBarDivider} />
                <div style={s.statBarItem}>
                    <span style={{ ...s.statBarDot, background: '#10b981' }} />
                    <span style={s.statBarLabel}>Showing</span>
                    <span style={s.statBarValue}>{filtered.length}</span>
                </div>
            </div>

            {/* Scan List */}
            {filtered.length === 0 ? (
                <div style={s.empty}>
                    <div style={{ fontSize: '52px', marginBottom: '16px', opacity: 0.4 }}>🔍</div>
                    <h3 style={{ color: 'rgba(255,255,255,0.5)', fontWeight: 600, margin: '0 0 8px' }}>No scans found</h3>
                    <p style={{ color: 'rgba(255,255,255,0.25)', fontSize: '13px', margin: 0 }}>
                        Run a scan from VS Code to get started
                    </p>
                </div>
            ) : (
                <div style={s.list}>
                    {filtered.map((sc, idx) => {
                        const topSev = sc.critical_count > 0 ? 'Critical' : sc.high_count > 0 ? 'High' : sc.medium_count > 0 ? 'Medium' : 'Low';
                        return (
                            <div key={sc.scan_id || idx} className="scan-row" style={s.row}
                                onClick={() => navigate(`/scans/${sc.scan_id}`)}
                                onMouseEnter={e => {
                                    e.currentTarget.style.borderLeftColor = '#00f0ff';
                                    e.currentTarget.style.borderLeftWidth = '3px';
                                    e.currentTarget.style.boxShadow = '0 0 20px rgba(0,240,255,0.08), inset 4px 0 12px rgba(0,240,255,0.04)';
                                    e.currentTarget.style.background = 'rgba(0,240,255,0.025)';
                                }}
                                onMouseLeave={e => {
                                    e.currentTarget.style.borderLeftColor = 'rgba(255,255,255,0.06)';
                                    e.currentTarget.style.borderLeftWidth = '1px';
                                    e.currentTarget.style.boxShadow = 'none';
                                    e.currentTarget.style.background = 'rgba(255,255,255,0.02)';
                                }}
                            >
                                <div style={s.rowLeft}>
                                    <div style={s.fileIconWrap}>
                                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14,2 14,8 20,8"/>
                                        </svg>
                                    </div>
                                    <div>
                                        <div style={s.filename}>{sc.filename || 'Unknown file'}</div>
                                        <div style={s.metaRow}>
                                            <span style={s.metaText}>{sc.scan_id?.slice(0, 8)}…</span>
                                            <span style={s.metaDot}>·</span>
                                            <span style={s.metaText}>{new Date(sc.created_at).toLocaleString()}</span>
                                        </div>
                                    </div>
                                </div>
                                <div style={s.rowRight}>
                                    <span style={s.langBadge}>{sc.language || '—'}</span>
                                    <SeverityBadge severity={topSev} />
                                    <div style={s.issuePill}>
                                        <span style={s.issueNum}>{sc.total_vulnerabilities || 0}</span>
                                        <span style={s.issueWord}>issues</span>
                                    </div>
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.25)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                        <polyline points="9,18 15,12 9,6"/>
                                    </svg>
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}

function ScanDetail({ scanId }) {
    const { user, token } = useAuth();
    const navigate = useNavigate();
    const [scan, setScan] = useState(null);
    const [loading, setLoading] = useState(true);
    const [expanded, setExpanded] = useState(null);
    const [sevFilter, setSevFilter] = useState('all');

    useEffect(() => {
        if (!user) return;
        fetch(`${API}/api/users/${user.user_id}/scans/${scanId}`, {
            headers: { Authorization: `Bearer ${token}` }
        })
            .then(r => r.json())
            .then(d => { setScan(d.scan); setLoading(false); })
            .catch(() => setLoading(false));
    }, [scanId, user, token]);

    if (loading) return <Spinner />;
    if (!scan) return (
        <div style={{ padding: '60px', textAlign: 'center' }}>
            <div style={{ fontSize: '48px', marginBottom: '16px' }}>⚠️</div>
            <p style={{ color: '#f87171', fontFamily: 'JetBrains Mono', fontSize: '14px' }}>Scan not found.</p>
        </div>
    );

    const vulns = scan.vulnerabilities || [];
    const filteredVulns = sevFilter === 'all' ? vulns : vulns.filter(v => v.severity?.toLowerCase() === sevFilter);

    const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    vulns.forEach(v => { if (sevCounts[v.severity] !== undefined) sevCounts[v.severity]++; });

    return (
        <div style={s.page} className="animate-fade-in">
            <style>{scansKeyframes}</style>
            {/* Back */}
            <button style={s.backBtn} onClick={() => navigate('/scans')}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="15,18 9,12 15,6"/>
                </svg>
                Back to Scans
            </button>

            {/* Detail Header — glassmorphism */}
            <div style={s.detailCard}>
                <div style={s.detailCardTop}>
                    <div style={s.detailFileIcon}>
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14,2 14,8 20,8"/>
                        </svg>
                    </div>
                    <div style={{ flex: 1 }}>
                        <h1 style={s.h1}>{scan.filename}</h1>
                        <div style={s.detailMeta}>
                            <span style={s.metaChip}>{scan.language}</span>
                            <span style={s.metaChip}>{scan.scan_id}</span>
                            <span style={s.metaChip}>{new Date(scan.created_at).toLocaleString()}</span>
                        </div>
                    </div>
                </div>

                {/* Summary counters with severity glow */}
                <div style={s.sevGrid}>
                    {Object.entries(sevCounts).map(([sev, cnt]) => (
                        <div key={sev} style={{
                            ...s.sevBox,
                            borderColor: sevColor(sev) + '33',
                            background: sevColor(sev) + '0a',
                            boxShadow: cnt > 0 ? `0 0 20px ${sevColor(sev)}15, inset 0 0 15px ${sevColor(sev)}08` : 'none',
                        }}>
                            <span style={{ ...s.sevNum, color: sevColor(sev) }}>{cnt}</span>
                            <span style={s.sevLabel}>{sev}</span>
                        </div>
                    ))}
                </div>
            </div>

            {/* Filter tabs */}
            <div style={s.filterRow}>
                <span style={s.filterLabel}>Filter by severity:</span>
                {['all', 'critical', 'high', 'medium', 'low'].map(f => (
                    <button key={f} style={{ ...s.filterBtn, ...(sevFilter === f ? s.filterActive : {}) }}
                        onClick={() => setSevFilter(f)}>
                        {f === 'all' ? `All (${vulns.length})` : `${f.charAt(0).toUpperCase() + f.slice(1)} (${sevCounts[f.charAt(0).toUpperCase() + f.slice(1)] || 0})`}
                    </button>
                ))}
            </div>

            {/* Vuln Cards */}
            <div style={s.vulnList}>
                {filteredVulns.length === 0 ? (
                    <div style={{ ...s.empty, padding: '60px' }}>
                        <div style={{ fontSize: '40px', opacity: 0.4, marginBottom: '12px' }}>✅</div>
                        <p style={{ color: 'rgba(255,255,255,0.4)', margin: 0 }}>No vulnerabilities found</p>
                    </div>
                ) : (
                    filteredVulns.map((v, i) => (
                        <div key={i} className="vuln-card" style={{
                            ...s.vulnCard,
                            borderLeftColor: sevColor(v.severity),
                            transition: 'all 0.2s ease',
                        }}
                            onMouseEnter={e => {
                                e.currentTarget.style.transform = 'scale(1.008)';
                                e.currentTarget.style.boxShadow = `0 0 20px ${sevColor(v.severity)}12, 0 4px 20px rgba(0,0,0,0.3)`;
                            }}
                            onMouseLeave={e => {
                                e.currentTarget.style.transform = 'scale(1)';
                                e.currentTarget.style.boxShadow = 'none';
                            }}
                        >
                            <div style={s.vulnHeader} onClick={() => setExpanded(expanded === i ? null : i)}>
                                <div style={s.vulnLeft}>
                                    <SeverityBadge severity={v.severity} size="lg" />
                                    <span style={s.vulnType}>{(v.type || v.vuln_type || 'Unknown')?.replace(/_/g, ' ')}</span>
                                    <span style={s.vulnLine}>line {v.line}</span>
                                    {(v.cwe_id || v.cwe) && <span style={s.cweChip}>CWE-{v.cwe_id || v.cwe}</span>}
                                </div>
                                <div style={{ ...s.expandBtn, transform: expanded === i ? 'rotate(180deg)' : 'rotate(0)' }}>
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                        <polyline points="6,9 12,15 18,9"/>
                                    </svg>
                                </div>
                            </div>

                            {expanded === i && (
                                <div style={s.vulnBody}>
                                    {v.snippet && (
                                        <div style={s.codeBlock}>
                                            <div style={s.codeHeader}>
                                                <span style={s.codeHeaderLabel}>Code Snippet</span>
                                                <span style={s.codeHeaderLine}>Line {v.line}</span>
                                            </div>
                                            <pre style={s.pre}>{v.snippet}</pre>
                                        </div>
                                    )}
                                    <div style={s.bodyGrid}>
                                        {v.description && (
                                            <div style={s.bodySection}>
                                                <div style={s.sectionHead}>
                                                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#a5b4fc" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                                        <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                                                    </svg>
                                                    Description
                                                </div>
                                                <p style={s.sectionText}>{v.description}</p>
                                            </div>
                                        )}
                                        {v.remediation && (
                                            <div style={s.bodySection}>
                                                <div style={{ ...s.sectionHead, color: '#6ee7b7' }}>
                                                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#6ee7b7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                                        <path d="M9 12l2 2 4-4m6 2a9 9 0 1 1-18 0 9 9 0 0 1 18 0z"/>
                                                    </svg>
                                                    Recommended Fix
                                                </div>
                                                <p style={{ ...s.sectionText, color: '#6ee7b7' }}>{v.remediation}</p>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}

function sevColor(sev) {
    return { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#10b981' }[sev] || '#10b981';
}

function Spinner() {
    return (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh', flexDirection: 'column', gap: '20px' }}>
            <div style={{ width: '36px', height: '36px', border: '3px solid rgba(0,240,255,0.2)', borderTopColor: '#00f0ff', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
            <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: '13px', fontFamily: 'JetBrains Mono', margin: 0 }}>Loading…</p>
        </div>
    );
}

const s = {
    page: { padding: '32px 36px', display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '1200px' },
    header: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: '16px' },
    h1: { color: '#fff', fontSize: '26px', fontWeight: 800, margin: '0 0 4px', letterSpacing: '-0.3px' },
    sub: { color: 'rgba(255,255,255,0.3)', fontSize: '13px', margin: 0 },
    headerRight: { display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' },
    searchWrap: {
        display: 'flex', alignItems: 'center', gap: '8px',
        background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '10px', padding: '9px 14px',
        transition: 'all 0.25s ease',
    },
    searchIcon: { color: 'rgba(255,255,255,0.3)', flexShrink: 0 },
    search: {
        background: 'transparent', border: 'none', outline: 'none',
        color: '#fff', fontSize: '13px', fontFamily: 'Inter', width: '220px'
    },
    filterGroup: { display: 'flex', gap: '4px', background: 'rgba(255,255,255,0.04)', borderRadius: '10px', padding: '4px' },
    filterBtn: {
        background: 'transparent', border: 'none', borderRadius: '7px', padding: '7px 14px',
        color: 'rgba(255,255,255,0.4)', fontSize: '12px', fontWeight: 600, cursor: 'pointer',
        transition: 'all 0.18s'
    },
    filterActive: { background: 'rgba(0,240,255,0.15)', color: '#00f0ff' },
    statsBar: {
        display: 'flex', alignItems: 'center', gap: '20px',
        background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(0,240,255,0.08)',
        borderRadius: '12px', padding: '12px 20px',
        backdropFilter: 'blur(10px)',
    },
    statBarItem: { display: 'flex', alignItems: 'center', gap: '8px' },
    statBarDot: { width: '8px', height: '8px', borderRadius: '50%', flexShrink: 0 },
    statBarLabel: { color: 'rgba(255,255,255,0.35)', fontSize: '12px' },
    statBarValue: { color: '#fff', fontSize: '14px', fontWeight: 700, fontFamily: 'JetBrains Mono' },
    statBarDivider: { width: '1px', height: '20px', background: 'rgba(255,255,255,0.08)' },
    list: { display: 'flex', flexDirection: 'column', gap: '8px' },
    row: {
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: '12px', padding: '16px 20px', cursor: 'pointer', gap: '12px', flexWrap: 'wrap',
        transition: 'all 0.25s ease',
        borderLeft: '1px solid rgba(255,255,255,0.06)',
    },
    rowLeft: { display: 'flex', alignItems: 'center', gap: '14px' },
    fileIconWrap: {
        width: '40px', height: '40px', borderRadius: '10px',
        background: 'rgba(0,240,255,0.06)', border: '1px solid rgba(0,240,255,0.15)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0
    },
    filename: { color: '#fff', fontSize: '14px', fontWeight: 600 },
    metaRow: { display: 'flex', alignItems: 'center', gap: '6px', marginTop: '3px' },
    metaText: { color: 'rgba(255,255,255,0.25)', fontSize: '11px', fontFamily: 'JetBrains Mono' },
    metaDot: { color: 'rgba(255,255,255,0.15)', fontSize: '11px' },
    rowRight: { display: 'flex', alignItems: 'center', gap: '10px' },
    langBadge: {
        background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)',
        borderRadius: '5px', padding: '2px 8px', color: 'rgba(255,255,255,0.4)',
        fontSize: '10px', fontFamily: 'JetBrains Mono'
    },
    issuePill: {
        background: 'rgba(0,240,255,0.08)', border: '1px solid rgba(0,240,255,0.2)',
        borderRadius: '6px', padding: '3px 10px', display: 'flex', gap: '4px', alignItems: 'center'
    },
    issueNum: { color: '#00f0ff', fontSize: '13px', fontWeight: 700, fontFamily: 'JetBrains Mono' },
    issueWord: { color: 'rgba(0,240,255,0.5)', fontSize: '11px' },
    empty: { textAlign: 'center', padding: '80px 40px', display: 'flex', flexDirection: 'column', alignItems: 'center' },
    backBtn: {
        display: 'flex', alignItems: 'center', gap: '6px', background: 'transparent',
        border: '1px solid rgba(0,240,255,0.15)', borderRadius: '8px', padding: '8px 14px',
        color: 'rgba(0,240,255,0.6)', fontSize: '13px', fontWeight: 500, cursor: 'pointer',
        alignSelf: 'flex-start', transition: 'all 0.2s'
    },
    detailCard: {
        background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(0,240,255,0.12)',
        borderRadius: '16px', padding: '24px',
        backdropFilter: 'blur(20px)',
        boxShadow: '0 0 30px rgba(0,240,255,0.04), 0 8px 32px rgba(0,0,0,0.3)',
    },
    detailCardTop: { display: 'flex', alignItems: 'flex-start', gap: '16px', marginBottom: '20px' },
    detailFileIcon: {
        width: '52px', height: '52px', borderRadius: '12px',
        background: 'rgba(0,240,255,0.08)', border: '1px solid rgba(0,240,255,0.2)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0
    },
    detailMeta: { display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '8px' },
    metaChip: {
        background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '6px', padding: '3px 10px', color: 'rgba(255,255,255,0.35)',
        fontSize: '11px', fontFamily: 'JetBrains Mono'
    },
    sevGrid: { display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '12px' },
    sevBox: {
        border: '1px solid', borderRadius: '12px', padding: '16px',
        display: 'flex', flexDirection: 'column', gap: '4px', alignItems: 'center',
        transition: 'all 0.3s ease',
    },
    sevNum: { fontSize: '28px', fontWeight: 800, lineHeight: 1 },
    sevLabel: { color: 'rgba(255,255,255,0.4)', fontSize: '11px', fontWeight: 600 },
    filterRow: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' },
    filterLabel: { color: 'rgba(255,255,255,0.3)', fontSize: '12px', marginRight: '4px' },
    vulnList: { display: 'flex', flexDirection: 'column', gap: '10px' },
    vulnCard: {
        background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)',
        borderLeft: '3px solid', borderRadius: '12px', overflow: 'hidden'
    },
    vulnHeader: {
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '16px 20px', cursor: 'pointer', transition: 'background 0.15s'
    },
    vulnLeft: { display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' },
    vulnType: { color: '#fff', fontSize: '14px', fontWeight: 600, textTransform: 'capitalize' },
    vulnLine: { color: 'rgba(255,255,255,0.3)', fontSize: '12px', fontFamily: 'JetBrains Mono' },
    cweChip: {
        background: 'rgba(0,240,255,0.08)', border: '1px solid rgba(0,240,255,0.2)',
        borderRadius: '5px', padding: '2px 8px', color: '#00f0ff',
        fontSize: '10px', fontFamily: 'JetBrains Mono'
    },
    expandBtn: { color: 'rgba(255,255,255,0.3)', transition: 'transform 0.2s' },
    vulnBody: { borderTop: '1px solid rgba(255,255,255,0.06)', padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' },
    codeBlock: { background: 'rgba(0,0,0,0.5)', borderRadius: '10px', overflow: 'hidden', border: '1px solid rgba(0,240,255,0.08)' },
    codeHeader: {
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        background: 'rgba(255,255,255,0.04)', padding: '8px 14px',
        borderBottom: '1px solid rgba(255,255,255,0.05)'
    },
    codeHeaderLabel: { color: 'rgba(255,255,255,0.3)', fontSize: '11px', fontFamily: 'JetBrains Mono' },
    codeHeaderLine: { color: 'rgba(0,240,255,0.6)', fontSize: '11px', fontFamily: 'JetBrains Mono' },
    pre: { margin: 0, padding: '16px', color: '#e2e8f0', fontFamily: 'JetBrains Mono', fontSize: '12px', overflowX: 'auto', lineHeight: 1.7 },
    bodyGrid: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' },
    bodySection: {},
    sectionHead: {
        display: 'flex', alignItems: 'center', gap: '6px',
        color: '#a5b4fc', fontSize: '11px', fontWeight: 700,
        letterSpacing: '0.5px', textTransform: 'uppercase',
        marginBottom: '8px', fontFamily: 'JetBrains Mono'
    },
    sectionText: { color: 'rgba(255,255,255,0.6)', fontSize: '13px', lineHeight: 1.7, margin: 0 }
};