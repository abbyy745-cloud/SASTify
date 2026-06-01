import React, { useState, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
    BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend,
    AreaChart, Area
} from 'recharts';
import { useDashboard } from '../hooks/useDashboard.jsx';
import { useAuth } from '../context/AuthContext.jsx';
import StatCard from '../components/StatCard.jsx';

/* ── Keyframe Animations ────────────────────────── */
const dashboardKeyframes = `
@keyframes dashGradientShift {
  0%   { background-position: 0% 50%; }
  50%  { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}
@keyframes dashDonutRingPulse {
  0%, 100% { box-shadow: 0 0 20px rgba(0,240,255,0.15), 0 0 40px rgba(139,92,246,0.1); transform: translate(-50%,-50%) scale(1); }
  50%      { box-shadow: 0 0 30px rgba(0,240,255,0.25), 0 0 60px rgba(139,92,246,0.18); transform: translate(-50%,-50%) scale(1.04); }
}
@keyframes dashFloatIcon {
  0%, 100% { transform: translateY(0px); }
  50%      { transform: translateY(-10px); }
}
@keyframes dashPulseBtn {
  0%, 100% { box-shadow: 0 4px 20px rgba(0,240,255,0.25), 0 0 30px rgba(0,240,255,0.08); }
  50%      { box-shadow: 0 4px 30px rgba(0,240,255,0.45), 0 0 50px rgba(0,240,255,0.18); }
}
@keyframes dashNeonBorderRotate {
  0%   { background-position: 0% 50%; }
  100% { background-position: 300% 50%; }
}
@keyframes dashScanlineMove {
  0%   { top: -2px; }
  100% { top: 100%; }
}
`;

const SEV_COLORS = {
    Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#10b981'
};

const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
        <div style={{
            background: 'rgba(8,8,16,0.95)', border: '1px solid rgba(0,240,255,0.15)',
            borderRadius: '12px', padding: '14px 18px', backdropFilter: 'blur(16px)',
            boxShadow: '0 8px 32px rgba(0,0,0,0.5), 0 0 20px rgba(0,240,255,0.08)'
        }}>
            {label && <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: '10px', margin: '0 0 8px', fontFamily: 'JetBrains Mono', letterSpacing: '0.5px', textTransform: 'uppercase' }}>{label}</p>}
            {payload.map((p, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: p.color, flexShrink: 0, boxShadow: `0 0 6px ${p.color}40` }} />
                    <span style={{ color: 'rgba(255,255,255,0.6)', fontSize: '12px' }}>{p.name}:</span>
                    <span style={{ color: '#fff', fontWeight: 700, fontSize: '12px', fontFamily: 'JetBrains Mono' }}>{p.value}</span>
                </div>
            ))}
        </div>
    );
};

function ChartCard({ title, subtitle, children, style = {} }) {
    const [hovered, setHovered] = useState(false);
    const cardRef = useRef(null);

    const handleMouseMove = useCallback((e) => {
        if (!cardRef.current) return;
        const rect = cardRef.current.getBoundingClientRect();
        const x = (e.clientX - rect.left) / rect.width - 0.5;
        const y = (e.clientY - rect.top) / rect.height - 0.5;
        cardRef.current.style.transform = `perspective(800px) rotateX(${y * -4}deg) rotateY(${x * 4}deg)`;
    }, []);

    const handleMouseLeave = useCallback(() => {
        if (cardRef.current) cardRef.current.style.transform = 'perspective(800px) rotateX(0deg) rotateY(0deg)';
        setHovered(false);
    }, []);

    return (
        <div
            ref={cardRef}
            onMouseMove={(e) => { handleMouseMove(e); setHovered(true); }}
            onMouseLeave={handleMouseLeave}
            style={{
                ...styles.chartCard,
                ...style,
                transition: 'transform 0.15s ease-out, box-shadow 0.3s ease, border-color 0.3s ease',
                backdropFilter: 'blur(20px)',
                background: 'rgba(255,255,255,0.025)',
                borderColor: hovered ? 'rgba(0,240,255,0.2)' : 'rgba(255,255,255,0.06)',
                boxShadow: hovered
                    ? '0 0 25px rgba(0,240,255,0.12), 0 0 50px rgba(139,92,246,0.06), 0 8px 32px rgba(0,0,0,0.4)'
                    : '0 4px 20px rgba(0,0,0,0.3)',
            }}
        >
            <div style={styles.chartHeader}>
                <div>
                    <h3 style={styles.chartTitle}>{title}</h3>
                    {subtitle && <p style={styles.chartSub}>{subtitle}</p>}
                </div>
            </div>
            {children}
        </div>
    );
}

function EmptyState({ message = 'No data available', icon = '📊' }) {
    return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '200px', gap: '14px' }}>
            <div style={{ fontSize: '36px', opacity: 0.3, animation: 'dashFloatIcon 3s ease-in-out infinite' }}>{icon}</div>
            <p style={{ color: 'rgba(255,255,255,0.2)', fontSize: '13px', margin: 0, fontFamily: 'JetBrains Mono' }}>{message}</p>
        </div>
    );
}

function Loader() {
    return (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh', flexDirection: 'column', gap: '20px' }}>
            <div style={{ position: 'relative', width: '44px', height: '44px' }}>
                <div style={{
                    position: 'absolute', inset: 0, border: '2px solid rgba(0,240,255,0.15)',
                    borderTopColor: '#00f0ff', borderRadius: '50%',
                    animation: 'spin 0.8s linear infinite'
                }} />
            </div>
            <p style={{ color: 'rgba(255,255,255,0.25)', fontSize: '13px', fontFamily: 'JetBrains Mono' }}>Loading analytics…</p>
        </div>
    );
}

export default function DashboardPage() {
    const { user } = useAuth();
    const { data, scans, loading } = useDashboard();
    const navigate = useNavigate();

    if (loading) return <Loader />;

    const stats = data?.user_stats || {};
    const topVulns = data?.most_common_vulnerabilities || [];
    const trends = data?.trends?.trends || [];

    let critical = 0, high = 0, medium = 0, low = 0;
    trends.forEach(d => {
        critical += d.critical || 0; high += d.high || 0;
        medium += d.medium || 0; low += d.low || 0;
    });
    const totalIssues = critical + high + medium + low;

    const pieData = [
        { name: 'Critical', value: critical },
        { name: 'High', value: high },
        { name: 'Medium', value: medium },
        { name: 'Low', value: low },
    ].filter(d => d.value > 0);

    const barData = topVulns.slice(0, 8).map(v => ({
        name: v.type.replace(/_/g, ' ').split(' ').slice(0, 2).join(' '),
        fullName: v.type.replace(/_/g, ' '),
        count: v.count,
    }));

    const recentScans = scans.slice(0, 5);
    const now = new Date();
    const greeting = now.getHours() < 12 ? 'Good morning' : now.getHours() < 17 ? 'Good afternoon' : 'Good evening';

    return (
        <div style={styles.page} className="animate-fade-in">
            {/* Inject keyframes */}
            <style>{dashboardKeyframes}</style>

            {/* Top banner with gradient mesh */}
            <div style={styles.topBanner}>
                {/* Animated gradient mesh background */}
                <div style={styles.bannerMeshBg} />
                <div style={styles.bannerLeft}>
                    <p style={styles.greeting}>{greeting}, {user?.name?.split(' ')[0] || 'Developer'}</p>
                    <h1 style={styles.pageTitle}>Security Overview</h1>
                    <p style={styles.pageSub}>Real-time vulnerability analysis across all your scanned projects</p>
                </div>
                <div style={styles.bannerRight}>
                    <button className="btn-primary" style={styles.scanBtn} onClick={() => navigate('/scans')}>
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                            <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
                        </svg>
                        View Scans
                    </button>
                    <button className="btn-primary" style={styles.analyticsBtn} onClick={() => navigate('/analytics')}>
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                            <line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/>
                            <line x1="6" y1="20" x2="6" y2="14"/>
                        </svg>
                        Analytics
                    </button>
                </div>
            </div>

            {/* Stat Cards */}
            <div style={styles.statsGrid} className="stagger-children">
                <StatCard
                    label="Total Scans" value={stats.total_scans || 0}
                    color="#818cf8" trendLabel="All time scans"
                    icon={<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#818cf8" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>}
                />
                <StatCard
                    label="Total Issues" value={stats.total_issues_found || totalIssues || 0}
                    color="#a78bfa" trendLabel="Vulnerabilities detected"
                    icon={<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>}
                />
                <StatCard
                    label="Critical Issues" value={critical}
                    color="#ef4444" trendLabel="Requires immediate action"
                    icon={<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>}
                />
                <StatCard
                    label="High Severity" value={high}
                    color="#f97316" trendLabel="High priority fixes"
                    icon={<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f97316" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2L4 6v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V6L12 2z"/></svg>}
                />
            </div>

            {/* Charts Row 1 */}
            <div style={styles.chartsRow}>
                {/* Donut severity */}
                <ChartCard title="Severity Distribution" subtitle="Breakdown by risk level" style={{ flex: 1 }}>
                    {pieData.length > 0 ? (
                        <>
                            <div style={{ position: 'relative' }}>
                                {/* Decorative glowing ring behind the donut */}
                                <div style={styles.donutGlowRing} />
                                <ResponsiveContainer width="100%" height={220}>
                                    <PieChart>
                                        <Pie data={pieData} dataKey="value" cx="50%" cy="50%"
                                            innerRadius={60} outerRadius={90}
                                            paddingAngle={4} strokeWidth={0}>
                                            {pieData.map((e, i) => (
                                                <Cell key={i} fill={SEV_COLORS[e.name]} opacity={0.85} />
                                            ))}
                                        </Pie>
                                        <Tooltip content={<CustomTooltip />} />
                                    </PieChart>
                                </ResponsiveContainer>
                            </div>
                            <div style={styles.legend}>
                                {pieData.map(e => (
                                    <div key={e.name} style={styles.legendItem}>
                                        <span style={{ ...styles.legendDot, background: SEV_COLORS[e.name], boxShadow: `0 0 6px ${SEV_COLORS[e.name]}40` }} />
                                        <span style={styles.legendName}>{e.name}</span>
                                        <span style={styles.legendCount}>{e.value}</span>
                                    </div>
                                ))}
                            </div>
                        </>
                    ) : <EmptyState message="Run a scan to see distribution" />}
                </ChartCard>

                {/* Top Vuln Types Bar */}
                <ChartCard title="Top Vulnerability Types" subtitle="Most frequently detected issues" style={{ flex: 2 }}>
                    {barData.length > 0 ? (
                        <ResponsiveContainer width="100%" height={260}>
                            <BarChart data={barData} margin={{ top: 10, right: 10, left: -20, bottom: 40 }}>
                                <defs>
                                    <linearGradient id="barGrad" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="0%" stopColor="#00f0ff" stopOpacity={0.9} />
                                        <stop offset="100%" stopColor="#8b5cf6" stopOpacity={0.5} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
                                <XAxis dataKey="name" tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                                    angle={-35} textAnchor="end" interval={0} />
                                <YAxis tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 11 }} axisLine={false} tickLine={false} />
                                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(0,240,255,0.04)' }} />
                                <Bar dataKey="count" name="Count" fill="url(#barGrad)" radius={[6, 6, 0, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    ) : <EmptyState message="No vulnerability data yet" />}
                </ChartCard>
            </div>

            {/* Trend Chart */}
            {trends.length > 0 && (
                <ChartCard title="7-Day Vulnerability Trend" subtitle="Daily breakdown by severity">
                    <ResponsiveContainer width="100%" height={220}>
                        <AreaChart data={trends} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                            <defs>
                                {Object.entries(SEV_COLORS).map(([k, v]) => (
                                    <linearGradient key={k} id={`area-${k}`} x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor={v} stopOpacity={0.2} />
                                        <stop offset="95%" stopColor={v} stopOpacity={0.01} />
                                    </linearGradient>
                                ))}
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
                            <XAxis dataKey="date" tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 11, fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false} />
                            <YAxis tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 11 }} axisLine={false} tickLine={false} />
                            <Tooltip content={<CustomTooltip />} />
                            <Legend wrapperStyle={{ fontSize: '12px', color: 'rgba(255,255,255,0.4)' }} />
                            {['critical', 'high', 'medium', 'low'].map((k, i) => (
                                <Area key={k} type="monotone" dataKey={k} name={k.charAt(0).toUpperCase() + k.slice(1)}
                                    stroke={Object.values(SEV_COLORS)[i]} strokeWidth={2}
                                    fill={`url(#area-${k.charAt(0).toUpperCase() + k.slice(1)})`} />
                            ))}
                        </AreaChart>
                    </ResponsiveContainer>
                </ChartCard>
            )}

            {/* Recent Scans */}
            <ChartCard title="Recent Scans" subtitle="Latest security scan results">
                {recentScans.length > 0 ? (
                    <div style={styles.scanList}>
                        {recentScans.map((sc, i) => (
                            <div key={sc.scan_id || i} className="scan-row" style={styles.scanRow}
                                onClick={() => navigate(`/scans/${sc.scan_id}`)}
                                onMouseEnter={e => {
                                    e.currentTarget.style.borderLeftColor = '#00f0ff';
                                    e.currentTarget.style.borderLeftWidth = '3px';
                                    e.currentTarget.style.boxShadow = '0 0 20px rgba(0,240,255,0.08), inset 3px 0 12px rgba(0,240,255,0.05)';
                                    e.currentTarget.style.background = 'rgba(0,240,255,0.03)';
                                }}
                                onMouseLeave={e => {
                                    e.currentTarget.style.borderLeftColor = 'rgba(255,255,255,0.05)';
                                    e.currentTarget.style.borderLeftWidth = '1px';
                                    e.currentTarget.style.boxShadow = 'none';
                                    e.currentTarget.style.background = 'rgba(255,255,255,0.015)';
                                }}
                            >
                                <div style={styles.scanLeft}>
                                    <div style={styles.scanFileIcon}>
                                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14,2 14,8 20,8"/>
                                        </svg>
                                    </div>
                                    <div>
                                        <div style={styles.scanFile}>{sc.filename || 'Scan Result'}</div>
                                        <div style={styles.scanMeta}>{sc.scan_id?.slice(0, 16)}… · {new Date(sc.created_at).toLocaleString()}</div>
                                    </div>
                                </div>
                                <div style={styles.scanRight}>
                                    <span style={styles.langTag}>{sc.language || '—'}</span>
                                    <span style={styles.issueCount}>{sc.total_vulnerabilities || 0} issues</span>
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.2)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                        <polyline points="9,18 15,12 9,6"/>
                                    </svg>
                                </div>
                            </div>
                        ))}
                        <button className="btn-primary" style={styles.viewAllBtn} onClick={() => navigate('/scans')}>
                            View All Scans
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                                <polyline points="9,18 15,12 9,6"/>
                            </svg>
                        </button>
                    </div>
                ) : (
                    <EmptyState message="No scans yet — run your first scan from VS Code" icon="🔍" />
                )}
            </ChartCard>
        </div>
    );
}

const styles = {
    page: { padding: '32px 40px', display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '1400px' },
    topBanner: {
        display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: '16px',
        position: 'relative', padding: '28px 30px', borderRadius: '20px', overflow: 'hidden',
        border: '1px solid rgba(0,240,255,0.08)',
    },
    bannerMeshBg: {
        position: 'absolute', inset: 0, zIndex: 0,
        background: 'linear-gradient(135deg, rgba(0,240,255,0.06) 0%, rgba(139,92,246,0.06) 25%, rgba(0,240,255,0.03) 50%, rgba(139,92,246,0.08) 75%, rgba(0,240,255,0.04) 100%)',
        backgroundSize: '400% 400%',
        animation: 'dashGradientShift 12s ease infinite',
    },
    bannerLeft: { position: 'relative', zIndex: 1 },
    greeting: { color: 'rgba(255,255,255,0.35)', fontSize: '13px', margin: '0 0 6px', fontWeight: 500 },
    pageTitle: {
        color: '#fff', fontSize: '30px', fontWeight: 800, margin: '0 0 8px',
        letterSpacing: '-0.5px', fontFamily: 'Outfit, Inter, sans-serif'
    },
    pageSub: { color: 'rgba(255,255,255,0.3)', fontSize: '14px', margin: 0 },
    bannerRight: { display: 'flex', gap: '10px', flexWrap: 'wrap', position: 'relative', zIndex: 1 },
    scanBtn: {
        display: 'flex', alignItems: 'center', gap: '8px',
        background: 'linear-gradient(135deg, #00c8d6, #00f0ff)',
        border: 'none', borderRadius: '12px', padding: '10px 20px',
        color: '#050609', fontSize: '14px', fontWeight: 700, cursor: 'pointer',
        animation: 'dashPulseBtn 2.5s ease-in-out infinite',
    },
    analyticsBtn: {
        display: 'flex', alignItems: 'center', gap: '8px',
        background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(0,240,255,0.15)',
        borderRadius: '12px', padding: '10px 20px',
        color: 'rgba(0,240,255,0.7)', fontSize: '14px', fontWeight: 600, cursor: 'pointer',
    },
    statsGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' },
    chartsRow: { display: 'flex', gap: '20px', flexWrap: 'wrap' },
    chartCard: {
        background: 'rgba(255,255,255,0.025)',
        border: '1px solid rgba(255,255,255,0.06)', borderRadius: '18px', padding: '24px',
        position: 'relative', overflow: 'hidden',
    },
    chartHeader: { marginBottom: '18px' },
    chartTitle: { color: '#fff', fontSize: '15px', fontWeight: 700, margin: '0 0 4px', fontFamily: 'Outfit, Inter, sans-serif' },
    chartSub: { color: 'rgba(255,255,255,0.25)', fontSize: '12px', margin: 0 },
    donutGlowRing: {
        position: 'absolute', top: '50%', left: '50%',
        width: '130px', height: '130px', borderRadius: '50%',
        border: '2px solid rgba(0,240,255,0.15)',
        animation: 'dashDonutRingPulse 3s ease-in-out infinite',
        pointerEvents: 'none',
    },
    legend: { display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '14px' },
    legendItem: {
        display: 'flex', alignItems: 'center', gap: '6px',
        background: 'rgba(255,255,255,0.03)', borderRadius: '8px', padding: '6px 12px',
        border: '1px solid rgba(255,255,255,0.04)',
    },
    legendDot: { width: '8px', height: '8px', borderRadius: '50%', flexShrink: 0 },
    legendName: { color: 'rgba(255,255,255,0.5)', fontSize: '11px', fontWeight: 500 },
    legendCount: { color: '#fff', fontSize: '12px', fontWeight: 700, fontFamily: 'JetBrains Mono', marginLeft: '2px' },
    scanList: { display: 'flex', flexDirection: 'column', gap: '8px' },
    scanRow: {
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        background: 'rgba(255,255,255,0.015)', border: '1px solid rgba(255,255,255,0.05)',
        borderRadius: '14px', padding: '14px 18px', cursor: 'pointer', gap: '12px', flexWrap: 'wrap',
        transition: 'all 0.25s ease',
        borderLeft: '1px solid rgba(255,255,255,0.05)',
    },
    scanLeft: { display: 'flex', alignItems: 'center', gap: '12px' },
    scanFileIcon: {
        width: '36px', height: '36px', borderRadius: '10px',
        background: 'rgba(0,240,255,0.06)', border: '1px solid rgba(0,240,255,0.15)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0
    },
    scanFile: { color: '#fff', fontSize: '14px', fontWeight: 600 },
    scanMeta: { color: 'rgba(255,255,255,0.2)', fontSize: '11px', fontFamily: 'JetBrains Mono', marginTop: '2px' },
    scanRight: { display: 'flex', alignItems: 'center', gap: '10px' },
    langTag: {
        background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '6px', padding: '2px 8px', color: 'rgba(255,255,255,0.35)',
        fontSize: '10px', fontFamily: 'JetBrains Mono'
    },
    issueCount: { color: 'rgba(255,255,255,0.4)', fontSize: '12px', fontFamily: 'JetBrains Mono' },
    viewAllBtn: {
        background: 'transparent', border: '1px solid rgba(0,240,255,0.2)',
        borderRadius: '10px', padding: '10px', color: '#00f0ff',
        fontSize: '13px', fontWeight: 600, cursor: 'pointer',
        marginTop: '6px', textAlign: 'center',
        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px',
        transition: 'all 0.25s ease',
    }
};