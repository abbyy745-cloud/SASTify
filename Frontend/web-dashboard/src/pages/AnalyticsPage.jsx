import React, { useState, useRef, useCallback } from 'react';
import {
    ResponsiveContainer, BarChart, Bar, XAxis, YAxis,
    CartesianGrid, Tooltip, AreaChart, Area, RadarChart,
    PolarGrid, PolarAngleAxis, Radar, PieChart, Pie, Cell
} from 'recharts';
import { useDashboard } from '../hooks/useDashboard.jsx';

/* ── Keyframe Animations ────────────────────────── */
const analyticsKeyframes = `
@keyframes analyticsScanLine {
  0%   { left: -30%; }
  100% { left: 130%; }
}
@keyframes analyticsRiskRingPulse {
  0%, 100% { transform: scale(1); opacity: 0.5; }
  50%      { transform: scale(1.12); opacity: 0.9; }
}
@keyframes analyticsRiskRingRotate {
  0%   { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}
@keyframes analyticsRadarPulse {
  0%, 100% { box-shadow: 0 0 30px rgba(0,240,255,0.08), 0 0 60px rgba(139,92,246,0.04); }
  50%      { box-shadow: 0 0 50px rgba(0,240,255,0.15), 0 0 90px rgba(139,92,246,0.08); }
}
@keyframes analyticsNeonBorder {
  0%   { background-position: 0% 50%; }
  100% { background-position: 300% 50%; }
}
@keyframes analyticsMetricGlow {
  0%, 100% { box-shadow: 0 0 15px rgba(0,240,255,0.05); }
  50%      { box-shadow: 0 0 25px rgba(0,240,255,0.12); }
}
`;

const SEV_COLORS = { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#10b981' };

const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
        <div style={{
            background: 'rgba(13,16,41,0.95)', border: '1px solid rgba(0,240,255,0.15)',
            borderRadius: '10px', padding: '12px 16px', backdropFilter: 'blur(12px)',
            boxShadow: '0 8px 32px rgba(0,0,0,0.5), 0 0 15px rgba(0,240,255,0.06)'
        }}>
            {label && <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: '11px', margin: '0 0 8px', fontFamily: 'JetBrains Mono' }}>{label}</p>}
            {payload.map((p, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: p.color || p.fill, flexShrink: 0 }} />
                    <span style={{ color: 'rgba(255,255,255,0.6)', fontSize: '12px' }}>{p.name}:</span>
                    <span style={{ color: '#fff', fontWeight: 700, fontSize: '12px', fontFamily: 'JetBrains Mono' }}>{p.value}</span>
                </div>
            ))}
        </div>
    );
};

function ChartCard({ title, subtitle, children, badge, isRadar }) {
    const [hovered, setHovered] = useState(false);
    const cardRef = useRef(null);

    const handleMouseMove = useCallback((e) => {
        if (!cardRef.current) return;
        const rect = cardRef.current.getBoundingClientRect();
        const x = (e.clientX - rect.left) / rect.width - 0.5;
        const y = (e.clientY - rect.top) / rect.height - 0.5;
        cardRef.current.style.transform = `perspective(800px) rotateX(${y * -3}deg) rotateY(${x * 3}deg)`;
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
                ...s.card,
                transition: 'transform 0.15s ease-out, box-shadow 0.3s ease, border-color 0.3s ease',
                backdropFilter: 'blur(16px)',
                borderColor: hovered ? 'rgba(0,240,255,0.2)' : 'rgba(255,255,255,0.07)',
                boxShadow: hovered
                    ? '0 0 25px rgba(0,240,255,0.1), 0 0 50px rgba(139,92,246,0.05), 0 8px 32px rgba(0,0,0,0.4)'
                    : '0 4px 20px rgba(0,0,0,0.2)',
                ...(isRadar ? { animation: 'analyticsRadarPulse 4s ease-in-out infinite' } : {}),
            }}
        >
            <div style={s.cardHeader}>
                <div>
                    <h3 style={s.cardTitle}>{title}</h3>
                    {subtitle && <p style={s.cardSub}>{subtitle}</p>}
                </div>
                {badge && <span style={s.cardBadge}>{badge}</span>}
            </div>
            {children}
        </div>
    );
}

function EmptyState() {
    return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '180px', gap: '10px' }}>
            <div style={{ fontSize: '32px', opacity: 0.25 }}>📊</div>
            <p style={{ color: 'rgba(255,255,255,0.2)', fontSize: '12px', margin: 0, fontFamily: 'JetBrains Mono' }}>No data yet</p>
        </div>
    );
}

function Spinner() {
    return (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh', flexDirection: 'column', gap: '20px' }}>
            <div style={{ width: '36px', height: '36px', border: '3px solid rgba(0,240,255,0.2)', borderTopColor: '#00f0ff', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
            <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: '13px', fontFamily: 'JetBrains Mono', margin: 0 }}>Loading analytics…</p>
        </div>
    );
}

export default function AnalyticsPage() {
    const { data, loading } = useDashboard();

    if (loading) return <Spinner />;

    const trends = data?.trends?.trends || [];
    const topVulns = data?.most_common_vulnerabilities || [];
    const stats = data?.user_stats || {};

    let critical = 0, high = 0, medium = 0, low = 0;
    trends.forEach(d => { critical += d.critical || 0; high += d.high || 0; medium += d.medium || 0; low += d.low || 0; });
    const total = critical + high + medium + low;

    const trendData = trends.map(d => ({
        ...d, total: (d.critical || 0) + (d.high || 0) + (d.medium || 0) + (d.low || 0)
    }));

    const vulnBar = topVulns.slice(0, 10).map(v => ({
        name: v.type.replace(/_/g, ' ').split(' ').slice(0, 3).join(' '),
        count: v.count
    }));

    const pieData = [
        { name: 'Critical', value: critical },
        { name: 'High', value: high },
        { name: 'Medium', value: medium },
        { name: 'Low', value: low },
    ].filter(d => d.value > 0);

    const radarData = topVulns.slice(0, 6).map(v => ({
        subject: v.type.replace(/_/g, ' ').split(' ').slice(0, 2).join(' '),
        count: v.count, fullMark: Math.max(...topVulns.map(x => x.count), 1)
    }));

    const riskScore = total === 0 ? 100 : Math.max(0, 100 - Math.round((critical * 10 + high * 5 + medium * 2 + low * 0.5)));

    const riskColor = riskScore >= 80 ? '#10b981' : riskScore >= 60 ? '#eab308' : '#ef4444';

    return (
        <div style={s.page} className="animate-fade-in">
            {/* Inject keyframes */}
            <style>{analyticsKeyframes}</style>

            {/* Header with scan line */}
            <div style={s.header}>
                <div style={{ position: 'relative' }}>
                    <h1 style={s.h1}>Analytics</h1>
                    <p style={s.sub}>Deep insights into your security posture and vulnerability patterns</p>
                    {/* Animated scan line */}
                    <div style={s.scanLineWrap}>
                        <div style={s.scanLine} />
                    </div>
                </div>
                <div style={s.riskScoreBox}>
                    {/* 3D perspective risk circle with animated ring */}
                    <div style={{ position: 'relative', perspective: '400px' }}>
                        {/* Animated outer ring */}
                        <div style={{
                            position: 'absolute', inset: '-6px', borderRadius: '50%',
                            border: `2px solid ${riskColor}40`,
                            animation: 'analyticsRiskRingPulse 3s ease-in-out infinite',
                        }} />
                        <div style={{
                            position: 'absolute', inset: '-10px', borderRadius: '50%',
                            border: `1px dashed ${riskColor}25`,
                            animation: 'analyticsRiskRingRotate 20s linear infinite',
                        }} />
                        <div style={{
                            ...s.riskCircle,
                            borderColor: riskColor,
                            boxShadow: `0 0 25px ${riskColor}30, 0 0 50px ${riskColor}10, inset 0 0 15px ${riskColor}08`,
                            transform: 'rotateX(8deg)',
                        }}>
                            <span style={{ ...s.riskNum, color: riskColor }}>
                                {riskScore}
                            </span>
                            <span style={s.riskLabel}>Risk Score</span>
                        </div>
                    </div>
                    <div>
                        <p style={s.riskTitle}>Security Posture</p>
                        <p style={{ ...s.riskStatus, color: riskColor }}>
                            {riskScore >= 80 ? '✓ Good' : riskScore >= 60 ? '⚠ Moderate' : '✗ Needs Attention'}
                        </p>
                        <p style={s.riskHint}>{total} issues across {stats.total_scans || 0} scans</p>
                    </div>
                </div>
            </div>

            {/* Top metrics row */}
            <div style={s.metricsRow}>
                {[
                    { label: 'Total Scans', value: stats.total_scans || 0, color: '#00f0ff', icon: '🔍' },
                    { label: 'Critical', value: critical, color: '#ef4444', icon: '🔴' },
                    { label: 'High', value: high, color: '#f97316', icon: '🟠' },
                    { label: 'Medium', value: medium, color: '#eab308', icon: '🟡' },
                    { label: 'Low', value: low, color: '#10b981', icon: '🟢' },
                ].map(m => (
                    <div key={m.label}
                        style={{ ...s.metricBox, borderColor: m.color + '22' }}
                        onMouseEnter={e => {
                            e.currentTarget.style.transform = 'scale(1.04)';
                            e.currentTarget.style.borderColor = m.color + '55';
                            e.currentTarget.style.boxShadow = `0 0 25px ${m.color}20, 0 0 50px ${m.color}08`;
                        }}
                        onMouseLeave={e => {
                            e.currentTarget.style.transform = 'scale(1)';
                            e.currentTarget.style.borderColor = m.color + '22';
                            e.currentTarget.style.boxShadow = 'none';
                        }}
                    >
                        <div style={{ fontSize: '20px', marginBottom: '8px' }}>{m.icon}</div>
                        <div style={{ ...s.metricVal, color: m.color }}>{m.value}</div>
                        <div style={s.metricLabel}>{m.label}</div>
                    </div>
                ))}
            </div>

            {/* Charts grid */}
            <div style={s.grid2}>
                {/* Trend Area */}
                <ChartCard title="Vulnerability Trend" subtitle="Issues discovered over time" badge="7 days">
                    {trendData.length > 0 ? (
                        <ResponsiveContainer width="100%" height={220}>
                            <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                                <defs>
                                    {Object.entries(SEV_COLORS).map(([k, v]) => (
                                        <linearGradient key={k} id={`ag-${k}`} x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor={v} stopOpacity={0.3} />
                                            <stop offset="95%" stopColor={v} stopOpacity={0.02} />
                                        </linearGradient>
                                    ))}
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                                <XAxis dataKey="date" tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10, fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false} />
                                <YAxis tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10 }} axisLine={false} tickLine={false} />
                                <Tooltip content={<CustomTooltip />} />
                                {['critical','high','medium','low'].map((k,i) => (
                                    <Area key={k} type="monotone" dataKey={k} name={k.charAt(0).toUpperCase()+k.slice(1)}
                                        stroke={Object.values(SEV_COLORS)[i]} strokeWidth={2}
                                        fill={`url(#ag-${Object.keys(SEV_COLORS)[i]})`} />
                                ))}
                            </AreaChart>
                        </ResponsiveContainer>
                    ) : <EmptyState />}
                </ChartCard>

                {/* Severity Donut */}
                <ChartCard title="Severity Split" subtitle="Proportion of each risk level">
                    {pieData.length > 0 ? (
                        <>
                            <ResponsiveContainer width="100%" height={180}>
                                <PieChart>
                                    <Pie data={pieData} dataKey="value" cx="50%" cy="50%"
                                        innerRadius={55} outerRadius={80} paddingAngle={3} strokeWidth={0}>
                                        {pieData.map((e, i) => <Cell key={i} fill={SEV_COLORS[e.name]} opacity={0.85} />)}
                                    </Pie>
                                    <Tooltip content={<CustomTooltip />} />
                                </PieChart>
                            </ResponsiveContainer>
                            <div style={s.legend}>
                                {pieData.map(e => (
                                    <div key={e.name} style={s.legendItem}>
                                        <span style={{ ...s.legendDot, background: SEV_COLORS[e.name], boxShadow: `0 0 6px ${SEV_COLORS[e.name]}40` }} />
                                        <span style={s.legendName}>{e.name}</span>
                                        <span style={s.legendPct}>{total > 0 ? Math.round((e.value/total)*100) : 0}%</span>
                                        <span style={s.legendVal}>{e.value}</span>
                                    </div>
                                ))}
                            </div>
                        </>
                    ) : <EmptyState />}
                </ChartCard>
            </div>

            {/* Top vulns horizontal bar */}
            <ChartCard title="Top 10 Vulnerability Types" subtitle="Most common vulnerabilities across all scans">
                {vulnBar.length > 0 ? (
                    <ResponsiveContainer width="100%" height={280}>
                        <BarChart data={vulnBar} layout="vertical" margin={{ top: 5, right: 30, left: 100, bottom: 5 }}>
                            <defs>
                                <linearGradient id="hbarGrad" x1="0" y1="0" x2="1" y2="0">
                                    <stop offset="0%" stopColor="#00f0ff" />
                                    <stop offset="100%" stopColor="#8b5cf6" />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                            <XAxis type="number" tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10 }} axisLine={false} tickLine={false} />
                            <YAxis type="category" dataKey="name" width={95} tick={{ fill: 'rgba(255,255,255,0.5)', fontSize: 10, fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false} />
                            <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(0,240,255,0.04)' }} />
                            <Bar dataKey="count" name="Occurrences" fill="url(#hbarGrad)" radius={[0, 4, 4, 0]} />
                        </BarChart>
                    </ResponsiveContainer>
                ) : <EmptyState />}
            </ChartCard>

            {/* Radar + daily totals */}
            <div style={s.grid2}>
                <ChartCard title="Vulnerability Radar" subtitle="Attack surface by category" isRadar>
                    {radarData.length > 0 ? (
                        <ResponsiveContainer width="100%" height={250}>
                            <RadarChart data={radarData} cx="50%" cy="50%" outerRadius={90}>
                                <PolarGrid stroke="rgba(0,240,255,0.1)" />
                                <PolarAngleAxis dataKey="subject" tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10 }} />
                                <Radar name="Issues" dataKey="count" stroke="#00f0ff" fill="#00f0ff" fillOpacity={0.18} strokeWidth={2} />
                                <Tooltip content={<CustomTooltip />} />
                            </RadarChart>
                        </ResponsiveContainer>
                    ) : <EmptyState />}
                </ChartCard>

                {/* Daily totals bar */}
                <ChartCard title="Daily Issue Volume" subtitle="Total issues found per day">
                    {trendData.length > 0 ? (
                        <ResponsiveContainer width="100%" height={250}>
                            <BarChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                                <defs>
                                    <linearGradient id="dailyGrad" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="0%" stopColor="#8b5cf6" stopOpacity={0.9} />
                                        <stop offset="100%" stopColor="#6366f1" stopOpacity={0.5} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                                <XAxis dataKey="date" tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10, fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false} />
                                <YAxis tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10 }} axisLine={false} tickLine={false} />
                                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(99,102,241,0.08)' }} />
                                <Bar dataKey="total" name="Total Issues" fill="url(#dailyGrad)" radius={[4, 4, 0, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    ) : <EmptyState />}
                </ChartCard>
            </div>
        </div>
    );
}

const s = {
    page: { padding: '32px 36px', display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '1400px' },
    header: {
        display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px',
        position: 'relative', overflow: 'hidden',
    },
    scanLineWrap: {
        position: 'absolute', bottom: '-2px', left: 0, right: 0, height: '2px', overflow: 'hidden',
        background: 'rgba(255,255,255,0.03)', borderRadius: '1px',
    },
    scanLine: {
        position: 'absolute', top: 0, width: '30%', height: '100%',
        background: 'linear-gradient(90deg, transparent, rgba(0,240,255,0.5), transparent)',
        animation: 'analyticsScanLine 4s linear infinite',
    },
    h1: { color: '#fff', fontSize: '28px', fontWeight: 800, margin: '0 0 6px', letterSpacing: '-0.5px' },
    sub: { color: 'rgba(255,255,255,0.3)', fontSize: '14px', margin: 0 },
    riskScoreBox: {
        display: 'flex', alignItems: 'center', gap: '20px',
        background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(0,240,255,0.12)',
        borderRadius: '16px', padding: '16px 22px',
        backdropFilter: 'blur(16px)',
        boxShadow: '0 0 30px rgba(0,240,255,0.05)',
    },
    riskCircle: {
        width: '72px', height: '72px', borderRadius: '50%', border: '3px solid',
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
        flexShrink: 0, position: 'relative',
    },
    riskNum: { fontSize: '24px', fontWeight: 800, lineHeight: 1, fontFamily: 'JetBrains Mono' },
    riskLabel: { fontSize: '9px', color: 'rgba(255,255,255,0.3)', letterSpacing: '0.5px', marginTop: '2px' },
    riskTitle: { color: 'rgba(255,255,255,0.5)', fontSize: '11px', margin: '0 0 4px', fontWeight: 600 },
    riskStatus: { fontSize: '14px', fontWeight: 700, margin: '0 0 4px' },
    riskHint: { color: 'rgba(255,255,255,0.25)', fontSize: '11px', margin: 0, fontFamily: 'JetBrains Mono' },
    metricsRow: { display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: '14px' },
    metricBox: {
        background: 'rgba(255,255,255,0.03)', border: '1px solid',
        borderRadius: '14px', padding: '18px 16px',
        display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center',
        transition: 'all 0.25s ease', cursor: 'default',
        backdropFilter: 'blur(10px)',
    },
    metricVal: { fontSize: '28px', fontWeight: 800, lineHeight: 1, fontFamily: 'JetBrains Mono', letterSpacing: '-1px' },
    metricLabel: { color: 'rgba(255,255,255,0.35)', fontSize: '11px', marginTop: '6px', fontWeight: 500 },
    grid2: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' },
    card: {
        background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: '16px', padding: '22px', position: 'relative', overflow: 'hidden',
    },
    cardHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '18px' },
    cardTitle: { color: '#fff', fontSize: '15px', fontWeight: 700, margin: '0 0 4px' },
    cardSub: { color: 'rgba(255,255,255,0.3)', fontSize: '12px', margin: 0 },
    cardBadge: {
        background: 'rgba(0,240,255,0.1)', border: '1px solid rgba(0,240,255,0.25)',
        borderRadius: '6px', padding: '3px 10px', color: '#00f0ff',
        fontSize: '11px', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap'
    },
    legend: { display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '8px' },
    legendItem: { display: 'flex', alignItems: 'center', gap: '8px' },
    legendDot: { width: '8px', height: '8px', borderRadius: '50%', flexShrink: 0 },
    legendName: { color: 'rgba(255,255,255,0.5)', fontSize: '12px', flex: 1 },
    legendPct: { color: 'rgba(255,255,255,0.3)', fontSize: '11px', fontFamily: 'JetBrains Mono', width: '35px', textAlign: 'right' },
    legendVal: { color: '#fff', fontSize: '12px', fontWeight: 700, fontFamily: 'JetBrains Mono', width: '30px', textAlign: 'right' },
};