import React, { useState } from 'react';
import { NavLink, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import { useDashboard } from '../hooks/useDashboard.jsx';

const links = [
    {
        to: '/dashboard', icon: (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/>
                <rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>
            </svg>
        ), label: 'Overview'
    },
    {
        to: '/scans', icon: (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
            </svg>
        ), label: 'Scan History'
    },
    {
        to: '/analytics', icon: (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/>
                <line x1="6" y1="20" x2="6" y2="14"/>
            </svg>
        ), label: 'Analytics'
    },
    {
        to: '/token', icon: (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
            </svg>
        ), label: 'API Token'
    },
];

export default function Sidebar() {
    const { user, logout } = useAuth();
    const { data } = useDashboard();
    const navigate = useNavigate();
    const location = useLocation();
    const [hovered, setHovered] = useState(null);
    const handleLogout = () => { logout(); navigate('/'); };
    const initials = (user?.name || user?.email || 'U').split(' ').map(w => w[0]).join('').slice(0,2).toUpperCase();

    // Compute dynamic security health score
    const stats = data?.user_stats || {};
    const trends = data?.trends?.trends || [];
    let critical = 0, high = 0, medium = 0, low = 0;
    trends.forEach(d => { critical += d.critical || 0; high += d.high || 0; medium += d.medium || 0; low += d.low || 0; });
    const total = critical + high + medium + low;
    const healthScore = total === 0 ? 100 : Math.max(0, 100 - Math.round((critical * 10 + high * 5 + medium * 2 + low * 0.5)));
    const healthLabel = healthScore >= 80 ? 'Good' : healthScore >= 60 ? 'Moderate' : 'Needs Work';

    return (
        <aside style={styles.sidebar}>
            {/* Ambient glow — enhanced cyan/purple */}
            <div style={styles.ambientGlow} />

            {/* Animated gradient right border */}
            <div style={{
                position: 'absolute', top: 0, right: 0, bottom: 0, width: '1px',
                background: 'linear-gradient(180deg, rgba(0,240,255,0.0), rgba(0,240,255,0.15), rgba(139,92,246,0.15), rgba(0,240,255,0.0))',
                backgroundSize: '100% 200%',
                animation: 'gradient-shift 4s ease-in-out infinite',
            }} />

            {/* Logo */}
            <div style={styles.logoWrap}>
                <div style={styles.logoMark}>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
                        <path d="M12 2L4 6v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V6L12 2z" fill="url(#shield-grad)"/>
                        <defs>
                            <linearGradient id="shield-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop offset="0%" stopColor="#00f0ff"/><stop offset="100%" stopColor="#8b5cf6"/>
                            </linearGradient>
                        </defs>
                    </svg>
                </div>
                <div>
                    <span style={styles.logoText}>SASTify</span>
                    <span style={styles.logoVersion}>v2.0</span>
                </div>
            </div>

            {/* Status pill — enhanced with radar sweep */}
            <div style={styles.statusPill}>
                <div style={styles.statusDotWrap}>
                    {/* Radar sweep behind the dot */}
                    <span style={{
                        position: 'absolute',
                        inset: '-5px',
                        borderRadius: '50%',
                        background: 'conic-gradient(from 0deg, transparent 0%, rgba(16,185,129,0.3) 30%, transparent 40%)',
                        animation: 'radar-sweep 2s linear infinite',
                    }} />
                    <span style={styles.statusDot} />
                    <span style={styles.statusDotPing} />
                </div>
                <span style={styles.statusText}>Scanner Active</span>
            </div>

            {/* Nav */}
            <nav style={styles.nav}>
                <p style={styles.navSection}>NAVIGATION</p>
                {links.map((l, i) => {
                    const isActive = location.pathname === l.to || 
                        (l.to !== '/' && location.pathname.startsWith(l.to));
                    return (
                        <NavLink key={l.to} to={l.to}
                            style={{
                                ...styles.link,
                                ...(isActive ? styles.activeLink : {}),
                                ...(hovered === i && !isActive ? styles.hoveredLink : {}),
                                animationDelay: `${i * 0.05}s`
                            }}
                            onMouseEnter={() => setHovered(i)}
                            onMouseLeave={() => setHovered(null)}
                        >
                            {/* Hover glow trail */}
                            {hovered === i && !isActive && (
                                <div style={{
                                    position: 'absolute', inset: 0,
                                    borderRadius: '12px',
                                    background: 'radial-gradient(ellipse at 30% 50%, rgba(0,240,255,0.06), transparent 70%)',
                                    pointerEvents: 'none',
                                }} />
                            )}
                            <span style={{
                                ...styles.iconWrap,
                                ...(isActive ? {
                                    ...styles.activeIconWrap,
                                    boxShadow: '0 0 12px rgba(0,240,255,0.25), 0 2px 8px rgba(99,102,241,0.2)',
                                } : {}),
                            }}>
                                {l.icon}
                            </span>
                            <span style={{ fontWeight: isActive ? 600 : 500 }}>{l.label}</span>
                            {isActive && <span style={styles.activeIndicator} />}
                        </NavLink>
                    );
                })}
            </nav>

            <div style={{ flex: 1 }} />

            {/* Security Score Widget */}
            <div style={styles.scoreWidget}>
                <div style={styles.scoreTop}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M12 2L4 6v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V6L12 2z"/>
                        </svg>
                        <span style={styles.scoreLabel}>Security Health</span>
                    </div>
                    <span style={{...styles.scoreValue, color: healthScore >= 80 ? '#10b981' : healthScore >= 60 ? '#eab308' : '#ef4444'}}>{healthLabel}</span>
                </div>
                <div style={styles.scoreBar}>
                    <div style={{...styles.scoreBarFill, width: `${healthScore}%`}}>
                        {/* Animated shimmer over the bar */}
                        <div style={{
                            position: 'absolute', inset: 0,
                            background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.25), transparent)',
                            animation: 'shimmer-bar 2s ease-in-out infinite',
                        }} />
                    </div>
                </div>
                <p style={styles.scoreHint}>Keep scanning to improve your score</p>
            </div>

            {/* User + Logout */}
            <div style={styles.bottomWrap}>
                <div style={styles.userRow}>
                    <div style={styles.avatar}>
                        <span>{initials}</span>
                    </div>
                    <div style={styles.userInfo}>
                        <div style={styles.userName}>{user?.name || 'Developer'}</div>
                        <div style={styles.userEmail}>{user?.email}</div>
                    </div>
                </div>
                <button style={styles.logout} onClick={handleLogout}
                    onMouseEnter={e => { e.currentTarget.style.background = 'rgba(239,68,68,0.12)'; e.currentTarget.style.borderColor = 'rgba(239,68,68,0.3)'; e.currentTarget.style.boxShadow = '0 0 20px rgba(239,68,68,0.1)'; }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'rgba(239,68,68,0.06)'; e.currentTarget.style.borderColor = 'rgba(239,68,68,0.15)'; e.currentTarget.style.boxShadow = 'none'; }}
                >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16,17 21,12 16,7"/>
                        <line x1="21" y1="12" x2="9" y2="12"/>
                    </svg>
                    Sign Out
                </button>
            </div>
        </aside>
    );
}

const styles = {
    sidebar: {
        width: '256px', minHeight: '100vh', flexShrink: 0,
        background: 'linear-gradient(180deg, rgba(8,8,20,0.85) 0%, rgba(5,6,12,0.9) 100%)',
        backdropFilter: 'blur(24px) saturate(1.3)',
        WebkitBackdropFilter: 'blur(24px) saturate(1.3)',
        borderRight: '1px solid rgba(0,240,255,0.04)',
        display: 'flex', flexDirection: 'column',
        padding: '20px 14px',
        position: 'sticky', top: 0, height: '100vh', overflowY: 'auto',
        overflowX: 'hidden', zIndex: 50,
    },
    ambientGlow: {
        position: 'absolute', top: '-100px', left: '-50px',
        width: '300px', height: '300px', borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(0,240,255,0.05) 0%, rgba(139,92,246,0.03) 40%, transparent 70%)',
        pointerEvents: 'none',
    },
    logoWrap: {
        display: 'flex', alignItems: 'center', gap: '12px',
        padding: '6px 10px', marginBottom: '20px', position: 'relative'
    },
    logoMark: {
        width: '40px', height: '40px', borderRadius: '12px',
        background: 'linear-gradient(135deg, rgba(0,240,255,0.12), rgba(139,92,246,0.15))',
        border: '1px solid rgba(0,240,255,0.15)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
        boxShadow: '0 4px 16px rgba(0,240,255,0.1), 0 0 24px rgba(0,240,255,0.06)',
        animation: 'neon-pulse 3s ease-in-out infinite',
    },
    logoText: {
        display: 'block', fontSize: '18px', fontWeight: 800, color: '#fff',
        letterSpacing: '-0.5px', lineHeight: 1, fontFamily: 'Outfit, Inter, sans-serif'
    },
    logoVersion: {
        display: 'block', fontSize: '10px', color: 'rgba(0,240,255,0.6)',
        fontFamily: 'JetBrains Mono', letterSpacing: '0.5px', marginTop: '2px'
    },
    statusPill: {
        display: 'flex', alignItems: 'center', gap: '8px',
        background: 'rgba(16,185,129,0.06)', border: '1px solid rgba(16,185,129,0.12)',
        borderRadius: '10px', padding: '10px 14px', marginBottom: '24px',
    },
    statusDotWrap: { position: 'relative', width: '8px', height: '8px', flexShrink: 0, overflow: 'visible' },
    statusDot: {
        position: 'absolute', inset: 0, borderRadius: '50%',
        background: '#10b981', zIndex: 1,
    },
    statusDotPing: {
        position: 'absolute', inset: '-2px', borderRadius: '50%',
        background: '#10b981', opacity: 0.4,
        animation: 'pulse-ring 2s ease-out infinite',
    },
    statusText: {
        fontSize: '11px', fontWeight: 500, color: 'rgba(16,185,129,0.85)',
        letterSpacing: '0.2px'
    },
    nav: { display: 'flex', flexDirection: 'column', gap: '2px' },
    navSection: {
        color: 'rgba(255,255,255,0.15)', fontSize: '10px', fontWeight: 700,
        letterSpacing: '1.5px', padding: '0 12px', marginBottom: '8px', marginTop: '4px'
    },
    link: {
        display: 'flex', alignItems: 'center', gap: '12px',
        padding: '10px 12px', borderRadius: '12px',
        color: 'rgba(255,255,255,0.4)', textDecoration: 'none',
        fontSize: '14px', fontWeight: 500, letterSpacing: '0.1px',
        transition: 'all 0.2s cubic-bezier(0.16,1,0.3,1)',
        position: 'relative', overflow: 'hidden',
    },
    activeLink: {
        background: 'linear-gradient(135deg, rgba(0,240,255,0.08), rgba(139,92,246,0.08))',
        color: '#a5b4fc',
        border: '1px solid rgba(0,240,255,0.12)',
        boxShadow: '0 2px 16px rgba(0,240,255,0.06), 0 0 12px rgba(139,92,246,0.05)',
    },
    hoveredLink: {
        background: 'rgba(0,240,255,0.04)',
        color: 'rgba(255,255,255,0.6)',
    },
    activeIndicator: {
        position: 'absolute', right: '8px', top: '50%', transform: 'translateY(-50%)',
        width: '4px', height: '16px', borderRadius: '2px',
        background: 'linear-gradient(180deg, #00f0ff, #8b5cf6)',
        boxShadow: '0 0 10px rgba(0,240,255,0.5), 0 0 20px rgba(0,240,255,0.2)',
    },
    iconWrap: {
        width: '34px', height: '34px', borderRadius: '10px',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'rgba(255,255,255,0.03)', flexShrink: 0,
        transition: 'all 0.2s ease',
    },
    activeIconWrap: {
        width: '34px', height: '34px', borderRadius: '10px',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'rgba(0,240,255,0.12)', flexShrink: 0,
    },
    scoreWidget: {
        background: 'rgba(10,10,30,0.5)', border: '1px solid rgba(0,240,255,0.06)',
        borderRadius: '14px', padding: '16px 18px', marginBottom: '16px',
        backdropFilter: 'blur(12px)',
    },
    scoreTop: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' },
    scoreLabel: { fontSize: '11px', color: 'rgba(255,255,255,0.35)', fontWeight: 500 },
    scoreValue: { fontSize: '11px', color: '#10b981', fontWeight: 700, letterSpacing: '0.3px' },
    scoreBar: {
        height: '4px', background: 'rgba(255,255,255,0.05)', borderRadius: '2px',
        overflow: 'hidden', marginBottom: '10px', position: 'relative',
    },
    scoreBarFill: {
        height: '100%', width: '72%',
        background: 'linear-gradient(90deg, #00f0ff, #8b5cf6, #10b981)',
        borderRadius: '2px',
        boxShadow: '0 0 10px rgba(0,240,255,0.3), 0 0 20px rgba(0,240,255,0.1)',
        position: 'relative', overflow: 'hidden',
    },
    scoreHint: { fontSize: '10px', color: 'rgba(255,255,255,0.2)', margin: 0, lineHeight: 1.4 },
    bottomWrap: {
        borderTop: '1px solid rgba(255,255,255,0.04)',
        paddingTop: '16px', display: 'flex', flexDirection: 'column', gap: '10px'
    },
    userRow: { display: 'flex', alignItems: 'center', gap: '10px', padding: '4px 8px' },
    avatar: {
        width: '38px', height: '38px', borderRadius: '12px', flexShrink: 0,
        background: 'linear-gradient(135deg, #00f0ff, #8b5cf6)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontWeight: 800, fontSize: '13px', color: '#fff',
        boxShadow: '0 4px 16px rgba(0,240,255,0.25), 0 0 20px rgba(139,92,246,0.15)',
    },
    userInfo: { minWidth: 0 },
    userName: {
        color: '#fff', fontSize: '13px', fontWeight: 600,
        whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis'
    },
    userEmail: {
        color: 'rgba(255,255,255,0.25)', fontSize: '11px',
        fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap',
        overflow: 'hidden', textOverflow: 'ellipsis', marginTop: '1px'
    },
    logout: {
        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
        background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.15)',
        borderRadius: '10px', padding: '9px', color: 'rgba(239,68,68,0.7)',
        fontSize: '13px', fontWeight: 600, cursor: 'pointer', width: '100%',
        transition: 'all 0.2s ease',
    }
};