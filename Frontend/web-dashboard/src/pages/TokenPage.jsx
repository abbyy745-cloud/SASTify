import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext.jsx';

/* ── Keyframe Animations ────────────────────────── */
const tokenKeyframes = `
@keyframes tokenScanLine {
  0%   { top: -2px; }
  100% { top: 100%; }
}
@keyframes tokenCopyGlow {
  0%, 100% { box-shadow: 0 4px 14px rgba(0,240,255,0.2); }
  50%      { box-shadow: 0 4px 24px rgba(0,240,255,0.4), 0 0 40px rgba(0,240,255,0.1); }
}
@keyframes tokenStepGlow {
  0%, 100% { box-shadow: 0 0 10px rgba(0,240,255,0.15); }
  50%      { box-shadow: 0 0 20px rgba(0,240,255,0.3); }
}
`;

export default function TokenPage() {
    const { user, token } = useAuth();
    const [copied, setCopied] = useState(false);
    const [visible, setVisible] = useState(false);
    const [copyHovered, setCopyHovered] = useState(false);

    const copy = () => {
        if (!token) return;
        navigator.clipboard.writeText(token);
        setCopied(true);
        setTimeout(() => setCopied(false), 2500);
    };

    const masked = token ? `${token.slice(0, 12)}${'•'.repeat(24)}${token.slice(-8)}` : '';

    return (
        <div style={s.page} className="animate-fade-in">
            <style>{tokenKeyframes}</style>
            <div style={s.header}>
                <h1 style={s.h1}>API Token</h1>
                <p style={s.sub}>Use this token to authenticate SASTify in VS Code and CI/CD pipelines</p>
            </div>

            <div style={s.grid}>
                {/* Token Card — glassmorphism */}
                <div style={s.tokenCard}>
                    <div style={s.tokenCardTop}>
                        <div style={s.tokenIconWrap}>
                            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
                            </svg>
                        </div>
                        <div>
                            <h3 style={s.cardTitle}>Your API Token</h3>
                            <p style={s.cardSub}>Keep this secret — it grants full API access</p>
                        </div>
                    </div>

                    {/* Token display with neon border and scan-line */}
                    <div style={s.tokenBox}>
                        {/* Scan line effect */}
                        <div style={s.tokenScanLine} />
                        <code style={s.tokenText}>{visible ? token : masked}</code>
                        <button style={s.eyeBtn} onClick={() => setVisible(!visible)} title={visible ? 'Hide' : 'Show'}
                            onMouseEnter={e => { e.currentTarget.style.color = '#00f0ff'; }}
                            onMouseLeave={e => { e.currentTarget.style.color = 'rgba(255,255,255,0.3)'; }}
                        >
                            {visible ? (
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                                    <line x1="1" y1="1" x2="23" y2="23"/>
                                </svg>
                            ) : (
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
                                </svg>
                            )}
                        </button>
                    </div>

                    <div style={s.actionRow}>
                        <button className="btn-primary" style={{
                            ...s.copyBtn,
                            ...(copyHovered ? {
                                animation: 'tokenCopyGlow 1.5s ease-in-out infinite',
                            } : {}),
                        }} onClick={copy}
                            onMouseEnter={() => setCopyHovered(true)}
                            onMouseLeave={() => setCopyHovered(false)}
                        >
                            {copied ? (
                                <>
                                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                                        <path d="M9 12l2 2 4-4m6 2a9 9 0 1 1-18 0 9 9 0 0 1 18 0z"/>
                                    </svg>
                                    Copied!
                                </>
                            ) : (
                                <>
                                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                                    </svg>
                                    Copy Token
                                </>
                            )}
                        </button>
                    </div>

                    <div style={s.warningBox}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                        <span style={s.warningText}>Never share or commit this token to version control</span>
                    </div>
                </div>

                {/* Account Info */}
                <div style={s.infoCard}>
                    <h3 style={s.cardTitle}>Account Details</h3>
                    <div style={s.infoList}>
                        <div style={s.infoRow}
                            onMouseEnter={e => {
                                e.currentTarget.style.background = 'rgba(0,240,255,0.02)';
                                e.currentTarget.style.paddingLeft = '12px';
                            }}
                            onMouseLeave={e => {
                                e.currentTarget.style.background = 'transparent';
                                e.currentTarget.style.paddingLeft = '0px';
                            }}
                        >
                            <span style={s.infoLabel}>Name</span>
                            <span style={s.infoVal}>{user?.name || '—'}</span>
                        </div>
                        <div style={s.divider} />
                        <div style={s.infoRow}
                            onMouseEnter={e => {
                                e.currentTarget.style.background = 'rgba(0,240,255,0.02)';
                                e.currentTarget.style.paddingLeft = '12px';
                            }}
                            onMouseLeave={e => {
                                e.currentTarget.style.background = 'transparent';
                                e.currentTarget.style.paddingLeft = '0px';
                            }}
                        >
                            <span style={s.infoLabel}>Email</span>
                            <span style={s.infoVal}>{user?.email || '—'}</span>
                        </div>
                        <div style={s.divider} />
                        <div style={s.infoRow}
                            onMouseEnter={e => {
                                e.currentTarget.style.background = 'rgba(0,240,255,0.02)';
                                e.currentTarget.style.paddingLeft = '12px';
                            }}
                            onMouseLeave={e => {
                                e.currentTarget.style.background = 'transparent';
                                e.currentTarget.style.paddingLeft = '0px';
                            }}
                        >
                            <span style={s.infoLabel}>User ID</span>
                            <span style={{ ...s.infoVal, fontFamily: 'JetBrains Mono', fontSize: '11px', color: 'rgba(255,255,255,0.3)' }}>{user?.user_id || '—'}</span>
                        </div>
                    </div>
                </div>

                {/* Setup Guide */}
                <div style={s.guideCard}>
                    <h3 style={s.cardTitle}>Quick Setup</h3>
                    <div style={s.steps}>
                        {[
                            { step: '1', title: 'Install Extension', desc: 'Search "SASTify" in the VS Code Marketplace and install it' },
                            { step: '2', title: 'Enter Token', desc: 'Press Ctrl+Shift+P → SASTify: Enter Token → paste your token' },
                            { step: '3', title: 'Start Scanning', desc: 'Open any file and run SASTify: Scan File or Scan Project' },
                        ].map(item => (
                            <div key={item.step} style={s.stepRow}>
                                <div style={s.stepNum}>{item.step}</div>
                                <div>
                                    <div style={s.stepTitle}>{item.title}</div>
                                    <div style={s.stepDesc}>{item.desc}</div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}

const s = {
    page: { padding: '32px 36px', display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '900px' },
    header: { marginBottom: '4px' },
    h1: { color: '#fff', fontSize: '28px', fontWeight: 800, margin: '0 0 6px', letterSpacing: '-0.5px' },
    sub: { color: 'rgba(255,255,255,0.35)', fontSize: '14px', margin: 0 },
    grid: { display: 'flex', flexDirection: 'column', gap: '16px' },
    tokenCard: {
        background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(0,240,255,0.15)',
        borderRadius: '16px', padding: '24px',
        backdropFilter: 'blur(20px)',
        boxShadow: '0 0 40px rgba(0,240,255,0.06), 0 8px 32px rgba(0,0,0,0.3)',
    },
    tokenCardTop: { display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '20px' },
    tokenIconWrap: {
        width: '48px', height: '48px', borderRadius: '12px', flexShrink: 0,
        background: 'rgba(0,240,255,0.08)', border: '1px solid rgba(0,240,255,0.2)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        boxShadow: '0 0 15px rgba(0,240,255,0.1)',
    },
    cardTitle: { color: '#fff', fontSize: '16px', fontWeight: 700, margin: '0 0 3px' },
    cardSub: { color: 'rgba(255,255,255,0.35)', fontSize: '12px', margin: 0 },
    tokenBox: {
        background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(0,240,255,0.2)',
        borderRadius: '10px', padding: '14px 16px', display: 'flex',
        justifyContent: 'space-between', alignItems: 'center', gap: '12px',
        marginBottom: '14px',
        position: 'relative', overflow: 'hidden',
        boxShadow: '0 0 15px rgba(0,240,255,0.04)',
    },
    tokenScanLine: {
        position: 'absolute', left: 0, right: 0, height: '1px',
        background: 'linear-gradient(90deg, transparent, rgba(0,240,255,0.35), transparent)',
        animation: 'tokenScanLine 4s linear infinite',
        pointerEvents: 'none',
    },
    tokenText: {
        color: '#00f0ff', fontFamily: 'JetBrains Mono', fontSize: '13px',
        wordBreak: 'break-all', flex: 1, position: 'relative', zIndex: 1,
    },
    eyeBtn: {
        background: 'transparent', border: 'none', cursor: 'pointer',
        color: 'rgba(255,255,255,0.3)', padding: '4px', flexShrink: 0,
        display: 'flex', alignItems: 'center', transition: 'color 0.2s',
        position: 'relative', zIndex: 1,
    },
    actionRow: { display: 'flex', gap: '10px', marginBottom: '14px' },
    copyBtn: {
        display: 'flex', alignItems: 'center', gap: '8px',
        background: 'linear-gradient(135deg, #00c8d6, #8b5cf6)', border: 'none',
        borderRadius: '9px', padding: '10px 20px', color: '#fff',
        fontSize: '14px', fontWeight: 600, cursor: 'pointer',
        boxShadow: '0 4px 14px rgba(0,240,255,0.2)',
        transition: 'all 0.25s ease',
    },
    warningBox: {
        display: 'flex', alignItems: 'center', gap: '8px',
        background: 'rgba(251,191,36,0.06)', border: '1px solid rgba(251,191,36,0.15)',
        borderRadius: '8px', padding: '10px 14px'
    },
    warningText: { color: 'rgba(251,191,36,0.8)', fontSize: '12px' },
    infoCard: {
        background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: '16px', padding: '22px',
        backdropFilter: 'blur(10px)',
    },
    infoList: { marginTop: '16px' },
    infoRow: {
        display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0',
        transition: 'all 0.25s ease', borderRadius: '8px',
    },
    infoLabel: { color: 'rgba(255,255,255,0.35)', fontSize: '13px', fontWeight: 500 },
    infoVal: { color: '#fff', fontSize: '14px', fontWeight: 600 },
    divider: { height: '1px', background: 'rgba(255,255,255,0.05)' },
    guideCard: {
        background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: '16px', padding: '22px',
        backdropFilter: 'blur(10px)',
    },
    steps: { marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '16px' },
    stepRow: { display: 'flex', gap: '14px', alignItems: 'flex-start' },
    stepNum: {
        width: '28px', height: '28px', borderRadius: '8px', flexShrink: 0,
        background: 'linear-gradient(135deg, #00c8d6, #8b5cf6)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: '#fff', fontSize: '13px', fontWeight: 800,
        boxShadow: '0 0 12px rgba(0,240,255,0.2)',
    },
    stepTitle: { color: '#fff', fontSize: '14px', fontWeight: 600, marginBottom: '3px' },
    stepDesc: { color: 'rgba(255,255,255,0.4)', fontSize: '13px', lineHeight: 1.5 }
};