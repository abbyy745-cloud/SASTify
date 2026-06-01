import React from 'react';

const SEV_CONFIG = {
    Critical: {
        bg: 'rgba(239,68,68,0.1)', text: '#f87171',
        border: 'rgba(239,68,68,0.18)', dot: '#ef4444',
        glow: 'rgba(239,68,68,0.35)'
    },
    High: {
        bg: 'rgba(249,115,22,0.1)', text: '#fb923c',
        border: 'rgba(249,115,22,0.18)', dot: '#f97316',
        glow: 'rgba(249,115,22,0.35)'
    },
    Medium: {
        bg: 'rgba(234,179,8,0.08)', text: '#fbbf24',
        border: 'rgba(234,179,8,0.18)', dot: '#eab308',
        glow: 'rgba(234,179,8,0.35)'
    },
    Low: {
        bg: 'rgba(16,185,129,0.08)', text: '#34d399',
        border: 'rgba(16,185,129,0.15)', dot: '#10b981',
        glow: 'rgba(16,185,129,0.35)'
    },
};

export default function SeverityBadge({ severity, size = 'sm' }) {
    const c = SEV_CONFIG[severity] || SEV_CONFIG.Low;
    const isLg = size === 'lg';

    return (
        <span style={{
            display: 'inline-flex', alignItems: 'center', gap: isLg ? '7px' : '5px',
            background: c.bg, color: c.text,
            border: `1px solid ${c.border}`,
            borderRadius: isLg ? '10px' : '7px',
            padding: isLg ? '5px 14px' : '3px 10px',
            fontSize: isLg ? '12px' : '10px',
            fontWeight: 700, fontFamily: 'JetBrains Mono',
            letterSpacing: '0.4px', whiteSpace: 'nowrap',
            transition: 'all 0.2s ease',
        }}>
            <span style={{
                width: isLg ? '7px' : '5px', height: isLg ? '7px' : '5px',
                borderRadius: '50%', background: c.dot, flexShrink: 0,
                boxShadow: `0 0 8px ${c.glow}`
            }} />
            {severity}
        </span>
    );
}