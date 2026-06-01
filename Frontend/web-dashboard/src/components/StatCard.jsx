import React, { useState, useEffect, useRef, useCallback } from 'react';

function useCountUp(target, duration = 1200) {
    const [value, setValue] = useState(0);
    const frameRef = useRef(null);

    useEffect(() => {
        if (!target || target === 0) { setValue(0); return; }
        const start = performance.now();
        const animate = (now) => {
            const elapsed = now - start;
            const progress = Math.min(elapsed / duration, 1);
            const ease = 1 - Math.pow(1 - progress, 3); // cubic ease-out
            setValue(Math.round(ease * target));
            if (progress < 1) frameRef.current = requestAnimationFrame(animate);
        };
        frameRef.current = requestAnimationFrame(animate);
        return () => cancelAnimationFrame(frameRef.current);
    }, [target, duration]);

    return value;
}

export default function StatCard({ label, value, sub, color = '#6366f1', icon, trend, trendLabel }) {
    const animated = useCountUp(typeof value === 'number' ? value : 0);
    const displayValue = typeof value === 'number' ? animated : (value ?? '—');
    const isPositiveTrend = trend > 0;
    const [isHovered, setIsHovered] = useState(false);
    const cardRef = useRef(null);

    const handleMouseMove = useCallback((e) => {
        if (!cardRef.current) return;
        const rect = cardRef.current.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const centerX = rect.width / 2;
        const centerY = rect.height / 2;
        const rotateX = ((y - centerY) / centerY) * -8;
        const rotateY = ((x - centerX) / centerX) * 8;
        cardRef.current.style.transform = `perspective(800px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
    }, []);

    const handleMouseLeave = useCallback(() => {
        setIsHovered(false);
        if (cardRef.current) cardRef.current.style.transform = 'perspective(800px) rotateX(0deg) rotateY(0deg)';
    }, []);

    return (
        <div
            ref={cardRef}
            className="stat-card"
            style={{
                ...styles.card,
                ...(isHovered ? {
                    borderColor: `${color}30`,
                    boxShadow: `0 0 30px rgba(0,240,255,0.12), 0 16px 48px ${color}18, 0 0 0 1px ${color}15`,
                } : {})
            }}
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={handleMouseLeave}
            onMouseMove={handleMouseMove}
        >
            {/* Animated gradient top border (cyan → purple → cyan) */}
            <div style={{
                position: 'absolute', top: 0, left: 0, right: 0,
                height: isHovered ? '3px' : '2px',
                background: isHovered
                    ? 'linear-gradient(90deg, #00f0ff, #8b5cf6, #6366f1, #00f0ff)'
                    : `linear-gradient(90deg, ${color}40, ${color}08)`,
                backgroundSize: '200% 100%',
                animation: isHovered ? 'gradient-shift 2s linear infinite' : 'none',
                transition: 'height 0.3s ease',
            }} />

            {/* Scan-line effect on hover */}
            {isHovered && (
                <div style={{
                    position: 'absolute', top: 0, left: 0, right: 0,
                    height: '40px',
                    background: 'linear-gradient(180deg, rgba(0,240,255,0.06), transparent)',
                    animation: 'scan-line 2s ease-in-out infinite',
                    pointerEvents: 'none',
                    zIndex: 1,
                }} />
            )}

            {/* Shimmer overlay on hover */}
            {isHovered && (
                <div style={{
                    position: 'absolute', inset: 0,
                    background: 'linear-gradient(105deg, transparent 40%, rgba(0,240,255,0.04) 45%, rgba(0,240,255,0.06) 50%, rgba(0,240,255,0.04) 55%, transparent 60%)',
                    backgroundSize: '200% 100%',
                    animation: 'shimmer 2s ease-in-out infinite',
                    pointerEvents: 'none',
                    borderRadius: '18px',
                    zIndex: 1,
                }} />
            )}

            {/* Subtle background glow — larger and more vibrant on hover */}
            <div style={{
                position: 'absolute', bottom: '-30px', right: '-30px',
                width: isHovered ? '180px' : '120px',
                height: isHovered ? '180px' : '120px',
                borderRadius: '50%',
                background: `radial-gradient(circle, ${color}${isHovered ? '15' : '08'} 0%, transparent 70%)`,
                pointerEvents: 'none',
                transition: 'all 0.4s ease',
                opacity: isHovered ? 1 : 0,
            }} />

            <div style={styles.top}>
                <div style={{
                    ...styles.iconBox,
                    background: `${color}0a`,
                    border: `1px solid ${color}18`,
                    ...(isHovered ? {
                        boxShadow: `0 4px 16px ${color}20, 0 0 12px ${color}10`,
                        background: `${color}12`,
                    } : {})
                }}>
                    {icon}
                </div>
                {trend !== undefined && (
                    <div style={{
                        display: 'flex', alignItems: 'center', gap: '4px',
                        color: isPositiveTrend ? '#f87171' : '#34d399',
                        fontSize: '11px', fontWeight: 700,
                        background: isPositiveTrend ? 'rgba(239,68,68,0.08)' : 'rgba(16,185,129,0.08)',
                        border: `1px solid ${isPositiveTrend ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)'}`,
                        borderRadius: '8px', padding: '3px 8px'
                    }}>
                        {isPositiveTrend ? '↑' : '↓'} {Math.abs(trend)}%
                    </div>
                )}
            </div>

            <div style={{
                ...styles.value,
                color,
                textShadow: `0 0 8px ${color}40, 0 0 20px ${color}15`,
            }}>
                {displayValue}
            </div>
            <div style={styles.label}>{label}</div>
            {sub && <div style={styles.sub}>{sub}</div>}
            {trendLabel && (
                <div style={styles.trendLabel}>{trendLabel}</div>
            )}
        </div>
    );
}

const styles = {
    card: {
        background: 'rgba(10,10,30,0.5)',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: '18px', padding: '22px 22px 20px',
        display: 'flex', flexDirection: 'column', gap: '6px',
        position: 'relative', overflow: 'hidden',
        cursor: 'default',
        transition: 'all 0.3s cubic-bezier(0.16,1,0.3,1), transform 0.15s ease-out',
        willChange: 'transform',
        transformStyle: 'preserve-3d',
    },
    top: {
        display: 'flex', justifyContent: 'space-between',
        alignItems: 'flex-start', marginBottom: '14px',
        position: 'relative', zIndex: 2,
    },
    iconBox: {
        width: '42px', height: '42px', borderRadius: '12px',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        transition: 'all 0.3s ease',
    },
    value: {
        fontSize: '36px', fontWeight: 800, lineHeight: 1,
        letterSpacing: '-1.5px', fontFamily: 'Outfit, Inter, sans-serif',
        position: 'relative', zIndex: 2,
    },
    label: {
        color: 'rgba(255,255,255,0.4)', fontSize: '13px',
        fontWeight: 500, letterSpacing: '0.2px', marginTop: '2px',
        position: 'relative', zIndex: 2,
    },
    sub: {
        color: 'rgba(255,255,255,0.2)', fontSize: '11px',
        fontFamily: 'JetBrains Mono', marginTop: '2px',
        position: 'relative', zIndex: 2,
    },
    trendLabel: {
        color: 'rgba(255,255,255,0.18)', fontSize: '10px', marginTop: '4px',
        fontFamily: 'JetBrains Mono',
        position: 'relative', zIndex: 2,
    }
};