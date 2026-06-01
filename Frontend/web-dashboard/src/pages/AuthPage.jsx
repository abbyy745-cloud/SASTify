import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext.jsx';
import { useNavigate } from 'react-router-dom';

/* ── Keyframe Animations ────────────────────────── */
const authKeyframes = `
@keyframes authParticleFloat {
  0%, 100% { transform: translateY(0px) translateX(0px); opacity: 0.3; }
  25%      { transform: translateY(-20px) translateX(8px); opacity: 0.7; }
  50%      { transform: translateY(-35px) translateX(-5px); opacity: 0.4; }
  75%      { transform: translateY(-15px) translateX(12px); opacity: 0.6; }
}
@keyframes authNeonBorderRotate {
  0%   { background-position: 0% 50%; }
  100% { background-position: 300% 50%; }
}
@keyframes authPulseSubmit {
  0%, 100% { box-shadow: 0 8px 24px rgba(0,240,255,0.2), 0 0 40px rgba(0,240,255,0.06), inset 0 1px 0 rgba(255,255,255,0.1); }
  50%      { box-shadow: 0 8px 36px rgba(0,240,255,0.35), 0 0 60px rgba(0,240,255,0.12), inset 0 1px 0 rgba(255,255,255,0.15); }
}
@keyframes authShieldRotate {
  0%, 100% { transform: perspective(600px) rotateY(0deg); }
  50%      { transform: perspective(600px) rotateY(12deg); }
}
@keyframes authTypewriter {
  from { width: 0; }
  to   { width: 100%; }
}
@keyframes authBlinkCaret {
  0%, 100% { border-color: #00f0ff; }
  50%      { border-color: transparent; }
}
@keyframes authScanlineToken {
  0%   { top: -2px; }
  100% { top: 100%; }
}
`;

const particles = Array.from({ length: 60 }, (_, i) => ({
    id: i,
    x: Math.random() * 100,
    y: Math.random() * 100,
    size: Math.random() * 2.5 + 0.5,
    delay: Math.random() * 8,
    duration: Math.random() * 12 + 6,
}));

export default function AuthPage() {
    const { login, register } = useAuth();
    const navigate = useNavigate();
    const [mode, setMode] = useState('login');
    const [form, setForm] = useState({ email: '', password: '', name: '' });
    const [err, setErr] = useState('');
    const [loading, setLoading] = useState(false);
    const [newToken, setNewToken] = useState('');
    const [copied, setCopied] = useState(false);
    const [pwVisible, setPwVisible] = useState(false);
    const [focusedField, setFocusedField] = useState(null);

    const handleChange = e => setForm(f => ({ ...f, [e.target.name]: e.target.value }));

    const handleSubmit = async e => {
        e.preventDefault();
        setErr('');
        setLoading(true);
        try {
            if (mode === 'login') {
                await login(form.email, form.password);
                navigate('/dashboard');
            } else {
                const data = await register(form.email, form.password, form.name);
                setNewToken(data.token);
            }
        } catch (e) {
            setErr(e.message);
        } finally {
            setLoading(false);
        }
    };

    const copy = () => {
        navigator.clipboard.writeText(newToken);
        setCopied(true);
        setTimeout(() => setCopied(false), 2500);
    };

    if (newToken) return (
        <div style={s.page}>
            <style>{authKeyframes}</style>
            <BgDecorations />
            <div style={{
                ...s.card,
                animation: 'scale-in 0.4s cubic-bezier(0.16,1,0.3,1) forwards',
                backdropFilter: 'blur(30px)',
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid rgba(0,240,255,0.15)',
                boxShadow: '0 32px 80px rgba(0,0,0,0.6), 0 0 40px rgba(0,240,255,0.08)',
            }}>
                <div style={s.successIcon}>
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M9 12l2 2 4-4m6 2a9 9 0 1 1-18 0 9 9 0 0 1 18 0z"/>
                    </svg>
                </div>
                <h2 style={s.successTitle}>Account Created!</h2>
                <p style={s.successSub}>
                    Copy your SASTify API token below. <strong style={{ color: '#fbbf24' }}>This is shown only once.</strong>
                </p>
                <div style={{
                    ...s.tokenBox,
                    position: 'relative', overflow: 'hidden',
                    border: '1px solid rgba(0,240,255,0.2)',
                    boxShadow: '0 0 20px rgba(0,240,255,0.06)',
                }}>
                    {/* Scan line effect on token */}
                    <div style={{
                        position: 'absolute', left: 0, right: 0, height: '1px',
                        background: 'linear-gradient(90deg, transparent, rgba(0,240,255,0.4), transparent)',
                        animation: 'authScanlineToken 3s linear infinite',
                        pointerEvents: 'none',
                    }} />
                    <code style={s.tokenCode}>{newToken}</code>
                </div>
                <button style={s.copyBtn} onClick={copy}
                    onMouseEnter={e => {
                        e.currentTarget.style.background = 'rgba(0,240,255,0.15)';
                        e.currentTarget.style.borderColor = 'rgba(0,240,255,0.4)';
                        e.currentTarget.style.boxShadow = '0 0 20px rgba(0,240,255,0.1)';
                    }}
                    onMouseLeave={e => {
                        e.currentTarget.style.background = 'rgba(0,240,255,0.08)';
                        e.currentTarget.style.borderColor = 'rgba(0,240,255,0.2)';
                        e.currentTarget.style.boxShadow = 'none';
                    }}
                >
                    {copied ? (
                        <><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M9 12l2 2 4-4"/></svg> Copied!</>
                    ) : (
                        <><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy Token</>
                    )}
                </button>
                <div style={s.instructionBox}>
                    <p style={s.instructionText}>
                        In VS Code: press <kbd style={s.kbd}>Ctrl+Shift+P</kbd> then <em>SASTify: Enter Token</em>
                    </p>
                </div>
                <button className="btn-primary" style={s.goBtn} onClick={() => navigate('/dashboard')}>
                    Go to Dashboard
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="9,18 15,12 9,6"/>
                    </svg>
                </button>
            </div>
        </div>
    );

    return (
        <div style={s.page}>
            <style>{authKeyframes}</style>
            <BgDecorations />
            <div style={s.leftPanel} className="animate-fade-in">
                <div style={s.brandWrap}>
                    {/* 3D rotating shield */}
                    <div style={{
                        ...s.brandMark,
                        animation: 'authShieldRotate 6s ease-in-out infinite',
                        boxShadow: '0 4px 20px rgba(0,240,255,0.2)',
                        border: '1px solid rgba(0,240,255,0.25)',
                    }}>
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
                            <path d="M12 2L4 6v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V6L12 2z" fill="url(#auth-shield)"/>
                            <defs>
                                <linearGradient id="auth-shield" x1="0%" y1="0%" x2="100%" y2="100%">
                                    <stop offset="0%" stopColor="#00f0ff"/><stop offset="100%" stopColor="#8b5cf6"/>
                                </linearGradient>
                            </defs>
                        </svg>
                    </div>
                    <span style={s.brandName}>SASTify</span>
                    <span style={s.brandBeta}>v2.0</span>
                </div>
                <h1 style={s.heroTitle}>
                    Secure your code<br />
                    {/* Typewriter effect on gradient text */}
                    <span style={{
                        ...s.heroGradient,
                        display: 'inline-block',
                        overflow: 'hidden',
                        whiteSpace: 'nowrap',
                        animation: 'authTypewriter 2.5s steps(16, end) forwards',
                        borderRight: '2px solid #00f0ff',
                    }}>before it ships</span>
                </h1>
                <p style={s.heroSub}>
                    AI-powered static analysis that catches vulnerabilities in Python, JavaScript, Java, Swift, Kotlin, Dart and more — right inside VS Code.
                </p>
                <div style={s.featureList}>
                    {[
                        { icon: (<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>), text: '197+ security rules', color: '#00f0ff' },
                        { icon: (<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z"/><path d="M12 6v6l4 2"/></svg>), text: 'AI-powered analysis', color: '#a78bfa' },
                        { icon: (<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#6ee7b7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>), text: 'Multi-language support', color: '#6ee7b7' },
                        { icon: (<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>), text: 'Real-time dashboard', color: '#fbbf24' },
                    ].map((f, i) => (
                        <div key={i} style={s.featureItem}>
                            <span style={{ ...s.featureIconWrap, background: `${f.color}10`, border: `1px solid ${f.color}20` }}>{f.icon}</span>
                            <span style={s.featureText}>{f.text}</span>
                        </div>
                    ))}
                </div>
            </div>

            {/* Login card with animated neon border wrapper */}
            <div style={s.cardNeonBorderWrap}>
                <div style={s.cardNeonBorderBg} />
                <div style={{
                    ...s.card,
                    backdropFilter: 'blur(30px)',
                    background: 'rgba(5,6,9,0.85)',
                    border: 'none',
                    margin: '1px',
                    borderRadius: '23px',
                }} className="animate-scale-in">
                    {/* Tabs */}
                    <div style={s.tabs}>
                        {[['login', 'Sign In'], ['register', 'Create Account']].map(([m, label]) => (
                            <button key={m} style={{ ...s.tab, ...(mode === m ? s.activeTab : {}) }}
                                onClick={() => { setMode(m); setErr(''); }}>
                                {label}
                            </button>
                        ))}
                    </div>

                    <h2 style={s.formTitle}>
                        {mode === 'login' ? 'Welcome back' : 'Get started free'}
                    </h2>
                    <p style={s.formSub}>
                        {mode === 'login' ? 'Sign in to your security dashboard' : 'Create your account to start scanning'}
                    </p>

                    <form onSubmit={handleSubmit} style={s.form}>
                        {mode === 'register' && (
                            <div style={s.field}>
                                <label style={s.label}>Full Name</label>
                                <input style={{
                                    ...s.input,
                                    ...(focusedField === 'name' ? s.inputFocused : {})
                                }} name="name" placeholder="Your full name"
                                    value={form.name} onChange={handleChange}
                                    onFocus={() => setFocusedField('name')}
                                    onBlur={() => setFocusedField(null)}
                                    required />
                            </div>
                        )}
                        <div style={s.field}>
                            <label style={s.label}>Email Address</label>
                            <input style={{
                                ...s.input,
                                ...(focusedField === 'email' ? s.inputFocused : {})
                            }} name="email" type="email"
                                placeholder="you@example.com" value={form.email}
                                onChange={handleChange}
                                onFocus={() => setFocusedField('email')}
                                onBlur={() => setFocusedField(null)}
                                required />
                        </div>
                        <div style={s.field}>
                            <label style={s.label}>Password</label>
                            <div style={s.pwWrap}>
                                <input style={{
                                    ...s.input, paddingRight: '44px',
                                    ...(focusedField === 'password' ? s.inputFocused : {})
                                }} name="password"
                                    type={pwVisible ? 'text' : 'password'}
                                    placeholder="••••••••" value={form.password}
                                    onChange={handleChange}
                                    onFocus={() => setFocusedField('password')}
                                    onBlur={() => setFocusedField(null)}
                                    required />
                                <button type="button" style={s.pwToggle} onClick={() => setPwVisible(!pwVisible)}>
                                    {pwVisible ? (
                                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.3)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
                                            <line x1="1" y1="1" x2="23" y2="23"/>
                                        </svg>
                                    ) : (
                                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.3)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
                                        </svg>
                                    )}
                                </button>
                            </div>
                        </div>

                        {err && (
                            <div style={s.errBox}>
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f87171" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                                </svg>
                                {err}
                            </div>
                        )}

                        <button className="btn-primary" style={{
                            ...s.submitBtn,
                            ...(loading ? { opacity: 0.6, cursor: 'not-allowed' } : {}),
                            animation: loading ? 'none' : 'authPulseSubmit 3s ease-in-out infinite',
                        }}
                            type="submit" disabled={loading}>
                            {loading ? (
                                <span style={{ display: 'flex', alignItems: 'center', gap: '8px', justifyContent: 'center' }}>
                                    <span style={{ width: '14px', height: '14px', border: '2px solid rgba(255,255,255,0.3)', borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.7s linear infinite', display: 'inline-block' }} />
                                    Please wait…
                                </span>
                            ) : mode === 'login' ? 'Sign In' : 'Create Account & Get Token'}
                        </button>
                    </form>
                </div>
            </div>
        </div>
    );
}

function BgDecorations() {
    return (
        <div style={{ position: 'fixed', inset: 0, pointerEvents: 'none', overflow: 'hidden', zIndex: 0 }}>
            {/* Large ambient orbs */}
            <div style={{
                position: 'absolute', width: '700px', height: '700px', borderRadius: '50%',
                background: 'radial-gradient(circle, rgba(0,240,255,0.07) 0%, transparent 65%)',
                top: '-250px', left: '-150px',
                filter: 'blur(40px)',
            }} />
            <div style={{
                position: 'absolute', width: '500px', height: '500px', borderRadius: '50%',
                background: 'radial-gradient(circle, rgba(139,92,246,0.06) 0%, transparent 65%)',
                bottom: '-150px', right: '-100px',
                filter: 'blur(40px)',
            }} />
            <div style={{
                position: 'absolute', width: '300px', height: '300px', borderRadius: '50%',
                background: 'radial-gradient(circle, rgba(0,240,255,0.04) 0%, transparent 70%)',
                top: '40%', left: '50%', transform: 'translate(-50%, -50%)',
                filter: 'blur(60px)',
            }} />
            {/* Dot grid */}
            <div style={{
                position: 'absolute', inset: 0,
                backgroundImage: 'radial-gradient(circle, rgba(0,240,255,0.03) 1px, transparent 1px)',
                backgroundSize: '48px 48px'
            }} />
            {/* Floating particles */}
            {particles.map(p => (
                <div key={p.id} style={{
                    position: 'absolute',
                    left: `${p.x}%`,
                    top: `${p.y}%`,
                    width: `${p.size}px`,
                    height: `${p.size}px`,
                    borderRadius: '50%',
                    background: p.id % 3 === 0 ? '#00f0ff' : p.id % 3 === 1 ? '#8b5cf6' : '#6ee7b7',
                    opacity: 0.3,
                    animation: `authParticleFloat ${p.duration}s ease-in-out ${p.delay}s infinite`,
                }} />
            ))}
        </div>
    );
}

const s = {
    page: {
        minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'linear-gradient(135deg, #050609 0%, #0a0d1a 40%, #050609 100%)',
        fontFamily: 'Inter, sans-serif', padding: '40px 20px', gap: '70px',
        position: 'relative', flexWrap: 'wrap'
    },
    leftPanel: { maxWidth: '460px', position: 'relative', zIndex: 1 },
    brandWrap: { display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '36px' },
    brandMark: {
        width: '48px', height: '48px', borderRadius: '14px',
        background: 'rgba(0,240,255,0.08)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
    },
    brandName: {
        fontSize: '24px', fontWeight: 800, color: '#fff', letterSpacing: '-0.5px',
        fontFamily: 'Outfit, Inter, sans-serif'
    },
    brandBeta: {
        fontSize: '10px', color: 'rgba(0,240,255,0.7)',
        fontFamily: 'JetBrains Mono', background: 'rgba(0,240,255,0.08)',
        padding: '2px 8px', borderRadius: '6px', letterSpacing: '0.5px',
    },
    heroTitle: {
        fontSize: '44px', fontWeight: 800, color: '#fff', lineHeight: 1.12,
        margin: '0 0 18px', letterSpacing: '-1.5px',
        fontFamily: 'Outfit, Inter, sans-serif'
    },
    heroGradient: {
        background: 'linear-gradient(135deg, #00f0ff, #8b5cf6, #a78bfa)',
        WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent'
    },
    heroSub: { color: 'rgba(255,255,255,0.4)', fontSize: '15px', lineHeight: 1.7, margin: '0 0 36px' },
    featureList: { display: 'flex', flexDirection: 'column', gap: '14px' },
    featureItem: { display: 'flex', alignItems: 'center', gap: '12px' },
    featureIconWrap: {
        width: '32px', height: '32px', borderRadius: '8px',
        display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
    },
    featureText: { color: 'rgba(255,255,255,0.55)', fontSize: '14px', fontWeight: 500 },
    /* Animated neon border wrapper */
    cardNeonBorderWrap: {
        position: 'relative', zIndex: 1, borderRadius: '24px', padding: '1px',
        overflow: 'hidden', width: '100%', maxWidth: '432px',
    },
    cardNeonBorderBg: {
        position: 'absolute', inset: '-2px', borderRadius: '24px',
        background: 'linear-gradient(90deg, #00f0ff, #8b5cf6, #00f0ff, #8b5cf6)',
        backgroundSize: '300% 100%',
        animation: 'authNeonBorderRotate 4s linear infinite',
        opacity: 0.5,
    },
    card: {
        background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: '24px', padding: '40px 36px', width: '100%', maxWidth: '430px',
        backdropFilter: 'blur(24px)', boxShadow: '0 32px 80px rgba(0,0,0,0.5)',
        position: 'relative', zIndex: 1,
    },
    tabs: {
        display: 'flex', background: 'rgba(255,255,255,0.03)',
        borderRadius: '14px', padding: '4px', marginBottom: '28px', gap: '4px'
    },
    tab: {
        flex: 1, padding: '10px', border: 'none', borderRadius: '10px',
        background: 'transparent', color: 'rgba(255,255,255,0.35)',
        fontSize: '13px', fontWeight: 600, cursor: 'pointer', transition: 'all 0.2s'
    },
    activeTab: {
        background: 'linear-gradient(135deg, rgba(0,240,255,0.15), rgba(139,92,246,0.12))',
        color: '#00f0ff', boxShadow: '0 2px 8px rgba(0,240,255,0.1)',
    },
    formTitle: {
        color: '#fff', fontSize: '24px', fontWeight: 800, margin: '0 0 6px',
        letterSpacing: '-0.5px', fontFamily: 'Outfit, Inter, sans-serif'
    },
    formSub: { color: 'rgba(255,255,255,0.3)', fontSize: '13px', margin: '0 0 28px' },
    form: { display: 'flex', flexDirection: 'column', gap: '18px' },
    field: { display: 'flex', flexDirection: 'column', gap: '8px' },
    label: { color: 'rgba(255,255,255,0.45)', fontSize: '12px', fontWeight: 600, letterSpacing: '0.5px', textTransform: 'uppercase' },
    input: {
        background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '12px', padding: '13px 16px', color: '#fff', fontSize: '14px',
        fontFamily: 'Inter', outline: 'none', transition: 'all 0.25s ease', width: '100%',
        boxSizing: 'border-box',
    },
    inputFocused: {
        borderColor: 'rgba(0,240,255,0.5)',
        boxShadow: '0 0 0 3px rgba(0,240,255,0.1), 0 0 25px rgba(0,240,255,0.1)',
        background: 'rgba(0,240,255,0.03)',
    },
    pwWrap: { position: 'relative' },
    pwToggle: {
        position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)',
        background: 'transparent', border: 'none', cursor: 'pointer', padding: '4px',
        display: 'flex', alignItems: 'center',
    },
    errBox: {
        display: 'flex', alignItems: 'center', gap: '8px',
        background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.15)',
        borderRadius: '10px', padding: '12px 16px', color: '#f87171', fontSize: '13px'
    },
    submitBtn: {
        background: 'linear-gradient(135deg, #00c8d6, #8b5cf6)', border: 'none',
        borderRadius: '12px', padding: '14px', color: '#fff', fontSize: '14px',
        fontWeight: 700, cursor: 'pointer', marginTop: '4px',
    },
    successIcon: {
        width: '68px', height: '68px', borderRadius: '50%',
        background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.15)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        margin: '0 auto 20px', boxShadow: '0 0 30px rgba(16,185,129,0.1)',
    },
    successTitle: {
        color: '#fff', fontSize: '24px', fontWeight: 800, textAlign: 'center', margin: '0 0 8px',
        fontFamily: 'Outfit, Inter, sans-serif'
    },
    successSub: { color: 'rgba(255,255,255,0.45)', fontSize: '13px', textAlign: 'center', lineHeight: 1.6, margin: '0 0 20px' },
    tokenBox: {
        background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(0,240,255,0.15)',
        borderRadius: '12px', padding: '16px', marginBottom: '12px', wordBreak: 'break-all'
    },
    tokenCode: { color: '#00f0ff', fontFamily: 'JetBrains Mono', fontSize: '12px' },
    copyBtn: {
        width: '100%', background: 'rgba(0,240,255,0.08)', border: '1px solid rgba(0,240,255,0.2)',
        borderRadius: '10px', padding: '12px', color: '#00f0ff', fontSize: '14px',
        fontWeight: 600, cursor: 'pointer', marginBottom: '16px', transition: 'all 0.25s',
        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
    },
    instructionBox: {
        background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)',
        borderRadius: '10px', padding: '14px 16px', marginBottom: '16px'
    },
    instructionText: { color: 'rgba(255,255,255,0.4)', fontSize: '12px', margin: 0, lineHeight: 1.6 },
    kbd: {
        background: 'rgba(255,255,255,0.08)', borderRadius: '5px', padding: '2px 7px',
        fontFamily: 'JetBrains Mono', fontSize: '11px', color: 'rgba(255,255,255,0.7)',
        border: '1px solid rgba(255,255,255,0.1)',
    },
    goBtn: {
        width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
        background: 'linear-gradient(135deg, #00c8d6, #8b5cf6)', border: 'none',
        borderRadius: '12px', padding: '14px', color: '#fff', fontSize: '14px',
        fontWeight: 700, cursor: 'pointer',
        boxShadow: '0 8px 24px rgba(0,240,255,0.2), inset 0 1px 0 rgba(255,255,255,0.1)',
    }
};