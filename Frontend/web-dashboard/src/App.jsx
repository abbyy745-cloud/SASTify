import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './context/AuthContext.jsx';

import AuthPage from './pages/AuthPage.jsx';
import DashboardPage from './pages/DashboardPage.jsx';
import ScansPage from './pages/ScansPage.jsx';
import Sidebar from './components/Sidebar.jsx';
import TokenPage from './pages/TokenPage.jsx';
import AnalyticsPage from './pages/AnalyticsPage.jsx';

const globalStyles = `
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&family=Outfit:wght@400;500;600;700;800;900&display=swap');

  @keyframes pulse-ring {
    0% { transform: scale(0.8); opacity: 0.8; }
    100% { transform: scale(1.6); opacity: 0; }
  }
  @keyframes spin {
    to { transform: rotate(360deg); }
  }
  @keyframes fade-in {
    from { opacity: 0; transform: translateY(16px); }
    to { opacity: 1; transform: translateY(0); }
  }
  @keyframes slide-in-left {
    from { opacity: 0; transform: translateX(-24px); }
    to { opacity: 1; transform: translateX(0); }
  }
  @keyframes gradient-shift {
    0%, 100% { background-position: 0% 50%; }
    50% { background-position: 100% 50%; }
  }
  @keyframes shimmer {
    0% { background-position: -200% 0; }
    100% { background-position: 200% 0; }
  }
  @keyframes count-up {
    from { opacity: 0; transform: translateY(8px); }
    to { opacity: 1; transform: translateY(0); }
  }
  @keyframes float {
    0%, 100% { transform: translateY(0px); }
    50% { transform: translateY(-6px); }
  }
  @keyframes glow-pulse {
    0%, 100% { box-shadow: 0 0 20px rgba(99,102,241,0.1); }
    50% { box-shadow: 0 0 40px rgba(99,102,241,0.25); }
  }
  @keyframes border-glow {
    0%, 100% { border-color: rgba(99,102,241,0.15); }
    50% { border-color: rgba(99,102,241,0.35); }
  }
  @keyframes scale-in {
    from { opacity: 0; transform: scale(0.95); }
    to { opacity: 1; transform: scale(1); }
  }
  @keyframes slide-up {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
  }

  /* === NEW 3D CYBERSECURITY KEYFRAMES === */

  @keyframes particle-float {
    0% { transform: translateY(0px) translateX(0px); opacity: 0; }
    10% { opacity: 1; }
    90% { opacity: 1; }
    100% { transform: translateY(-100vh) translateX(20px); opacity: 0; }
  }

  @keyframes neon-pulse {
    0%, 100% {
      box-shadow: 0 0 5px rgba(0,240,255,0.2), 0 0 20px rgba(0,240,255,0.1), 0 0 40px rgba(0,240,255,0.05);
    }
    50% {
      box-shadow: 0 0 10px rgba(0,240,255,0.4), 0 0 40px rgba(0,240,255,0.2), 0 0 80px rgba(0,240,255,0.1);
    }
  }

  @keyframes border-rotate {
    0% { --border-angle: 0deg; }
    100% { --border-angle: 360deg; }
  }

  @keyframes mesh-shift {
    0%, 100% {
      background-position: 0% 0%, 100% 100%, 50% 50%;
    }
    25% {
      background-position: 100% 0%, 0% 100%, 50% 0%;
    }
    50% {
      background-position: 100% 100%, 0% 0%, 0% 50%;
    }
    75% {
      background-position: 0% 100%, 100% 0%, 100% 50%;
    }
  }

  @keyframes tilt-reset {
    to { transform: perspective(800px) rotateX(0deg) rotateY(0deg); }
  }

  @keyframes scan-line {
    0% { transform: translateY(-100%); opacity: 0; }
    50% { opacity: 1; }
    100% { transform: translateY(400%); opacity: 0; }
  }

  @keyframes text-glow {
    0%, 100% { text-shadow: 0 0 4px currentColor, 0 0 11px rgba(0,240,255,0.15); }
    50% { text-shadow: 0 0 8px currentColor, 0 0 20px rgba(0,240,255,0.3), 0 0 40px rgba(0,240,255,0.1); }
  }

  @keyframes radar-sweep {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  @keyframes shimmer-bar {
    0% { transform: translateX(-100%); }
    100% { transform: translateX(200%); }
  }

  .animate-fade-in { animation: fade-in 0.5s cubic-bezier(0.16,1,0.3,1) forwards; }
  .animate-slide-left { animation: slide-in-left 0.4s cubic-bezier(0.16,1,0.3,1) forwards; }
  .animate-scale-in { animation: scale-in 0.4s cubic-bezier(0.16,1,0.3,1) forwards; }
  .animate-slide-up { animation: slide-up 0.5s cubic-bezier(0.16,1,0.3,1) forwards; }

  .nav-link-hover { transition: all 0.2s cubic-bezier(0.16,1,0.3,1) !important; }
  .nav-link-hover:hover { background: rgba(99,102,241,0.1) !important; color: #a5b4fc !important; }

  .scan-row { transition: all 0.25s cubic-bezier(0.16,1,0.3,1) !important; }
  .scan-row:hover {
    background: rgba(99,102,241,0.06) !important;
    border-color: rgba(99,102,241,0.25) !important;
    transform: translateX(4px);
    box-shadow: 0 4px 24px rgba(99,102,241,0.08) !important;
  }

  .stat-card { transition: all 0.3s cubic-bezier(0.16,1,0.3,1) !important; }
  .stat-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 0 30px rgba(0,240,255,0.15), 0 20px 60px rgba(99,102,241,0.2) !important;
    border-color: rgba(0,240,255,0.2) !important;
  }

  .btn-primary { transition: all 0.2s cubic-bezier(0.16,1,0.3,1) !important; }
  .btn-primary:hover { opacity: 0.9; transform: translateY(-1px); box-shadow: 0 8px 24px rgba(99,102,241,0.3) !important; }
  .btn-primary:active { transform: translateY(0); }

  .glass-card {
    background: rgba(10,10,30,0.6) !important;
    backdrop-filter: blur(24px) saturate(1.2) !important;
    -webkit-backdrop-filter: blur(24px) saturate(1.2) !important;
    border: 1px solid rgba(255,255,255,0.06) !important;
  }

  .neon-border {
    position: relative;
    border: none !important;
  }
  .neon-border::before {
    content: '';
    position: absolute;
    inset: -1px;
    border-radius: inherit;
    padding: 1px;
    background: conic-gradient(from var(--border-angle, 0deg), #00f0ff, #8b5cf6, #6366f1, #00f0ff);
    -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
    -webkit-mask-composite: xor;
    mask-composite: exclude;
    animation: border-rotate 4s linear infinite;
    pointer-events: none;
  }

  .vuln-card { transition: all 0.25s cubic-bezier(0.16,1,0.3,1) !important; }
  .vuln-card:hover { border-color: rgba(255,255,255,0.12) !important; box-shadow: 0 8px 32px rgba(0,0,0,0.3) !important; }
  .vuln-card:hover .vuln-header { background: rgba(255,255,255,0.03) !important; }

  input:focus, select:focus {
    border-color: rgba(0,240,255,0.4) !important;
    box-shadow: 0 0 0 3px rgba(0,240,255,0.08), 0 0 20px rgba(0,240,255,0.06) !important;
    outline: none !important;
  }

  .chart-tooltip { backdrop-filter: blur(16px); }
  .recharts-tooltip-wrapper { z-index: 9999 !important; }

  /* Staggered animations for child elements */
  .stagger-children > * { opacity: 0; animation: slide-up 0.4s cubic-bezier(0.16,1,0.3,1) forwards; }
  .stagger-children > *:nth-child(1) { animation-delay: 0.05s; }
  .stagger-children > *:nth-child(2) { animation-delay: 0.1s; }
  .stagger-children > *:nth-child(3) { animation-delay: 0.15s; }
  .stagger-children > *:nth-child(4) { animation-delay: 0.2s; }
  .stagger-children > *:nth-child(5) { animation-delay: 0.25s; }
  .stagger-children > *:nth-child(6) { animation-delay: 0.3s; }
`;

// Generate particle data once (stable across renders)
const particles = Array.from({ length: 30 }, (_, i) => ({
    id: i,
    left: `${Math.random() * 100}%`,
    top: `${Math.random() * 100}%`,
    size: 2 + Math.random() * 2,
    delay: Math.random() * 8,
    duration: 8 + Math.random() * 12,
    color: i % 3 === 0 ? 'rgba(139,92,246,0.10)' : 'rgba(0,240,255,0.15)',
}));

function ParticleBackground() {
    return (
        <div style={{
            position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0, overflow: 'hidden',
        }}>
            {particles.map(p => (
                <div key={p.id} style={{
                    position: 'absolute',
                    left: p.left,
                    top: p.top,
                    width: `${p.size}px`,
                    height: `${p.size}px`,
                    borderRadius: '50%',
                    background: p.color,
                    boxShadow: `0 0 ${p.size * 2}px ${p.color}`,
                    animation: `particle-float ${p.duration}s ease-in-out ${p.delay}s infinite`,
                    willChange: 'transform, opacity',
                }} />
            ))}
        </div>
    );
}

function LoadingScreen() {
    return (
        <div style={{
            minHeight: '100vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'radial-gradient(ellipse at 50% 20%, rgba(0,240,255,0.06) 0%, rgba(139,92,246,0.04) 30%, #050609 70%)',
            flexDirection: 'column',
            gap: '36px',
            position: 'relative',
            overflow: 'hidden',
        }}>
            {/* Subtle particles behind loader */}
            <ParticleBackground />

            {/* Mesh gradient overlay */}
            <div style={{
                position: 'absolute', inset: 0, pointerEvents: 'none',
                background: 'radial-gradient(circle at 30% 40%, rgba(0,240,255,0.03) 0%, transparent 50%), radial-gradient(circle at 70% 60%, rgba(139,92,246,0.03) 0%, transparent 50%)',
                animation: 'mesh-shift 10s ease-in-out infinite',
            }} />

            {/* Large spinner with neon glow */}
            <div style={{ position: 'relative', width: '96px', height: '96px', zIndex: 1 }}>
                {/* Outer neon ring */}
                <div style={{
                    position: 'absolute', inset: '-8px',
                    border: '1px solid rgba(0,240,255,0.1)',
                    borderRadius: '50%',
                    animation: 'neon-pulse 2s ease-in-out infinite',
                }} />
                <div style={{
                    position: 'absolute', inset: 0, border: '2px solid rgba(0,240,255,0.15)',
                    borderRadius: '50%', animation: 'pulse-ring 2s ease-out infinite'
                }} />
                <div style={{
                    position: 'absolute', inset: '6px', border: '2px solid transparent',
                    borderTopColor: '#00f0ff', borderRightColor: '#8b5cf6', borderRadius: '50%',
                    animation: 'spin 0.8s linear infinite',
                    filter: 'drop-shadow(0 0 6px rgba(0,240,255,0.4))',
                }} />
                <div style={{
                    position: 'absolute', inset: '12px', border: '1.5px solid transparent',
                    borderBottomColor: '#8b5cf6', borderLeftColor: '#00f0ff', borderRadius: '50%',
                    animation: 'spin 1.4s linear infinite reverse',
                    filter: 'drop-shadow(0 0 4px rgba(139,92,246,0.3))',
                }} />
                <div style={{
                    position: 'absolute', inset: '22px',
                    background: 'linear-gradient(135deg, #00f0ff, #8b5cf6)',
                    borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                    boxShadow: '0 0 30px rgba(0,240,255,0.4), 0 0 60px rgba(139,92,246,0.2)',
                }}>
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
                        <path d="M12 2L4 6v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V6L12 2z" fill="white" fillOpacity="0.9"/>
                    </svg>
                </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px', zIndex: 1 }}>
                <p style={{
                    color: 'rgba(0,240,255,0.6)', fontFamily: 'Outfit', fontSize: '16px',
                    margin: 0, fontWeight: 600, letterSpacing: '1px',
                    textShadow: '0 0 10px rgba(0,240,255,0.2)',
                }}>
                    Loading SASTify
                </p>
                <div style={{
                    width: '160px', height: '2px', borderRadius: '1px',
                    background: 'rgba(0,240,255,0.1)', overflow: 'hidden'
                }}>
                    <div style={{
                        width: '40%', height: '100%',
                        background: 'linear-gradient(90deg, transparent, #00f0ff, #8b5cf6, transparent)',
                        animation: 'shimmer 1.5s ease-in-out infinite',
                        backgroundSize: '200% 100%'
                    }} />
                </div>
            </div>
        </div>
    );
}

function App() {
    const { user, loading } = useAuth();

    if (loading) return <LoadingScreen />;

    return (
        <>
            <style>{globalStyles}</style>
            <Router>
                {!user ? (
                    <Routes>
                        <Route path="*" element={<AuthPage />} />
                    </Routes>
                ) : (
                    <div style={{
                        display: 'flex',
                        background: 'radial-gradient(ellipse at 20% 0%, rgba(0,240,255,0.03) 0%, rgba(139,92,246,0.02) 25%, #050609 55%)',
                        minHeight: '100vh',
                        position: 'relative',
                    }}>
                        <ParticleBackground />
                        <Sidebar />
                        <div style={{ flex: 1, minWidth: 0, position: 'relative', zIndex: 1 }}>
                            <Routes>
                                <Route path="/" element={<Navigate to="/dashboard" />} />
                                <Route path="/dashboard" element={<DashboardPage />} />
                                <Route path="/scans" element={<ScansPage />} />
                                <Route path="/scans/:scanId" element={<ScansPage />} />
                                <Route path="/analytics" element={<AnalyticsPage />} />
                                <Route path="/token" element={<TokenPage />} />
                                <Route path="*" element={<Navigate to="/dashboard" />} />
                            </Routes>
                        </div>
                    </div>
                )}
            </Router>
        </>
    );
}

export default App;