import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import { AuthProvider } from './context/AuthContext.jsx';

class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null };
    }
    static getDerivedStateFromError(error) {
        return { hasError: true, error };
    }
    componentDidCatch(error, errorInfo) {
        console.error('SASTify Dashboard Error:', error, errorInfo);
    }
    render() {
        if (this.state.hasError) {
            return (
                <div style={{
                    minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
                    background: '#050609', color: '#fff', fontFamily: 'Inter, system-ui, sans-serif',
                    flexDirection: 'column', gap: '16px', padding: '40px'
                }}>
                    <div style={{ fontSize: '48px' }}>⚠️</div>
                    <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 700 }}>Something went wrong</h2>
                    <p style={{ color: 'rgba(255,255,255,0.4)', margin: 0, fontSize: '14px', maxWidth: '400px', textAlign: 'center', lineHeight: 1.6 }}>
                        {this.state.error?.message || 'An unexpected error occurred. Please try reloading the page.'}
                    </p>
                    <button onClick={() => window.location.reload()} style={{
                        background: 'linear-gradient(135deg, #6366f1, #8b5cf6)', border: 'none',
                        borderRadius: '10px', padding: '10px 24px', color: '#fff', fontSize: '14px',
                        fontWeight: 600, cursor: 'pointer', marginTop: '8px',
                        boxShadow: '0 4px 20px rgba(99,102,241,0.3)'
                    }}>
                        Reload Page
                    </button>
                </div>
            );
        }
        return this.props.children;
    }
}

ReactDOM.createRoot(document.getElementById('root')).render(
    <React.StrictMode>
        <ErrorBoundary>
            <AuthProvider>
                <App />
            </AuthProvider>
        </ErrorBoundary>
    </React.StrictMode>
);