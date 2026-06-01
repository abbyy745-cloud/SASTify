import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

const API = import.meta.env.VITE_API_URL || (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' ? 'http://127.0.0.1:8000' : window.location.origin);

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(() => localStorage.getItem('sastify_token'));
    const [loading, setLoading] = useState(true);

    const logout = useCallback(() => {
        localStorage.removeItem('sastify_token');
        localStorage.removeItem('sastify_user');
        setToken(null);
        setUser(null);
    }, []);

    // ── Restore session on mount / page reload ──────────────────────────────
    // 1. Try to hydrate from localStorage first (instant, no network needed)
    // 2. Then validate against the backend in the background
    useEffect(() => {
        const savedToken = localStorage.getItem('sastify_token');
        const savedUser  = localStorage.getItem('sastify_user');

        if (!savedToken) {
            // No token at all — go straight to login
            setLoading(false);
            return;
        }

        // Hydrate user from cache immediately so the dashboard shows instantly
        if (savedUser) {
            try {
                const parsed = JSON.parse(savedUser);
                setUser(parsed);
                setToken(savedToken);
            } catch {
                // Corrupt cache — clear it
                localStorage.removeItem('sastify_user');
            }
        }

        // Validate token against backend (non-blocking)
        fetch(`${API}/api/auth/me`, {
            headers: { Authorization: `Bearer ${savedToken}` }
        })
            .then(res => {
                if (!res.ok) throw new Error('Token invalid');
                return res.json();
            })
            .then(data => {
                const freshUser = {
                    user_id: data.user_id,
                    email: data.email,
                    name: data.name || data.email?.split('@')[0] || 'Developer'
                };
                setUser(freshUser);
                setToken(savedToken);
                // Update cache with fresh data
                localStorage.setItem('sastify_user', JSON.stringify(freshUser));
            })
            .catch(() => {
                // Only log out if we had NO cached user — if we do have a cached
                // user, keep them signed in even if backend is unreachable. This
                // prevents logouts on network blips.
                if (!savedUser) {
                    logout();
                }
            })
            .finally(() => {
                setLoading(false);
            });
    }, []);  // eslint-disable-line react-hooks/exhaustive-deps

    // ✅ LOGIN
    const login = async (email, password) => {
        const res = await fetch(`${API}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await res.json();

        if (!res.ok) {
            throw new Error(data.detail || 'Login failed');
        }

        const userData = {
            user_id: data.user_id,
            email: data.email,
            name: data.name || email.split('@')[0]
        };

        // Persist to localStorage so reloads don't lose the session
        localStorage.setItem('sastify_token', data.token);
        localStorage.setItem('sastify_user', JSON.stringify(userData));
        setToken(data.token);
        setUser(userData);

        return data;
    };

    // ✅ REGISTER
    const register = async (email, password, name) => {
        const res = await fetch(`${API}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, name })
        });

        const data = await res.json();

        if (!res.ok) {
            throw new Error(data.detail || 'Registration failed');
        }

        const userData = {
            user_id: data.user_id,
            email: data.email,
            name: data.name || name || email.split('@')[0]
        };

        localStorage.setItem('sastify_token', data.token);
        localStorage.setItem('sastify_user', JSON.stringify(userData));
        setToken(data.token);
        setUser(userData);

        return data;
    };

    return (
        <AuthContext.Provider value={{
            user,
            token,
            loading,
            login,
            register,
            logout
        }}>
            {children}
        </AuthContext.Provider>
    );
}

export const useAuth = () => useContext(AuthContext);
export { API };