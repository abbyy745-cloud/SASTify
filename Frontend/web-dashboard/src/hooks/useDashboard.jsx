import { useState, useEffect, useCallback } from 'react';
import { useAuth, API } from '../context/AuthContext.jsx';

export function useDashboard() {
    const { user, token } = useAuth();

    const [data, setData] = useState(null);
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const fetchAll = useCallback(async () => {
        if (!token || !user) {
            setLoading(false);
            return;
        }

        try {
            setLoading(true);
            setError(null);

            const headers = {
                Authorization: `Bearer ${token}`
            };

            // Fetch analytics and scans in parallel
            const [analyticsRes, scansRes] = await Promise.all([
                fetch(`${API}/api/analytics`, { headers }),
                fetch(`${API}/api/users/${user.user_id}/scans?limit=50`, { headers })
            ]);

            if (!analyticsRes.ok) {
                throw new Error("Failed to fetch analytics");
            }

            const dash = await analyticsRes.json();
            setData(dash);

            // Use real scan data with full metadata if available
            if (scansRes.ok) {
                const scansData = await scansRes.json();
                setScans(scansData.scans || []);
            } else {
                // Fallback: use scan IDs from analytics
                const scanHistory = dash.user_stats?.scan_history || [];
                setScans(
                    scanHistory.map((id) => ({
                        scan_id: id,
                        filename: "Scan Result",
                        language: "-",
                        total_vulnerabilities: 0,
                        critical_count: 0,
                        high_count: 0,
                        medium_count: 0,
                        created_at: new Date().toISOString()
                    }))
                );
            }

        } catch (err) {
            console.error("Dashboard error:", err);
            setError(err.message || 'Failed to load dashboard data');
            setData(null);
            setScans([]);
        } finally {
            setLoading(false);
        }
    }, [token, user]);

    useEffect(() => {
        fetchAll();
    }, [fetchAll]);

    return { data, scans, loading, error, refetch: fetchAll };
}