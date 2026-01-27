import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import ScanDetails from './components/ScanDetails';
import Analytics from './components/Analytics';
import Header from './components/Header';
import './styles/App.css';
import { fetchAnalytics, fetchScanResults } from './services/api';

function App() {
  const [scans, setScans] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchInitialData();
  }, []);

  const fetchInitialData = async () => {
    try {
      // Fetch real analytics data
      const analyticsData = await fetchAnalytics('test_user_001'); // Using a test user for now
      setAnalytics(analyticsData);

      // Fetch recent scans from history
      if (analyticsData.user_stats && analyticsData.user_stats.scan_history) {
        const scanPromises = analyticsData.user_stats.scan_history.slice(-10).reverse().map(scanId =>
          fetchScanResults(scanId).catch(e => null)
        );
        const scansData = (await Promise.all(scanPromises)).filter(s => s !== null);
        setScans(scansData);
      }
    } catch (error) {
      console.error('Failed to fetch data:', error);
      // Fallback to mock data if API fails (for demo purposes)
      setAnalytics({
        user_stats: { total_scans: 0, total_issues_found: 0, false_positive_history: {} },
        false_positive_stats: { total_feedback: 0, false_positives: 0, false_positive_rate: 0, common_fp_types: [] },
        total_scans_in_system: 0,
        most_common_vulnerabilities: []
      });
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-800 flex items-center justify-center">
        <div className="text-white text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p>Loading SASTify Dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <Router>
      <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-800">
        <Header />
        <Routes>
          <Route path="/" element={<Dashboard scans={scans} analytics={analytics} />} />
          <Route path="/scan/:scanId" element={<ScanDetails />} />
          <Route path="/analytics" element={<Analytics analytics={analytics} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;