import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, AlertTriangle, CheckCircle, BarChart3, Zap, Code2 } from 'lucide-react';

const Dashboard = ({ scans, analytics }) => {
  const stats = [
    {
      title: 'Total Scans',
      value: analytics?.user_stats.total_scans || 0,
      icon: Shield,
      color: 'blue',
      description: 'Security scans performed'
    },
    {
      title: 'Issues Found',
      value: analytics?.user_stats.total_issues_found || 0,
      icon: AlertTriangle,
      color: 'red',
      description: 'Potential vulnerabilities detected'
    },
    {
      title: 'False Positive Rate',
      value: `${((analytics?.false_positive_stats.false_positive_rate || 0) * 100).toFixed(1)}%`,
      icon: CheckCircle,
      color: 'green',
      description: 'Accuracy improvement'
    },
    {
      title: 'Avg. Scan Time',
      value: '1.2s',
      icon: Zap,
      color: 'yellow',
      description: 'Fast security analysis'
    }
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">SASTify Security Dashboard</h1>
        <p className="text-gray-400">AI-powered static application security testing</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {stats.map((stat, index) => {
          const Icon = stat.icon;
          return (
            <div key={index} className="bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-700 hover:border-blue-500 transition-all duration-300 hover:transform hover:scale-105">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <p className="text-gray-400 text-sm font-medium">{stat.title}</p>
                  <p className="text-2xl font-bold text-white mt-1">{stat.value}</p>
                </div>
                <div className={`p-3 rounded-lg bg-${stat.color}-500 bg-opacity-10`}>
                  <Icon className={`h-6 w-6 text-${stat.color}-400`} />
                </div>
              </div>
              <p className="text-gray-500 text-sm">{stat.description}</p>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Recent Scans */}
        <div className="bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-700">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold text-white">Recent Scans</h2>
            <Link to="/analytics" className="text-blue-400 hover:text-blue-300 text-sm font-medium flex items-center">
              <BarChart3 className="h-4 w-4 mr-1" />
              View All
            </Link>
          </div>
          
          <div className="space-y-4">
            {scans.slice(0, 5).map((scan) => (
              <div key={scan.scan_id} className="bg-gray-700 rounded-lg p-4 hover:bg-gray-650 transition-colors border border-gray-600 hover:border-blue-400">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <div className={`p-2 rounded-lg ${
                      scan.language === 'python' ? 'bg-blue-500 bg-opacity-10' : 'bg-yellow-500 bg-opacity-10'
                    }`}>
                      <Code2 className={`h-4 w-4 ${
                        scan.language === 'python' ? 'text-blue-400' : 'text-yellow-400'
                      }`} />
                    </div>
                    <div>
                      <p className="text-white font-medium">{scan.language.toUpperCase()} Scan</p>
                      <p className="text-gray-400 text-sm">
                        {new Date(scan.timestamp).toLocaleDateString()} • {scan.scan_time}
                      </p>
                    </div>
                  </div>
                  <Link 
                    to={`/scan/${scan.scan_id}`}
                    className="bg-blue-500 hover:bg-blue-600 text-white px-3 py-1 rounded-lg text-sm font-medium transition-colors"
                  >
                    View
                  </Link>
                </div>
                
                <div className="flex items-center space-x-4 text-sm">
                  <div className="flex items-center space-x-1">
                    <AlertTriangle className="h-4 w-4 text-red-400" />
                    <span className="text-white">{scan.total_issues_found} issues</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <CheckCircle className="h-4 w-4 text-green-400" />
                    <span className="text-gray-400">{scan.issues_after_fp_filter} after filter</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Vulnerability Overview */}
        <div className="bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-700">
          <h2 className="text-xl font-semibold text-white mb-6">Vulnerability Overview</h2>
          
          <div className="space-y-4">
            {analytics?.most_common_vulnerabilities.slice(0, 6).map((vuln, index) => (
              <div key={vuln.type} className="flex items-center justify-between p-3 bg-gray-700 rounded-lg hover:bg-gray-650 transition-colors">
                <div className="flex items-center space-x-3">
                  <div className="w-3 h-3 rounded-full bg-orange-500"></div>
                  <span className="text-white font-medium capitalize">
                    {vuln.type.replace(/_/g, ' ')}
                  </span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-gray-400 text-sm">{vuln.count} occurrences</span>
                  <div className="w-20 bg-gray-600 rounded-full h-2">
                    <div 
                      className="bg-blue-500 h-2 rounded-full transition-all duration-500" 
                      style={{ width: `${(vuln.count / analytics.most_common_vulnerabilities[0].count) * 100}%` }}
                    ></div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* False Positive Stats */}
          <div className="mt-6 pt-6 border-t border-gray-700">
            <h3 className="text-lg font-semibold text-white mb-4">False Positive Analysis</h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="text-center p-4 bg-green-500 bg-opacity-10 rounded-lg border border-green-500 border-opacity-20">
                <p className="text-2xl font-bold text-green-400">
                  {((1 - analytics?.false_positive_stats.false_positive_rate) * 100).toFixed(1)}%
                </p>
                <p className="text-gray-400 text-sm">Accuracy Rate</p>
              </div>
              <div className="text-center p-4 bg-blue-500 bg-opacity-10 rounded-lg border border-blue-500 border-opacity-20">
                <p className="text-2xl font-bold text-blue-400">
                  {analytics?.false_positive_stats.false_positives || 0}
                </p>
                <p className="text-gray-400 text-sm">False Positives</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="mt-8 bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-700">
        <h2 className="text-xl font-semibold text-white mb-4">Quick Actions</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button className="bg-blue-500 hover:bg-blue-600 text-white p-4 rounded-lg transition-colors flex items-center justify-center space-x-2 transform hover:scale-105 duration-200">
            <Code2 className="h-5 w-5" />
            <span>New Security Scan</span>
          </button>
          <button className="bg-green-500 hover:bg-green-600 text-white p-4 rounded-lg transition-colors flex items-center justify-center space-x-2 transform hover:scale-105 duration-200">
            <BarChart3 className="h-5 w-5" />
            <span>View Analytics</span>
          </button>
          <button className="bg-purple-500 hover:bg-purple-600 text-white p-4 rounded-lg transition-colors flex items-center justify-center space-x-2 transform hover:scale-105 duration-200">
            <Shield className="h-5 w-5" />
            <span>Security Report</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;