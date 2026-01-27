import React from 'react';
import { useParams } from 'react-router-dom';
import { ArrowLeft, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';

const ScanDetails = () => {
  const { scanId } = useParams();
  
  // Mock data for demonstration
  const scanData = {
    scan_id: scanId,
    timestamp: new Date().toISOString(),
    language: 'python',
    total_issues_found: 8,
    issues_after_fp_filter: 5,
    scan_time: '1.2s',
    issues: [
      {
        type: 'hardcoded_secret',
        line: 3,
        snippet: 'password = "super_secret_123"',
        confidence: 0.9,
        severity: 'High',
        scanner: 'pattern_matching',
        description: 'Hardcoded password found in source code'
      },
      {
        type: 'sql_injection',
        line: 15,
        snippet: 'query = f"SELECT * FROM users WHERE id = {user_input}"',
        confidence: 0.8,
        severity: 'High',
        scanner: 'ast_analysis',
        description: 'Potential SQL injection with f-string formatting'
      }
    ]
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-500',
      high: 'bg-orange-500',
      medium: 'bg-yellow-500',
      low: 'bg-green-500'
    };
    return colors[severity.toLowerCase()] || 'bg-gray-500';
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center space-x-4">
          <button className="text-gray-400 hover:text-white transition-colors">
            <ArrowLeft className="h-5 w-5" />
          </button>
          <div>
            <h1 className="text-3xl font-bold text-white">Scan Details</h1>
            <p className="text-gray-400">Scan ID: {scanId}</p>
          </div>
        </div>
        <div className="text-right">
          <p className="text-gray-400">Scan Time</p>
          <p className="text-white font-semibold">{scanData.scan_time}</p>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="bg-gray-800 rounded-xl p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Issues</p>
              <p className="text-2xl font-bold text-white">{scanData.total_issues_found}</p>
            </div>
            <AlertTriangle className="h-8 w-8 text-red-400" />
          </div>
        </div>
        
        <div className="bg-gray-800 rounded-xl p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">After FP Filter</p>
              <p className="text-2xl font-bold text-white">{scanData.issues_after_fp_filter}</p>
            </div>
            <CheckCircle className="h-8 w-8 text-green-400" />
          </div>
        </div>
        
        <div className="bg-gray-800 rounded-xl p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Language</p>
              <p className="text-2xl font-bold text-white capitalize">{scanData.language}</p>
            </div>
            <div className="text-2xl">🐍</div>
          </div>
        </div>
        
        <div className="bg-gray-800 rounded-xl p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Filtered Out</p>
              <p className="text-2xl font-bold text-white">
                {scanData.total_issues_found - scanData.issues_after_fp_filter}
              </p>
            </div>
            <XCircle className="h-8 w-8 text-orange-400" />
          </div>
        </div>
      </div>

      {/* Issues List */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <h2 className="text-xl font-semibold text-white mb-6">Security Issues Found</h2>
        
        <div className="space-y-4">
          {scanData.issues.map((issue, index) => (
            <div key={index} className="bg-gray-700 rounded-lg p-6 border-l-4 border-orange-500">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <div className={`w-3 h-3 rounded-full ${getSeverityColor(issue.severity)}`}></div>
                  <h3 className="text-lg font-semibold text-white capitalize">
                    {issue.type.replace(/_/g, ' ')}
                  </h3>
                </div>
                <div className="flex items-center space-x-2">
                  <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                    issue.severity === 'High' ? 'bg-red-500 text-white' :
                    issue.severity === 'Medium' ? 'bg-orange-500 text-white' :
                    'bg-yellow-500 text-black'
                  }`}>
                    {issue.severity}
                  </span>
                  <span className="text-gray-400 text-sm">
                    Confidence: {(issue.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
              
              <div className="mb-4">
                <p className="text-gray-300 mb-2">{issue.description}</p>
                <div className="bg-gray-900 rounded-lg p-4 font-mono text-sm">
                  <div className="text-gray-400">Line {issue.line}:</div>
                  <div className="text-white mt-1">{issue.snippet}</div>
                </div>
              </div>
              
              <div className="flex items-center justify-between">
                <div className="text-gray-400 text-sm">
                  Detected by: {issue.scanner}
                </div>
                <div className="flex space-x-2">
                  <button className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
                    Analyze with AI
                  </button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
                    Mark as False Positive
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
        
        {scanData.issues.length === 0 && (
          <div className="text-center py-12">
            <CheckCircle className="h-16 w-16 text-green-400 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-white mb-2">No Security Issues Found</h3>
            <p className="text-gray-400">Great job! Your code appears to be secure.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanDetails;