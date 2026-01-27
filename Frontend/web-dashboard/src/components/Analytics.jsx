import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { AlertTriangle, CheckCircle, XCircle, TrendingUp } from 'lucide-react';

const Analytics = ({ analytics }) => {
  const vulnerabilityData = analytics?.most_common_vulnerabilities || [];
  const falsePositiveData = analytics?.false_positive_stats.common_fp_types || [];

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8', '#82CA9D'];

  const scanTrendData = [
    { name: 'Jan', issues: 45, scans: 12 },
    { name: 'Feb', issues: 52, scans: 15 },
    { name: 'Mar', issues: 38, scans: 18 },
    { name: 'Apr', issues: 61, scans: 22 },
    { name: 'May', issues: 55, scans: 19 },
    { name: 'Jun', issues: 48, scans: 21 }
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Security Analytics</h1>
        <p className="text-gray-400">Comprehensive security insights and trends</p>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Issues</p>
              <p className="text-2xl font-bold text-white mt-1">{analytics?.user_stats.total_issues_found || 0}</p>
            </div>
            <AlertTriangle className="h-8 w-8 text-red-400" />
          </div>
          <div className="mt-2 flex items-center text-sm">
            <TrendingUp className="h-4 w-4 text-green-400 mr-1" />
            <span className="text-green-400">+12% this month</span>
          </div>
        </div>

        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">False Positive Rate</p>
              <p className="text-2xl font-bold text-white mt-1">
                {((analytics?.false_positive_stats.false_positive_rate || 0) * 100).toFixed(1)}%
              </p>
            </div>
            <XCircle className="h-8 w-8 text-orange-400" />
          </div>
          <div className="mt-2 flex items-center text-sm">
            <TrendingUp className="h-4 w-4 text-green-400 mr-1" />
            <span className="text-green-400">-5% improvement</span>
          </div>
        </div>

        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Accuracy Rate</p>
              <p className="text-2xl font-bold text-white mt-1">
                {((1 - (analytics?.false_positive_stats.false_positive_rate || 0)) * 100).toFixed(1)}%
              </p>
            </div>
            <CheckCircle className="h-8 w-8 text-green-400" />
          </div>
          <div className="mt-2 text-sm text-gray-400">Detection precision</div>
        </div>

        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Avg. Issues/Scan</p>
              <p className="text-2xl font-bold text-white mt-1">
                {analytics?.user_stats.total_scans ? 
                  Math.round(analytics.user_stats.total_issues_found / analytics.user_stats.total_scans) : 0
                }
              </p>
            </div>
            <TrendingUp className="h-8 w-8 text-blue-400" />
          </div>
          <div className="mt-2 text-sm text-gray-400">Per scan average</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        {/* Vulnerability Distribution */}
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <h3 className="text-xl font-semibold text-white mb-4">Vulnerability Distribution</h3>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={vulnerabilityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis 
                  dataKey="type" 
                  angle={-45}
                  textAnchor="end"
                  height={80}
                  tick={{ fill: '#9CA3AF', fontSize: 12 }}
                  tickFormatter={(value) => value.replace(/_/g, ' ').substring(0, 12)}
                />
                <YAxis tick={{ fill: '#9CA3AF' }} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1F2937', borderColor: '#374151', color: 'white' }}
                  formatter={(value) => [value, 'Count']}
                  labelFormatter={(label) => `Type: ${label.replace(/_/g, ' ')}`}
                />
                <Bar dataKey="count" fill="#3B82F6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* False Positive Breakdown */}
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <h3 className="text-xl font-semibold text-white mb-4">False Positive Analysis</h3>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={falsePositiveData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ type, percent }) => `${type.replace(/_/g, ' ').substring(0, 12)} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="count"
                >
                  {falsePositiveData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1F2937', borderColor: '#374151', color: 'white' }}
                  formatter={(value) => [value, 'Count']}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Scan Trends */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <h3 className="text-xl font-semibold text-white mb-4">Scan Trends & Performance</h3>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={scanTrendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="name" tick={{ fill: '#9CA3AF' }} />
              <YAxis tick={{ fill: '#9CA3AF' }} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#1F2937', borderColor: '#374151', color: 'white' }}
              />
              <Legend />
              <Bar dataKey="issues" name="Security Issues" fill="#EF4444" radius={[4, 4, 0, 0]} />
              <Bar dataKey="scans" name="Scans" fill="#3B82F6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recommendations */}
      <div className="mt-8 bg-gray-800 rounded-xl p-6 border border-gray-700">
        <h3 className="text-xl font-semibold text-white mb-4">Security Recommendations</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-blue-500 bg-opacity-10 border border-blue-500 rounded-lg p-4">
            <h4 className="text-blue-400 font-semibold mb-2">Improve Secret Detection</h4>
            <p className="text-gray-300 text-sm">
              {falsePositiveData.find(fp => fp.type === 'hardcoded_secret')?.count || 0} hardcoded secrets 
              were marked as false positives. Consider updating detection patterns.
            </p>
          </div>
          <div className="bg-green-500 bg-opacity-10 border border-green-500 rounded-lg p-4">
            <h4 className="text-green-400 font-semibold mb-2">SQL Injection Training</h4>
            <p className="text-gray-300 text-sm">
              SQL injection detection shows high accuracy. Continue current training patterns 
              for optimal results.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Analytics;