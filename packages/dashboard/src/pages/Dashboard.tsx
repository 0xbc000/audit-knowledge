import { useQuery } from '@tanstack/react-query';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import { Shield, AlertTriangle, CheckCircle, Clock, FileCode, Bug } from 'lucide-react';
import { dashboardApi } from '../api/client';
import { StatsCard } from '../components/StatsCard';
import { SeverityBadge } from '../components/SeverityBadge';

const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#ca8a04',
  LOW: '#16a34a',
  INFO: '#2563eb',
};

export function Dashboard() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard-overview'],
    queryFn: () => dashboardApi.getOverview(),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center text-red-600 p-8">
        Failed to load dashboard data. Please try again.
      </div>
    );
  }

  const stats = data?.data.stats;
  const recentAudits = data?.data.recentAudits || [];
  const charts = data?.data.charts;

  // Prepare chart data
  const severityData = charts?.findingsBySeverity 
    ? Object.entries(charts.findingsBySeverity).map(([name, value]) => ({
        name,
        value,
        color: SEVERITY_COLORS[name as keyof typeof SEVERITY_COLORS] || '#6b7280',
      }))
    : [];

  const categoryData = charts?.findingsByCategory
    ? Object.entries(charts.findingsByCategory).map(([name, value]) => ({
        name: name.replace(/_/g, ' '),
        value,
      }))
    : [];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <div className="text-sm text-gray-500">
          Last updated: {new Date().toLocaleTimeString()}
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard
          title="Total Projects"
          value={stats?.totalProjects || 0}
          icon={<FileCode className="w-6 h-6" />}
          color="blue"
        />
        <StatsCard
          title="Total Audits"
          value={stats?.totalAudits || 0}
          icon={<Shield className="w-6 h-6" />}
          color="purple"
        />
        <StatsCard
          title="Active Audits"
          value={stats?.activeAudits || 0}
          icon={<Clock className="w-6 h-6" />}
          color="yellow"
        />
        <StatsCard
          title="Total Findings"
          value={stats?.totalFindings || 0}
          icon={<Bug className="w-6 h-6" />}
          color="red"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="card">
          <h3 className="card-header">Findings by Severity</h3>
          {severityData.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={2}
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-500">
              No data available
            </div>
          )}
        </div>

        {/* Category Distribution */}
        <div className="card">
          <h3 className="card-header">Findings by Category</h3>
          {categoryData.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categoryData} layout="vertical">
                  <XAxis type="number" />
                  <YAxis type="category" dataKey="name" width={120} tick={{ fontSize: 12 }} />
                  <Tooltip />
                  <Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-500">
              No data available
            </div>
          )}
        </div>
      </div>

      {/* Recent Audits */}
      <div className="card">
        <h3 className="card-header">Recent Audits</h3>
        {recentAudits.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200">
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-500">Project</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-500">Status</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-500">Findings</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-500">Date</th>
                </tr>
              </thead>
              <tbody>
                {recentAudits.map((audit) => (
                  <tr key={audit.id} className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-3 px-4">
                      <div className="font-medium text-gray-900">{audit.project?.name || 'Unknown'}</div>
                      <div className="text-sm text-gray-500 truncate max-w-xs">
                        {audit.project?.githubUrl}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${
                        audit.status === 'COMPLETED' ? 'bg-green-100 text-green-800' :
                        audit.status === 'IN_PROGRESS' ? 'bg-blue-100 text-blue-800' :
                        audit.status === 'FAILED' ? 'bg-red-100 text-red-800' :
                        'bg-gray-100 text-gray-800'
                      }`}>
                        {audit.status === 'COMPLETED' && <CheckCircle className="w-3 h-3" />}
                        {audit.status === 'IN_PROGRESS' && <Clock className="w-3 h-3" />}
                        {audit.status === 'FAILED' && <AlertTriangle className="w-3 h-3" />}
                        {audit.status}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        {audit.criticalCount > 0 && (
                          <span className="text-xs bg-red-100 text-red-800 px-1.5 py-0.5 rounded">
                            {audit.criticalCount} Critical
                          </span>
                        )}
                        {audit.highCount > 0 && (
                          <span className="text-xs bg-orange-100 text-orange-800 px-1.5 py-0.5 rounded">
                            {audit.highCount} High
                          </span>
                        )}
                        <span className="text-sm text-gray-600">
                          {audit.totalFindings} total
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-sm text-gray-500">
                      {new Date(audit.createdAt).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8 text-gray-500">
            No audits yet. Start your first audit!
          </div>
        )}
      </div>
    </div>
  );
}
