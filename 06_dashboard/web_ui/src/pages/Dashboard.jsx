import React, { useState, useEffect } from 'react';
import { apiService } from '../services/api';

const severityColors = {
  critical: 'bg-red-600',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-400',
  info: 'bg-gray-400',
};

function StatCard({ title, value, subtitle, color }) {
  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-sm font-medium text-gray-500">{title}</h3>
      <p className={`text-3xl font-bold mt-2 ${color || 'text-gray-900'}`}>{value}</p>
      {subtitle && <p className="text-sm text-gray-400 mt-1">{subtitle}</p>}
    </div>
  );
}

function AlertRow({ alert }) {
  return (
    <tr className="border-b hover:bg-gray-50">
      <td className="px-4 py-3 text-sm">{new Date(alert.timestamp).toLocaleString()}</td>
      <td className="px-4 py-3">
        <span className={`px-2 py-1 rounded text-xs text-white ${severityColors[alert.severity] || 'bg-gray-400'}`}>
          {alert.severity?.toUpperCase()}
        </span>
      </td>
      <td className="px-4 py-3 text-sm">{alert.rule_id}</td>
      <td className="px-4 py-3 text-sm">{alert.description}</td>
      <td className="px-4 py-3 text-sm text-gray-500">{alert.mitre_ids?.join(', ')}</td>
    </tr>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const [statsData, alertsData] = await Promise.all([
          apiService.getStats(),
          apiService.getRecentAlerts(),
        ]);
        setStats(statsData);
        setAlerts(alertsData);
      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <div className="flex items-center justify-center h-64">Loading...</div>;
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Threat Overview</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard title="Active Alerts" value={stats?.active_alerts || 0} color="text-red-600" />
        <StatCard title="Agents Online" value={stats?.agents_online || 0} color="text-green-600" />
        <StatCard title="Samples Analyzed" value={stats?.samples_analyzed || 0} />
        <StatCard title="Detection Rate" value={`${stats?.detection_rate || 0}%`} color="text-blue-600" />
      </div>

      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b">
          <h2 className="text-lg font-semibold">Recent Alerts</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Rule</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Description</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">MITRE</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert, i) => <AlertRow key={alert.id || i} alert={alert} />)}
              {alerts.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-400">No recent alerts</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
