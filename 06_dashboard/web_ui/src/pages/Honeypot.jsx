import React, { useState, useEffect } from 'react';
import { apiService } from '../services/api';

export default function Honeypot() {
  const [captures, setCaptures] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const [capturesData, statsData] = await Promise.all([
          apiService.getHoneypotCaptures(),
          apiService.getHoneypotStats(),
        ]);
        setCaptures(capturesData);
        setStats(statsData);
      } catch (err) {
        console.error('Failed to load honeypot data:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  if (loading) return <div className="flex items-center justify-center h-64">Loading...</div>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Honeypot Intelligence</h1>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-sm font-medium text-gray-500">Total Captures</h3>
          <p className="text-3xl font-bold mt-2">{stats?.total_captures || 0}</p>
        </div>
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-sm font-medium text-gray-500">Unique Attackers</h3>
          <p className="text-3xl font-bold mt-2 text-red-600">{stats?.unique_attackers || 0}</p>
        </div>
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-sm font-medium text-gray-500">Samples Collected</h3>
          <p className="text-3xl font-bold mt-2 text-blue-600">{stats?.samples_collected || 0}</p>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b">
          <h2 className="text-lg font-semibold">Recent Captures</h2>
        </div>
        <div className="divide-y">
          {captures.map((capture, i) => (
            <div key={capture.id || i} className="px-6 py-4">
              <div className="flex justify-between items-start">
                <div>
                  <span className="font-mono text-sm">{capture.remote_ip}</span>
                  <span className="mx-2 text-gray-400">→</span>
                  <span className="text-sm font-medium">{capture.method} {capture.path}</span>
                </div>
                <span className="text-xs text-gray-400">
                  {new Date(capture.timestamp).toLocaleString()}
                </span>
              </div>
              {capture.indicators?.length > 0 && (
                <div className="mt-2 flex gap-2">
                  {capture.indicators.map((ind, j) => (
                    <span key={j} className="px-2 py-1 bg-red-100 text-red-700 text-xs rounded">
                      {ind.type}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
          {captures.length === 0 && (
            <div className="px-6 py-8 text-center text-gray-400">No captures yet</div>
          )}
        </div>
      </div>
    </div>
  );
}
