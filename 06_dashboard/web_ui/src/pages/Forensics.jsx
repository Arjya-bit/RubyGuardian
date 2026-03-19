import React, { useState, useMemo, useCallback } from 'react';
import { useApi } from '../hooks/useApi';
import MemoryDumpViewer from '../components/forensics/MemoryDumpViewer';
import IOCTable from '../components/forensics/IOCTable';
import LoadingSpinner from '../components/common/LoadingSpinner';
import ErrorBoundary from '../components/common/ErrorBoundary';
import Badge from '../components/common/Badge';

const FORENSIC_TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'memory', label: 'Memory Dumps' },
  { id: 'iocs', label: 'Indicators of Compromise' },
  { id: 'artifacts', label: 'Artifacts' },
];

export default function Forensics() {
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedReport, setSelectedReport] = useState(null);
  const [timeRange, setTimeRange] = useState('24h');

  const { data: reports, loading, error, refetch } = useApi('/api/forensics/reports', {
    params: { range: timeRange },
  });

  const { data: iocs, loading: iocsLoading } = useApi('/api/forensics/iocs', {
    params: { range: timeRange },
  });

  const stats = useMemo(() => {
    if (!reports) return { total: 0, critical: 0, withMemoryDump: 0, iocCount: 0 };
    return {
      total: reports.length,
      critical: reports.filter((r) => r.severity === 'critical').length,
      withMemoryDump: reports.filter((r) => r.memory_dump_path).length,
      iocCount: iocs?.length || 0,
    };
  }, [reports, iocs]);

  const handleReportSelect = useCallback((report) => {
    setSelectedReport(report);
    setActiveTab('memory');
  }, []);

  const renderOverview = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Reports', value: stats.total, color: 'text-blue-400' },
          { label: 'Critical Findings', value: stats.critical, color: 'text-red-400' },
          { label: 'Memory Dumps', value: stats.withMemoryDump, color: 'text-purple-400' },
          { label: 'IOCs Extracted', value: stats.iocCount, color: 'text-amber-400' },
        ].map((stat) => (
          <div key={stat.label} className="bg-dark-800 rounded-lg p-4 border border-dark-700">
            <p className="text-sm text-gray-400">{stat.label}</p>
            <p className={`text-3xl font-bold mt-1 ${stat.color}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      <div className="bg-dark-800 rounded-lg border border-dark-700">
        <div className="p-4 border-b border-dark-700">
          <h3 className="text-lg font-semibold text-white">Recent Forensic Reports</h3>
        </div>
        <div className="divide-y divide-dark-700">
          {reports?.map((report) => (
            <button
              key={report.id}
              onClick={() => handleReportSelect(report)}
              className="w-full p-4 text-left hover:bg-dark-700 transition-colors"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-white font-medium">{report.title}</p>
                  <p className="text-sm text-gray-400 mt-1">
                    PID {report.pid} &middot; {report.process_name} &middot;{' '}
                    {new Date(report.timestamp).toLocaleString()}
                  </p>
                </div>
                <Badge variant={report.severity}>{report.severity}</Badge>
              </div>
              {report.mitre_techniques?.length > 0 && (
                <div className="flex gap-2 mt-2">
                  {report.mitre_techniques.map((t) => (
                    <Badge key={t} variant="info" size="sm">{t}</Badge>
                  ))}
                </div>
              )}
            </button>
          ))}
          {reports?.length === 0 && (
            <p className="p-8 text-center text-gray-500">No forensic reports in selected time range.</p>
          )}
        </div>
      </div>
    </div>
  );

  if (loading) return <LoadingSpinner message="Loading forensic data..." />;
  if (error) return (
    <div className="text-center py-12">
      <p className="text-red-400 mb-4">Failed to load forensic data: {error.message}</p>
      <button onClick={refetch} className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
        Retry
      </button>
    </div>
  );

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-white">Forensic Analysis</h1>
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="bg-dark-800 border border-dark-600 text-white rounded px-3 py-2"
          >
            <option value="1h">Last Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
        </div>

        <div className="flex gap-1 bg-dark-800 rounded-lg p-1 border border-dark-700">
          {FORENSIC_TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-dark-700'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab === 'overview' && renderOverview()}
        {activeTab === 'memory' && (
          <MemoryDumpViewer report={selectedReport} onBack={() => setActiveTab('overview')} />
        )}
        {activeTab === 'iocs' && <IOCTable iocs={iocs} loading={iocsLoading} />}
        {activeTab === 'artifacts' && (
          <div className="bg-dark-800 rounded-lg p-8 border border-dark-700 text-center text-gray-400">
            <p>Artifact browser coming soon. View raw artifacts in Kibana.</p>
          </div>
        )}
      </div>
    </ErrorBoundary>
  );
}
