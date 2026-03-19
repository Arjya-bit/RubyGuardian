import React, { useState, useMemo, useCallback } from 'react';
import Badge, { SeverityBadge, MitreBadge } from '../common/Badge';

const COLUMNS = [
  { key: 'timestamp', label: 'Time', sortable: true, width: 'w-40' },
  { key: 'severity', label: 'Severity', sortable: true, width: 'w-28' },
  { key: 'rule_name', label: 'Rule', sortable: true, width: 'w-48' },
  { key: 'process_name', label: 'Process', sortable: true, width: 'w-32' },
  { key: 'pid', label: 'PID', sortable: true, width: 'w-20' },
  { key: 'mitre_technique', label: 'MITRE', sortable: false, width: 'w-32' },
  { key: 'threat_score', label: 'Score', sortable: true, width: 'w-24' },
  { key: 'status', label: 'Status', sortable: true, width: 'w-28' },
];

const PAGE_SIZES = [25, 50, 100];

/**
 * AlertTable - Sortable, filterable, paginated table of security alerts.
 *
 * @param {Object} props
 * @param {Array} props.alerts - Array of alert objects
 * @param {Function} [props.onAlertClick] - Callback when an alert row is clicked
 * @param {Function} [props.onAcknowledge] - Callback to acknowledge an alert
 * @param {boolean} [props.loading] - Show loading state
 */
export default function AlertTable({ alerts = [], onAlertClick, onAcknowledge, loading = false }) {
  const [sortKey, setSortKey] = useState('timestamp');
  const [sortDir, setSortDir] = useState('desc');
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(25);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  const handleSort = useCallback((key) => {
    if (key === sortKey) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
    setPage(0);
  }, [sortKey]);

  const filteredAlerts = useMemo(() => {
    let result = [...alerts];

    if (filterSeverity !== 'all') {
      result = result.filter((a) => a.severity === filterSeverity);
    }
    if (filterStatus !== 'all') {
      result = result.filter((a) => a.status === filterStatus);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (a) =>
          a.rule_name?.toLowerCase().includes(q) ||
          a.process_name?.toLowerCase().includes(q) ||
          a.mitre_technique?.toLowerCase().includes(q)
      );
    }

    result.sort((a, b) => {
      const aVal = a[sortKey] ?? '';
      const bVal = b[sortKey] ?? '';
      const cmp = typeof aVal === 'number' ? aVal - bVal : String(aVal).localeCompare(String(bVal));
      return sortDir === 'asc' ? cmp : -cmp;
    });

    return result;
  }, [alerts, filterSeverity, filterStatus, searchQuery, sortKey, sortDir]);

  const pageCount = Math.ceil(filteredAlerts.length / pageSize);
  const pagedAlerts = filteredAlerts.slice(page * pageSize, (page + 1) * pageSize);

  const formatTime = (ts) => {
    if (!ts) return '--';
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  const renderScoreBar = (score) => {
    const pct = Math.min(100, Math.max(0, (score || 0) * 100));
    const color = pct >= 80 ? 'bg-red-500' : pct >= 50 ? 'bg-orange-500' : 'bg-green-500';
    return (
      <div className="flex items-center gap-2">
        <div className="w-16 h-2 bg-dark-600 rounded-full overflow-hidden">
          <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
        </div>
        <span className="text-xs text-gray-400">{pct.toFixed(0)}</span>
      </div>
    );
  };

  return (
    <div className="bg-dark-800 rounded-lg border border-dark-700 overflow-hidden">
      {/* Filters */}
      <div className="p-4 border-b border-dark-700 flex flex-wrap items-center gap-3">
        <input
          type="text"
          placeholder="Search rules, processes..."
          value={searchQuery}
          onChange={(e) => { setSearchQuery(e.target.value); setPage(0); }}
          className="bg-dark-700 border border-dark-600 rounded px-3 py-1.5 text-sm text-white placeholder-gray-500 w-64"
        />
        <select
          value={filterSeverity}
          onChange={(e) => { setFilterSeverity(e.target.value); setPage(0); }}
          className="bg-dark-700 border border-dark-600 rounded px-3 py-1.5 text-sm text-white"
        >
          <option value="all">All Severities</option>
          {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
        <select
          value={filterStatus}
          onChange={(e) => { setFilterStatus(e.target.value); setPage(0); }}
          className="bg-dark-700 border border-dark-600 rounded px-3 py-1.5 text-sm text-white"
        >
          <option value="all">All Statuses</option>
          <option value="new">New</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
        </select>
        <span className="ml-auto text-sm text-gray-400">
          {filteredAlerts.length} alert{filteredAlerts.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-dark-700 text-gray-400">
              {COLUMNS.map((col) => (
                <th
                  key={col.key}
                  className={`px-4 py-3 text-left font-medium ${col.width} ${
                    col.sortable ? 'cursor-pointer hover:text-white select-none' : ''
                  }`}
                  onClick={() => col.sortable && handleSort(col.key)}
                >
                  <span className="flex items-center gap-1">
                    {col.label}
                    {col.sortable && sortKey === col.key && (
                      <span className="text-blue-400">{sortDir === 'asc' ? '\u2191' : '\u2193'}</span>
                    )}
                  </span>
                </th>
              ))}
              <th className="px-4 py-3 w-20" />
            </tr>
          </thead>
          <tbody className="divide-y divide-dark-700">
            {loading && (
              <tr><td colSpan={COLUMNS.length + 1} className="px-4 py-8 text-center text-gray-500">Loading alerts...</td></tr>
            )}
            {!loading && pagedAlerts.length === 0 && (
              <tr><td colSpan={COLUMNS.length + 1} className="px-4 py-8 text-center text-gray-500">No alerts match the current filters.</td></tr>
            )}
            {!loading && pagedAlerts.map((alert) => (
              <tr
                key={alert.id}
                onClick={() => onAlertClick?.(alert)}
                className="hover:bg-dark-700 cursor-pointer transition-colors"
              >
                <td className="px-4 py-3 text-gray-300 font-mono text-xs">{formatTime(alert.timestamp)}</td>
                <td className="px-4 py-3"><SeverityBadge severity={alert.severity} /></td>
                <td className="px-4 py-3 text-white font-medium truncate max-w-[200px]">{alert.rule_name}</td>
                <td className="px-4 py-3 text-gray-300 font-mono">{alert.process_name}</td>
                <td className="px-4 py-3 text-gray-400 font-mono">{alert.pid}</td>
                <td className="px-4 py-3">
                  {alert.mitre_technique && <MitreBadge techniqueId={alert.mitre_technique} />}
                </td>
                <td className="px-4 py-3">{renderScoreBar(alert.threat_score)}</td>
                <td className="px-4 py-3">
                  <Badge variant={alert.status === 'new' ? 'error' : alert.status === 'acknowledged' ? 'warning' : 'success'} size="xs">
                    {alert.status}
                  </Badge>
                </td>
                <td className="px-4 py-3">
                  {alert.status === 'new' && onAcknowledge && (
                    <button
                      onClick={(e) => { e.stopPropagation(); onAcknowledge(alert.id); }}
                      className="text-xs text-blue-400 hover:text-blue-300"
                    >
                      ACK
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="p-4 border-t border-dark-700 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-400">Rows:</span>
          <select
            value={pageSize}
            onChange={(e) => { setPageSize(Number(e.target.value)); setPage(0); }}
            className="bg-dark-700 border border-dark-600 rounded px-2 py-1 text-sm text-white"
          >
            {PAGE_SIZES.map((s) => (<option key={s} value={s}>{s}</option>))}
          </select>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className="px-3 py-1 text-sm rounded bg-dark-700 text-gray-300 disabled:opacity-40 hover:bg-dark-600"
          >
            Prev
          </button>
          <span className="text-sm text-gray-400">
            {page + 1} / {Math.max(1, pageCount)}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
            disabled={page >= pageCount - 1}
            className="px-3 py-1 text-sm rounded bg-dark-700 text-gray-300 disabled:opacity-40 hover:bg-dark-600"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
