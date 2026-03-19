import React, { useState, useMemo, useCallback } from 'react';
import Badge from '../common/Badge';
import { SkeletonLoader } from '../common/LoadingSpinner';

const IOC_TYPE_CONFIG = {
  ip: { label: 'IP Address', variant: 'info', icon: '\u{1F310}' },
  domain: { label: 'Domain', variant: 'purple', icon: '\u{1F517}' },
  hash_md5: { label: 'MD5 Hash', variant: 'neutral', icon: '#' },
  hash_sha256: { label: 'SHA-256 Hash', variant: 'neutral', icon: '#' },
  url: { label: 'URL', variant: 'warning', icon: '\u{1F310}' },
  file_path: { label: 'File Path', variant: 'neutral', icon: '\u{1F4C1}' },
  email: { label: 'Email', variant: 'info', icon: '\u2709' },
  mutex: { label: 'Mutex', variant: 'purple', icon: '\u{1F512}' },
  registry_key: { label: 'Registry Key', variant: 'warning', icon: '\u{1F5DD}' },
  user_agent: { label: 'User Agent', variant: 'neutral', icon: '\u{1F4BB}' },
};

const COLUMNS = [
  { key: 'type', label: 'Type', width: 'w-32' },
  { key: 'value', label: 'Indicator Value', width: 'flex-1' },
  { key: 'confidence', label: 'Confidence', width: 'w-28' },
  { key: 'source', label: 'Source', width: 'w-36' },
  { key: 'first_seen', label: 'First Seen', width: 'w-36' },
  { key: 'context', label: 'Context', width: 'w-40' },
];

/**
 * IOCTable - Table of Indicators of Compromise extracted from forensic analysis.
 * Supports filtering by IOC type, sorting, export, and bulk actions.
 *
 * @param {Object} props
 * @param {Array} props.iocs - Array of IOC objects
 * @param {boolean} [props.loading] - Loading state
 * @param {Function} [props.onExport] - Export callback
 * @param {Function} [props.onIocClick] - IOC click callback
 */
export default function IOCTable({ iocs = [], loading = false, onExport, onIocClick }) {
  const [sortKey, setSortKey] = useState('confidence');
  const [sortDir, setSortDir] = useState('desc');
  const [filterType, setFilterType] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [copiedId, setCopiedId] = useState(null);

  const handleSort = useCallback((key) => {
    if (key === sortKey) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
  }, [sortKey]);

  const filteredIocs = useMemo(() => {
    let result = [...iocs];

    if (filterType !== 'all') {
      result = result.filter((ioc) => ioc.type === filterType);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (ioc) =>
          ioc.value?.toLowerCase().includes(q) ||
          ioc.context?.toLowerCase().includes(q) ||
          ioc.source?.toLowerCase().includes(q)
      );
    }

    result.sort((a, b) => {
      const aVal = a[sortKey] ?? '';
      const bVal = b[sortKey] ?? '';
      const cmp = typeof aVal === 'number' ? aVal - bVal : String(aVal).localeCompare(String(bVal));
      return sortDir === 'asc' ? cmp : -cmp;
    });

    return result;
  }, [iocs, filterType, searchQuery, sortKey, sortDir]);

  const iocTypeCounts = useMemo(() => {
    const counts = {};
    iocs.forEach((ioc) => {
      counts[ioc.type] = (counts[ioc.type] || 0) + 1;
    });
    return counts;
  }, [iocs]);

  const toggleSelect = useCallback((id) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const toggleSelectAll = useCallback(() => {
    if (selectedIds.size === filteredIocs.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filteredIocs.map((ioc) => ioc.id)));
    }
  }, [selectedIds, filteredIocs]);

  const copyToClipboard = useCallback(async (value, id) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch {
      // Clipboard API may not be available
    }
  }, []);

  const handleExport = useCallback(() => {
    const exportData = filteredIocs
      .filter((ioc) => selectedIds.size === 0 || selectedIds.has(ioc.id))
      .map((ioc) => `${ioc.type},${ioc.value},${ioc.confidence},${ioc.source}`)
      .join('\n');
    const header = 'type,value,confidence,source\n';
    onExport?.(header + exportData);
  }, [filteredIocs, selectedIds, onExport]);

  const renderConfidence = (confidence) => {
    const pct = Math.round((confidence || 0) * 100);
    const color = pct >= 80 ? 'text-red-400' : pct >= 50 ? 'text-amber-400' : 'text-gray-400';
    return <span className={`font-mono text-xs ${color}`}>{pct}%</span>;
  };

  if (loading) {
    return (
      <div className="bg-dark-800 rounded-lg border border-dark-700 p-6">
        <SkeletonLoader lines={8} />
      </div>
    );
  }

  return (
    <div className="bg-dark-800 rounded-lg border border-dark-700 overflow-hidden">
      {/* Toolbar */}
      <div className="p-4 border-b border-dark-700">
        <div className="flex flex-wrap items-center gap-3">
          <input
            type="text"
            placeholder="Search IOCs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="bg-dark-700 border border-dark-600 rounded px-3 py-1.5 text-sm text-white placeholder-gray-500 w-64 font-mono"
          />
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-dark-700 border border-dark-600 rounded px-3 py-1.5 text-sm text-white"
          >
            <option value="all">All Types ({iocs.length})</option>
            {Object.entries(iocTypeCounts).map(([type, count]) => (
              <option key={type} value={type}>
                {IOC_TYPE_CONFIG[type]?.label || type} ({count})
              </option>
            ))}
          </select>

          <div className="ml-auto flex items-center gap-2">
            {selectedIds.size > 0 && (
              <span className="text-xs text-gray-400">{selectedIds.size} selected</span>
            )}
            <button
              onClick={handleExport}
              className="px-3 py-1.5 text-xs bg-dark-700 text-gray-300 rounded hover:bg-dark-600 transition-colors"
            >
              Export CSV
            </button>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-dark-700 text-gray-400">
              <th className="px-4 py-3 w-8">
                <input
                  type="checkbox"
                  checked={selectedIds.size === filteredIocs.length && filteredIocs.length > 0}
                  onChange={toggleSelectAll}
                  className="rounded border-dark-600"
                />
              </th>
              {COLUMNS.map((col) => (
                <th
                  key={col.key}
                  className={`px-4 py-3 text-left font-medium cursor-pointer hover:text-white select-none ${col.width}`}
                  onClick={() => handleSort(col.key)}
                >
                  <span className="flex items-center gap-1">
                    {col.label}
                    {sortKey === col.key && (
                      <span className="text-blue-400">{sortDir === 'asc' ? '\u2191' : '\u2193'}</span>
                    )}
                  </span>
                </th>
              ))}
              <th className="px-4 py-3 w-16" />
            </tr>
          </thead>
          <tbody className="divide-y divide-dark-700">
            {filteredIocs.length === 0 && (
              <tr>
                <td colSpan={COLUMNS.length + 2} className="px-4 py-8 text-center text-gray-500">
                  {iocs.length === 0 ? 'No IOCs extracted from forensic analysis.' : 'No IOCs match the current filters.'}
                </td>
              </tr>
            )}
            {filteredIocs.map((ioc) => {
              const typeConfig = IOC_TYPE_CONFIG[ioc.type] || { label: ioc.type, variant: 'neutral', icon: '?' };
              return (
                <tr
                  key={ioc.id}
                  className="hover:bg-dark-700 transition-colors"
                  onClick={() => onIocClick?.(ioc)}
                >
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      checked={selectedIds.has(ioc.id)}
                      onChange={() => toggleSelect(ioc.id)}
                      onClick={(e) => e.stopPropagation()}
                      className="rounded border-dark-600"
                    />
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant={typeConfig.variant} size="xs">{typeConfig.icon} {typeConfig.label}</Badge>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-white break-all max-w-[300px]">
                    {ioc.value}
                  </td>
                  <td className="px-4 py-3">{renderConfidence(ioc.confidence)}</td>
                  <td className="px-4 py-3 text-gray-400 text-xs">{ioc.source}</td>
                  <td className="px-4 py-3 text-gray-400 text-xs">
                    {ioc.first_seen ? new Date(ioc.first_seen).toLocaleString() : '--'}
                  </td>
                  <td className="px-4 py-3 text-gray-400 text-xs truncate max-w-[160px]">{ioc.context}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={(e) => { e.stopPropagation(); copyToClipboard(ioc.value, ioc.id); }}
                      className="text-xs text-gray-500 hover:text-white transition-colors"
                      title="Copy to clipboard"
                    >
                      {copiedId === ioc.id ? '\u2713' : '\u{1F4CB}'}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Footer stats */}
      <div className="p-3 border-t border-dark-700 flex items-center justify-between text-xs text-gray-500">
        <span>{filteredIocs.length} indicator{filteredIocs.length !== 1 ? 's' : ''} shown</span>
        <div className="flex gap-3">
          {Object.entries(iocTypeCounts).slice(0, 5).map(([type, count]) => (
            <span key={type}>{IOC_TYPE_CONFIG[type]?.label || type}: {count}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
