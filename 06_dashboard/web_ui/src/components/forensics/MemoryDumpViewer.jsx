import React, { useState, useMemo, useCallback } from 'react';
import { useApi } from '../../hooks/useApi';
import LoadingSpinner from '../common/LoadingSpinner';
import Badge from '../common/Badge';

const BYTES_PER_ROW = 16;
const ROWS_PER_PAGE = 32;

const HIGHLIGHT_PATTERNS = {
  shellcode: { pattern: /\x90{4,}|[\xcc]{2,}|\x48\x31\xc0/, color: 'bg-red-900/40', label: 'Shellcode' },
  strings: { pattern: /[\x20-\x7e]{4,}/, color: 'bg-blue-900/40', label: 'ASCII Strings' },
  nulls: { pattern: /\x00{8,}/, color: 'bg-gray-800/40', label: 'Null Region' },
};

/**
 * MemoryDumpViewer - Hex viewer for process memory dumps captured during forensic analysis.
 * Supports hex + ASCII display, region highlighting, string extraction, and navigation.
 *
 * @param {Object} props
 * @param {Object} [props.report] - Forensic report object containing memory dump reference
 * @param {Function} [props.onBack] - Callback to navigate back
 */
export default function MemoryDumpViewer({ report, onBack }) {
  const [viewMode, setViewMode] = useState('hex');
  const [currentPage, setCurrentPage] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [highlightMode, setHighlightMode] = useState('none');
  const [selectedRegion, setSelectedRegion] = useState(null);

  const dumpPath = report?.memory_dump_path;
  const { data: dumpData, loading, error } = useApi(
    dumpPath ? `/api/forensics/memory-dump/${report.id}` : null,
    { params: { offset: currentPage * BYTES_PER_ROW * ROWS_PER_PAGE, limit: BYTES_PER_ROW * ROWS_PER_PAGE } }
  );

  const { data: regions } = useApi(
    dumpPath ? `/api/forensics/memory-dump/${report.id}/regions` : null
  );

  const { data: strings } = useApi(
    viewMode === 'strings' && dumpPath ? `/api/forensics/memory-dump/${report.id}/strings` : null
  );

  const hexRows = useMemo(() => {
    if (!dumpData?.bytes) return [];
    const bytes = dumpData.bytes;
    const rows = [];
    const baseOffset = currentPage * BYTES_PER_ROW * ROWS_PER_PAGE;

    for (let i = 0; i < bytes.length; i += BYTES_PER_ROW) {
      const rowBytes = bytes.slice(i, i + BYTES_PER_ROW);
      const offset = baseOffset + i;
      const hex = rowBytes.map((b) => b.toString(16).padStart(2, '0')).join(' ');
      const ascii = rowBytes.map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.')).join('');
      rows.push({ offset, hex, ascii, bytes: rowBytes });
    }
    return rows;
  }, [dumpData, currentPage]);

  const totalPages = dumpData ? Math.ceil((dumpData.totalSize || 0) / (BYTES_PER_ROW * ROWS_PER_PAGE)) : 0;

  const handleSearch = useCallback(() => {
    if (!searchQuery) return;
    // Search would be handled by API in production
    console.log('Searching for:', searchQuery);
  }, [searchQuery]);

  if (!report) {
    return (
      <div className="bg-dark-800 rounded-lg border border-dark-700 p-8 text-center">
        <p className="text-gray-400 mb-4">Select a forensic report to view its memory dump.</p>
        {onBack && (
          <button onClick={onBack} className="px-4 py-2 bg-dark-700 text-white rounded hover:bg-dark-600">
            Back to Reports
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {onBack && (
            <button onClick={onBack} className="text-gray-400 hover:text-white transition-colors">
              &larr; Back
            </button>
          )}
          <div>
            <h3 className="text-lg font-semibold text-white">Memory Dump: {report.process_name}</h3>
            <p className="text-sm text-gray-400">PID {report.pid} &middot; {dumpData?.totalSize ? `${(dumpData.totalSize / 1024).toFixed(1)} KB` : 'Loading...'}</p>
          </div>
        </div>
        <div className="flex gap-2">
          {['hex', 'strings', 'regions'].map((mode) => (
            <button
              key={mode}
              onClick={() => setViewMode(mode)}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                viewMode === mode ? 'bg-blue-600 text-white' : 'bg-dark-700 text-gray-400 hover:text-white'
              }`}
            >
              {mode.charAt(0).toUpperCase() + mode.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Search bar */}
      <div className="flex gap-2">
        <input
          type="text"
          placeholder="Search hex (e.g. 4d5a) or ASCII string..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
          className="flex-1 bg-dark-700 border border-dark-600 rounded px-3 py-2 text-sm text-white placeholder-gray-500 font-mono"
        />
        <select
          value={highlightMode}
          onChange={(e) => setHighlightMode(e.target.value)}
          className="bg-dark-700 border border-dark-600 rounded px-3 py-2 text-sm text-white"
        >
          <option value="none">No Highlight</option>
          <option value="shellcode">Shellcode Patterns</option>
          <option value="strings">ASCII Strings</option>
          <option value="nulls">Null Regions</option>
        </select>
      </div>

      {/* Hex View */}
      {viewMode === 'hex' && (
        <div className="bg-dark-900 rounded-lg border border-dark-700 overflow-hidden">
          {loading ? (
            <LoadingSpinner message="Loading memory dump..." />
          ) : error ? (
            <p className="p-8 text-center text-red-400">Failed to load memory dump: {error.message}</p>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full font-mono text-xs">
                  <thead>
                    <tr className="border-b border-dark-700 text-gray-500">
                      <th className="px-4 py-2 text-left w-24">Offset</th>
                      <th className="px-4 py-2 text-left">Hex</th>
                      <th className="px-4 py-2 text-left w-40">ASCII</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-dark-800">
                    {hexRows.map((row) => (
                      <tr key={row.offset} className="hover:bg-dark-800 transition-colors">
                        <td className="px-4 py-1 text-blue-400">{row.offset.toString(16).padStart(8, '0')}</td>
                        <td className="px-4 py-1 text-gray-300 tracking-wider">{row.hex}</td>
                        <td className="px-4 py-1 text-green-400">{row.ascii}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              <div className="p-3 border-t border-dark-700 flex items-center justify-between">
                <button
                  onClick={() => setCurrentPage((p) => Math.max(0, p - 1))}
                  disabled={currentPage === 0}
                  className="px-3 py-1 text-xs rounded bg-dark-700 text-gray-300 disabled:opacity-40"
                >
                  Previous
                </button>
                <span className="text-xs text-gray-400">Page {currentPage + 1} / {Math.max(1, totalPages)}</span>
                <button
                  onClick={() => setCurrentPage((p) => Math.min(totalPages - 1, p + 1))}
                  disabled={currentPage >= totalPages - 1}
                  className="px-3 py-1 text-xs rounded bg-dark-700 text-gray-300 disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            </>
          )}
        </div>
      )}

      {/* Strings View */}
      {viewMode === 'strings' && (
        <div className="bg-dark-900 rounded-lg border border-dark-700 p-4 max-h-[500px] overflow-y-auto">
          <h4 className="text-sm font-medium text-gray-400 mb-3">Extracted Strings ({strings?.length || 0})</h4>
          <div className="space-y-1 font-mono text-xs">
            {strings?.map((s, i) => (
              <div key={i} className="flex gap-4 hover:bg-dark-800 px-2 py-1 rounded">
                <span className="text-blue-400 w-20 flex-shrink-0">{s.offset?.toString(16).padStart(8, '0')}</span>
                <span className="text-green-400 break-all">{s.value}</span>
              </div>
            )) || <p className="text-gray-500">No strings extracted.</p>}
          </div>
        </div>
      )}

      {/* Regions View */}
      {viewMode === 'regions' && (
        <div className="bg-dark-900 rounded-lg border border-dark-700 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-dark-700 text-gray-400">
                <th className="px-4 py-2 text-left">Address Range</th>
                <th className="px-4 py-2 text-left">Size</th>
                <th className="px-4 py-2 text-left">Permissions</th>
                <th className="px-4 py-2 text-left">Type</th>
                <th className="px-4 py-2 text-left">Entropy</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-800">
              {regions?.map((region, i) => (
                <tr
                  key={i}
                  onClick={() => setSelectedRegion(region)}
                  className={`hover:bg-dark-800 cursor-pointer ${selectedRegion === region ? 'bg-dark-800' : ''}`}
                >
                  <td className="px-4 py-2 font-mono text-xs text-blue-400">
                    {region.start_addr} - {region.end_addr}
                  </td>
                  <td className="px-4 py-2 text-gray-300">{region.size_human}</td>
                  <td className="px-4 py-2">
                    <Badge variant={region.permissions?.includes('x') ? 'error' : 'neutral'} size="xs">
                      {region.permissions}
                    </Badge>
                  </td>
                  <td className="px-4 py-2 text-gray-400">{region.type}</td>
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-2 bg-dark-600 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${region.entropy > 7 ? 'bg-red-500' : region.entropy > 5 ? 'bg-amber-500' : 'bg-green-500'}`}
                          style={{ width: `${(region.entropy / 8) * 100}%` }}
                        />
                      </div>
                      <span className="text-xs text-gray-400">{region.entropy?.toFixed(2)}</span>
                    </div>
                  </td>
                </tr>
              )) || (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-500">No memory regions available.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
