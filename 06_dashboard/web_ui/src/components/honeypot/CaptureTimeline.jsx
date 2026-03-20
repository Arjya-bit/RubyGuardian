import React, { useState } from 'react';

const SAMPLE_CAPTURES = [
  { id: 1, timestamp: '2024-01-15T14:32:00Z', type: 'gem_install', source: '203.0.113.42', detail: 'Attempted install of malicious_gem-0.1.0', severity: 'critical', techniques: ['T1195.001'] },
  { id: 2, timestamp: '2024-01-15T14:28:00Z', type: 'eval_attempt', source: '198.51.100.7', detail: 'Base64-encoded eval payload in POST body', severity: 'high', techniques: ['T1059.007', 'T1027'] },
  { id: 3, timestamp: '2024-01-15T14:15:00Z', type: 'file_access', source: '203.0.113.42', detail: 'Path traversal: GET /../../../etc/passwd', severity: 'high', techniques: ['T1005'] },
  { id: 4, timestamp: '2024-01-15T13:45:00Z', type: 'credential_probe', source: '192.0.2.100', detail: 'Accessed fake .env credentials file', severity: 'medium', techniques: ['T1552.001'] },
  { id: 5, timestamp: '2024-01-15T13:20:00Z', type: 'network_scan', source: '198.51.100.22', detail: 'Port scan detected (22,80,443,3000,8080)', severity: 'low', techniques: ['T1046'] },
];

const severityStyles = {
  critical: 'border-red-500 bg-red-500/10',
  high: 'border-orange-500 bg-orange-500/10',
  medium: 'border-yellow-500 bg-yellow-500/10',
  low: 'border-blue-500 bg-blue-500/10',
};

const typeIcons = {
  gem_install: 'M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4',
  eval_attempt: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4',
  file_access: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
  credential_probe: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z',
  network_scan: 'M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9',
};

export default function CaptureTimeline({ captures = SAMPLE_CAPTURES }) {
  const [expandedId, setExpandedId] = useState(null);
  const [filter, setFilter] = useState('all');

  const filtered = filter === 'all' ? captures : captures.filter(c => c.severity === filter);

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-semibold dark:text-white">Capture Timeline</h3>
        <div className="flex gap-1">
          {['all', 'critical', 'high', 'medium', 'low'].map(s => (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={`px-2 py-1 text-xs rounded capitalize ${
                filter === s ? 'bg-red-600 text-white' : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-3">
        {filtered.map(capture => (
          <div
            key={capture.id}
            className={`border-l-4 rounded-r-lg p-3 cursor-pointer transition-all ${severityStyles[capture.severity]} ${
              expandedId === capture.id ? 'ring-1 ring-gray-300 dark:ring-gray-600' : ''
            }`}
            onClick={() => setExpandedId(expandedId === capture.id ? null : capture.id)}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-2">
                <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={typeIcons[capture.type] || typeIcons.file_access} />
                </svg>
                <span className="text-sm font-medium dark:text-white">{capture.detail}</span>
              </div>
              <span className="text-xs text-gray-400 whitespace-nowrap ml-2">
                {new Date(capture.timestamp).toLocaleTimeString()}
              </span>
            </div>

            {expandedId === capture.id && (
              <div className="mt-3 pt-3 border-t border-gray-200 dark:border-gray-600 text-sm space-y-1">
                <div className="text-gray-600 dark:text-gray-400">Source: {capture.source}</div>
                <div className="text-gray-600 dark:text-gray-400">Type: {capture.type.replace('_', ' ')}</div>
                <div className="flex gap-1 mt-2">
                  {capture.techniques.map(t => (
                    <span key={t} className="px-2 py-0.5 bg-gray-200 dark:bg-gray-700 rounded text-xs font-mono">{t}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
