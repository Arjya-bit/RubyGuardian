import React, { useState, useMemo, useRef, useEffect } from 'react';
import Badge, { SeverityBadge } from '../common/Badge';

const SEVERITY_COLORS = {
  critical: { bg: 'bg-red-500', border: 'border-red-500', text: 'text-red-400' },
  high: { bg: 'bg-orange-500', border: 'border-orange-500', text: 'text-orange-400' },
  medium: { bg: 'bg-amber-500', border: 'border-amber-500', text: 'text-amber-400' },
  low: { bg: 'bg-green-500', border: 'border-green-500', text: 'text-green-400' },
  info: { bg: 'bg-blue-500', border: 'border-blue-500', text: 'text-blue-400' },
};

const EVENT_ICONS = {
  process_spawn: '\u2699',
  network_connect: '\u{1F310}',
  file_write: '\u{1F4C4}',
  memory_injection: '\u{1F9E0}',
  code_execution: '\u26A1',
  dns_query: '\u{1F50D}',
  syscall_anomaly: '\u26A0',
};

/**
 * EventTimeline - Vertical timeline visualization of security events
 * with severity-colored markers, expandable details, and auto-scroll for live events.
 *
 * @param {Object} props
 * @param {Array} props.events - Array of event objects sorted by timestamp
 * @param {boolean} [props.autoScroll] - Auto-scroll to latest events
 * @param {number} [props.maxEvents] - Maximum events to display
 * @param {Function} [props.onEventClick] - Callback when event is clicked
 * @param {boolean} [props.showMiniChart] - Show severity mini-chart at top
 */
export default function EventTimeline({
  events = [],
  autoScroll = true,
  maxEvents = 200,
  onEventClick,
  showMiniChart = true,
}) {
  const [expandedId, setExpandedId] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterType, setFilterType] = useState('all');
  const bottomRef = useRef(null);
  const containerRef = useRef(null);

  const filteredEvents = useMemo(() => {
    let result = events.slice(-maxEvents);
    if (filterSeverity !== 'all') {
      result = result.filter((e) => e.severity === filterSeverity);
    }
    if (filterType !== 'all') {
      result = result.filter((e) => e.event_type === filterType);
    }
    return result;
  }, [events, maxEvents, filterSeverity, filterType]);

  const eventTypes = useMemo(() => {
    const types = new Set(events.map((e) => e.event_type).filter(Boolean));
    return Array.from(types).sort();
  }, [events]);

  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    filteredEvents.forEach((e) => {
      if (counts[e.severity] !== undefined) counts[e.severity]++;
    });
    return counts;
  }, [filteredEvents]);

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [filteredEvents.length, autoScroll]);

  const formatTimestamp = (ts) => {
    if (!ts) return '--:--:--';
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  const formatDate = (ts) => {
    if (!ts) return '';
    return new Date(ts).toLocaleDateString([], { month: 'short', day: 'numeric' });
  };

  const toggleExpanded = (id) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="bg-dark-800 rounded-lg border border-dark-700 overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-dark-700">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-lg font-semibold text-white">Event Timeline</h3>
          <span className="text-sm text-gray-400">{filteredEvents.length} events</span>
        </div>

        {/* Mini severity chart */}
        {showMiniChart && (
          <div className="flex gap-1 h-6 rounded overflow-hidden mb-3">
            {Object.entries(severityCounts).map(([sev, count]) => {
              const total = filteredEvents.length || 1;
              const pct = (count / total) * 100;
              if (pct === 0) return null;
              return (
                <div
                  key={sev}
                  className={`${SEVERITY_COLORS[sev]?.bg || 'bg-gray-500'} transition-all duration-500`}
                  style={{ width: `${pct}%` }}
                  title={`${sev}: ${count}`}
                />
              );
            })}
          </div>
        )}

        {/* Filters */}
        <div className="flex gap-2">
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-dark-700 border border-dark-600 rounded px-2 py-1 text-xs text-white"
          >
            <option value="all">All Severities</option>
            {Object.keys(SEVERITY_COLORS).map((s) => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)} ({severityCounts[s]})</option>
            ))}
          </select>
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-dark-700 border border-dark-600 rounded px-2 py-1 text-xs text-white"
          >
            <option value="all">All Types</option>
            {eventTypes.map((t) => (
              <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Timeline */}
      <div ref={containerRef} className="max-h-[600px] overflow-y-auto p-4">
        {filteredEvents.length === 0 && (
          <p className="text-center text-gray-500 py-8">No events to display.</p>
        )}

        <div className="relative">
          {/* Vertical line */}
          <div className="absolute left-[22px] top-0 bottom-0 w-px bg-dark-600" />

          {filteredEvents.map((event, idx) => {
            const colors = SEVERITY_COLORS[event.severity] || SEVERITY_COLORS.info;
            const isExpanded = expandedId === event.id;
            const showDate = idx === 0 ||
              formatDate(event.timestamp) !== formatDate(filteredEvents[idx - 1]?.timestamp);

            return (
              <div key={event.id || idx}>
                {showDate && (
                  <div className="flex items-center gap-3 mb-3 mt-2">
                    <div className={`w-[45px] h-6 rounded ${colors.bg} bg-opacity-20 flex items-center justify-center`}>
                      <span className="text-[10px] text-gray-300 font-medium">{formatDate(event.timestamp)}</span>
                    </div>
                  </div>
                )}

                <div className="flex gap-4 mb-3 group">
                  {/* Timeline marker */}
                  <div className="flex-shrink-0 relative z-10">
                    <div className={`w-[45px] h-[45px] rounded-full border-2 ${colors.border} bg-dark-900 flex items-center justify-center text-lg`}>
                      {EVENT_ICONS[event.event_type] || '\u{1F6E1}'}
                    </div>
                  </div>

                  {/* Event content */}
                  <div
                    className={`flex-1 bg-dark-900 rounded-lg border border-dark-700 p-3 cursor-pointer
                      hover:border-dark-500 transition-colors ${isExpanded ? 'ring-1 ring-blue-500' : ''}`}
                    onClick={() => { toggleExpanded(event.id); onEventClick?.(event); }}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <p className="text-white font-medium text-sm">
                          {event.rule_name || event.event_type?.replace(/_/g, ' ') || 'Event'}
                        </p>
                        <p className="text-xs text-gray-400 mt-0.5">
                          {formatTimestamp(event.timestamp)}
                          {event.process_name && ` \u00B7 ${event.process_name}`}
                          {event.pid && ` (PID: ${event.pid})`}
                        </p>
                      </div>
                      <SeverityBadge severity={event.severity} size="xs" />
                    </div>

                    {isExpanded && (
                      <div className="mt-3 pt-3 border-t border-dark-700 space-y-2 text-xs">
                        {event.description && (
                          <p className="text-gray-300">{event.description}</p>
                        )}
                        <div className="grid grid-cols-2 gap-2">
                          {event.source_ip && (
                            <div><span className="text-gray-500">Source IP:</span> <span className="text-gray-300 font-mono">{event.source_ip}</span></div>
                          )}
                          {event.destination_ip && (
                            <div><span className="text-gray-500">Dest IP:</span> <span className="text-gray-300 font-mono">{event.destination_ip}</span></div>
                          )}
                          {event.mitre_technique && (
                            <div><span className="text-gray-500">MITRE:</span> <Badge variant="purple" size="xs">{event.mitre_technique}</Badge></div>
                          )}
                          {event.threat_score != null && (
                            <div><span className="text-gray-500">Score:</span> <span className="text-gray-300">{(event.threat_score * 100).toFixed(1)}%</span></div>
                          )}
                        </div>
                        {event.command_line && (
                          <pre className="bg-dark-800 rounded p-2 text-gray-400 font-mono overflow-x-auto">{event.command_line}</pre>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
          <div ref={bottomRef} />
        </div>
      </div>
    </div>
  );
}
