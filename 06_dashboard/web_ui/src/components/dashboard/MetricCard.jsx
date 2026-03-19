import React, { useMemo } from 'react';

const TREND_CONFIG = {
  up: { icon: '\u2191', color: 'text-green-400', bgColor: 'bg-green-900/30' },
  down: { icon: '\u2193', color: 'text-red-400', bgColor: 'bg-red-900/30' },
  neutral: { icon: '\u2192', color: 'text-gray-400', bgColor: 'bg-gray-900/30' },
  'up-bad': { icon: '\u2191', color: 'text-red-400', bgColor: 'bg-red-900/30' },
  'down-good': { icon: '\u2193', color: 'text-green-400', bgColor: 'bg-green-900/30' },
};

const ICON_MAP = {
  shield: (
    <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  ),
  alert: (
    <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  activity: (
    <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  ),
  cpu: (
    <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="4" y="4" width="16" height="16" rx="2" ry="2" />
      <rect x="9" y="9" width="6" height="6" />
      <line x1="9" y1="1" x2="9" y2="4" /><line x1="15" y1="1" x2="15" y2="4" />
      <line x1="9" y1="20" x2="9" y2="23" /><line x1="15" y1="20" x2="15" y2="23" />
      <line x1="20" y1="9" x2="23" y2="9" /><line x1="20" y1="14" x2="23" y2="14" />
      <line x1="1" y1="9" x2="4" y2="9" /><line x1="1" y1="14" x2="4" y2="14" />
    </svg>
  ),
  network: (
    <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
    </svg>
  ),
};

/**
 * MetricCard - Displays a single KPI metric with optional trend indicator,
 * sparkline chart, and icon. Used on the dashboard overview.
 *
 * @param {Object} props
 * @param {string} props.title - Metric label
 * @param {string|number} props.value - Primary metric value
 * @param {string} [props.subtitle] - Secondary description text
 * @param {string} [props.icon] - Icon name from ICON_MAP
 * @param {'up'|'down'|'neutral'|'up-bad'|'down-good'} [props.trend] - Trend direction
 * @param {string|number} [props.trendValue] - Trend percentage or value
 * @param {string} [props.trendLabel] - Trend description (e.g. "vs last hour")
 * @param {Array<number>} [props.sparkline] - Data points for mini chart
 * @param {string} [props.color] - Accent color class
 * @param {Function} [props.onClick] - Click handler
 */
export default function MetricCard({
  title,
  value,
  subtitle,
  icon,
  trend,
  trendValue,
  trendLabel = 'vs last period',
  sparkline,
  color = 'text-blue-400',
  onClick,
}) {
  const trendConfig = TREND_CONFIG[trend] || TREND_CONFIG.neutral;

  const sparklinePath = useMemo(() => {
    if (!sparkline || sparkline.length < 2) return null;
    const width = 100;
    const height = 30;
    const max = Math.max(...sparkline);
    const min = Math.min(...sparkline);
    const range = max - min || 1;
    const step = width / (sparkline.length - 1);

    const points = sparkline.map((val, i) => {
      const x = i * step;
      const y = height - ((val - min) / range) * height;
      return `${x},${y}`;
    });

    return {
      line: `M ${points.join(' L ')}`,
      area: `M 0,${height} L ${points.join(' L ')} L ${width},${height} Z`,
    };
  }, [sparkline]);

  return (
    <div
      onClick={onClick}
      className={`bg-dark-800 rounded-lg border border-dark-700 p-5 transition-all duration-200
        ${onClick ? 'cursor-pointer hover:border-dark-500 hover:bg-dark-750' : ''}`}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <p className="text-sm text-gray-400 font-medium truncate">{title}</p>
          <p className={`text-3xl font-bold mt-1 ${color}`}>
            {typeof value === 'number' ? value.toLocaleString() : value}
          </p>
          {subtitle && <p className="text-xs text-gray-500 mt-1">{subtitle}</p>}
        </div>

        {icon && ICON_MAP[icon] && (
          <div className={`flex-shrink-0 p-2 rounded-lg bg-dark-700 ${color}`}>
            {ICON_MAP[icon]}
          </div>
        )}
      </div>

      {/* Sparkline */}
      {sparklinePath && (
        <div className="mt-3">
          <svg viewBox="0 0 100 30" className="w-full h-8" preserveAspectRatio="none">
            <defs>
              <linearGradient id={`spark-grad-${title}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="currentColor" stopOpacity="0.3" />
                <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
              </linearGradient>
            </defs>
            <path
              d={sparklinePath.area}
              fill={`url(#spark-grad-${title})`}
              className={color}
            />
            <path
              d={sparklinePath.line}
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              className={color}
            />
          </svg>
        </div>
      )}

      {/* Trend indicator */}
      {trend && trendValue != null && (
        <div className="mt-3 flex items-center gap-2">
          <span className={`inline-flex items-center gap-1 text-xs font-medium px-1.5 py-0.5 rounded ${trendConfig.bgColor} ${trendConfig.color}`}>
            {trendConfig.icon} {trendValue}%
          </span>
          <span className="text-xs text-gray-500">{trendLabel}</span>
        </div>
      )}
    </div>
  );
}

/**
 * MetricCardGrid - Responsive grid layout for multiple MetricCards.
 */
export function MetricCardGrid({ children, columns = 4 }) {
  const colClass = {
    2: 'grid-cols-1 sm:grid-cols-2',
    3: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3',
    4: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-4',
  };

  return (
    <div className={`grid gap-4 ${colClass[columns] || colClass[4]}`}>
      {children}
    </div>
  );
}
