import React from 'react';

const VARIANT_STYLES = {
  critical: 'bg-red-900/50 text-red-300 border-red-700',
  high: 'bg-orange-900/50 text-orange-300 border-orange-700',
  medium: 'bg-amber-900/50 text-amber-300 border-amber-700',
  low: 'bg-green-900/50 text-green-300 border-green-700',
  info: 'bg-blue-900/50 text-blue-300 border-blue-700',
  success: 'bg-emerald-900/50 text-emerald-300 border-emerald-700',
  warning: 'bg-yellow-900/50 text-yellow-300 border-yellow-700',
  error: 'bg-red-900/50 text-red-300 border-red-700',
  neutral: 'bg-gray-800/50 text-gray-300 border-gray-600',
  purple: 'bg-purple-900/50 text-purple-300 border-purple-700',
};

const SIZE_STYLES = {
  xs: 'text-[10px] px-1.5 py-0.5',
  sm: 'text-xs px-2 py-0.5',
  md: 'text-sm px-2.5 py-1',
  lg: 'text-base px-3 py-1.5',
};

/**
 * Badge - Displays a colored label or tag for severity levels, statuses,
 * MITRE ATT&CK technique IDs, and other categorical information.
 *
 * @param {Object} props
 * @param {string} props.children - Badge text content
 * @param {string} [props.variant='neutral'] - Color variant
 * @param {'xs'|'sm'|'md'|'lg'} [props.size='sm'] - Badge size
 * @param {boolean} [props.dot] - Show a status dot indicator
 * @param {boolean} [props.removable] - Show remove/close button
 * @param {Function} [props.onRemove] - Callback when remove is clicked
 * @param {boolean} [props.pulse] - Animate with a pulse effect
 * @param {string} [props.icon] - Optional icon element
 * @param {string} [props.className] - Additional CSS classes
 */
export default function Badge({
  children,
  variant = 'neutral',
  size = 'sm',
  dot = false,
  removable = false,
  onRemove,
  pulse = false,
  icon,
  className = '',
}) {
  const variantClass = VARIANT_STYLES[variant] || VARIANT_STYLES.neutral;
  const sizeClass = SIZE_STYLES[size] || SIZE_STYLES.sm;

  return (
    <span
      className={`
        inline-flex items-center gap-1.5 rounded-full border font-medium
        whitespace-nowrap select-none
        ${variantClass} ${sizeClass} ${className}
      `}
    >
      {dot && (
        <span className="relative flex h-2 w-2">
          {pulse && (
            <span
              className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                variant === 'critical' ? 'bg-red-400' :
                variant === 'high' ? 'bg-orange-400' :
                variant === 'success' ? 'bg-emerald-400' :
                'bg-current'
              }`}
            />
          )}
          <span className="relative inline-flex rounded-full h-2 w-2 bg-current" />
        </span>
      )}
      {icon && <span className="flex-shrink-0">{icon}</span>}
      {children}
      {removable && (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onRemove?.();
          }}
          className="ml-0.5 -mr-1 h-4 w-4 rounded-full inline-flex items-center justify-center
                     hover:bg-white/20 transition-colors focus:outline-none"
          aria-label={`Remove ${children}`}
        >
          <svg className="h-3 w-3" viewBox="0 0 12 12" fill="currentColor">
            <path d="M3.17 3.17a.75.75 0 011.06 0L6 4.94l1.77-1.77a.75.75 0 111.06 1.06L7.06 6l1.77 1.77a.75.75 0 11-1.06 1.06L6 7.06 4.23 8.83a.75.75 0 01-1.06-1.06L4.94 6 3.17 4.23a.75.75 0 010-1.06z" />
          </svg>
        </button>
      )}
    </span>
  );
}

/**
 * SeverityBadge - Convenience wrapper that maps severity strings to badge variants.
 */
export function SeverityBadge({ severity, ...props }) {
  const severityMap = {
    critical: { variant: 'critical', dot: true, pulse: true },
    high: { variant: 'high', dot: true },
    medium: { variant: 'medium' },
    low: { variant: 'low' },
    info: { variant: 'info' },
  };

  const config = severityMap[severity?.toLowerCase()] || severityMap.info;

  return (
    <Badge {...config} {...props}>
      {severity?.toUpperCase() || 'UNKNOWN'}
    </Badge>
  );
}

/**
 * MitreBadge - Badge specifically for MITRE ATT&CK technique IDs.
 */
export function MitreBadge({ techniqueId, techniqueName, ...props }) {
  return (
    <Badge variant="purple" size="xs" {...props}>
      {techniqueId}{techniqueName ? ` - ${techniqueName}` : ''}
    </Badge>
  );
}
