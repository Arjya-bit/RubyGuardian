import React from 'react';

const SIZE_CLASSES = {
  sm: 'h-4 w-4 border-2',
  md: 'h-8 w-8 border-2',
  lg: 'h-12 w-12 border-3',
  xl: 'h-16 w-16 border-4',
};

const COLOR_CLASSES = {
  blue: 'border-blue-500',
  red: 'border-red-500',
  green: 'border-green-500',
  white: 'border-white',
  gray: 'border-gray-400',
};

/**
 * LoadingSpinner - Animated spinner for loading states.
 *
 * @param {Object} props
 * @param {'sm'|'md'|'lg'|'xl'} [props.size='lg'] - Spinner size
 * @param {'blue'|'red'|'green'|'white'|'gray'} [props.color='blue'] - Spinner color
 * @param {string} [props.message] - Optional loading message
 * @param {boolean} [props.fullScreen] - Center in full viewport
 * @param {boolean} [props.overlay] - Show with dark overlay background
 * @param {string} [props.className] - Additional CSS classes
 */
export default function LoadingSpinner({
  size = 'lg',
  color = 'blue',
  message,
  fullScreen = false,
  overlay = false,
  className = '',
}) {
  const sizeClass = SIZE_CLASSES[size] || SIZE_CLASSES.lg;
  const colorClass = COLOR_CLASSES[color] || COLOR_CLASSES.blue;

  const spinner = (
    <div className={`flex flex-col items-center justify-center gap-3 ${className}`}>
      <div
        className={`animate-spin rounded-full border-t-transparent ${sizeClass} ${colorClass}`}
        role="status"
        aria-label="Loading"
      />
      {message && (
        <p className="text-sm text-gray-400 animate-pulse">{message}</p>
      )}
    </div>
  );

  if (fullScreen) {
    return (
      <div className="fixed inset-0 flex items-center justify-center z-50 bg-dark-950">
        {spinner}
      </div>
    );
  }

  if (overlay) {
    return (
      <div className="absolute inset-0 flex items-center justify-center z-40 bg-dark-950/80 backdrop-blur-sm rounded-lg">
        {spinner}
      </div>
    );
  }

  return (
    <div className="flex items-center justify-center py-12">
      {spinner}
    </div>
  );
}

/**
 * InlineSpinner - Small inline spinner for buttons and text.
 */
export function InlineSpinner({ size = 'sm', color = 'white' }) {
  const sizeClass = SIZE_CLASSES[size] || SIZE_CLASSES.sm;
  const colorClass = COLOR_CLASSES[color] || COLOR_CLASSES.white;

  return (
    <span
      className={`inline-block animate-spin rounded-full border-t-transparent ${sizeClass} ${colorClass}`}
      role="status"
      aria-label="Loading"
    />
  );
}

/**
 * SkeletonLoader - Placeholder skeleton for content that is loading.
 */
export function SkeletonLoader({ lines = 3, className = '' }) {
  return (
    <div className={`animate-pulse space-y-3 ${className}`} role="status" aria-label="Loading content">
      {Array.from({ length: lines }, (_, i) => (
        <div
          key={i}
          className="h-4 bg-dark-700 rounded"
          style={{ width: `${Math.max(40, 100 - i * 15)}%` }}
        />
      ))}
    </div>
  );
}
