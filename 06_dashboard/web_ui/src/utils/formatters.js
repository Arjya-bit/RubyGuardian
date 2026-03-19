/**
 * RubyGuardian Dashboard - Formatting Utilities
 *
 * Date, number, byte, and security-specific formatters
 * used across the dashboard UI components.
 */

/**
 * Format a timestamp into a human-readable relative time string.
 * @param {string|number|Date} timestamp - The timestamp to format
 * @returns {string} Relative time string (e.g., "2 minutes ago")
 */
export function timeAgo(timestamp) {
  if (!timestamp) return 'Unknown';
  const now = Date.now();
  const then = new Date(timestamp).getTime();
  const diffMs = now - then;

  if (diffMs < 0) return 'Just now';

  const seconds = Math.floor(diffMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (seconds < 10) return 'Just now';
  if (seconds < 60) return `${seconds}s ago`;
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;
  return formatDate(timestamp);
}

/**
 * Format a timestamp to locale date string.
 * @param {string|number|Date} timestamp
 * @param {Object} [options] - Intl.DateTimeFormat options
 * @returns {string}
 */
export function formatDate(timestamp, options = {}) {
  if (!timestamp) return '--';
  const defaults = { year: 'numeric', month: 'short', day: 'numeric' };
  return new Date(timestamp).toLocaleDateString(undefined, { ...defaults, ...options });
}

/**
 * Format a timestamp to locale time string with seconds.
 * @param {string|number|Date} timestamp
 * @returns {string}
 */
export function formatTime(timestamp) {
  if (!timestamp) return '--:--:--';
  return new Date(timestamp).toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

/**
 * Format a timestamp to full datetime string.
 * @param {string|number|Date} timestamp
 * @returns {string}
 */
export function formatDateTime(timestamp) {
  if (!timestamp) return '--';
  return `${formatDate(timestamp)} ${formatTime(timestamp)}`;
}

/**
 * Format a number with locale-appropriate separators.
 * @param {number} value
 * @param {number} [decimals=0] - Number of decimal places
 * @returns {string}
 */
export function formatNumber(value, decimals = 0) {
  if (value == null || isNaN(value)) return '--';
  return Number(value).toLocaleString(undefined, {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
}

/**
 * Format bytes into human-readable string (KB, MB, GB, etc.).
 * @param {number} bytes - Number of bytes
 * @param {number} [decimals=1] - Decimal places
 * @returns {string}
 */
export function formatBytes(bytes, decimals = 1) {
  if (bytes == null || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
  const value = bytes / Math.pow(k, i);
  return `${value.toFixed(decimals)} ${sizes[i]}`;
}

/**
 * Format a percentage value.
 * @param {number} value - Value between 0 and 1 (or 0-100 if isPercent=true)
 * @param {number} [decimals=1] - Decimal places
 * @param {boolean} [isPercent=false] - If true, value is already 0-100
 * @returns {string}
 */
export function formatPercent(value, decimals = 1, isPercent = false) {
  if (value == null || isNaN(value)) return '--';
  const pct = isPercent ? value : value * 100;
  return `${pct.toFixed(decimals)}%`;
}

/**
 * Format a duration in milliseconds to human-readable string.
 * @param {number} ms - Duration in milliseconds
 * @returns {string}
 */
export function formatDuration(ms) {
  if (ms == null) return '--';
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
  const hours = Math.floor(ms / 3600000);
  const minutes = Math.floor((ms % 3600000) / 60000);
  return `${hours}h ${minutes}m`;
}

/**
 * Format an IP address with optional port.
 * @param {string} ip - IP address
 * @param {number} [port] - Port number
 * @returns {string}
 */
export function formatIpAddress(ip, port) {
  if (!ip) return '--';
  if (port) return `${ip}:${port}`;
  return ip;
}

/**
 * Format a process ID for display.
 * @param {number} pid
 * @returns {string}
 */
export function formatPid(pid) {
  if (pid == null) return '--';
  return String(pid).padStart(5, ' ');
}

/**
 * Format a threat score (0-1) with color-coded label.
 * @param {number} score - Score between 0 and 1
 * @returns {{ label: string, value: string, level: string }}
 */
export function formatThreatScore(score) {
  if (score == null || isNaN(score)) return { label: 'Unknown', value: '--', level: 'unknown' };
  const pct = Math.round(score * 100);
  if (pct >= 80) return { label: 'Critical', value: `${pct}`, level: 'critical' };
  if (pct >= 60) return { label: 'High', value: `${pct}`, level: 'high' };
  if (pct >= 40) return { label: 'Medium', value: `${pct}`, level: 'medium' };
  if (pct >= 20) return { label: 'Low', value: `${pct}`, level: 'low' };
  return { label: 'Info', value: `${pct}`, level: 'info' };
}

/**
 * Format a MITRE ATT&CK technique ID for display.
 * @param {string} techniqueId - e.g., "T1055.012"
 * @returns {string}
 */
export function formatMitreTechnique(techniqueId) {
  if (!techniqueId) return '--';
  return techniqueId.toUpperCase();
}

/**
 * Truncate a string with ellipsis if it exceeds maxLength.
 * @param {string} str
 * @param {number} [maxLength=50]
 * @returns {string}
 */
export function truncate(str, maxLength = 50) {
  if (!str) return '';
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + '...';
}

/**
 * Format a hex address (e.g., memory address).
 * @param {number|string} address
 * @param {number} [width=16] - Pad to this many hex digits
 * @returns {string}
 */
export function formatHexAddress(address, width = 16) {
  if (address == null) return '--';
  const hex = typeof address === 'number' ? address.toString(16) : String(address);
  return '0x' + hex.padStart(width, '0').toUpperCase();
}
