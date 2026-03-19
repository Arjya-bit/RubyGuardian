/**
 * RubyGuardian Dashboard - Application Constants
 *
 * Central location for all configuration constants, enums,
 * endpoint URLs, and static mappings used throughout the dashboard.
 */

// --- API Configuration ---
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';
export const WS_BASE_URL = import.meta.env.VITE_WS_BASE_URL || `ws://${window.location.host}/ws`;
export const API_TIMEOUT = 30000;
export const API_RETRY_COUNT = 3;
export const API_RETRY_DELAY = 1000;

// --- API Endpoints ---
export const ENDPOINTS = {
  EVENTS: '/events',
  ALERTS: '/alerts',
  FORENSICS: '/forensics/reports',
  FORENSICS_IOCS: '/forensics/iocs',
  FORENSICS_MEMORY: '/forensics/memory-dump',
  CLASSIFIER: '/classifier',
  CLASSIFIER_FEATURES: '/classifier/features',
  CLASSIFIER_PREDICT: '/classifier/predict',
  HONEYPOT: '/honeypot/captures',
  SETTINGS: '/settings',
  HEALTH: '/health',
  METRICS: '/metrics',
  ERRORS_REPORT: '/errors/report',
};

// --- WebSocket Channels ---
export const WS_CHANNELS = {
  EVENTS: 'events',
  ALERTS: 'alerts',
  FORENSICS: 'forensics',
  METRICS: 'metrics',
  HONEYPOT: 'honeypot',
};

// --- Severity Levels ---
export const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_CONFIG = {
  critical: { label: 'Critical', color: '#ff1744', bgClass: 'bg-red-500', textClass: 'text-red-400', weight: 5 },
  high: { label: 'High', color: '#ff6d00', bgClass: 'bg-orange-500', textClass: 'text-orange-400', weight: 4 },
  medium: { label: 'Medium', color: '#ffab00', bgClass: 'bg-amber-500', textClass: 'text-amber-400', weight: 3 },
  low: { label: 'Low', color: '#66bb6a', bgClass: 'bg-green-500', textClass: 'text-green-400', weight: 2 },
  info: { label: 'Info', color: '#42a5f5', bgClass: 'bg-blue-500', textClass: 'text-blue-400', weight: 1 },
};

// --- Alert Statuses ---
export const ALERT_STATUSES = ['new', 'acknowledged', 'investigating', 'resolved', 'false_positive'];

export const ALERT_STATUS_CONFIG = {
  new: { label: 'New', variant: 'error', color: '#ff1744' },
  acknowledged: { label: 'Acknowledged', variant: 'warning', color: '#ffab00' },
  investigating: { label: 'Investigating', variant: 'info', color: '#42a5f5' },
  resolved: { label: 'Resolved', variant: 'success', color: '#66bb6a' },
  false_positive: { label: 'False Positive', variant: 'neutral', color: '#9e9e9e' },
};

// --- Event Types ---
export const EVENT_TYPES = {
  PROCESS_SPAWN: 'process_spawn',
  NETWORK_CONNECT: 'network_connect',
  FILE_WRITE: 'file_write',
  FILE_READ: 'file_read',
  MEMORY_INJECTION: 'memory_injection',
  CODE_EXECUTION: 'code_execution',
  DNS_QUERY: 'dns_query',
  SYSCALL_ANOMALY: 'syscall_anomaly',
  PRIVILEGE_ESCALATION: 'privilege_escalation',
  REGISTRY_MODIFICATION: 'registry_modification',
};

export const EVENT_TYPE_LABELS = {
  [EVENT_TYPES.PROCESS_SPAWN]: 'Process Spawn',
  [EVENT_TYPES.NETWORK_CONNECT]: 'Network Connection',
  [EVENT_TYPES.FILE_WRITE]: 'File Write',
  [EVENT_TYPES.FILE_READ]: 'File Read',
  [EVENT_TYPES.MEMORY_INJECTION]: 'Memory Injection',
  [EVENT_TYPES.CODE_EXECUTION]: 'Code Execution',
  [EVENT_TYPES.DNS_QUERY]: 'DNS Query',
  [EVENT_TYPES.SYSCALL_ANOMALY]: 'Syscall Anomaly',
  [EVENT_TYPES.PRIVILEGE_ESCALATION]: 'Privilege Escalation',
  [EVENT_TYPES.REGISTRY_MODIFICATION]: 'Registry Modification',
};

// --- MITRE ATT&CK Tactics ---
export const MITRE_TACTICS = {
  TA0001: 'Initial Access',
  TA0002: 'Execution',
  TA0003: 'Persistence',
  TA0004: 'Privilege Escalation',
  TA0005: 'Defense Evasion',
  TA0006: 'Credential Access',
  TA0007: 'Discovery',
  TA0008: 'Lateral Movement',
  TA0009: 'Collection',
  TA0010: 'Exfiltration',
  TA0011: 'Command and Control',
  TA0040: 'Impact',
};

// --- Key MITRE Techniques for RubyGuardian ---
export const MITRE_TECHNIQUES = {
  'T1059.005': { name: 'Ruby Script Execution', tactic: 'TA0002' },
  'T1055.012': { name: 'Process Hollowing', tactic: 'TA0005' },
  'T1055.001': { name: 'DLL Injection', tactic: 'TA0005' },
  'T1027': { name: 'Obfuscated Files/Info', tactic: 'TA0005' },
  'T1041': { name: 'Exfiltration Over C2', tactic: 'TA0010' },
  'T1071.001': { name: 'Web Protocols', tactic: 'TA0011' },
  'T1071.004': { name: 'DNS C2', tactic: 'TA0011' },
  'T1140': { name: 'Deobfuscate/Decode', tactic: 'TA0005' },
  'T1106': { name: 'Native API', tactic: 'TA0002' },
  'T1082': { name: 'System Discovery', tactic: 'TA0007' },
};

// --- IOC Types ---
export const IOC_TYPES = ['ip', 'domain', 'hash_md5', 'hash_sha256', 'url', 'file_path', 'email', 'mutex', 'registry_key', 'user_agent'];

// --- Dashboard Refresh Intervals ---
export const REFRESH_INTERVALS = {
  REAL_TIME: 1000,
  FAST: 5000,
  NORMAL: 15000,
  SLOW: 60000,
  MANUAL: 0,
};

// --- Time Range Options ---
export const TIME_RANGES = [
  { value: '15m', label: 'Last 15 Minutes' },
  { value: '1h', label: 'Last Hour' },
  { value: '6h', label: 'Last 6 Hours' },
  { value: '24h', label: 'Last 24 Hours' },
  { value: '7d', label: 'Last 7 Days' },
  { value: '30d', label: 'Last 30 Days' },
  { value: 'custom', label: 'Custom Range' },
];

// --- Chart Color Palettes ---
export const CHART_COLORS = {
  severity: ['#ff1744', '#ff6d00', '#ffab00', '#66bb6a', '#42a5f5'],
  categorical: ['#42a5f5', '#ab47bc', '#26a69a', '#ff7043', '#8d6e63', '#78909c', '#ec407a', '#7e57c2'],
  sequential: ['#e3f2fd', '#90caf9', '#42a5f5', '#1e88e5', '#1565c0', '#0d47a1'],
};

// --- Pagination ---
export const DEFAULT_PAGE_SIZE = 25;
export const PAGE_SIZE_OPTIONS = [10, 25, 50, 100];

// --- Application Metadata ---
export const APP_NAME = 'RubyGuardian';
export const APP_VERSION = '1.0.0';
export const APP_DESCRIPTION = 'Ruby Runtime Security Monitoring & Threat Detection Platform';
