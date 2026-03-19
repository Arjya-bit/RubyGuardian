import React, { useState, useCallback, useEffect } from 'react';
import { useApi } from '../hooks/useApi';
import LoadingSpinner from '../components/common/LoadingSpinner';
import ErrorBoundary from '../components/common/ErrorBoundary';

const SEVERITY_OPTIONS = ['info', 'low', 'medium', 'high', 'critical'];

const SETTING_SECTIONS = [
  { id: 'detection', label: 'Detection Engine', icon: 'shield' },
  { id: 'ml', label: 'ML Classifier', icon: 'cpu' },
  { id: 'notifications', label: 'Notifications', icon: 'bell' },
  { id: 'integrations', label: 'Integrations', icon: 'plug' },
  { id: 'system', label: 'System', icon: 'settings' },
];

function ToggleSwitch({ enabled, onChange, label }) {
  return (
    <label className="flex items-center justify-between cursor-pointer">
      <span className="text-sm text-gray-300">{label}</span>
      <button
        type="button"
        role="switch"
        aria-checked={enabled}
        onClick={() => onChange(!enabled)}
        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
          enabled ? 'bg-blue-600' : 'bg-dark-600'
        }`}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
            enabled ? 'translate-x-6' : 'translate-x-1'
          }`}
        />
      </button>
    </label>
  );
}

function SettingCard({ title, description, children }) {
  return (
    <div className="bg-dark-800 rounded-lg border border-dark-700 p-6">
      <h3 className="text-lg font-semibold text-white">{title}</h3>
      {description && <p className="text-sm text-gray-400 mt-1 mb-4">{description}</p>}
      <div className="space-y-4 mt-4">{children}</div>
    </div>
  );
}

export default function Settings() {
  const [activeSection, setActiveSection] = useState('detection');
  const [saveStatus, setSaveStatus] = useState(null);
  const { data: config, loading, error } = useApi('/api/settings');

  const [settings, setSettings] = useState({
    detection: {
      enabled: true,
      minSeverity: 'low',
      correlationWindow: 300,
      enableHeuristics: true,
      maxEventsPerSecond: 1000,
      enableSyscallMonitoring: true,
      enableNetworkMonitoring: true,
      enableFileMonitoring: true,
    },
    ml: {
      enabled: true,
      modelVersion: 'latest',
      confidenceThreshold: 0.85,
      batchSize: 64,
      enableAutoRetrain: false,
      retrainIntervalHours: 168,
      featureExtractionMode: 'full',
    },
    notifications: {
      emailEnabled: false,
      emailRecipients: '',
      slackEnabled: false,
      slackWebhookUrl: '',
      webhookEnabled: false,
      webhookUrl: '',
      minAlertSeverity: 'high',
    },
    integrations: {
      elasticsearchUrl: 'http://elasticsearch:9200',
      kibanaUrl: 'http://kibana:5601',
      grafanaUrl: 'http://grafana:3000',
      syslogForwardEnabled: false,
      syslogHost: '',
      syslogPort: 514,
    },
    system: {
      logLevel: 'info',
      dataRetentionDays: 90,
      maxStorageGb: 50,
      enableMetrics: true,
      metricsPort: 9090,
      enableProfiling: false,
    },
  });

  useEffect(() => {
    if (config) setSettings((prev) => ({ ...prev, ...config }));
  }, [config]);

  const updateSetting = useCallback((section, key, value) => {
    setSettings((prev) => ({
      ...prev,
      [section]: { ...prev[section], [key]: value },
    }));
    setSaveStatus(null);
  }, []);

  const handleSave = useCallback(async () => {
    setSaveStatus('saving');
    try {
      await fetch('/api/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      });
      setSaveStatus('saved');
      setTimeout(() => setSaveStatus(null), 3000);
    } catch {
      setSaveStatus('error');
    }
  }, [settings]);

  if (loading) return <LoadingSpinner message="Loading settings..." />;

  const renderDetection = () => (
    <div className="space-y-6">
      <SettingCard title="Detection Engine" description="Configure the real-time threat detection engine.">
        <ToggleSwitch
          label="Enable Detection Engine"
          enabled={settings.detection.enabled}
          onChange={(v) => updateSetting('detection', 'enabled', v)}
        />
        <div>
          <label className="block text-sm text-gray-300 mb-1">Minimum Alert Severity</label>
          <select
            value={settings.detection.minSeverity}
            onChange={(e) => updateSetting('detection', 'minSeverity', e.target.value)}
            className="w-full bg-dark-700 border border-dark-600 rounded px-3 py-2 text-white"
          >
            {SEVERITY_OPTIONS.map((s) => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-sm text-gray-300 mb-1">Correlation Window (seconds)</label>
          <input
            type="number"
            value={settings.detection.correlationWindow}
            onChange={(e) => updateSetting('detection', 'correlationWindow', parseInt(e.target.value, 10))}
            className="w-full bg-dark-700 border border-dark-600 rounded px-3 py-2 text-white"
            min={10}
            max={3600}
          />
        </div>
        <div>
          <label className="block text-sm text-gray-300 mb-1">Max Events/Second</label>
          <input
            type="number"
            value={settings.detection.maxEventsPerSecond}
            onChange={(e) => updateSetting('detection', 'maxEventsPerSecond', parseInt(e.target.value, 10))}
            className="w-full bg-dark-700 border border-dark-600 rounded px-3 py-2 text-white"
            min={100}
            max={10000}
          />
        </div>
      </SettingCard>
      <SettingCard title="Monitoring Sources" description="Enable or disable individual monitoring subsystems.">
        <ToggleSwitch
          label="Syscall Monitoring"
          enabled={settings.detection.enableSyscallMonitoring}
          onChange={(v) => updateSetting('detection', 'enableSyscallMonitoring', v)}
        />
        <ToggleSwitch
          label="Network Monitoring"
          enabled={settings.detection.enableNetworkMonitoring}
          onChange={(v) => updateSetting('detection', 'enableNetworkMonitoring', v)}
        />
        <ToggleSwitch
          label="File System Monitoring"
          enabled={settings.detection.enableFileMonitoring}
          onChange={(v) => updateSetting('detection', 'enableFileMonitoring', v)}
        />
        <ToggleSwitch
          label="Heuristic Analysis"
          enabled={settings.detection.enableHeuristics}
          onChange={(v) => updateSetting('detection', 'enableHeuristics', v)}
        />
      </SettingCard>
    </div>
  );

  const renderMl = () => (
    <SettingCard title="ML Classifier" description="Configure the machine learning threat classifier.">
      <ToggleSwitch
        label="Enable ML Classification"
        enabled={settings.ml.enabled}
        onChange={(v) => updateSetting('ml', 'enabled', v)}
      />
      <div>
        <label className="block text-sm text-gray-300 mb-1">
          Confidence Threshold: {settings.ml.confidenceThreshold}
        </label>
        <input
          type="range"
          min="0.5"
          max="0.99"
          step="0.01"
          value={settings.ml.confidenceThreshold}
          onChange={(e) => updateSetting('ml', 'confidenceThreshold', parseFloat(e.target.value))}
          className="w-full"
        />
      </div>
      <div>
        <label className="block text-sm text-gray-300 mb-1">Batch Size</label>
        <select
          value={settings.ml.batchSize}
          onChange={(e) => updateSetting('ml', 'batchSize', parseInt(e.target.value, 10))}
          className="w-full bg-dark-700 border border-dark-600 rounded px-3 py-2 text-white"
        >
          {[16, 32, 64, 128, 256].map((b) => (
            <option key={b} value={b}>{b}</option>
          ))}
        </select>
      </div>
      <ToggleSwitch
        label="Auto-Retrain on Drift"
        enabled={settings.ml.enableAutoRetrain}
        onChange={(v) => updateSetting('ml', 'enableAutoRetrain', v)}
      />
    </SettingCard>
  );

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-white">Settings</h1>
          <button
            onClick={handleSave}
            disabled={saveStatus === 'saving'}
            className={`px-6 py-2 rounded font-medium transition-colors ${
              saveStatus === 'saved'
                ? 'bg-green-600 text-white'
                : saveStatus === 'error'
                ? 'bg-red-600 text-white'
                : 'bg-blue-600 text-white hover:bg-blue-700'
            }`}
          >
            {saveStatus === 'saving' ? 'Saving...' : saveStatus === 'saved' ? 'Saved' : 'Save Changes'}
          </button>
        </div>

        <div className="flex gap-6">
          <nav className="w-48 flex-shrink-0 space-y-1">
            {SETTING_SECTIONS.map((section) => (
              <button
                key={section.id}
                onClick={() => setActiveSection(section.id)}
                className={`w-full text-left px-4 py-2 rounded text-sm font-medium transition-colors ${
                  activeSection === section.id
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-dark-800'
                }`}
              >
                {section.label}
              </button>
            ))}
          </nav>

          <div className="flex-1">
            {activeSection === 'detection' && renderDetection()}
            {activeSection === 'ml' && renderMl()}
            {activeSection === 'notifications' && (
              <SettingCard title="Notifications" description="Configure alert notification channels.">
                <ToggleSwitch
                  label="Email Notifications"
                  enabled={settings.notifications.emailEnabled}
                  onChange={(v) => updateSetting('notifications', 'emailEnabled', v)}
                />
                <ToggleSwitch
                  label="Slack Notifications"
                  enabled={settings.notifications.slackEnabled}
                  onChange={(v) => updateSetting('notifications', 'slackEnabled', v)}
                />
                <div>
                  <label className="block text-sm text-gray-300 mb-1">Minimum Alert Severity</label>
                  <select
                    value={settings.notifications.minAlertSeverity}
                    onChange={(e) => updateSetting('notifications', 'minAlertSeverity', e.target.value)}
                    className="w-full bg-dark-700 border border-dark-600 rounded px-3 py-2 text-white"
                  >
                    {SEVERITY_OPTIONS.map((s) => (
                      <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                    ))}
                  </select>
                </div>
              </SettingCard>
            )}
            {activeSection === 'integrations' && (
              <SettingCard title="Integrations" description="External service connections.">
                <p className="text-sm text-gray-400">
                  Elasticsearch: {settings.integrations.elasticsearchUrl}
                </p>
                <p className="text-sm text-gray-400">
                  Kibana: {settings.integrations.kibanaUrl}
                </p>
              </SettingCard>
            )}
            {activeSection === 'system' && (
              <SettingCard title="System" description="General system settings.">
                <div>
                  <label className="block text-sm text-gray-300 mb-1">Log Level</label>
                  <select
                    value={settings.system.logLevel}
                    onChange={(e) => updateSetting('system', 'logLevel', e.target.value)}
                    className="w-full bg-dark-700 border border-dark-600 rounded px-3 py-2 text-white"
                  >
                    {['debug', 'info', 'warn', 'error'].map((l) => (
                      <option key={l} value={l}>{l.toUpperCase()}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-gray-300 mb-1">Data Retention (days)</label>
                  <input
                    type="number"
                    value={settings.system.dataRetentionDays}
                    onChange={(e) => updateSetting('system', 'dataRetentionDays', parseInt(e.target.value, 10))}
                    className="w-full bg-dark-700 border border-dark-600 rounded px-3 py-2 text-white"
                    min={7}
                    max={365}
                  />
                </div>
                <ToggleSwitch
                  label="Enable Prometheus Metrics"
                  enabled={settings.system.enableMetrics}
                  onChange={(v) => updateSetting('system', 'enableMetrics', v)}
                />
              </SettingCard>
            )}
          </div>
        </div>

        {error && (
          <div className="bg-red-900/30 border border-red-700 rounded p-4 text-red-300 text-sm">
            Warning: Could not load saved settings. Showing defaults. Error: {error.message}
          </div>
        )}
      </div>
    </ErrorBoundary>
  );
}
