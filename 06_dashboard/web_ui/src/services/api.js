/**
 * RubyGuardian Dashboard - API Service
 *
 * Centralized API client for communicating with the RubyGuardian backend
 * services (detection engine, ML classifier, honeypot, Elasticsearch).
 */

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';
const ES_BASE = import.meta.env.VITE_ES_BASE || 'http://localhost:9200';

async function fetchJSON(url, options = {}) {
  const response = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });

  if (!response.ok) {
    const error = await response.text().catch(() => 'Unknown error');
    throw new Error(`API error ${response.status}: ${error}`);
  }

  return response.json();
}

export const apiService = {
  // Health check
  async healthCheck() {
    return fetchJSON(`${API_BASE}/health`);
  },

  // Dashboard stats
  async getStats() {
    return fetchJSON(`${API_BASE}/stats`).catch(() => ({
      active_alerts: 0,
      agents_online: 0,
      samples_analyzed: 0,
      detection_rate: 0,
    }));
  },

  // Recent alerts from Elasticsearch
  async getRecentAlerts(limit = 50) {
    try {
      const data = await fetchJSON(`${ES_BASE}/ruby-guardian-events-*/_search`, {
        method: 'POST',
        body: JSON.stringify({
          size: limit,
          sort: [{ '@timestamp': { order: 'desc' } }],
          query: { match_all: {} },
        }),
      });
      return data.hits?.hits?.map((h) => h._source) || [];
    } catch {
      return [];
    }
  },

  // ML Classifier
  async classifyScript(sourceCode) {
    return fetchJSON(`${API_BASE}/classify`, {
      method: 'POST',
      body: JSON.stringify({ source_code: sourceCode, include_features: true }),
    });
  },

  async getModelInfo() {
    return fetchJSON(`${API_BASE}/model/info`);
  },

  // Honeypot
  async getHoneypotCaptures(limit = 50) {
    try {
      const data = await fetchJSON(`${ES_BASE}/honeypot-captures-*/_search`, {
        method: 'POST',
        body: JSON.stringify({
          size: limit,
          sort: [{ timestamp: { order: 'desc' } }],
        }),
      });
      return data.hits?.hits?.map((h) => h._source) || [];
    } catch {
      return [];
    }
  },

  async getHoneypotStats() {
    return fetchJSON(`${API_BASE}/honeypot/stats`).catch(() => ({
      total_captures: 0,
      unique_attackers: 0,
      samples_collected: 0,
    }));
  },

  // Forensics
  async getForensicReports(limit = 20) {
    try {
      const data = await fetchJSON(`${ES_BASE}/forensic-reports-*/_search`, {
        method: 'POST',
        body: JSON.stringify({
          size: limit,
          sort: [{ timestamp: { order: 'desc' } }],
        }),
      });
      return data.hits?.hits?.map((h) => h._source) || [];
    } catch {
      return [];
    }
  },
};
