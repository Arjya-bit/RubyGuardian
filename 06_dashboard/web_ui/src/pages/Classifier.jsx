import React, { useState } from 'react';
import { apiService } from '../services/api';

export default function Classifier() {
  const [sourceCode, setSourceCode] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleClassify() {
    if (!sourceCode.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.classifyScript(sourceCode);
      setResult(data);
    } catch (err) {
      setError(err.message || 'Classification failed');
    } finally {
      setLoading(false);
    }
  }

  const riskColors = {
    critical: 'text-red-700 bg-red-100',
    high: 'text-orange-700 bg-orange-100',
    medium: 'text-yellow-700 bg-yellow-100',
    low: 'text-green-700 bg-green-100',
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">ML Classifier</h1>

      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold mb-4">Classify Ruby Script</h2>
        <textarea
          className="w-full h-48 p-4 border rounded-lg font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          placeholder="Paste Ruby source code here..."
          value={sourceCode}
          onChange={(e) => setSourceCode(e.target.value)}
        />
        <button
          onClick={handleClassify}
          disabled={loading || !sourceCode.trim()}
          className="mt-4 px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? 'Analyzing...' : 'Classify'}
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">{error}</div>
      )}

      {result && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold mb-4">Classification Result</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
              <span className="text-sm text-gray-500">Prediction</span>
              <p className="text-2xl font-bold capitalize">{result.prediction}</p>
            </div>
            <div>
              <span className="text-sm text-gray-500">Confidence</span>
              <p className="text-2xl font-bold">{(result.confidence * 100).toFixed(1)}%</p>
            </div>
            <div>
              <span className="text-sm text-gray-500">Risk Level</span>
              <p className={`text-2xl font-bold capitalize px-3 py-1 rounded inline-block ${riskColors[result.risk_level] || ''}`}>
                {result.risk_level}
              </p>
            </div>
          </div>
          {result.probabilities && (
            <div className="mt-6">
              <h3 className="text-sm font-medium text-gray-500 mb-2">Class Probabilities</h3>
              {Object.entries(result.probabilities).map(([cls, prob]) => (
                <div key={cls} className="flex items-center gap-3 mb-2">
                  <span className="w-24 text-sm capitalize">{cls}</span>
                  <div className="flex-1 bg-gray-200 rounded-full h-3">
                    <div
                      className="bg-blue-600 h-3 rounded-full"
                      style={{ width: `${prob * 100}%` }}
                    />
                  </div>
                  <span className="text-sm w-16 text-right">{(prob * 100).toFixed(1)}%</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
