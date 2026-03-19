import React, { useState, useMemo } from 'react';
import { useApi } from '../../hooks/useApi';
import LoadingSpinner from '../common/LoadingSpinner';

const BAR_COLORS = [
  'bg-blue-500', 'bg-cyan-500', 'bg-emerald-500', 'bg-amber-500', 'bg-red-500',
  'bg-purple-500', 'bg-pink-500', 'bg-indigo-500', 'bg-teal-500', 'bg-orange-500',
];

/**
 * FeatureChart - Visualizes ML classifier feature importance scores
 * as horizontal bar charts with comparison between models and analysis views.
 *
 * @param {Object} props
 * @param {Array} [props.features] - Array of { name, importance, category } objects
 * @param {string} [props.modelVersion] - Current model version identifier
 * @param {boolean} [props.showCategories] - Group features by category
 * @param {number} [props.topN] - Number of top features to display
 */
export default function FeatureChart({
  features: propFeatures,
  modelVersion = 'latest',
  showCategories = true,
  topN = 20,
}) {
  const [viewMode, setViewMode] = useState('importance');
  const [hoveredFeature, setHoveredFeature] = useState(null);
  const [selectedCategory, setSelectedCategory] = useState('all');

  const { data: apiFeatures, loading } = useApi(
    !propFeatures ? `/api/classifier/features?model=${modelVersion}` : null
  );

  const features = propFeatures || apiFeatures || [];

  const sortedFeatures = useMemo(() => {
    let result = [...features];

    if (selectedCategory !== 'all') {
      result = result.filter((f) => f.category === selectedCategory);
    }

    result.sort((a, b) => (b.importance || 0) - (a.importance || 0));
    return result.slice(0, topN);
  }, [features, topN, selectedCategory]);

  const categories = useMemo(() => {
    const cats = new Set(features.map((f) => f.category).filter(Boolean));
    return Array.from(cats).sort();
  }, [features]);

  const maxImportance = useMemo(() => {
    return Math.max(...sortedFeatures.map((f) => f.importance || 0), 0.01);
  }, [sortedFeatures]);

  const categoryStats = useMemo(() => {
    const stats = {};
    features.forEach((f) => {
      const cat = f.category || 'uncategorized';
      if (!stats[cat]) stats[cat] = { count: 0, totalImportance: 0, maxImportance: 0 };
      stats[cat].count++;
      stats[cat].totalImportance += f.importance || 0;
      stats[cat].maxImportance = Math.max(stats[cat].maxImportance, f.importance || 0);
    });
    return stats;
  }, [features]);

  if (loading) return <LoadingSpinner message="Loading feature importance data..." />;

  return (
    <div className="bg-dark-800 rounded-lg border border-dark-700 overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-dark-700">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 className="text-lg font-semibold text-white">Feature Importance</h3>
            <p className="text-xs text-gray-400 mt-0.5">
              Model: {modelVersion} &middot; {features.length} features total
            </p>
          </div>
          <div className="flex gap-1">
            {['importance', 'category', 'distribution'].map((mode) => (
              <button
                key={mode}
                onClick={() => setViewMode(mode)}
                className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                  viewMode === mode ? 'bg-blue-600 text-white' : 'bg-dark-700 text-gray-400 hover:text-white'
                }`}
              >
                {mode.charAt(0).toUpperCase() + mode.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {showCategories && viewMode === 'importance' && (
          <div className="flex gap-2 flex-wrap">
            <button
              onClick={() => setSelectedCategory('all')}
              className={`px-2 py-0.5 rounded text-xs ${
                selectedCategory === 'all' ? 'bg-blue-600 text-white' : 'bg-dark-700 text-gray-400'
              }`}
            >
              All
            </button>
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-2 py-0.5 rounded text-xs ${
                  selectedCategory === cat ? 'bg-blue-600 text-white' : 'bg-dark-700 text-gray-400'
                }`}
              >
                {cat} ({categoryStats[cat]?.count || 0})
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Importance Bar Chart */}
      {viewMode === 'importance' && (
        <div className="p-4 space-y-2">
          {sortedFeatures.length === 0 && (
            <p className="text-center text-gray-500 py-4">No features to display.</p>
          )}
          {sortedFeatures.map((feature, idx) => {
            const pct = ((feature.importance || 0) / maxImportance) * 100;
            const colorClass = BAR_COLORS[idx % BAR_COLORS.length];
            const isHovered = hoveredFeature === feature.name;

            return (
              <div
                key={feature.name}
                className={`group flex items-center gap-3 py-1.5 px-2 rounded transition-colors ${
                  isHovered ? 'bg-dark-700' : ''
                }`}
                onMouseEnter={() => setHoveredFeature(feature.name)}
                onMouseLeave={() => setHoveredFeature(null)}
              >
                <span className="text-xs text-gray-400 w-6 text-right">{idx + 1}</span>
                <span className="text-sm text-gray-300 w-48 truncate font-mono" title={feature.name}>
                  {feature.name}
                </span>
                <div className="flex-1 h-5 bg-dark-900 rounded overflow-hidden relative">
                  <div
                    className={`h-full ${colorClass} rounded transition-all duration-500`}
                    style={{ width: `${pct}%` }}
                  />
                  {isHovered && (
                    <span className="absolute inset-0 flex items-center justify-center text-xs text-white font-medium">
                      {(feature.importance * 100).toFixed(2)}%
                    </span>
                  )}
                </div>
                <span className="text-xs text-gray-500 w-16 text-right font-mono">
                  {feature.importance?.toFixed(4)}
                </span>
              </div>
            );
          })}
        </div>
      )}

      {/* Category Overview */}
      {viewMode === 'category' && (
        <div className="p-4 space-y-4">
          {Object.entries(categoryStats)
            .sort(([, a], [, b]) => b.totalImportance - a.totalImportance)
            .map(([cat, stats], idx) => (
              <div key={cat} className="bg-dark-900 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-medium text-white">{cat}</h4>
                  <span className="text-xs text-gray-400">{stats.count} features</span>
                </div>
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div>
                    <p className="text-xs text-gray-500">Total Importance</p>
                    <p className="text-lg font-bold text-blue-400">{(stats.totalImportance * 100).toFixed(1)}%</p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-500">Max Feature</p>
                    <p className="text-lg font-bold text-emerald-400">{(stats.maxImportance * 100).toFixed(1)}%</p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-500">Avg Importance</p>
                    <p className="text-lg font-bold text-amber-400">
                      {((stats.totalImportance / stats.count) * 100).toFixed(1)}%
                    </p>
                  </div>
                </div>
                <div className="mt-2 h-2 bg-dark-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${BAR_COLORS[idx % BAR_COLORS.length]} rounded-full`}
                    style={{ width: `${Math.min(100, stats.totalImportance * 100)}%` }}
                  />
                </div>
              </div>
            ))}
        </div>
      )}

      {/* Distribution View */}
      {viewMode === 'distribution' && (
        <div className="p-4">
          <div className="h-64 flex items-end gap-1 px-4">
            {(() => {
              const buckets = Array(20).fill(0);
              features.forEach((f) => {
                const idx = Math.min(19, Math.floor((f.importance || 0) * 20));
                buckets[idx]++;
              });
              const maxBucket = Math.max(...buckets, 1);
              return buckets.map((count, i) => (
                <div key={i} className="flex-1 flex flex-col items-center gap-1">
                  <span className="text-[10px] text-gray-500">{count}</span>
                  <div
                    className="w-full bg-blue-500 rounded-t transition-all duration-300 min-h-[2px]"
                    style={{ height: `${(count / maxBucket) * 200}px` }}
                  />
                </div>
              ));
            })()}
          </div>
          <div className="flex justify-between px-4 mt-1">
            <span className="text-[10px] text-gray-500">0%</span>
            <span className="text-[10px] text-gray-500">50%</span>
            <span className="text-[10px] text-gray-500">100%</span>
          </div>
          <p className="text-center text-xs text-gray-400 mt-2">Feature importance distribution</p>
        </div>
      )}

      {/* Footer */}
      <div className="p-3 border-t border-dark-700 text-xs text-gray-500 flex items-center justify-between">
        <span>Showing top {sortedFeatures.length} of {features.length} features</span>
        <span>Model version: {modelVersion}</span>
      </div>
    </div>
  );
}
