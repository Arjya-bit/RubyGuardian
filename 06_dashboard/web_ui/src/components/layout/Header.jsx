import React, { useState } from 'react';

export default function Header({ onToggleSidebar, agentStatus = 'connected' }) {
  const [showNotifications, setShowNotifications] = useState(false);

  const statusColors = {
    connected: 'bg-green-500',
    disconnected: 'bg-red-500',
    reconnecting: 'bg-yellow-500',
  };

  return (
    <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-6 py-3 flex items-center justify-between">
      <div className="flex items-center gap-4">
        <button
          onClick={onToggleSidebar}
          className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
          aria-label="Toggle sidebar"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>

        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${statusColors[agentStatus]}`} />
          <span className="text-sm text-gray-600 dark:text-gray-300 capitalize">
            Agent: {agentStatus}
          </span>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 relative"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
            </svg>
            <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
              3
            </span>
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg z-50">
              <div className="p-3 border-b border-gray-200 dark:border-gray-700 font-semibold text-sm">
                Recent Alerts
              </div>
              <div className="max-h-64 overflow-y-auto">
                {[
                  { severity: 'critical', message: 'Process injection detected on target-01', time: '2m ago' },
                  { severity: 'high', message: 'Suspicious eval() pattern in captured sample', time: '15m ago' },
                  { severity: 'medium', message: 'New connection to honeypot from 203.0.113.42', time: '1h ago' },
                ].map((alert, i) => (
                  <div key={i} className="p-3 border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 text-xs rounded font-medium ${
                        alert.severity === 'critical' ? 'bg-red-100 text-red-700' :
                        alert.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                        'bg-yellow-100 text-yellow-700'
                      }`}>
                        {alert.severity}
                      </span>
                      <span className="text-xs text-gray-400">{alert.time}</span>
                    </div>
                    <p className="text-sm mt-1 text-gray-700 dark:text-gray-300">{alert.message}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
