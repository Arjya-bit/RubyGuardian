import React, { useState, useRef, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { useApp } from '../App';

const pageTitles = {
  '/dashboard': 'Threat Dashboard',
  '/processes': 'Process Monitor',
  '/classifier': 'ML Classifier',
  '/forensics': 'Forensic Analysis',
  '/honeypot': 'Honeypot Intelligence',
  '/settings': 'Settings',
};

function ConnectionBadge({ status }) {
  const colors = {
    connected: 'bg-green-500',
    connecting: 'bg-yellow-500 animate-pulse',
    disconnected: 'bg-red-500',
    error: 'bg-red-500',
  };

  return (
    <div className="flex items-center gap-2 text-xs text-dark-400">
      <span className={`w-2 h-2 rounded-full ${colors[status] || colors.disconnected}`} />
      <span className="hidden sm:inline capitalize">{status}</span>
    </div>
  );
}

function NotificationDropdown({ notifications, onClear }) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const unreadCount = notifications.filter((n) => !n.read).length;

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="relative p-2 rounded-lg text-dark-400 hover:text-dark-200 hover:bg-dark-800 transition-colors"
      >
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
        </svg>
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 w-4 h-4 rounded-full bg-red-500 text-white text-[10px] flex items-center justify-center font-bold">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {isOpen && (
        <div className="absolute right-0 top-full mt-2 w-80 bg-dark-800 border border-dark-600 rounded-lg shadow-2xl z-50 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-dark-600">
            <h3 className="text-sm font-semibold text-dark-100">Notifications</h3>
            {notifications.length > 0 && (
              <button
                onClick={onClear}
                className="text-xs text-dark-400 hover:text-dark-200 transition-colors"
              >
                Clear all
              </button>
            )}
          </div>
          <div className="max-h-80 overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="px-4 py-8 text-center text-dark-500 text-sm">
                No notifications
              </div>
            ) : (
              notifications.slice(0, 20).map((notification) => {
                const severityDot = {
                  critical: 'bg-red-500',
                  high: 'bg-orange-500',
                  medium: 'bg-yellow-500',
                  low: 'bg-blue-500',
                };
                return (
                  <div
                    key={notification.id}
                    className="px-4 py-3 border-b border-dark-700 hover:bg-dark-750 transition-colors"
                  >
                    <div className="flex items-start gap-2">
                      <span
                        className={`w-2 h-2 mt-1.5 rounded-full flex-shrink-0 ${
                          severityDot[notification.severity] || 'bg-dark-500'
                        }`}
                      />
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium text-dark-100 truncate">
                          {notification.title}
                        </p>
                        {notification.message && (
                          <p className="text-xs text-dark-400 mt-0.5 line-clamp-2">
                            {notification.message}
                          </p>
                        )}
                        <p className="text-xs text-dark-500 mt-1">
                          {new Date(notification.timestamp).toLocaleTimeString()}
                        </p>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function Header() {
  const location = useLocation();
  const { notifications, alertCounts, clearAlertCounts, connectionStatus } = useApp();
  const pageTitle = pageTitles[location.pathname] || 'RubyGuardian';

  return (
    <header className="h-16 bg-dark-900/80 backdrop-blur-sm border-b border-dark-700 flex items-center justify-between px-6 flex-shrink-0">
      <div className="flex items-center gap-4">
        <h2 className="text-lg font-semibold text-dark-100">{pageTitle}</h2>
        <span className="text-xs text-dark-500 hidden md:inline">
          {new Date().toLocaleDateString('en-US', {
            weekday: 'long',
            year: 'numeric',
            month: 'long',
            day: 'numeric',
          })}
        </span>
      </div>

      <div className="flex items-center gap-4">
        <ConnectionBadge status={connectionStatus} />

        <div className="hidden md:flex items-center gap-2 text-xs">
          {alertCounts.critical > 0 && (
            <span className="px-2 py-1 rounded bg-red-900/50 text-red-300 border border-red-800">
              {alertCounts.critical} Critical
            </span>
          )}
          {alertCounts.high > 0 && (
            <span className="px-2 py-1 rounded bg-orange-900/50 text-orange-300 border border-orange-800">
              {alertCounts.high} High
            </span>
          )}
        </div>

        <NotificationDropdown
          notifications={notifications}
          onClear={clearAlertCounts}
        />

        <a
          href={import.meta.env.VITE_KIBANA_URL || 'http://localhost:5601'}
          target="_blank"
          rel="noopener noreferrer"
          className="p-2 rounded-lg text-dark-400 hover:text-dark-200 hover:bg-dark-800 transition-colors"
          title="Open Kibana"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
          </svg>
        </a>
      </div>
    </header>
  );
}
