import React, { useState, useEffect, useCallback, createContext, useContext } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import Layout from './components/Layout';
import ThreatDashboard from './pages/ThreatDashboard';
import ProcessTable from './pages/ProcessTable';
import ClassifierInterface from './pages/ClassifierInterface';
import ForensicAnalysis from './pages/ForensicAnalysis';
import HoneypotIntel from './pages/HoneypotIntel';
import Settings from './pages/Settings';
import { useWebSocket } from './hooks/useWebSocket';
import { SEVERITY_LEVELS, WS_EVENTS } from './utils/constants';

const AppContext = createContext(null);

export function useApp() {
  return useContext(AppContext);
}

function NotificationToast({ notification, onDismiss }) {
  const severityColors = {
    critical: 'bg-red-900/90 border-red-500 text-red-100',
    high: 'bg-orange-900/90 border-orange-500 text-orange-100',
    medium: 'bg-yellow-900/90 border-yellow-500 text-yellow-100',
    low: 'bg-blue-900/90 border-blue-500 text-blue-100',
    info: 'bg-dark-700/90 border-dark-500 text-dark-100',
  };

  return (
    <div
      className={`fixed top-4 right-4 z-50 max-w-md p-4 rounded-lg border shadow-2xl
        animate-fade-in ${severityColors[notification.severity] || severityColors.info}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className="inline-block w-2 h-2 rounded-full bg-current animate-pulse" />
            <span className="font-semibold text-sm uppercase tracking-wide">
              {notification.severity || 'info'}
            </span>
          </div>
          <p className="text-sm font-medium">{notification.title}</p>
          {notification.message && (
            <p className="text-xs mt-1 opacity-80">{notification.message}</p>
          )}
          <p className="text-xs mt-2 opacity-60">
            {new Date(notification.timestamp).toLocaleTimeString()}
          </p>
        </div>
        <button
          onClick={onDismiss}
          className="text-current opacity-60 hover:opacity-100 transition-opacity text-lg leading-none"
        >
          x
        </button>
      </div>
    </div>
  );
}

function AlertBanner({ criticalCount, highCount }) {
  if (criticalCount === 0 && highCount === 0) return null;

  return (
    <div className="bg-red-900/30 border-b border-red-800 px-4 py-2">
      <div className="flex items-center gap-4 text-sm">
        <span className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
          <span className="font-semibold text-red-300">Active Threats:</span>
        </span>
        {criticalCount > 0 && (
          <span className="px-2 py-0.5 rounded bg-red-800 text-red-200 text-xs font-bold">
            {criticalCount} CRITICAL
          </span>
        )}
        {highCount > 0 && (
          <span className="px-2 py-0.5 rounded bg-orange-800 text-orange-200 text-xs font-bold">
            {highCount} HIGH
          </span>
        )}
      </div>
    </div>
  );
}

export default function App() {
  const location = useLocation();
  const [notifications, setNotifications] = useState([]);
  const [activeNotification, setActiveNotification] = useState(null);
  const [alertCounts, setAlertCounts] = useState({ critical: 0, high: 0 });
  const [recentEvents, setRecentEvents] = useState([]);
  const [darkMode, setDarkMode] = useState(true);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('disconnected');

  const enableWebSocket = import.meta.env.VITE_ENABLE_WEBSOCKET !== 'false';
  const wsUrl = import.meta.env.VITE_WS_URL || 'ws://localhost:4000/ws';

  const handleWebSocketMessage = useCallback((data) => {
    if (!data || !data.type) return;

    switch (data.type) {
      case WS_EVENTS.THREAT_EVENT: {
        const event = data.payload;
        setRecentEvents((prev) => [event, ...prev].slice(0, 500));

        if (event.severity === SEVERITY_LEVELS.CRITICAL || event.severity === SEVERITY_LEVELS.HIGH) {
          setAlertCounts((prev) => ({
            ...prev,
            [event.severity]: prev[event.severity] + 1,
          }));

          const notification = {
            id: event.event_id || Date.now(),
            severity: event.severity,
            title: `${event.event_type || 'Security Event'} detected`,
            message: event.attack?.description || `Threat score: ${event.threat_score}`,
            timestamp: event['@timestamp'] || new Date().toISOString(),
          };
          setNotifications((prev) => [notification, ...prev].slice(0, 100));
          setActiveNotification(notification);

          setTimeout(() => {
            setActiveNotification((current) =>
              current?.id === notification.id ? null : current
            );
          }, 8000);
        }
        break;
      }

      case WS_EVENTS.AGENT_STATUS: {
        break;
      }

      case WS_EVENTS.SYSTEM_HEALTH: {
        break;
      }

      default:
        break;
    }
  }, []);

  const handleWsStatusChange = useCallback((status) => {
    setConnectionStatus(status);
  }, []);

  const { sendMessage } = useWebSocket(
    enableWebSocket ? wsUrl : null,
    handleWebSocketMessage,
    handleWsStatusChange
  );

  useEffect(() => {
    document.documentElement.classList.toggle('dark', darkMode);
  }, [darkMode]);

  const dismissNotification = useCallback(() => {
    setActiveNotification(null);
  }, []);

  const clearAlertCounts = useCallback(() => {
    setAlertCounts({ critical: 0, high: 0 });
  }, []);

  const toggleDarkMode = useCallback(() => {
    setDarkMode((prev) => !prev);
  }, []);

  const toggleSidebar = useCallback(() => {
    setSidebarCollapsed((prev) => !prev);
  }, []);

  const contextValue = {
    notifications,
    recentEvents,
    alertCounts,
    clearAlertCounts,
    connectionStatus,
    sendMessage,
    darkMode,
    toggleDarkMode,
    sidebarCollapsed,
    toggleSidebar,
  };

  return (
    <AppContext.Provider value={contextValue}>
      <div className="min-h-screen bg-dark-950 text-dark-100">
        <AlertBanner
          criticalCount={alertCounts.critical}
          highCount={alertCounts.high}
        />

        {activeNotification && (
          <NotificationToast
            notification={activeNotification}
            onDismiss={dismissNotification}
          />
        )}

        <Layout>
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<ThreatDashboard />} />
            <Route path="/processes" element={<ProcessTable />} />
            <Route path="/classifier" element={<ClassifierInterface />} />
            <Route path="/forensics" element={<ForensicAnalysis />} />
            <Route path="/honeypot" element={<HoneypotIntel />} />
            <Route path="/settings" element={<Settings />} />
            <Route
              path="*"
              element={
                <div className="flex items-center justify-center h-full">
                  <div className="text-center">
                    <h1 className="text-6xl font-bold text-dark-500 mb-4">404</h1>
                    <p className="text-dark-400 text-lg">Page not found</p>
                  </div>
                </div>
              }
            />
          </Routes>
        </Layout>
      </div>
    </AppContext.Provider>
  );
}
