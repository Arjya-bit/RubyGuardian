import { useState, useEffect, useRef, useCallback } from 'react';
import { createWebSocket, WS_EVENTS } from '../services/websocket';

/**
 * useWebSocket - React hook for managing a WebSocket connection with
 * automatic reconnection, heartbeat, and message buffering.
 *
 * @param {string} channel - WebSocket channel/topic to subscribe to
 * @param {Object} [options] - Configuration options
 * @param {boolean} [options.enabled=true] - Whether the connection should be active
 * @param {Function} [options.onMessage] - Callback for incoming messages
 * @param {Function} [options.onError] - Callback for errors
 * @param {Function} [options.onConnect] - Callback when connection opens
 * @param {Function} [options.onDisconnect] - Callback when connection closes
 * @param {number} [options.bufferSize=100] - Max messages to buffer
 * @param {boolean} [options.autoReconnect=true] - Auto reconnect on disconnect
 *
 * @returns {Object} WebSocket state and controls
 */
export default function useWebSocket(channel, options = {}) {
  const {
    enabled = true,
    onMessage,
    onError,
    onConnect,
    onDisconnect,
    bufferSize = 100,
    autoReconnect = true,
  } = options;

  const [status, setStatus] = useState('disconnected'); // disconnected | connecting | connected | error
  const [messages, setMessages] = useState([]);
  const [lastMessage, setLastMessage] = useState(null);
  const [error, setError] = useState(null);
  const [reconnectCount, setReconnectCount] = useState(0);

  const wsRef = useRef(null);
  const onMessageRef = useRef(onMessage);
  const onErrorRef = useRef(onError);
  const onConnectRef = useRef(onConnect);
  const onDisconnectRef = useRef(onDisconnect);

  // Keep callbacks fresh without re-triggering effects
  useEffect(() => { onMessageRef.current = onMessage; }, [onMessage]);
  useEffect(() => { onErrorRef.current = onError; }, [onError]);
  useEffect(() => { onConnectRef.current = onConnect; }, [onConnect]);
  useEffect(() => { onDisconnectRef.current = onDisconnect; }, [onDisconnect]);

  const addMessage = useCallback((msg) => {
    setMessages((prev) => {
      const next = [...prev, msg];
      return next.length > bufferSize ? next.slice(-bufferSize) : next;
    });
    setLastMessage(msg);
  }, [bufferSize]);

  const connect = useCallback(() => {
    if (!channel || !enabled) return;

    setStatus('connecting');
    setError(null);

    const ws = createWebSocket(channel);

    ws.on(WS_EVENTS.OPEN, () => {
      setStatus('connected');
      setReconnectCount(0);
      onConnectRef.current?.();
    });

    ws.on(WS_EVENTS.MESSAGE, (data) => {
      const parsed = typeof data === 'string' ? JSON.parse(data) : data;
      addMessage(parsed);
      onMessageRef.current?.(parsed);
    });

    ws.on(WS_EVENTS.ERROR, (err) => {
      setStatus('error');
      setError(err);
      onErrorRef.current?.(err);
    });

    ws.on(WS_EVENTS.CLOSE, (event) => {
      setStatus('disconnected');
      onDisconnectRef.current?.(event);

      if (autoReconnect && enabled) {
        setReconnectCount((c) => c + 1);
      }
    });

    wsRef.current = ws;
    ws.connect();

    return ws;
  }, [channel, enabled, autoReconnect, addMessage]);

  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.disconnect();
      wsRef.current = null;
    }
    setStatus('disconnected');
  }, []);

  const send = useCallback((data) => {
    if (wsRef.current && status === 'connected') {
      wsRef.current.send(typeof data === 'string' ? data : JSON.stringify(data));
      return true;
    }
    return false;
  }, [status]);

  const clearMessages = useCallback(() => {
    setMessages([]);
    setLastMessage(null);
  }, []);

  // Auto-connect and cleanup
  useEffect(() => {
    if (enabled && channel) {
      const ws = connect();
      return () => {
        ws?.disconnect();
      };
    } else {
      disconnect();
    }
  }, [channel, enabled]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-reconnect with exponential backoff
  useEffect(() => {
    if (!autoReconnect || !enabled || reconnectCount === 0 || status === 'connected') return;

    const delay = Math.min(1000 * Math.pow(2, reconnectCount - 1), 30000);
    const timer = setTimeout(() => {
      connect();
    }, delay);

    return () => clearTimeout(timer);
  }, [reconnectCount, autoReconnect, enabled, status]); // eslint-disable-line react-hooks/exhaustive-deps

  return {
    status,
    connected: status === 'connected',
    connecting: status === 'connecting',
    messages,
    lastMessage,
    error,
    reconnectCount,
    send,
    connect,
    disconnect,
    clearMessages,
  };
}

/**
 * useEventStream - Convenience hook for subscribing to a specific event type
 * via WebSocket. Filters messages by event type.
 *
 * @param {string} eventType - Event type to filter for
 * @param {Object} [options] - Same options as useWebSocket
 */
export function useEventStream(eventType, options = {}) {
  const [filteredMessages, setFilteredMessages] = useState([]);

  const handleMessage = useCallback((msg) => {
    if (msg.type === eventType || msg.event_type === eventType) {
      setFilteredMessages((prev) => {
        const next = [...prev, msg];
        return next.length > (options.bufferSize || 100) ? next.slice(-(options.bufferSize || 100)) : next;
      });
    }
    options.onMessage?.(msg);
  }, [eventType, options]);

  const ws = useWebSocket(options.channel || 'events', {
    ...options,
    onMessage: handleMessage,
  });

  return {
    ...ws,
    messages: filteredMessages,
    lastMessage: filteredMessages[filteredMessages.length - 1] || null,
  };
}
