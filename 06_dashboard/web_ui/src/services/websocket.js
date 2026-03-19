/**
 * RubyGuardian Dashboard - WebSocket Service
 *
 * Provides a WebSocket client with automatic reconnection,
 * heartbeat/keepalive, message queuing, and channel subscription.
 */

import { WS_BASE_URL } from '../utils/constants';

export const WS_EVENTS = {
  OPEN: 'open',
  CLOSE: 'close',
  MESSAGE: 'message',
  ERROR: 'error',
  RECONNECTING: 'reconnecting',
  HEARTBEAT: 'heartbeat',
};

const DEFAULT_OPTIONS = {
  reconnectMaxRetries: 10,
  reconnectBaseDelay: 1000,
  reconnectMaxDelay: 30000,
  heartbeatInterval: 30000,
  heartbeatTimeout: 10000,
  messageQueueSize: 100,
  protocols: [],
};

/**
 * WebSocketClient - Manages a single WebSocket connection with auto-reconnect,
 * heartbeat, message queuing, and event emission.
 */
class WebSocketClient {
  constructor(channel, options = {}) {
    this.channel = channel;
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.url = `${WS_BASE_URL}/${channel}`;
    this.ws = null;
    this.listeners = {};
    this.messageQueue = [];
    this.reconnectAttempts = 0;
    this.reconnectTimer = null;
    this.heartbeatTimer = null;
    this.heartbeatTimeoutTimer = null;
    this.intentionalClose = false;
    this.connected = false;
  }

  /**
   * Register an event listener.
   * @param {string} event - Event name from WS_EVENTS
   * @param {Function} callback - Event handler
   * @returns {Function} Unsubscribe function
   */
  on(event, callback) {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event].push(callback);
    return () => {
      this.listeners[event] = this.listeners[event].filter((cb) => cb !== callback);
    };
  }

  /**
   * Emit an event to all registered listeners.
   * @param {string} event
   * @param {*} data
   */
  emit(event, data) {
    const handlers = this.listeners[event] || [];
    handlers.forEach((handler) => {
      try {
        handler(data);
      } catch (err) {
        console.error(`[WebSocket] Error in ${event} handler:`, err);
      }
    });
  }

  /**
   * Establish the WebSocket connection.
   */
  connect() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    this.intentionalClose = false;

    try {
      this.ws = new WebSocket(this.url, this.options.protocols);
    } catch (err) {
      this.emit(WS_EVENTS.ERROR, err);
      this.scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this.connected = true;
      this.reconnectAttempts = 0;
      this.emit(WS_EVENTS.OPEN, { channel: this.channel });
      this.startHeartbeat();
      this.flushMessageQueue();
    };

    this.ws.onmessage = (event) => {
      let data;
      try {
        data = JSON.parse(event.data);
      } catch {
        data = event.data;
      }

      // Handle heartbeat pong
      if (data && data.type === 'pong') {
        this.onHeartbeatResponse();
        return;
      }

      this.emit(WS_EVENTS.MESSAGE, data);
    };

    this.ws.onerror = (event) => {
      this.emit(WS_EVENTS.ERROR, event);
    };

    this.ws.onclose = (event) => {
      this.connected = false;
      this.stopHeartbeat();
      this.emit(WS_EVENTS.CLOSE, {
        code: event.code,
        reason: event.reason,
        wasClean: event.wasClean,
      });

      if (!this.intentionalClose) {
        this.scheduleReconnect();
      }
    };
  }

  /**
   * Send data through the WebSocket. Queues if not connected.
   * @param {string|Object} data - Data to send
   * @returns {boolean} Whether the message was sent immediately
   */
  send(data) {
    const message = typeof data === 'string' ? data : JSON.stringify(data);

    if (this.connected && this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(message);
      return true;
    }

    // Queue message for later delivery
    if (this.messageQueue.length < this.options.messageQueueSize) {
      this.messageQueue.push(message);
    }
    return false;
  }

  /**
   * Flush queued messages after reconnection.
   */
  flushMessageQueue() {
    while (this.messageQueue.length > 0 && this.connected) {
      const message = this.messageQueue.shift();
      this.ws.send(message);
    }
  }

  /**
   * Gracefully disconnect the WebSocket.
   */
  disconnect() {
    this.intentionalClose = true;
    this.stopHeartbeat();
    clearTimeout(this.reconnectTimer);

    if (this.ws) {
      if (this.ws.readyState === WebSocket.OPEN) {
        this.ws.close(1000, 'Client disconnect');
      }
      this.ws = null;
    }

    this.connected = false;
    this.messageQueue = [];
  }

  /**
   * Schedule a reconnection attempt with exponential backoff.
   */
  scheduleReconnect() {
    if (this.intentionalClose) return;
    if (this.reconnectAttempts >= this.options.reconnectMaxRetries) {
      this.emit(WS_EVENTS.ERROR, new Error('Max reconnection attempts reached'));
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(
      this.options.reconnectBaseDelay * Math.pow(2, this.reconnectAttempts - 1),
      this.options.reconnectMaxDelay
    );
    // Add jitter to prevent thundering herd
    const jitter = delay * 0.2 * Math.random();

    this.emit(WS_EVENTS.RECONNECTING, {
      attempt: this.reconnectAttempts,
      maxRetries: this.options.reconnectMaxRetries,
      delay: delay + jitter,
    });

    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay + jitter);
  }

  /**
   * Start the heartbeat/keepalive mechanism.
   */
  startHeartbeat() {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.connected) {
        this.send({ type: 'ping', timestamp: Date.now() });
        this.heartbeatTimeoutTimer = setTimeout(() => {
          // No pong received - connection might be dead
          if (this.ws) {
            this.ws.close(4000, 'Heartbeat timeout');
          }
        }, this.options.heartbeatTimeout);
      }
    }, this.options.heartbeatInterval);
  }

  /**
   * Stop the heartbeat mechanism.
   */
  stopHeartbeat() {
    clearInterval(this.heartbeatTimer);
    clearTimeout(this.heartbeatTimeoutTimer);
    this.heartbeatTimer = null;
    this.heartbeatTimeoutTimer = null;
  }

  /**
   * Handle heartbeat pong response.
   */
  onHeartbeatResponse() {
    clearTimeout(this.heartbeatTimeoutTimer);
    this.emit(WS_EVENTS.HEARTBEAT, { timestamp: Date.now() });
  }
}

// --- Connection Pool ---
const connectionPool = new Map();

/**
 * Create or retrieve a WebSocket connection for a given channel.
 * Reuses existing connections to the same channel.
 *
 * @param {string} channel - Channel name to connect to
 * @param {Object} [options] - WebSocket options
 * @returns {WebSocketClient} WebSocket client instance
 */
export function createWebSocket(channel, options = {}) {
  const existingClient = connectionPool.get(channel);
  if (existingClient && existingClient.connected) {
    return existingClient;
  }

  const client = new WebSocketClient(channel, options);
  connectionPool.set(channel, client);
  return client;
}

/**
 * Disconnect and remove all pooled WebSocket connections.
 */
export function disconnectAll() {
  for (const [channel, client] of connectionPool.entries()) {
    client.disconnect();
    connectionPool.delete(channel);
  }
}

/**
 * Get the current connection status of all channels.
 * @returns {Object} Map of channel name to connection status
 */
export function getConnectionStatus() {
  const status = {};
  for (const [channel, client] of connectionPool.entries()) {
    status[channel] = {
      connected: client.connected,
      reconnectAttempts: client.reconnectAttempts,
      queuedMessages: client.messageQueue.length,
    };
  }
  return status;
}

export default WebSocketClient;
