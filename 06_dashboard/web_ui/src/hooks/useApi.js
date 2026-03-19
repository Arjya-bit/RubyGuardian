import { useState, useEffect, useRef, useCallback, useMemo } from 'react';

const DEFAULT_BASE_URL = '/api';
const DEFAULT_TIMEOUT = 30000;
const cache = new Map();
const CACHE_TTL = 60000; // 1 minute

/**
 * useApi - React hook for fetching data from the RubyGuardian API.
 * Supports caching, automatic refetching, abort on unmount, and error handling.
 *
 * @param {string|null} url - API endpoint (null to skip fetching)
 * @param {Object} [options] - Fetch options
 * @param {Object} [options.params] - URL query parameters
 * @param {string} [options.method='GET'] - HTTP method
 * @param {Object} [options.body] - Request body (auto-serialized to JSON)
 * @param {Object} [options.headers] - Additional headers
 * @param {boolean} [options.cache=true] - Enable response caching
 * @param {number} [options.cacheTTL] - Cache time-to-live in ms
 * @param {number} [options.refreshInterval] - Auto-refresh interval in ms
 * @param {boolean} [options.immediate=true] - Fetch immediately on mount
 * @param {number} [options.timeout] - Request timeout in ms
 *
 * @returns {Object} { data, loading, error, refetch, mutate }
 */
export function useApi(url, options = {}) {
  const {
    params,
    method = 'GET',
    body,
    headers: extraHeaders,
    cache: enableCache = true,
    cacheTTL = CACHE_TTL,
    refreshInterval,
    immediate = true,
    timeout = DEFAULT_TIMEOUT,
  } = options;

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(!!url && immediate);
  const [error, setError] = useState(null);
  const abortRef = useRef(null);
  const mountedRef = useRef(true);
  const fetchCountRef = useRef(0);

  const fullUrl = useMemo(() => {
    if (!url) return null;
    const base = url.startsWith('http') ? url : `${DEFAULT_BASE_URL}${url}`;
    if (!params) return base;

    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value != null) searchParams.set(key, String(value));
    });
    const qs = searchParams.toString();
    return qs ? `${base}?${qs}` : base;
  }, [url, params]);

  const cacheKey = useMemo(() => {
    if (!enableCache || method !== 'GET') return null;
    return `${method}:${fullUrl}`;
  }, [enableCache, method, fullUrl]);

  const fetchData = useCallback(async (skipCache = false) => {
    if (!fullUrl) return;

    // Check cache first
    if (cacheKey && !skipCache) {
      const cached = cache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < cacheTTL) {
        setData(cached.data);
        setLoading(false);
        setError(null);
        return cached.data;
      }
    }

    // Abort any in-flight request
    if (abortRef.current) {
      abortRef.current.abort();
    }

    const controller = new AbortController();
    abortRef.current = controller;
    const fetchId = ++fetchCountRef.current;

    setLoading(true);
    setError(null);

    // Set up timeout
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const requestHeaders = {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...extraHeaders,
      };

      const requestOptions = {
        method,
        headers: requestHeaders,
        signal: controller.signal,
      };

      if (body && method !== 'GET') {
        requestOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
      }

      const response = await fetch(fullUrl, requestOptions);

      clearTimeout(timeoutId);

      // Ensure this is still the latest request
      if (fetchId !== fetchCountRef.current || !mountedRef.current) return;

      if (!response.ok) {
        const errorBody = await response.text().catch(() => '');
        let parsedError;
        try {
          parsedError = JSON.parse(errorBody);
        } catch {
          parsedError = { message: errorBody || response.statusText };
        }
        throw new ApiError(
          parsedError.message || `HTTP ${response.status}: ${response.statusText}`,
          response.status,
          parsedError
        );
      }

      const contentType = response.headers.get('content-type');
      const responseData = contentType?.includes('application/json')
        ? await response.json()
        : await response.text();

      if (fetchId !== fetchCountRef.current || !mountedRef.current) return;

      // Update cache
      if (cacheKey) {
        cache.set(cacheKey, { data: responseData, timestamp: Date.now() });
      }

      setData(responseData);
      setError(null);
      return responseData;
    } catch (err) {
      clearTimeout(timeoutId);

      if (err.name === 'AbortError') return;
      if (fetchId !== fetchCountRef.current || !mountedRef.current) return;

      setError(err instanceof ApiError ? err : new ApiError(err.message, 0, null));
    } finally {
      if (fetchId === fetchCountRef.current && mountedRef.current) {
        setLoading(false);
      }
    }
  }, [fullUrl, method, body, extraHeaders, timeout, cacheKey, cacheTTL]);

  // Optimistic update
  const mutate = useCallback((newData) => {
    if (typeof newData === 'function') {
      setData((prev) => newData(prev));
    } else {
      setData(newData);
    }
    if (cacheKey) {
      cache.set(cacheKey, { data: typeof newData === 'function' ? newData(data) : newData, timestamp: Date.now() });
    }
  }, [cacheKey, data]);

  // Initial fetch
  useEffect(() => {
    mountedRef.current = true;
    if (immediate && fullUrl) {
      fetchData();
    }
    return () => {
      mountedRef.current = false;
      if (abortRef.current) abortRef.current.abort();
    };
  }, [fullUrl, immediate]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-refresh
  useEffect(() => {
    if (!refreshInterval || !fullUrl) return;
    const interval = setInterval(() => fetchData(true), refreshInterval);
    return () => clearInterval(interval);
  }, [refreshInterval, fullUrl, fetchData]);

  return {
    data,
    loading,
    error,
    refetch: () => fetchData(true),
    mutate,
  };
}

/**
 * ApiError - Custom error class for API errors with status code and body.
 */
class ApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

/**
 * clearApiCache - Clears the entire API response cache or entries matching a pattern.
 */
export function clearApiCache(pattern) {
  if (!pattern) {
    cache.clear();
    return;
  }
  for (const key of cache.keys()) {
    if (key.includes(pattern)) cache.delete(key);
  }
}

/**
 * useMutation - Hook for POST/PUT/DELETE API operations.
 *
 * @param {string} url - API endpoint
 * @param {Object} [options] - Options including method, onSuccess, onError
 * @returns {Object} { mutate, data, loading, error }
 */
export function useMutation(url, options = {}) {
  const { method = 'POST', onSuccess, onError: onMutationError } = options;
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const mutate = useCallback(async (body, overrides = {}) => {
    setLoading(true);
    setError(null);
    try {
      const fullUrl = url.startsWith('http') ? url : `${DEFAULT_BASE_URL}${url}`;
      const response = await fetch(fullUrl, {
        method: overrides.method || method,
        headers: { 'Content-Type': 'application/json', ...overrides.headers },
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        throw new ApiError(`HTTP ${response.status}`, response.status, await response.json().catch(() => null));
      }
      const result = await response.json();
      setData(result);
      onSuccess?.(result);
      return result;
    } catch (err) {
      setError(err);
      onMutationError?.(err);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [url, method, onSuccess, onMutationError]);

  return { mutate, data, loading, error };
}

export default useApi;
