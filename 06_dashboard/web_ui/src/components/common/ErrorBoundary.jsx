import React, { Component } from 'react';

/**
 * ErrorBoundary - Catches JavaScript errors in child component tree and displays
 * a fallback UI instead of crashing the entire application.
 *
 * Usage:
 *   <ErrorBoundary fallback={<CustomError />} onError={logToService}>
 *     <ComponentThatMightFail />
 *   </ErrorBoundary>
 */
class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      eventId: null,
    };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    const eventId = `err_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    this.setState({ errorInfo, eventId });

    if (this.props.onError) {
      this.props.onError(error, errorInfo, eventId);
    }

    // Log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.error('[ErrorBoundary]', error);
      console.error('[ErrorBoundary] Component stack:', errorInfo?.componentStack);
    }

    // Attempt to report to backend
    try {
      fetch('/api/errors/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          eventId,
          message: error?.message,
          stack: error?.stack,
          componentStack: errorInfo?.componentStack,
          url: window.location.href,
          timestamp: new Date().toISOString(),
          userAgent: navigator.userAgent,
        }),
      }).catch(() => {
        // Silently fail - error reporting should not cause additional errors
      });
    } catch {
      // Ignore reporting failures
    }
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null, eventId: null });
  };

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      // Use custom fallback if provided
      if (this.props.fallback) {
        return typeof this.props.fallback === 'function'
          ? this.props.fallback({
              error: this.state.error,
              errorInfo: this.state.errorInfo,
              eventId: this.state.eventId,
              reset: this.handleReset,
            })
          : this.props.fallback;
      }

      // Default error UI
      return (
        <div className="flex items-center justify-center min-h-[300px] p-6">
          <div className="max-w-lg w-full bg-dark-800 border border-red-800 rounded-lg p-6 text-center">
            <div className="mx-auto w-12 h-12 mb-4 text-red-500">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
            </div>

            <h2 className="text-xl font-semibold text-white mb-2">Something went wrong</h2>
            <p className="text-gray-400 mb-4">
              An unexpected error occurred in this component. The error has been logged for investigation.
            </p>

            {this.state.eventId && (
              <p className="text-xs text-gray-500 mb-4 font-mono">
                Error ID: {this.state.eventId}
              </p>
            )}

            {process.env.NODE_ENV === 'development' && this.state.error && (
              <details className="text-left mb-4">
                <summary className="text-sm text-gray-400 cursor-pointer hover:text-gray-300">
                  Error details (development only)
                </summary>
                <pre className="mt-2 p-3 bg-dark-900 rounded text-xs text-red-400 overflow-auto max-h-48">
                  {this.state.error.toString()}
                  {this.state.errorInfo?.componentStack}
                </pre>
              </details>
            )}

            <div className="flex gap-3 justify-center">
              <button
                onClick={this.handleReset}
                className="px-4 py-2 bg-dark-700 text-white rounded hover:bg-dark-600 transition-colors text-sm"
              >
                Try Again
              </button>
              <button
                onClick={this.handleReload}
                className="px-4 py-2 bg-red-700 text-white rounded hover:bg-red-600 transition-colors text-sm"
              >
                Reload Page
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
