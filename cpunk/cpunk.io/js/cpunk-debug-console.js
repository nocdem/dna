/**
 * CPUNK Debug Console Library v1.0
 * Advanced debugging and monitoring for DNA registration
 * 
 * Dependencies: None
 * Features: Logging, Performance tracking, Export capabilities
 */

class CPUNKDebugConsole {
    constructor(config = {}) {
        // Configuration
        this.enabled = config.enabled !== false;
        this.verbosity = config.verbosity || 'info'; // 'error', 'warn', 'info', 'debug', 'trace'
        this.logToConsole = config.logToConsole !== false;
        this.logToUI = config.logToUI || false;
        this.maxLogs = config.maxLogs || 1000;
        this.maxPerformanceEntries = config.maxPerformanceEntries || 500;
        
        // UI Element
        this.uiElement = config.uiElement || null;
        
        // Storage
        this.logs = [];
        this.metrics = {};
        this.timers = new Map();
        
        // Performance tracking
        this.performance = {
            apiCalls: [],
            transactions: [],
            verifications: [],
            phases: []
        };
        
        // Log levels (for filtering)
        this.levels = {
            'error': 0,
            'warn': 1,
            'info': 2,
            'debug': 3,
            'trace': 4
        };
        
        // Session info
        this.session = {
            id: this.generateId(),
            startTime: Date.now(),
            userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : 'Unknown',
            url: typeof window !== 'undefined' ? window.location.href : 'Unknown'
        };
        
        // Initialize
        this.init();
    }

    init() {
        if (!this.enabled) return;
        
        this.log('Debug console initialized', {
            session: this.session.id,
            verbosity: this.verbosity,
            version: '1.0'
        }, 'debug');
        
        // Setup UI if element provided
        if (this.uiElement) {
            this.setupUI();
        }
        
        // Track page performance
        if (typeof window !== 'undefined') {
            this.trackPageLoad();
        }
    }

    // Core Logging Methods
    log(message, data = null, level = 'info') {
        if (!this.enabled || !this.shouldLog(level)) return;
        
        const entry = {
            id: this.generateId(),
            timestamp: new Date().toISOString(),
            time: Date.now(),
            level,
            message,
            data: this.sanitizeData(data),
            stack: this.getCallStack(),
            session: this.session.id
        };
        
        this.addLog(entry);
        this.outputLog(entry);
        
        return entry.id;
    }

    error(message, error = null, data = null) {
        const errorData = {
            ...data,
            error: error ? {
                message: error.message,
                stack: error.stack,
                name: error.name
            } : null
        };
        
        return this.log(message, errorData, 'error');
    }

    warn(message, data = null) {
        return this.log(message, data, 'warn');
    }

    info(message, data = null) {
        return this.log(message, data, 'info');
    }

    debug(message, data = null) {
        return this.log(message, data, 'debug');
    }

    trace(message, data = null) {
        return this.log(message, data, 'trace');
    }

    // Specialized Tracking Methods
    trackAPICall(method, url, duration, response = null) {
        const call = {
            id: this.generateId(),
            timestamp: Date.now(),
            method: method.toUpperCase(),
            url: this.sanitizeUrl(url),
            duration,
            status: response?.status || response?.status_code || 'unknown',
            success: this.isSuccessResponse(response),
            responseSize: this.calculateResponseSize(response),
            error: response?.error || response?.description || null
        };
        
        this.performance.apiCalls.push(call);
        this.trimPerformanceArray(this.performance.apiCalls);
        
        this.debug('API Call tracked', call);
        
        // Update metrics
        this.updateMetric('api_calls_total', 1);
        this.updateMetric('api_duration_total', duration);
        
        if (!call.success) {
            this.updateMetric('api_errors_total', 1);
            this.warn('API call failed', call);
        }
        
        return call.id;
    }

    trackTransaction(txHash, amount, token, status = 'sent') {
        const tx = {
            id: this.generateId(),
            timestamp: Date.now(),
            txHash,
            amount,
            token,
            status,
            confirmed: false
        };
        
        this.performance.transactions.push(tx);
        this.trimPerformanceArray(this.performance.transactions);
        
        this.info('Transaction tracked', tx);
        
        this.updateMetric('transactions_total', 1);
        
        return tx.id;
    }

    trackVerification(attempt, success, duration, txHash) {
        const verification = {
            id: this.generateId(),
            timestamp: Date.now(),
            attempt,
            success,
            duration,
            txHash
        };
        
        this.performance.verifications.push(verification);
        this.trimPerformanceArray(this.performance.verifications);
        
        const message = success ? 'Verification successful' : 'Verification failed';
        this.log(message, verification, success ? 'info' : 'debug');
        
        this.updateMetric('verifications_total', 1);
        
        if (success) {
            this.updateMetric('verifications_successful', 1);
        }
        
        return verification.id;
    }

    trackPhase(phase, action = 'start', data = null) {
        const entry = {
            id: this.generateId(),
            timestamp: Date.now(),
            phase,
            action, // 'start', 'complete', 'error'
            data,
            duration: null
        };
        
        // Calculate duration if completing a phase
        if (action === 'complete' || action === 'error') {
            const startEntry = this.performance.phases
                .slice()
                .reverse()
                .find(p => p.phase === phase && p.action === 'start');
                
            if (startEntry) {
                entry.duration = entry.timestamp - startEntry.timestamp;
            }
        }
        
        this.performance.phases.push(entry);
        this.trimPerformanceArray(this.performance.phases);
        
        const level = action === 'error' ? 'error' : 'info';
        this.log(`Phase ${phase} ${action}`, entry, level);
        
        return entry.id;
    }

    // Timer Management
    startTimer(name) {
        const startTime = Date.now();
        this.timers.set(name, startTime);
        
        this.trace(`Timer started: ${name}`);
        
        return startTime;
    }

    endTimer(name) {
        if (!this.timers.has(name)) {
            this.warn(`Timer not found: ${name}`);
            return null;
        }
        
        const startTime = this.timers.get(name);
        const duration = Date.now() - startTime;
        
        this.timers.delete(name);
        
        this.debug(`Timer ended: ${name}`, { 
            duration: `${duration}ms`,
            startTime: new Date(startTime).toISOString()
        });
        
        return duration;
    }

    getTimerDuration(name) {
        if (!this.timers.has(name)) return null;
        return Date.now() - this.timers.get(name);
    }

    listActiveTimers() {
        const active = [];
        this.timers.forEach((startTime, name) => {
            active.push({
                name,
                duration: Date.now() - startTime,
                startTime: new Date(startTime).toISOString()
            });
        });
        return active;
    }

    // Metrics Management
    updateMetric(name, value, operation = 'add') {
        if (!this.metrics[name]) {
            this.metrics[name] = {
                count: 0,
                sum: 0,
                min: Infinity,
                max: -Infinity,
                avg: 0,
                last: null,
                updated: Date.now()
            };
        }
        
        const metric = this.metrics[name];
        
        switch (operation) {
            case 'add':
                metric.count++;
                metric.sum += value;
                metric.min = Math.min(metric.min, value);
                metric.max = Math.max(metric.max, value);
                metric.avg = metric.sum / metric.count;
                break;
            case 'set':
                metric.last = value;
                break;
            case 'increment':
                metric.count += (value || 1);
                break;
        }
        
        metric.updated = Date.now();
    }

    getMetric(name) {
        return this.metrics[name] || null;
    }

    getAllMetrics() {
        // Defensive check to ensure logs array exists
        if (!this.logs || !Array.isArray(this.logs)) {
            this.logs = [];
        }
        
        return {
            session: {
                id: this.session.id,
                duration: Date.now() - this.session.startTime,
                startTime: new Date(this.session.startTime).toISOString()
            },
            counts: {
                logs: this.logs.length,
                errors: this.logs.filter(l => l.level === 'error').length,
                warnings: this.logs.filter(l => l.level === 'warn').length,
                activeTimers: this.timers.size
            },
            performance: {
                apiCalls: {
                    total: this.performance.apiCalls.length,
                    errors: this.performance.apiCalls.filter(c => !c.success).length,
                    avgDuration: this.calculateAverage(this.performance.apiCalls, 'duration')
                },
                transactions: {
                    total: this.performance.transactions.length,
                    confirmed: this.performance.transactions.filter(t => t.confirmed).length
                },
                verifications: {
                    total: this.performance.verifications.length,
                    successful: this.performance.verifications.filter(v => v.success).length,
                    successRate: this.calculateSuccessRate(this.performance.verifications)
                }
            },
            metrics: this.metrics
        };
    }

    // Display and Export
    displaySummary() {
        const summary = this.getAllMetrics();
        
        if (this.logToConsole) {
            console.group('🔍 Debug Console Summary');
            console.table(summary.counts);
            console.table(summary.performance);
            console.groupEnd();
        }
        
        this.info('Debug summary generated', summary);
        
        return summary;
    }

    displayTimeline(filter = null) {
        // Defensive check to ensure logs array exists
        if (!this.logs || !Array.isArray(this.logs)) {
            this.logs = [];
        }
        
        const timeline = this.logs
            .filter(log => !filter || filter.includes(log.level))
            .map(log => ({
                time: new Date(log.time).toLocaleTimeString(),
                level: log.level.toUpperCase(),
                message: log.message,
                data: log.data ? '📋' : ''
            }));
        
        if (this.logToConsole) {
            console.table(timeline);
        }
        
        return timeline;
    }

    exportLogs(format = 'json', filter = null) {
        // Defensive check to ensure logs array exists
        if (!this.logs || !Array.isArray(this.logs)) {
            this.logs = [];
        }
        const logs = filter ? this.logs.filter(filter) : this.logs;
        
        switch (format.toLowerCase()) {
            case 'json':
                return JSON.stringify(logs, null, 2);
            
            case 'csv':
                return this.logsToCSV(logs);
            
            case 'text':
                return logs.map(log => 
                    `[${log.timestamp}] [${log.level.toUpperCase()}] ${log.message}${log.data ? ' | ' + JSON.stringify(log.data) : ''}`
                ).join('\n');
            
            default:
                return logs;
        }
    }

    exportMetrics(format = 'json') {
        const metrics = this.getAllMetrics();
        
        if (format === 'json') {
            return JSON.stringify(metrics, null, 2);
        } else if (format === 'csv') {
            return this.metricsToCSV(metrics);
        }
        
        return metrics;
    }

    // Utility Methods
    shouldLog(level) {
        const currentLevel = this.levels[this.verbosity] || 2;
        const messageLevel = this.levels[level] || 2;
        return messageLevel <= currentLevel;
    }

    addLog(entry) {
        this.logs.push(entry);
        
        // Maintain max logs limit
        if (this.logs.length > this.maxLogs) {
            this.logs.shift();
        }
    }

    outputLog(entry) {
        // Console output
        if (this.logToConsole && this.shouldLog(entry.level)) {
            const style = this.getLogStyle(entry.level);
            const prefix = `[${entry.timestamp}] [${entry.level.toUpperCase()}]`;
            
            if (entry.data) {
                console.log(`%c${prefix} ${entry.message}`, style, entry.data);
            } else {
                console.log(`%c${prefix} ${entry.message}`, style);
            }
        }
        
        // UI output
        if (this.logToUI && this.uiElement) {
            this.appendToUI(entry);
        }
    }

    getLogStyle(level) {
        const styles = {
            error: 'color: #ff4444; font-weight: bold; background: #2a0000; padding: 2px 4px;',
            warn: 'color: #ffbb33; background: #2a2a00; padding: 2px 4px;',
            info: 'color: #00C851; background: #002a00; padding: 2px 4px;',
            debug: 'color: #33b5e5; background: #00142a; padding: 2px 4px;',
            trace: 'color: #999999; background: #1a1a1a; padding: 2px 4px;'
        };
        return styles[level] || '';
    }

    setupUI() {
        if (!this.uiElement) return;
        
        this.uiElement.innerHTML = `
            <div class="debug-console-header">
                <h4>🔍 Debug Console</h4>
                <div class="debug-controls">
                    <button id="debug-clear">Clear</button>
                    <button id="debug-export">Export</button>
                    <button id="debug-summary">Summary</button>
                    <select id="debug-level">
                        <option value="trace">Trace</option>
                        <option value="debug">Debug</option>
                        <option value="info" selected>Info</option>
                        <option value="warn">Warn</option>
                        <option value="error">Error</option>
                    </select>
                </div>
            </div>
            <div class="debug-logs" id="debug-logs-container"></div>
        `;
        
        // Add event listeners
        this.uiElement.querySelector('#debug-clear').addEventListener('click', () => this.clear());
        this.uiElement.querySelector('#debug-export').addEventListener('click', () => this.downloadExport());
        this.uiElement.querySelector('#debug-summary').addEventListener('click', () => this.displaySummary());
        this.uiElement.querySelector('#debug-level').addEventListener('change', (e) => {
            this.verbosity = e.target.value;
            this.refreshUI();
        });
    }

    appendToUI(entry) {
        const container = this.uiElement?.querySelector('#debug-logs-container');
        if (!container) return;
        
        const logDiv = document.createElement('div');
        logDiv.className = `debug-log debug-${entry.level}`;
        logDiv.innerHTML = `
            <span class="debug-time">${new Date(entry.time).toLocaleTimeString()}</span>
            <span class="debug-level">[${entry.level.toUpperCase()}]</span>
            <span class="debug-message">${this.escapeHtml(entry.message)}</span>
            ${entry.data ? `<details class="debug-data"><summary>Data</summary><pre>${this.escapeHtml(JSON.stringify(entry.data, null, 2))}</pre></details>` : ''}
        `;
        
        container.appendChild(logDiv);
        container.scrollTop = container.scrollHeight;
        
        // Remove old entries if too many
        const maxUILogs = 100;
        const logs = container.children;
        if (logs.length > maxUILogs) {
            container.removeChild(logs[0]);
        }
    }

    refreshUI() {
        const container = this.uiElement?.querySelector('#debug-logs-container');
        if (!container) return;
        
        container.innerHTML = '';
        
        // Defensive check to ensure logs array exists
        if (!this.logs || !Array.isArray(this.logs)) {
            this.logs = [];
        }
        
        // Re-add logs that match current verbosity
        this.logs
            .filter(log => this.shouldLog(log.level))
            .slice(-100) // Last 100 logs
            .forEach(log => this.appendToUI(log));
    }

    clear() {
        this.logs = [];
        this.metrics = {};
        this.timers.clear();
        this.performance = {
            apiCalls: [],
            transactions: [],
            verifications: [],
            phases: []
        };
        
        if (this.uiElement) {
            const container = this.uiElement.querySelector('#debug-logs-container');
            if (container) container.innerHTML = '';
        }
        
        this.info('Debug console cleared');
    }

    downloadExport() {
        const data = {
            session: this.session,
            logs: this.logs,
            metrics: this.getAllMetrics(),
            performance: this.performance,
            exported: new Date().toISOString()
        };
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cpunk-debug-${this.session.id.slice(0, 8)}-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
        
        this.info('Debug data exported');
    }

    // Helper Methods
    sanitizeData(data) {
        if (!data) return null;
        
        // Remove sensitive information
        const sanitized = JSON.parse(JSON.stringify(data));
        
        // Recursively remove keys that might contain sensitive data
        const removeKeys = ['password', 'private', 'secret', 'key', 'token'];
        
        function cleanObject(obj) {
            if (typeof obj !== 'object' || obj === null) return obj;
            
            for (const key in obj) {
                if (removeKeys.some(sensitive => key.toLowerCase().includes(sensitive))) {
                    obj[key] = '[REDACTED]';
                } else if (typeof obj[key] === 'object') {
                    cleanObject(obj[key]);
                }
            }
            return obj;
        }
        
        return cleanObject(sanitized);
    }

    sanitizeUrl(url) {
        try {
            const urlObj = new URL(url);
            // Remove sensitive query parameters
            const sensitiveParams = ['key', 'token', 'password', 'secret'];
            sensitiveParams.forEach(param => {
                if (urlObj.searchParams.has(param)) {
                    urlObj.searchParams.set(param, '[REDACTED]');
                }
            });
            return urlObj.toString();
        } catch {
            return url;
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    getCallStack() {
        const stack = new Error().stack;
        if (!stack) return '';
        
        const lines = stack.split('\n');
        // Skip this function and the calling log function
        return lines.slice(4, 6).map(line => line.trim()).join(' ← ');
    }

    generateId() {
        return Math.random().toString(36).substr(2, 9);
    }

    trimPerformanceArray(array) {
        if (array.length > this.maxPerformanceEntries) {
            array.splice(0, array.length - this.maxPerformanceEntries);
        }
    }

    isSuccessResponse(response) {
        if (!response) return false;
        if (response.status === 'ok') return true;
        if (response.status_code === 0) return true;
        if (response.success === true) return true;
        
        // For DNA availability checks, "not found" (status_code: -1) is actually success
        // It means the nickname is available for registration
        if (response.status_code === -1 && response.message === 'NOK' && 
            response.description && response.description.includes('not found')) {
            return true;
        }
        
        return false;
    }

    calculateResponseSize(response) {
        return response ? JSON.stringify(response).length : 0;
    }

    calculateAverage(array, field) {
        if (array.length === 0) return 0;
        const sum = array.reduce((acc, item) => acc + (item[field] || 0), 0);
        return Math.round(sum / array.length);
    }

    calculateSuccessRate(verifications) {
        if (verifications.length === 0) return 0;
        const successes = verifications.filter(v => v.success).length;
        return Math.round((successes / verifications.length) * 100);
    }

    logsToCSV(logs) {
        const headers = ['timestamp', 'level', 'message', 'data', 'stack'];
        const rows = logs.map(log => [
            log.timestamp,
            log.level,
            log.message,
            log.data ? JSON.stringify(log.data) : '',
            log.stack || ''
        ]);
        
        return [headers, ...rows]
            .map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
            .join('\n');
    }

    metricsToCSV(metrics) {
        const rows = [];
        rows.push(['metric', 'value', 'type']);
        
        // Session info
        rows.push(['session_id', metrics.session.id, 'string']);
        rows.push(['session_duration', metrics.session.duration, 'number']);
        
        // Counts
        Object.entries(metrics.counts).forEach(([key, value]) => {
            rows.push([`count_${key}`, value, 'number']);
        });
        
        // Performance
        Object.entries(metrics.performance).forEach(([category, data]) => {
            Object.entries(data).forEach(([key, value]) => {
                rows.push([`${category}_${key}`, value, typeof value]);
            });
        });
        
        return rows.map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
    }

    trackPageLoad() {
        if (typeof performance !== 'undefined' && performance.timing) {
            const timing = performance.timing;
            const pageLoadTime = timing.loadEventEnd - timing.navigationStart;
            
            this.updateMetric('page_load_time', pageLoadTime);
            this.debug('Page load tracked', {
                loadTime: pageLoadTime,
                domContentLoaded: timing.domContentLoadedEventEnd - timing.navigationStart,
                domComplete: timing.domComplete - timing.navigationStart
            });
        }
    }
}

// CSS for UI (inject if needed)
CPUNKDebugConsole.injectCSS = function() {
    if (typeof document === 'undefined') return;
    
    const style = document.createElement('style');
    style.textContent = `
        .debug-console-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: #1a1a1a;
            border-bottom: 1px solid #333;
        }
        
        .debug-controls {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .debug-controls button, .debug-controls select {
            padding: 5px 10px;
            background: #333;
            color: white;
            border: 1px solid #555;
            border-radius: 3px;
            cursor: pointer;
        }
        
        .debug-logs {
            max-height: 300px;
            overflow-y: auto;
            background: #0a0a0a;
            font-family: monospace;
            font-size: 12px;
        }
        
        .debug-log {
            padding: 5px 10px;
            border-bottom: 1px solid #222;
            display: flex;
            align-items: flex-start;
            gap: 10px;
        }
        
        .debug-time {
            color: #666;
            flex-shrink: 0;
        }
        
        .debug-level {
            flex-shrink: 0;
            font-weight: bold;
        }
        
        .debug-error .debug-level { color: #ff4444; }
        .debug-warn .debug-level { color: #ffbb33; }
        .debug-info .debug-level { color: #00C851; }
        .debug-debug .debug-level { color: #33b5e5; }
        .debug-trace .debug-level { color: #999; }
        
        .debug-message {
            flex: 1;
        }
        
        .debug-data {
            margin-top: 5px;
        }
        
        .debug-data summary {
            cursor: pointer;
            color: #33b5e5;
        }
        
        .debug-data pre {
            margin: 5px 0;
            padding: 10px;
            background: #111;
            border-radius: 3px;
            overflow-x: auto;
        }
    `;
    
    document.head.appendChild(style);
};

// Export for use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CPUNKDebugConsole;
}