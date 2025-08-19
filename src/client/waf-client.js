/**
 * Client-side WAF Protection Module
 * Injects security features directly into the browser
 */

(function(window, document) {
    'use strict';
    
    const WAFClient = {
        version: '1.0.0',
        config: {
            enabled: true,
            reportUri: '/waf/report',
            wsEndpoint: null,
            apiKey: null,
            protections: {
                xss: true,
                clickjacking: true,
                csp: true,
                sri: true,
                referrerPolicy: true,
                formProtection: true,
                ajaxProtection: true,
                consoleProtection: false,
                debuggerProtection: false,
                contextMenuProtection: false,
                clipboardProtection: false,
                dragDropProtection: false
            },
            monitoring: {
                events: true,
                errors: true,
                performance: true,
                resources: true
            },
            rateLimit: {
                maxRequests: 100,
                window: 60000
            }
        },
        
        stats: {
            blocked: 0,
            violations: [],
            errors: [],
            requests: []
        },
        
        ws: null,
        initialized: false
    };
    
    /**
     * Initialize WAF Client
     */
    WAFClient.init = function(userConfig) {
        if (this.initialized) return;
        
        // Merge user config
        if (userConfig) {
            this.config = Object.assign({}, this.config, userConfig);
        }
        
        // Setup protections
        if (this.config.protections.xss) this.setupXSSProtection();
        if (this.config.protections.clickjacking) this.setupClickjackingProtection();
        if (this.config.protections.csp) this.setupCSPMonitoring();
        if (this.config.protections.formProtection) this.setupFormProtection();
        if (this.config.protections.ajaxProtection) this.setupAjaxProtection();
        if (this.config.protections.consoleProtection) this.setupConsoleProtection();
        if (this.config.protections.debuggerProtection) this.setupDebuggerProtection();
        if (this.config.protections.contextMenuProtection) this.setupContextMenuProtection();
        if (this.config.protections.clipboardProtection) this.setupClipboardProtection();
        if (this.config.protections.dragDropProtection) this.setupDragDropProtection();
        
        // Setup monitoring
        if (this.config.monitoring.events) this.setupEventMonitoring();
        if (this.config.monitoring.errors) this.setupErrorMonitoring();
        if (this.config.monitoring.performance) this.setupPerformanceMonitoring();
        if (this.config.monitoring.resources) this.setupResourceMonitoring();
        
        // Setup WebSocket connection if configured
        if (this.config.wsEndpoint) {
            this.setupWebSocket();
        }
        
        // Setup rate limiting
        this.setupRateLimiting();
        
        this.initialized = true;
        console.log('[WAF Client] Initialized v' + this.version);
    };
    
    /**
     * XSS Protection
     */
    WAFClient.setupXSSProtection = function() {
        // Override dangerous methods
        const dangerousMethods = [
            'eval', 'Function', 'setTimeout', 'setInterval'
        ];
        
        dangerousMethods.forEach(method => {
            const original = window[method];
            window[method] = function() {
                const args = Array.prototype.slice.call(arguments);
                
                // Check for suspicious patterns
                if (WAFClient.detectXSS(args[0])) {
                    WAFClient.block('xss', {
                        method: method,
                        payload: args[0]
                    });
                    return;
                }
                
                return original.apply(this, args);
            };
        });
        
        // Monitor innerHTML and outerHTML
        const monitorProperty = (obj, prop) => {
            const descriptor = Object.getOwnPropertyDescriptor(obj.prototype, prop);
            if (!descriptor) return;
            
            Object.defineProperty(obj.prototype, prop, {
                set: function(value) {
                    if (WAFClient.detectXSS(value)) {
                        WAFClient.block('xss', {
                            property: prop,
                            payload: value
                        });
                        return;
                    }
                    descriptor.set.call(this, value);
                },
                get: descriptor.get
            });
        };
        
        monitorProperty(Element, 'innerHTML');
        monitorProperty(Element, 'outerHTML');
        
        // Monitor document.write
        const originalWrite = document.write;
        document.write = function(html) {
            if (WAFClient.detectXSS(html)) {
                WAFClient.block('xss', {
                    method: 'document.write',
                    payload: html
                });
                return;
            }
            originalWrite.call(document, html);
        };
    };
    
    /**
     * Detect XSS patterns
     */
    WAFClient.detectXSS = function(input) {
        if (typeof input !== 'string') return false;
        
        const patterns = [
            /<script[^>]*>.*?<\/script>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /<iframe/gi,
            /<object/gi,
            /<embed/gi,
            /eval\s*\(/gi,
            /expression\s*\(/gi
        ];
        
        for (const pattern of patterns) {
            if (pattern.test(input)) {
                return true;
            }
        }
        
        return false;
    };
    
    /**
     * Clickjacking Protection
     */
    WAFClient.setupClickjackingProtection = function() {
        // Check if in iframe
        if (window.self !== window.top) {
            // Check X-Frame-Options
            fetch(window.location.href, { method: 'HEAD' })
                .then(response => {
                    const xfo = response.headers.get('X-Frame-Options');
                    if (xfo && (xfo === 'DENY' || xfo === 'SAMEORIGIN')) {
                        WAFClient.block('clickjacking', {
                            location: window.location.href,
                            parent: document.referrer
                        });
                        
                        // Try to break out of frame
                        try {
                            window.top.location = window.self.location;
                        } catch (e) {
                            document.body.innerHTML = '<h1>Security Warning: Clickjacking Detected</h1>';
                        }
                    }
                });
        }
    };
    
    /**
     * CSP Monitoring
     */
    WAFClient.setupCSPMonitoring = function() {
        document.addEventListener('securitypolicyviolation', (e) => {
            WAFClient.report('csp-violation', {
                blockedUri: e.blockedURI,
                columnNumber: e.columnNumber,
                disposition: e.disposition,
                documentUri: e.documentURI,
                effectiveDirective: e.effectiveDirective,
                lineNumber: e.lineNumber,
                originalPolicy: e.originalPolicy,
                referrer: e.referrer,
                sample: e.sample,
                sourceFile: e.sourceFile,
                statusCode: e.statusCode,
                violatedDirective: e.violatedDirective
            });
        });
    };
    
    /**
     * Form Protection
     */
    WAFClient.setupFormProtection = function() {
        // Add CSRF tokens to forms
        document.addEventListener('submit', (e) => {
            const form = e.target;
            
            // Check if form has CSRF token
            if (!form.querySelector('input[name="_csrf"]')) {
                const token = WAFClient.getCSRFToken();
                if (token) {
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = '_csrf';
                    input.value = token;
                    form.appendChild(input);
                }
            }
            
            // Validate form data
            const formData = new FormData(form);
            for (const [key, value] of formData.entries()) {
                if (WAFClient.detectXSS(value)) {
                    e.preventDefault();
                    WAFClient.block('form-xss', {
                        field: key,
                        value: value
                    });
                    return false;
                }
            }
        });
        
        // Monitor form field changes
        document.addEventListener('input', (e) => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
                if (WAFClient.detectXSS(e.target.value)) {
                    WAFClient.warn('input-xss', {
                        field: e.target.name,
                        value: e.target.value
                    });
                }
            }
        });
    };
    
    /**
     * AJAX Protection
     */
    WAFClient.setupAjaxProtection = function() {
        // XMLHttpRequest protection
        const originalOpen = XMLHttpRequest.prototype.open;
        const originalSend = XMLHttpRequest.prototype.send;
        
        XMLHttpRequest.prototype.open = function(method, url) {
            this._wafMethod = method;
            this._wafUrl = url;
            return originalOpen.apply(this, arguments);
        };
        
        XMLHttpRequest.prototype.send = function(data) {
            // Check rate limit
            if (!WAFClient.checkRateLimit(this._wafUrl)) {
                WAFClient.block('rate-limit', {
                    url: this._wafUrl,
                    method: this._wafMethod
                });
                return;
            }
            
            // Add CSRF token to headers
            const token = WAFClient.getCSRFToken();
            if (token && this._wafMethod !== 'GET') {
                this.setRequestHeader('X-CSRF-Token', token);
            }
            
            // Check for XSS in request data
            if (data && WAFClient.detectXSS(data)) {
                WAFClient.block('ajax-xss', {
                    url: this._wafUrl,
                    method: this._wafMethod,
                    data: data
                });
                return;
            }
            
            return originalSend.apply(this, arguments);
        };
        
        // Fetch API protection
        const originalFetch = window.fetch;
        window.fetch = function(url, options = {}) {
            // Check rate limit
            if (!WAFClient.checkRateLimit(url)) {
                return Promise.reject(new Error('Rate limit exceeded'));
            }
            
            // Add CSRF token
            const token = WAFClient.getCSRFToken();
            if (token && options.method && options.method !== 'GET') {
                options.headers = options.headers || {};
                options.headers['X-CSRF-Token'] = token;
            }
            
            // Check for XSS in request body
            if (options.body && WAFClient.detectXSS(options.body)) {
                WAFClient.block('fetch-xss', {
                    url: url,
                    method: options.method,
                    body: options.body
                });
                return Promise.reject(new Error('XSS detected in request'));
            }
            
            return originalFetch.apply(this, arguments);
        };
    };
    
    /**
     * Console Protection
     */
    WAFClient.setupConsoleProtection = function() {
        const methods = ['log', 'warn', 'error', 'info', 'debug'];
        
        methods.forEach(method => {
            const original = console[method];
            console[method] = function() {
                // Check for sensitive data leakage
                const args = Array.prototype.slice.call(arguments);
                const sensitive = WAFClient.detectSensitiveData(args.join(' '));
                
                if (sensitive) {
                    WAFClient.warn('console-leak', {
                        method: method,
                        data: sensitive
                    });
                }
                
                return original.apply(console, arguments);
            };
        });
    };
    
    /**
     * Debugger Protection
     */
    WAFClient.setupDebuggerProtection = function() {
        // Detect DevTools
        let devtools = { open: false, orientation: null };
        const threshold = 160;
        
        setInterval(() => {
            if (window.outerHeight - window.innerHeight > threshold || 
                window.outerWidth - window.innerWidth > threshold) {
                if (!devtools.open) {
                    devtools.open = true;
                    WAFClient.report('devtools-open', {
                        timestamp: Date.now()
                    });
                }
            } else {
                devtools.open = false;
            }
        }, 500);
        
        // Anti-debugging
        if (this.config.protections.debuggerProtection) {
            setInterval(() => {
                debugger;
            }, 100);
        }
    };
    
    /**
     * Context Menu Protection
     */
    WAFClient.setupContextMenuProtection = function() {
        document.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            WAFClient.report('context-menu', {
                x: e.clientX,
                y: e.clientY
            });
            return false;
        });
    };
    
    /**
     * Clipboard Protection
     */
    WAFClient.setupClipboardProtection = function() {
        // Monitor copy events
        document.addEventListener('copy', (e) => {
            const selection = window.getSelection().toString();
            const sensitive = WAFClient.detectSensitiveData(selection);
            
            if (sensitive) {
                e.preventDefault();
                WAFClient.block('clipboard-copy', {
                    data: sensitive
                });
            }
        });
        
        // Monitor paste events
        document.addEventListener('paste', (e) => {
            const data = e.clipboardData.getData('text');
            
            if (WAFClient.detectXSS(data)) {
                e.preventDefault();
                WAFClient.block('clipboard-paste-xss', {
                    data: data
                });
            }
        });
    };
    
    /**
     * Drag & Drop Protection
     */
    WAFClient.setupDragDropProtection = function() {
        document.addEventListener('drop', (e) => {
            const data = e.dataTransfer.getData('text');
            
            if (WAFClient.detectXSS(data)) {
                e.preventDefault();
                WAFClient.block('drop-xss', {
                    data: data
                });
            }
        });
    };
    
    /**
     * Event Monitoring
     */
    WAFClient.setupEventMonitoring = function() {
        const suspiciousEvents = [
            'mousemove', 'mousedown', 'mouseup', 'click',
            'keydown', 'keyup', 'keypress'
        ];
        
        const eventCounts = {};
        const threshold = 1000; // Events per second
        
        suspiciousEvents.forEach(eventType => {
            eventCounts[eventType] = [];
            
            document.addEventListener(eventType, () => {
                const now = Date.now();
                eventCounts[eventType].push(now);
                
                // Keep only last second of events
                eventCounts[eventType] = eventCounts[eventType].filter(t => now - t < 1000);
                
                // Check for automated behavior
                if (eventCounts[eventType].length > threshold) {
                    WAFClient.warn('suspicious-events', {
                        type: eventType,
                        count: eventCounts[eventType].length
                    });
                }
            }, true);
        });
    };
    
    /**
     * Error Monitoring
     */
    WAFClient.setupErrorMonitoring = function() {
        window.addEventListener('error', (e) => {
            WAFClient.report('js-error', {
                message: e.message,
                source: e.filename,
                line: e.lineno,
                column: e.colno,
                stack: e.error ? e.error.stack : null
            });
        });
        
        window.addEventListener('unhandledrejection', (e) => {
            WAFClient.report('promise-rejection', {
                reason: e.reason,
                promise: e.promise
            });
        });
    };
    
    /**
     * Performance Monitoring
     */
    WAFClient.setupPerformanceMonitoring = function() {
        if (window.PerformanceObserver) {
            // Monitor long tasks
            const observer = new PerformanceObserver((list) => {
                for (const entry of list.getEntries()) {
                    if (entry.duration > 50) {
                        WAFClient.report('long-task', {
                            duration: entry.duration,
                            startTime: entry.startTime,
                            name: entry.name
                        });
                    }
                }
            });
            
            try {
                observer.observe({ entryTypes: ['longtask'] });
            } catch (e) {
                // Long task monitoring not supported
            }
        }
    };
    
    /**
     * Resource Monitoring
     */
    WAFClient.setupResourceMonitoring = function() {
        if (window.PerformanceObserver) {
            const observer = new PerformanceObserver((list) => {
                for (const entry of list.getEntries()) {
                    // Check for suspicious resources
                    if (entry.name.includes('eval') || entry.name.includes('javascript:')) {
                        WAFClient.block('suspicious-resource', {
                            name: entry.name,
                            type: entry.entryType
                        });
                    }
                }
            });
            
            try {
                observer.observe({ entryTypes: ['resource'] });
            } catch (e) {
                // Resource timing not supported
            }
        }
    };
    
    /**
     * WebSocket Connection
     */
    WAFClient.setupWebSocket = function() {
        if (!this.config.wsEndpoint) return;
        
        try {
            const url = new URL(this.config.wsEndpoint, window.location.origin);
            if (this.config.apiKey) {
                url.searchParams.set('apiKey', this.config.apiKey);
            }
            
            this.ws = new WebSocket(url.toString());
            
            this.ws.onopen = () => {
                console.log('[WAF Client] WebSocket connected');
                this.ws.send(JSON.stringify({
                    type: 'subscribe',
                    data: { channels: ['threats', 'alerts'] }
                }));
            };
            
            this.ws.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    this.handleWebSocketMessage(message);
                } catch (e) {
                    console.error('[WAF Client] WebSocket message error:', e);
                }
            };
            
            this.ws.onerror = (error) => {
                console.error('[WAF Client] WebSocket error:', error);
            };
            
            this.ws.onclose = () => {
                console.log('[WAF Client] WebSocket disconnected');
                // Reconnect after 5 seconds
                setTimeout(() => this.setupWebSocket(), 5000);
            };
        } catch (error) {
            console.error('[WAF Client] WebSocket setup error:', error);
        }
    };
    
    /**
     * Handle WebSocket Messages
     */
    WAFClient.handleWebSocketMessage = function(message) {
        switch (message.type) {
            case 'threat':
                this.handleThreat(message.data);
                break;
            case 'alert':
                this.handleAlert(message.data);
                break;
            case 'config-update':
                this.updateConfig(message.data);
                break;
        }
    };
    
    /**
     * Rate Limiting
     */
    WAFClient.setupRateLimiting = function() {
        this.requestLog = [];
    };
    
    WAFClient.checkRateLimit = function(url) {
        const now = Date.now();
        const window = this.config.rateLimit.window;
        
        // Clean old requests
        this.requestLog = this.requestLog.filter(t => now - t < window);
        
        // Check limit
        if (this.requestLog.length >= this.config.rateLimit.maxRequests) {
            return false;
        }
        
        this.requestLog.push(now);
        return true;
    };
    
    /**
     * CSRF Token Management
     */
    WAFClient.getCSRFToken = function() {
        // Try to get from meta tag
        const meta = document.querySelector('meta[name="csrf-token"]');
        if (meta) return meta.content;
        
        // Try to get from cookie
        const cookies = document.cookie.split(';');
        for (const cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'csrf-token') return value;
        }
        
        return null;
    };
    
    /**
     * Sensitive Data Detection
     */
    WAFClient.detectSensitiveData = function(input) {
        if (typeof input !== 'string') return null;
        
        const patterns = {
            creditCard: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
            ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
            email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
            apiKey: /\b[A-Za-z0-9]{32,}\b/g,
            jwt: /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/g
        };
        
        for (const [type, pattern] of Object.entries(patterns)) {
            const match = input.match(pattern);
            if (match) {
                return { type, match: match[0] };
            }
        }
        
        return null;
    };
    
    /**
     * Threat Handling
     */
    WAFClient.block = function(type, details) {
        this.stats.blocked++;
        this.stats.violations.push({
            type,
            details,
            timestamp: Date.now()
        });
        
        this.report('blocked', { type, details });
        
        console.warn('[WAF Client] Blocked:', type, details);
    };
    
    WAFClient.warn = function(type, details) {
        this.report('warning', { type, details });
        console.warn('[WAF Client] Warning:', type, details);
    };
    
    /**
     * Reporting
     */
    WAFClient.report = function(type, data) {
        const report = {
            type,
            data,
            timestamp: Date.now(),
            url: window.location.href,
            userAgent: navigator.userAgent
        };
        
        // Send via WebSocket if connected
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: 'report',
                data: report
            }));
        }
        
        // Send via HTTP
        if (this.config.reportUri) {
            fetch(this.config.reportUri, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(report)
            }).catch(error => {
                console.error('[WAF Client] Report error:', error);
            });
        }
    };
    
    /**
     * Get Statistics
     */
    WAFClient.getStats = function() {
        return this.stats;
    };
    
    /**
     * Update Configuration
     */
    WAFClient.updateConfig = function(config) {
        this.config = Object.assign({}, this.config, config);
        console.log('[WAF Client] Configuration updated');
    };
    
    // Auto-initialize if configured
    if (window.WAF_CONFIG) {
        WAFClient.init(window.WAF_CONFIG);
    }
    
    // Expose to global scope
    window.WAFClient = WAFClient;
    
})(window, document);