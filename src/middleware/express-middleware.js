const WAFCore = require('../core/waf-core');
const WAFLogger = require('../core/logger');

class WAFMiddleware {
    constructor(config = {}) {
        this.config = {
            enabled: true,
            mode: 'monitor', // 'monitor', 'block', 'learning'
            blockResponse: {
                status: 403,
                message: 'Access Denied',
                details: false // Set to true to include threat details in response
            },
            excludePaths: ['/health', '/metrics', '/favicon.ico'],
            trustProxy: true,
            logBlocked: true,
            logAllRequests: false,
            customBlockPage: null,
            bypassHeader: null, // Header to bypass WAF (for testing)
            ...config
        };
        
        this.waf = new WAFCore(this.config);
        this.logger = new WAFLogger(this.config.logging);
        this.initialized = false;
    }

    async initialize() {
        if (this.initialized) return;
        
        await this.waf.initialize();
        await this.logger.initialize();
        
        // Setup WAF event listeners
        this.setupEventListeners();
        
        this.initialized = true;
        console.log('[WAF Middleware] Initialized successfully');
    }

    setupEventListeners() {
        this.waf.on('threat-detected', (analysis) => {
            this.logger.logSecurity(analysis);
        });
        
        this.waf.on('request-analyzed', (analysis) => {
            if (this.config.logAllRequests) {
                this.logger.log('debug', 'Request analyzed', analysis);
            }
        });
        
        this.waf.on('plugin-log', (logEntry) => {
            this.logger.log(logEntry.level, logEntry.message, logEntry);
        });
    }

    middleware() {
        return async (req, res, next) => {
            // Initialize if not already done
            if (!this.initialized) {
                await this.initialize();
            }
            
            // Check if WAF is enabled
            if (!this.config.enabled) {
                return next();
            }
            
            // Check bypass header
            if (this.config.bypassHeader && req.headers[this.config.bypassHeader]) {
                return next();
            }
            
            // Check excluded paths
            if (this.isExcludedPath(req.path)) {
                return next();
            }
            
            const startTime = Date.now();
            
            try {
                // Prepare request data for analysis
                const requestData = this.prepareRequestData(req);
                
                // Analyze request
                const analysis = await this.waf.analyze(requestData);
                
                // Attach analysis to request for downstream use
                req.wafAnalysis = analysis;
                
                // Log request
                const duration = Date.now() - startTime;
                if (this.config.logAllRequests || analysis.blocked) {
                    this.logger.logAccess(requestData, {
                        status: analysis.blocked ? 403 : 200,
                        duration,
                        blocked: analysis.blocked
                    });
                }
                
                // Log performance
                this.logger.logPerformance('waf_analysis_duration', duration, {
                    blocked: analysis.blocked,
                    threats: analysis.threats.length
                });
                
                // Handle blocking
                if (analysis.blocked && this.config.mode === 'block') {
                    return this.blockRequest(req, res, analysis);
                }
                
                // Add security headers
                this.addSecurityHeaders(res, analysis);
                
                next();
            } catch (error) {
                this.logger.log('error', 'WAF middleware error', {
                    error: error.message,
                    stack: error.stack,
                    path: req.path
                });
                
                // Fail open - don't block on errors
                next();
            }
        };
    }

    prepareRequestData(req) {
        return {
            method: req.method,
            path: req.path,
            url: req.url,
            query: req.query,
            body: req.body,
            headers: req.headers,
            ip: this.getClientIP(req),
            protocol: req.protocol,
            hostname: req.hostname,
            cookies: req.cookies,
            sessionID: req.sessionID || req.session?.id,
            user: req.user,
            connection: {
                remoteAddress: req.connection?.remoteAddress,
                encrypted: req.connection?.encrypted
            }
        };
    }

    getClientIP(req) {
        if (this.config.trustProxy) {
            // Check various headers for real IP
            const headers = [
                'x-real-ip',
                'x-forwarded-for',
                'cf-connecting-ip',
                'x-client-ip',
                'x-forwarded',
                'forwarded-for',
                'forwarded'
            ];
            
            for (const header of headers) {
                const value = req.headers[header];
                if (value) {
                    // Handle comma-separated list
                    const ips = value.split(',').map(ip => ip.trim());
                    return ips[0];
                }
            }
        }
        
        return req.connection?.remoteAddress || req.ip;
    }

    isExcludedPath(path) {
        for (const excludedPath of this.config.excludePaths) {
            if (typeof excludedPath === 'string') {
                if (path === excludedPath || path.startsWith(excludedPath)) {
                    return true;
                }
            } else if (excludedPath instanceof RegExp) {
                if (excludedPath.test(path)) {
                    return true;
                }
            }
        }
        return false;
    }

    blockRequest(req, res, analysis) {
        // Log blocked request
        if (this.config.logBlocked) {
            this.logger.log('warn', 'Request blocked', {
                ip: analysis.ip,
                path: analysis.path,
                method: analysis.method,
                threats: analysis.threats,
                score: analysis.score
            });
        }
        
        // Custom block page
        if (this.config.customBlockPage) {
            return res.status(this.config.blockResponse.status)
                     .sendFile(this.config.customBlockPage);
        }
        
        // JSON response
        const response = {
            error: this.config.blockResponse.message,
            requestId: analysis.id
        };
        
        if (this.config.blockResponse.details) {
            response.threats = analysis.threats.map(t => ({
                type: t.type || t.plugin,
                severity: t.severity
            }));
            response.score = analysis.score;
        }
        
        return res.status(this.config.blockResponse.status).json(response);
    }

    addSecurityHeaders(res, analysis) {
        // Add security headers
        res.setHeader('X-WAF-Protected', 'true');
        res.setHeader('X-Request-ID', analysis.id);
        
        // Add standard security headers if not present
        if (!res.getHeader('X-Content-Type-Options')) {
            res.setHeader('X-Content-Type-Options', 'nosniff');
        }
        
        if (!res.getHeader('X-Frame-Options')) {
            res.setHeader('X-Frame-Options', 'DENY');
        }
        
        if (!res.getHeader('X-XSS-Protection')) {
            res.setHeader('X-XSS-Protection', '1; mode=block');
        }
        
        if (!res.getHeader('Strict-Transport-Security')) {
            res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }
        
        if (!res.getHeader('Referrer-Policy')) {
            res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
        }
    }

    // Rate limiting middleware
    rateLimitMiddleware(options = {}) {
        const limits = {
            windowMs: 60000,
            max: 100,
            message: 'Too many requests',
            ...options
        };
        
        const requests = new Map();
        
        return (req, res, next) => {
            const ip = this.getClientIP(req);
            const now = Date.now();
            
            if (!requests.has(ip)) {
                requests.set(ip, []);
            }
            
            const userRequests = requests.get(ip);
            const windowStart = now - limits.windowMs;
            
            // Filter old requests
            const recentRequests = userRequests.filter(t => t > windowStart);
            requests.set(ip, recentRequests);
            
            if (recentRequests.length >= limits.max) {
                return res.status(429).json({
                    error: limits.message,
                    retryAfter: Math.ceil(limits.windowMs / 1000)
                });
            }
            
            recentRequests.push(now);
            next();
        };
    }

    // CORS middleware with security
    corsMiddleware(options = {}) {
        const config = {
            origin: true,
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
            maxAge: 86400,
            ...options
        };
        
        return (req, res, next) => {
            const origin = req.headers.origin;
            
            if (config.origin === true) {
                res.setHeader('Access-Control-Allow-Origin', origin || '*');
            } else if (typeof config.origin === 'string') {
                res.setHeader('Access-Control-Allow-Origin', config.origin);
            } else if (Array.isArray(config.origin)) {
                if (config.origin.includes(origin)) {
                    res.setHeader('Access-Control-Allow-Origin', origin);
                }
            }
            
            if (config.credentials) {
                res.setHeader('Access-Control-Allow-Credentials', 'true');
            }
            
            if (req.method === 'OPTIONS') {
                res.setHeader('Access-Control-Allow-Methods', config.methods.join(', '));
                res.setHeader('Access-Control-Allow-Headers', config.allowedHeaders.join(', '));
                res.setHeader('Access-Control-Max-Age', config.maxAge);
                return res.sendStatus(204);
            }
            
            next();
        };
    }

    // Get WAF statistics
    async getStats() {
        const wafStats = this.waf.getStats();
        const loggerStats = await this.logger.getStats();
        
        return {
            waf: wafStats,
            logger: loggerStats,
            middleware: {
                initialized: this.initialized,
                mode: this.config.mode,
                enabled: this.config.enabled
            }
        };
    }

    // Update configuration
    updateConfig(newConfig) {
        this.config = { ...this.config, ...newConfig };
        this.waf.config = { ...this.waf.config, ...newConfig };
        
        this.logger.log('info', 'WAF configuration updated', {
            changes: Object.keys(newConfig)
        });
    }

    // Cleanup
    async cleanup() {
        await this.waf.cleanup();
        await this.logger.cleanup();
        this.initialized = false;
    }
}

// Factory function for easy setup
function createWAFMiddleware(config) {
    const wafMiddleware = new WAFMiddleware(config);
    return wafMiddleware.middleware();
}

module.exports = {
    WAFMiddleware,
    createWAFMiddleware
};