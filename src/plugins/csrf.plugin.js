const PluginBase = require('../core/plugin-base');
const crypto = require('crypto');

class CSRFPlugin extends PluginBase {
    constructor(waf) {
        super(waf);
        this.name = 'csrf-protection';
        this.version = '1.0.0';
        this.description = 'Detects and prevents CSRF attacks';
        this.priority = 7;
        
        // CSRF configuration
        this.config = {
            tokenLength: 32,
            tokenTimeout: 3600000, // 1 hour
            checkMethods: ['POST', 'PUT', 'DELETE', 'PATCH'],
            headerName: 'x-csrf-token',
            cookieName: 'csrf-token',
            formFieldName: '_csrf',
            sameSiteStrict: true,
            doubleSubmitCookie: true,
            originCheck: true,
            refererCheck: true,
            customHeaders: ['x-requested-with'],
            trustedOrigins: [],
            excludePaths: ['/api/public', '/health', '/metrics']
        };
        
        // Token storage (in production, use Redis or similar)
        this.tokenStore = new Map();
        this.sessionStore = new Map();
    }

    async initialize() {
        // Start cleanup interval for expired tokens
        this.cleanupInterval = setInterval(() => {
            this.cleanupExpiredTokens();
        }, 300000); // Clean every 5 minutes
        
        return true;
    }

    async analyze(request, analysis) {
        // Skip CSRF check for safe methods
        if (!this.config.checkMethods.includes(request.method?.toUpperCase())) {
            return { threat: null };
        }

        // Skip excluded paths
        if (this.isExcludedPath(request.path)) {
            return { threat: null };
        }

        const threats = [];
        
        // Perform various CSRF checks
        const checks = [
            this.checkToken(request),
            this.checkOrigin(request),
            this.checkReferer(request),
            this.checkCustomHeaders(request),
            this.checkDoubleSubmitCookie(request),
            this.checkContentType(request)
        ];

        for (const check of checks) {
            const result = await check;
            if (result && result.failed) {
                threats.push(result);
            }
        }

        this.updateStats('analyzed');

        if (threats.length > 0) {
            this.updateStats('threats');
            
            const maxSeverity = Math.max(...threats.map(t => t.severity));
            
            this.log('warn', 'CSRF threat detected', {
                ip: analysis.ip,
                path: analysis.path,
                method: request.method,
                threats: threats.length,
                checks: threats.map(t => t.check)
            });

            return {
                threat: {
                    type: 'csrf',
                    severity: maxSeverity,
                    details: {
                        failedChecks: threats,
                        recommendation: this.getRecommendation(threats)
                    }
                }
            };
        }

        return { threat: null };
    }

    async checkToken(request) {
        const token = this.extractToken(request);
        
        if (!token) {
            return {
                check: 'token_missing',
                severity: 8,
                failed: true,
                message: 'CSRF token not found in request'
            };
        }

        // Validate token
        const sessionId = this.getSessionId(request);
        const storedToken = this.tokenStore.get(sessionId);
        
        if (!storedToken) {
            return {
                check: 'token_invalid',
                severity: 8,
                failed: true,
                message: 'No valid token found for session'
            };
        }

        if (storedToken.token !== token) {
            return {
                check: 'token_mismatch',
                severity: 9,
                failed: true,
                message: 'CSRF token does not match stored token'
            };
        }

        if (Date.now() - storedToken.created > this.config.tokenTimeout) {
            return {
                check: 'token_expired',
                severity: 7,
                failed: true,
                message: 'CSRF token has expired'
            };
        }

        return null;
    }

    async checkOrigin(request) {
        if (!this.config.originCheck) return null;
        
        const origin = request.headers?.origin;
        const host = request.headers?.host;
        
        if (!origin && request.method !== 'GET') {
            // Origin header missing for state-changing request
            return {
                check: 'origin_missing',
                severity: 6,
                failed: true,
                message: 'Origin header missing for state-changing request'
            };
        }

        if (origin && host) {
            const originUrl = new URL(origin);
            const expectedOrigin = `${request.protocol || 'https'}://${host}`;
            
            if (origin !== expectedOrigin && !this.isTrustedOrigin(origin)) {
                return {
                    check: 'origin_mismatch',
                    severity: 9,
                    failed: true,
                    message: `Origin ${origin} does not match expected ${expectedOrigin}`
                };
            }
        }

        return null;
    }

    async checkReferer(request) {
        if (!this.config.refererCheck) return null;
        
        const referer = request.headers?.referer || request.headers?.referrer;
        const host = request.headers?.host;
        
        if (!referer && request.method !== 'GET') {
            // Some browsers don't send referer, so this is lower severity
            return {
                check: 'referer_missing',
                severity: 5,
                failed: true,
                message: 'Referer header missing for state-changing request'
            };
        }

        if (referer && host) {
            try {
                const refererUrl = new URL(referer);
                const expectedHost = host.split(':')[0];
                
                if (refererUrl.hostname !== expectedHost && !this.isTrustedOrigin(referer)) {
                    return {
                        check: 'referer_mismatch',
                        severity: 8,
                        failed: true,
                        message: `Referer ${refererUrl.hostname} does not match expected ${expectedHost}`
                    };
                }
            } catch (e) {
                return {
                    check: 'referer_invalid',
                    severity: 6,
                    failed: true,
                    message: 'Invalid referer header format'
                };
            }
        }

        return null;
    }

    async checkCustomHeaders(request) {
        // Check for custom headers that indicate AJAX requests
        for (const header of this.config.customHeaders) {
            if (request.headers?.[header]) {
                // Custom header present, likely legitimate AJAX request
                return null;
            }
        }

        // Check if this looks like an AJAX request without custom headers
        const contentType = request.headers?.['content-type'];
        if (contentType && contentType.includes('application/json')) {
            // JSON request without custom headers might be suspicious
            return {
                check: 'custom_headers_missing',
                severity: 5,
                failed: true,
                message: 'JSON request without expected custom headers'
            };
        }

        return null;
    }

    async checkDoubleSubmitCookie(request) {
        if (!this.config.doubleSubmitCookie) return null;
        
        const cookieToken = this.extractCookieToken(request);
        const headerToken = request.headers?.[this.config.headerName];
        
        if (cookieToken && headerToken) {
            if (cookieToken !== headerToken) {
                return {
                    check: 'double_submit_mismatch',
                    severity: 8,
                    failed: true,
                    message: 'Cookie token does not match header token'
                };
            }
        }

        return null;
    }

    async checkContentType(request) {
        const contentType = request.headers?.['content-type'];
        
        // Check for suspicious content types that might indicate CSRF
        if (request.method === 'POST' && !contentType) {
            return {
                check: 'content_type_missing',
                severity: 4,
                failed: true,
                message: 'POST request without Content-Type header'
            };
        }

        // Simple form submissions might be CSRF attempts
        if (contentType === 'application/x-www-form-urlencoded' || 
            contentType === 'multipart/form-data') {
            // These need additional validation
            if (!this.extractToken(request)) {
                return {
                    check: 'form_without_token',
                    severity: 7,
                    failed: true,
                    message: 'Form submission without CSRF token'
                };
            }
        }

        return null;
    }

    extractToken(request) {
        // Check header
        let token = request.headers?.[this.config.headerName];
        if (token) return token;
        
        // Check body
        if (request.body) {
            if (typeof request.body === 'object' && request.body[this.config.formFieldName]) {
                return request.body[this.config.formFieldName];
            }
            
            // Check if body is form data string
            if (typeof request.body === 'string') {
                const match = request.body.match(new RegExp(`${this.config.formFieldName}=([^&]+)`));
                if (match) return match[1];
            }
        }
        
        // Check query parameters
        if (request.query && request.query[this.config.formFieldName]) {
            return request.query[this.config.formFieldName];
        }
        
        return null;
    }

    extractCookieToken(request) {
        const cookies = request.headers?.cookie;
        if (!cookies) return null;
        
        const cookieMatch = cookies.match(new RegExp(`${this.config.cookieName}=([^;]+)`));
        return cookieMatch ? cookieMatch[1] : null;
    }

    getSessionId(request) {
        // Extract session ID from cookies or generate from IP + User-Agent
        const cookies = request.headers?.cookie;
        if (cookies) {
            const sessionMatch = cookies.match(/session=([^;]+)/);
            if (sessionMatch) return sessionMatch[1];
        }
        
        // Fallback to IP + User-Agent hash
        const ip = request.ip || request.connection?.remoteAddress || 'unknown';
        const ua = request.headers?.['user-agent'] || 'unknown';
        return crypto.createHash('sha256').update(`${ip}:${ua}`).digest('hex');
    }

    generateToken() {
        return crypto.randomBytes(this.config.tokenLength).toString('hex');
    }

    storeToken(sessionId, token) {
        this.tokenStore.set(sessionId, {
            token,
            created: Date.now()
        });
    }

    isExcludedPath(path) {
        if (!path) return false;
        
        for (const excludedPath of this.config.excludePaths) {
            if (path.startsWith(excludedPath)) {
                return true;
            }
        }
        
        return false;
    }

    isTrustedOrigin(origin) {
        if (!origin) return false;
        
        for (const trustedOrigin of this.config.trustedOrigins) {
            if (origin === trustedOrigin || origin.startsWith(trustedOrigin)) {
                return true;
            }
        }
        
        return false;
    }

    cleanupExpiredTokens() {
        const now = Date.now();
        
        for (const [sessionId, tokenData] of this.tokenStore) {
            if (now - tokenData.created > this.config.tokenTimeout) {
                this.tokenStore.delete(sessionId);
            }
        }
    }

    getRecommendation(threats) {
        const recommendations = [];
        const failedChecks = threats.map(t => t.check);
        
        if (failedChecks.includes('token_missing') || failedChecks.includes('token_invalid')) {
            recommendations.push('Implement CSRF token validation for all state-changing requests');
        }
        
        if (failedChecks.includes('origin_mismatch') || failedChecks.includes('referer_mismatch')) {
            recommendations.push('Validate Origin and Referer headers match expected values');
        }
        
        if (failedChecks.includes('custom_headers_missing')) {
            recommendations.push('Use custom headers for AJAX requests (e.g., X-Requested-With)');
        }
        
        if (failedChecks.includes('double_submit_mismatch')) {
            recommendations.push('Implement double-submit cookie pattern correctly');
        }
        
        recommendations.push('Consider using SameSite cookie attribute');
        
        return recommendations;
    }

    async cleanup() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
        this.tokenStore.clear();
        this.sessionStore.clear();
        return true;
    }
}

module.exports = CSRFPlugin;