const PluginBase = require('../core/plugin-base');

class RateLimitPlugin extends PluginBase {
    constructor(waf) {
        super(waf);
        this.name = 'rate-limit-protection';
        this.version = '1.0.0';
        this.description = 'Rate limiting and DDoS protection';
        this.priority = 10;
        
        this.config = {
            windowSize: 60000, // 1 minute
            maxRequests: 100,
            maxRequestsPerPath: 50,
            maxRequestsPerSecond: 10,
            blockDuration: 300000, // 5 minutes
            progressiveDelay: true,
            burstAllowance: 20,
            ipWhitelist: ['127.0.0.1', '::1'],
            pathLimits: {
                '/api/login': { window: 60000, max: 5 },
                '/api/register': { window: 60000, max: 3 },
                '/api/password-reset': { window: 3600000, max: 3 },
                '/api/search': { window: 60000, max: 30 }
            }
        };
        
        // Rate limit tracking
        this.requests = new Map();
        this.blocked = new Map();
        this.pathRequests = new Map();
        this.burstTracking = new Map();
    }

    async initialize() {
        // Cleanup interval
        this.cleanupInterval = setInterval(() => {
            this.cleanup();
        }, 60000);
        
        return true;
    }

    async analyze(request, analysis) {
        const ip = analysis.ip;
        const path = analysis.path;
        const now = Date.now();
        
        // Check whitelist
        if (this.isWhitelisted(ip)) {
            return { threat: null };
        }
        
        // Check if IP is currently blocked
        if (this.isBlocked(ip)) {
            return {
                threat: {
                    type: 'rate_limit_blocked',
                    severity: 10,
                    details: {
                        reason: 'IP is temporarily blocked due to rate limit violations',
                        unblockTime: this.blocked.get(ip).unblockTime
                    }
                }
            };
        }
        
        const threats = [];
        
        // Check global rate limit
        const globalViolation = this.checkGlobalRateLimit(ip, now);
        if (globalViolation) threats.push(globalViolation);
        
        // Check path-specific rate limit
        const pathViolation = this.checkPathRateLimit(ip, path, now);
        if (pathViolation) threats.push(pathViolation);
        
        // Check burst detection
        const burstViolation = this.checkBurstRate(ip, now);
        if (burstViolation) threats.push(burstViolation);
        
        // Check for DDoS patterns
        const ddosViolation = this.checkDDoSPatterns(ip, request, now);
        if (ddosViolation) threats.push(ddosViolation);
        
        this.updateStats('analyzed');
        
        if (threats.length > 0) {
            this.updateStats('threats');
            
            const maxSeverity = Math.max(...threats.map(t => t.severity));
            
            // Block IP if severity is high
            if (maxSeverity >= 8) {
                this.blockIP(ip, now);
            }
            
            this.log('warn', 'Rate limit violation detected', {
                ip,
                path,
                violations: threats.map(t => t.type)
            });
            
            return {
                threat: {
                    type: 'rate_limit',
                    severity: maxSeverity,
                    details: {
                        violations: threats,
                        currentRate: this.getCurrentRate(ip),
                        recommendation: 'Implement client-side rate limiting and retry logic'
                    }
                }
            };
        }
        
        // Track request
        this.trackRequest(ip, path, now);
        
        return { threat: null };
    }

    checkGlobalRateLimit(ip, now) {
        const requests = this.getRecentRequests(ip, now, this.config.windowSize);
        
        if (requests.length > this.config.maxRequests) {
            return {
                type: 'global_rate_limit',
                severity: 7,
                limit: this.config.maxRequests,
                current: requests.length,
                window: this.config.windowSize
            };
        }
        
        return null;
    }

    checkPathRateLimit(ip, path, now) {
        // Check if path has specific limits
        const pathConfig = this.config.pathLimits[path];
        if (!pathConfig) {
            // Check general path limit
            const key = `${ip}:${path}`;
            const requests = this.getPathRequests(key, now, this.config.windowSize);
            
            if (requests.length > this.config.maxRequestsPerPath) {
                return {
                    type: 'path_rate_limit',
                    severity: 6,
                    path,
                    limit: this.config.maxRequestsPerPath,
                    current: requests.length,
                    window: this.config.windowSize
                };
            }
        } else {
            // Check specific path limit
            const key = `${ip}:${path}`;
            const requests = this.getPathRequests(key, now, pathConfig.window);
            
            if (requests.length > pathConfig.max) {
                return {
                    type: 'critical_path_rate_limit',
                    severity: 9,
                    path,
                    limit: pathConfig.max,
                    current: requests.length,
                    window: pathConfig.window
                };
            }
        }
        
        return null;
    }

    checkBurstRate(ip, now) {
        const oneSecondAgo = now - 1000;
        const requests = this.getRecentRequests(ip, now, 1000);
        
        if (requests.length > this.config.maxRequestsPerSecond) {
            // Track burst
            if (!this.burstTracking.has(ip)) {
                this.burstTracking.set(ip, []);
            }
            
            const bursts = this.burstTracking.get(ip);
            bursts.push(now);
            
            // Clean old bursts
            const recentBursts = bursts.filter(t => now - t < 60000);
            this.burstTracking.set(ip, recentBursts);
            
            // Escalate severity based on burst frequency
            const severity = recentBursts.length > 5 ? 9 : 7;
            
            return {
                type: 'burst_rate_limit',
                severity,
                requestsPerSecond: requests.length,
                limit: this.config.maxRequestsPerSecond,
                burstCount: recentBursts.length
            };
        }
        
        return null;
    }

    checkDDoSPatterns(ip, request, now) {
        const patterns = [];
        
        // Check for identical requests in rapid succession
        const recentRequests = this.getRecentRequests(ip, now, 5000);
        if (recentRequests.length > 20) {
            // Check if requests are identical
            const requestFingerprint = this.getRequestFingerprint(request);
            const identicalCount = recentRequests.filter(r => 
                r.fingerprint === requestFingerprint
            ).length;
            
            if (identicalCount > 15) {
                patterns.push({
                    pattern: 'identical_requests',
                    count: identicalCount,
                    severity: 9
                });
            }
        }
        
        // Check for suspicious user agent
        const ua = request.headers?.['user-agent'];
        if (!ua || ua.length < 10) {
            patterns.push({
                pattern: 'suspicious_user_agent',
                severity: 5
            });
        }
        
        // Check for missing common headers
        const headers = request.headers || {};
        if (!headers['accept'] || !headers['accept-language']) {
            patterns.push({
                pattern: 'missing_headers',
                severity: 4
            });
        }
        
        // Check for rapid connection from same IP
        if (recentRequests.length > 50) {
            patterns.push({
                pattern: 'rapid_connections',
                count: recentRequests.length,
                severity: 8
            });
        }
        
        if (patterns.length >= 2) {
            const maxSeverity = Math.max(...patterns.map(p => p.severity));
            return {
                type: 'ddos_pattern',
                severity: Math.min(10, maxSeverity + 1),
                patterns
            };
        }
        
        return null;
    }

    trackRequest(ip, path, now) {
        // Track global requests
        if (!this.requests.has(ip)) {
            this.requests.set(ip, []);
        }
        
        const requests = this.requests.get(ip);
        requests.push({
            timestamp: now,
            path,
            fingerprint: this.getRequestFingerprint({ path })
        });
        
        // Limit array size
        if (requests.length > 1000) {
            requests.splice(0, requests.length - 1000);
        }
        
        // Track path-specific requests
        const pathKey = `${ip}:${path}`;
        if (!this.pathRequests.has(pathKey)) {
            this.pathRequests.set(pathKey, []);
        }
        
        const pathReqs = this.pathRequests.get(pathKey);
        pathReqs.push(now);
        
        // Limit array size
        if (pathReqs.length > 100) {
            pathReqs.splice(0, pathReqs.length - 100);
        }
    }

    getRecentRequests(ip, now, window) {
        const requests = this.requests.get(ip) || [];
        const cutoff = now - window;
        return requests.filter(r => r.timestamp > cutoff);
    }

    getPathRequests(key, now, window) {
        const requests = this.pathRequests.get(key) || [];
        const cutoff = now - window;
        return requests.filter(t => t > cutoff);
    }

    getCurrentRate(ip) {
        const now = Date.now();
        const oneMinute = this.getRecentRequests(ip, now, 60000);
        const oneSecond = this.getRecentRequests(ip, now, 1000);
        
        return {
            requestsPerMinute: oneMinute.length,
            requestsPerSecond: oneSecond.length
        };
    }

    getRequestFingerprint(request) {
        const parts = [
            request.path || '',
            request.method || '',
            JSON.stringify(request.query || {}),
            request.headers?.['user-agent'] || ''
        ];
        
        return parts.join('|');
    }

    isWhitelisted(ip) {
        return this.config.ipWhitelist.includes(ip);
    }

    isBlocked(ip) {
        const blockInfo = this.blocked.get(ip);
        if (!blockInfo) return false;
        
        const now = Date.now();
        if (now > blockInfo.unblockTime) {
            this.blocked.delete(ip);
            return false;
        }
        
        return true;
    }

    blockIP(ip, now) {
        const unblockTime = now + this.config.blockDuration;
        
        this.blocked.set(ip, {
            blockedAt: now,
            unblockTime,
            violations: (this.blocked.get(ip)?.violations || 0) + 1
        });
        
        this.log('info', 'IP blocked', {
            ip,
            duration: this.config.blockDuration,
            unblockTime: new Date(unblockTime).toISOString()
        });
    }

    cleanup() {
        const now = Date.now();
        
        // Clean old requests
        for (const [ip, requests] of this.requests) {
            const recent = requests.filter(r => now - r.timestamp < 300000); // Keep 5 minutes
            if (recent.length === 0) {
                this.requests.delete(ip);
            } else {
                this.requests.set(ip, recent);
            }
        }
        
        // Clean path requests
        for (const [key, timestamps] of this.pathRequests) {
            const recent = timestamps.filter(t => now - t < 300000);
            if (recent.length === 0) {
                this.pathRequests.delete(key);
            } else {
                this.pathRequests.set(key, recent);
            }
        }
        
        // Clean expired blocks
        for (const [ip, blockInfo] of this.blocked) {
            if (now > blockInfo.unblockTime) {
                this.blocked.delete(ip);
            }
        }
        
        // Clean burst tracking
        for (const [ip, bursts] of this.burstTracking) {
            const recent = bursts.filter(t => now - t < 60000);
            if (recent.length === 0) {
                this.burstTracking.delete(ip);
            } else {
                this.burstTracking.set(ip, recent);
            }
        }
    }

    async cleanup() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
        
        this.requests.clear();
        this.blocked.clear();
        this.pathRequests.clear();
        this.burstTracking.clear();
        
        return true;
    }
}

module.exports = RateLimitPlugin;