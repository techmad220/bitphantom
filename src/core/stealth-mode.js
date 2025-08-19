const crypto = require('crypto');
const EventEmitter = require('events');

class StealthMode extends EventEmitter {
    constructor(config = {}) {
        super();
        
        this.config = {
            enabled: true,
            mode: 'ghost', // 'ghost', 'chameleon', 'honeypot', 'aggressive'
            
            // Response manipulation
            randomizeLatency: true,
            latencyRange: [50, 200], // ms
            fakeServerHeaders: true,
            serverOptions: ['nginx', 'apache', 'iis', 'cloudflare'],
            hideWAFSignatures: true,
            
            // Error handling
            customErrorPages: true,
            genericErrors: true,
            suppressStackTraces: true,
            fakeVulnerabilities: false, // Honeypot mode
            
            // Detection evasion
            bypassDetection: true,
            rotateFingerprints: true,
            mimicNormalTraffic: true,
            
            // Advanced features
            polymorphicResponses: true,
            encryptedLogging: true,
            antiReplay: true,
            antiTiming: true,
            
            // Deception
            honeytokens: [],
            fakePaths: ['/admin.php', '/wp-admin', '/.git', '/.env'],
            trapResponses: true,
            
            ...config
        };
        
        this.fingerprints = new Map();
        this.sessionKeys = new Map();
        this.honeytokenHits = new Map();
    }
    
    async processRequest(request, response, analysis) {
        if (!this.config.enabled) return;
        
        // Add random latency to prevent timing analysis
        if (this.config.randomizeLatency) {
            await this.addRandomLatency();
        }
        
        // Rotate fingerprints
        if (this.config.rotateFingerprints) {
            this.rotateRequestFingerprint(request);
        }
        
        // Check for honeytokens
        this.checkHoneytokens(request, analysis);
        
        // Check for fake paths (honeypot)
        if (this.checkFakePaths(request, analysis)) {
            return this.sendHoneypotResponse(response);
        }
        
        return false;
    }
    
    async processResponse(response, analysis) {
        // Hide WAF signatures
        if (this.config.hideWAFSignatures) {
            this.removeWAFSignatures(response);
        }
        
        // Fake server headers
        if (this.config.fakeServerHeaders) {
            this.setFakeServerHeaders(response);
        }
        
        // Polymorphic responses
        if (this.config.polymorphicResponses && analysis.blocked) {
            return this.generatePolymorphicResponse(response);
        }
        
        // Add anti-debugging headers
        this.addAntiDebuggingHeaders(response);
    }
    
    async addRandomLatency() {
        const [min, max] = this.config.latencyRange;
        const delay = Math.floor(Math.random() * (max - min + 1)) + min;
        
        // Add jitter to prevent statistical analysis
        const jitter = Math.random() * 10 - 5;
        
        return new Promise(resolve => setTimeout(resolve, delay + jitter));
    }
    
    rotateRequestFingerprint(request) {
        const ip = request.ip;
        
        if (!this.fingerprints.has(ip)) {
            this.fingerprints.set(ip, {
                sessionId: this.generateSessionId(),
                rotationCount: 0,
                lastRotation: Date.now()
            });
        }
        
        const fingerprint = this.fingerprints.get(ip);
        const timeSinceRotation = Date.now() - fingerprint.lastRotation;
        
        // Rotate every 5-10 minutes randomly
        const rotationInterval = 300000 + Math.random() * 300000;
        
        if (timeSinceRotation > rotationInterval) {
            fingerprint.sessionId = this.generateSessionId();
            fingerprint.rotationCount++;
            fingerprint.lastRotation = Date.now();
            
            this.emit('fingerprint-rotated', {
                ip,
                newSessionId: fingerprint.sessionId,
                rotationCount: fingerprint.rotationCount
            });
        }
        
        // Modify request headers to appear different
        this.obfuscateHeaders(request);
    }
    
    obfuscateHeaders(request) {
        // Randomly modify non-essential headers
        const modifications = [
            () => {
                // Vary Accept-Encoding
                const encodings = ['gzip', 'deflate', 'br', 'identity'];
                request.headers['accept-encoding'] = encodings
                    .sort(() => Math.random() - 0.5)
                    .slice(0, Math.floor(Math.random() * 3) + 1)
                    .join(', ');
            },
            () => {
                // Vary Accept-Language
                if (request.headers['accept-language']) {
                    const parts = request.headers['accept-language'].split(',');
                    request.headers['accept-language'] = parts
                        .sort(() => Math.random() - 0.5)
                        .join(',');
                }
            },
            () => {
                // Add random cache control
                const cacheOptions = ['no-cache', 'no-store', 'max-age=0', 'must-revalidate'];
                request.headers['cache-control'] = cacheOptions[Math.floor(Math.random() * cacheOptions.length)];
            }
        ];
        
        // Apply random modifications
        const numMods = Math.floor(Math.random() * modifications.length);
        for (let i = 0; i < numMods; i++) {
            modifications[Math.floor(Math.random() * modifications.length)]();
        }
    }
    
    removeWAFSignatures(response) {
        // Remove any headers that might identify the WAF
        const headersToRemove = [
            'x-waf-protected',
            'x-waf-score',
            'x-waf-request-id',
            'x-security-by',
            'x-protected-by',
            'x-firewall',
            'x-application-context'
        ];
        
        headersToRemove.forEach(header => {
            response.removeHeader(header);
        });
        
        // Obfuscate remaining security headers
        if (response.getHeader('x-content-type-options')) {
            // Randomly vary capitalization
            const value = response.getHeader('x-content-type-options');
            response.setHeader('X-Content-Type-Options', value);
        }
    }
    
    setFakeServerHeaders(response) {
        const servers = {
            nginx: {
                'Server': `nginx/${this.randomVersion('1.18', '1.21')}`,
                'X-Powered-By': Math.random() > 0.5 ? 'PHP/7.4.3' : undefined
            },
            apache: {
                'Server': `Apache/${this.randomVersion('2.4.41', '2.4.48')} (Ubuntu)`,
                'X-Powered-By': 'PHP/7.4.3'
            },
            iis: {
                'Server': `Microsoft-IIS/${this.randomVersion('8.5', '10.0')}`,
                'X-Powered-By': 'ASP.NET',
                'X-AspNet-Version': '4.0.30319'
            },
            cloudflare: {
                'Server': 'cloudflare',
                'CF-RAY': this.generateCloudflareRay(),
                'CF-Cache-Status': 'DYNAMIC'
            }
        };
        
        const serverType = this.config.serverOptions[Math.floor(Math.random() * this.config.serverOptions.length)];
        const headers = servers[serverType];
        
        Object.entries(headers).forEach(([key, value]) => {
            if (value !== undefined) {
                response.setHeader(key, value);
            }
        });
    }
    
    generatePolymorphicResponse(response) {
        const templates = [
            {
                status: 403,
                body: '<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>You don\'t have permission to access this resource.</p></body></html>'
            },
            {
                status: 404,
                body: '<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>'
            },
            {
                status: 500,
                body: '<html><head><title>500 Internal Server Error</title></head><body><h1>Internal Server Error</h1><p>The server encountered an internal error and was unable to complete your request.</p></body></html>'
            },
            {
                status: 503,
                body: '<html><head><title>503 Service Unavailable</title></head><body><h1>Service Temporarily Unavailable</h1><p>The server is temporarily unable to service your request due to maintenance downtime or capacity problems.</p></body></html>'
            }
        ];
        
        const template = templates[Math.floor(Math.random() * templates.length)];
        
        // Add random variations
        const body = this.addRandomComments(template.body);
        
        response.status(template.status);
        response.setHeader('Content-Type', 'text/html');
        response.send(body);
        
        return true;
    }
    
    addRandomComments(html) {
        const comments = [
            '<!-- Generated by server -->',
            '<!-- Page rendered in ' + (Math.random() * 100).toFixed(2) + 'ms -->',
            '<!-- Request ID: ' + crypto.randomBytes(16).toString('hex') + ' -->',
            '<!-- Cache: MISS -->',
            '<!-- Node: ' + Math.floor(Math.random() * 10) + ' -->'
        ];
        
        // Insert random comments
        const numComments = Math.floor(Math.random() * 3) + 1;
        for (let i = 0; i < numComments; i++) {
            const comment = comments[Math.floor(Math.random() * comments.length)];
            const position = Math.floor(Math.random() * html.length);
            html = html.slice(0, position) + comment + html.slice(position);
        }
        
        return html;
    }
    
    checkHoneytokens(request, analysis) {
        const requestData = JSON.stringify({
            body: request.body,
            query: request.query,
            headers: request.headers
        });
        
        for (const token of this.config.honeytokens) {
            if (requestData.includes(token)) {
                // Honeytoken detected!
                this.honeytokenHits.set(token, {
                    ip: request.ip,
                    timestamp: Date.now(),
                    path: request.path,
                    fullRequest: requestData
                });
                
                analysis.threats.push({
                    type: 'honeytoken',
                    severity: 10,
                    details: {
                        token: token.substring(0, 10) + '...',
                        alert: 'CRITICAL: Honeytoken accessed'
                    }
                });
                
                this.emit('honeytoken-triggered', {
                    ip: request.ip,
                    token,
                    request: requestData
                });
                
                return true;
            }
        }
        
        return false;
    }
    
    checkFakePaths(request, analysis) {
        for (const fakePath of this.config.fakePaths) {
            if (request.path.includes(fakePath)) {
                analysis.threats.push({
                    type: 'honeypot-path',
                    severity: 9,
                    details: {
                        path: fakePath,
                        alert: 'Honeypot path accessed'
                    }
                });
                
                this.emit('honeypot-triggered', {
                    ip: request.ip,
                    path: request.path,
                    fakePath
                });
                
                return true;
            }
        }
        
        return false;
    }
    
    sendHoneypotResponse(response) {
        // Send a realistic but fake response
        const fakeResponses = {
            '/.git': {
                status: 200,
                body: 'ref: refs/heads/master\n',
                contentType: 'text/plain'
            },
            '/.env': {
                status: 200,
                body: 'APP_ENV=production\nAPP_KEY=base64:' + crypto.randomBytes(32).toString('base64') + '\nDB_CONNECTION=mysql\n',
                contentType: 'text/plain'
            },
            '/wp-admin': {
                status: 302,
                redirect: '/wp-login.php',
                body: ''
            },
            '/admin.php': {
                status: 200,
                body: '<html><head><title>Admin Panel</title></head><body><form><input type="password" name="password"/></form></body></html>',
                contentType: 'text/html'
            }
        };
        
        const path = response.req.path;
        let fakeResponse = null;
        
        for (const [fakePath, resp] of Object.entries(fakeResponses)) {
            if (path.includes(fakePath)) {
                fakeResponse = resp;
                break;
            }
        }
        
        if (fakeResponse) {
            response.status(fakeResponse.status);
            if (fakeResponse.redirect) {
                response.redirect(fakeResponse.redirect);
            } else {
                response.setHeader('Content-Type', fakeResponse.contentType);
                response.send(fakeResponse.body);
            }
        } else {
            // Generic honeypot response
            response.status(200);
            response.send('<!-- Honeypot -->\n');
        }
        
        return true;
    }
    
    addAntiDebuggingHeaders(response) {
        // Add headers that make debugging harder
        response.setHeader('X-XSS-Protection', '1; mode=block');
        response.setHeader('X-Content-Type-Options', 'nosniff');
        response.setHeader('X-Frame-Options', 'DENY');
        
        // Add fake timing headers to confuse timing attacks
        response.setHeader('X-Response-Time', Math.floor(Math.random() * 100) + 'ms');
        
        // Add cache-busting headers
        response.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        response.setHeader('Pragma', 'no-cache');
        response.setHeader('Expires', '0');
        
        // Add fake correlation IDs
        response.setHeader('X-Correlation-ID', crypto.randomBytes(16).toString('hex'));
    }
    
    generateSessionId() {
        return crypto.randomBytes(32).toString('hex');
    }
    
    generateCloudflareRay() {
        return crypto.randomBytes(8).toString('hex') + '-' + 
               ['IAD', 'DFW', 'ORD', 'LAX', 'ATL'][Math.floor(Math.random() * 5)];
    }
    
    randomVersion(min, max) {
        const minParts = min.split('.').map(Number);
        const maxParts = max.split('.').map(Number);
        
        const version = [];
        for (let i = 0; i < minParts.length; i++) {
            const minVal = minParts[i];
            const maxVal = maxParts[i];
            version.push(Math.floor(Math.random() * (maxVal - minVal + 1)) + minVal);
        }
        
        return version.join('.');
    }
    
    encryptLog(data) {
        if (!this.config.encryptedLogging) return data;
        
        const algorithm = 'aes-256-gcm';
        const key = crypto.scryptSync(process.env.LOG_ENCRYPTION_KEY || 'default-key', 'salt', 32);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(algorithm, key, iv);
        
        let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const authTag = cipher.getAuthTag();
        
        return {
            encrypted: true,
            data: encrypted,
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex')
        };
    }
    
    getMetrics() {
        return {
            mode: this.config.mode,
            fingerprintRotations: Array.from(this.fingerprints.values())
                .reduce((sum, f) => sum + f.rotationCount, 0),
            honeytokenHits: this.honeytokenHits.size,
            activeSessions: this.fingerprints.size
        };
    }
}

module.exports = StealthMode;