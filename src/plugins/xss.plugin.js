const PluginBase = require('../core/plugin-base');

class XSSPlugin extends PluginBase {
    constructor(waf) {
        super(waf);
        this.name = 'xss-protection';
        this.version = '1.0.0';
        this.description = 'Detects and prevents XSS attacks';
        this.priority = 8;
        
        // XSS patterns to detect
        this.patterns = [
            // Script tags
            /<script[^>]*>.*?<\/script>/gi,
            /<script[^>]*\/>/gi,
            
            // Event handlers
            /on\w+\s*=\s*["'][^"']*["']/gi,
            /on\w+\s*=\s*[^>\s]*/gi,
            
            // JavaScript protocol
            /javascript\s*:/gi,
            /vbscript\s*:/gi,
            
            // Data URI with script
            /data:.*?script/gi,
            
            // Common XSS vectors
            /<iframe[^>]*>/gi,
            /<embed[^>]*>/gi,
            /<object[^>]*>/gi,
            
            // Expression evaluation
            /eval\s*\(/gi,
            /expression\s*\(/gi,
            /Function\s*\(/gi,
            
            // Encoded attacks
            /&#x[0-9a-f]+;/gi,
            /&#\d+;/gi,
            /%3Cscript/gi,
            
            // CSS injection
            /style\s*=\s*["'][^"']*expression/gi,
            /-moz-binding/gi,
            /behavior\s*:/gi,
            
            // SVG attacks
            /<svg[^>]*onload/gi,
            
            // Meta refresh
            /<meta[^>]*http-equiv[^>]*refresh/gi,
            
            // Base tag manipulation
            /<base[^>]*href/gi
        ];

        // Additional context-specific patterns
        this.contextPatterns = {
            html: [
                /document\./gi,
                /window\./gi,
                /alert\s*\(/gi,
                /prompt\s*\(/gi,
                /confirm\s*\(/gi
            ],
            attribute: [
                /^javascript:/gi,
                /^data:.*script/gi
            ],
            url: [
                /javascript:/gi,
                /data:text\/html/gi
            ]
        };

        // Severity scores for different XSS types
        this.severityMap = {
            script_tag: 10,
            event_handler: 9,
            javascript_protocol: 9,
            eval_function: 10,
            encoded_attack: 8,
            css_injection: 7,
            svg_attack: 8,
            iframe: 7,
            meta_refresh: 6,
            base_tag: 7
        };
    }

    async analyze(request, analysis) {
        const threats = [];
        
        // Check all input vectors
        const inputVectors = [
            { data: JSON.stringify(request.query || {}), type: 'query' },
            { data: JSON.stringify(request.body || {}), type: 'body' },
            { data: JSON.stringify(request.headers || {}), type: 'headers' },
            { data: request.path || '', type: 'path' }
        ];

        for (const vector of inputVectors) {
            const xssThreats = this.scanForXSS(vector.data, vector.type);
            threats.push(...xssThreats);
        }

        // Check for suspicious patterns in cookies
        if (request.headers?.cookie) {
            const cookieThreats = this.scanCookies(request.headers.cookie);
            threats.push(...cookieThreats);
        }

        // Check referer for XSS
        if (request.headers?.referer) {
            const refererThreats = this.scanReferer(request.headers.referer);
            threats.push(...refererThreats);
        }

        this.updateStats('analyzed');

        if (threats.length > 0) {
            this.updateStats('threats');
            
            // Calculate overall severity
            const maxSeverity = Math.max(...threats.map(t => t.severity));
            
            this.log('warn', 'XSS threat detected', {
                ip: analysis.ip,
                path: analysis.path,
                threats: threats.length,
                maxSeverity
            });

            return {
                threat: {
                    type: 'xss',
                    severity: maxSeverity,
                    details: {
                        vectors: threats,
                        confidence: this.calculateConfidence(threats)
                    }
                }
            };
        }

        return { threat: null };
    }

    scanForXSS(input, inputType) {
        const threats = [];
        const decodedInput = this.decodeInput(input);
        
        // Check against main patterns
        for (let i = 0; i < this.patterns.length; i++) {
            const pattern = this.patterns[i];
            if (pattern.test(input) || pattern.test(decodedInput)) {
                threats.push({
                    pattern: pattern.source,
                    location: inputType,
                    severity: this.getPatternSeverity(i),
                    matched: input.match(pattern)?.[0] || decodedInput.match(pattern)?.[0]
                });
                
                // Reset pattern for next use
                pattern.lastIndex = 0;
            }
        }

        // Check context-specific patterns
        for (const [context, patterns] of Object.entries(this.contextPatterns)) {
            for (const pattern of patterns) {
                if (pattern.test(input) || pattern.test(decodedInput)) {
                    threats.push({
                        pattern: pattern.source,
                        location: inputType,
                        context,
                        severity: 7,
                        matched: input.match(pattern)?.[0] || decodedInput.match(pattern)?.[0]
                    });
                    pattern.lastIndex = 0;
                }
            }
        }

        return threats;
    }

    scanCookies(cookieString) {
        const threats = [];
        const cookies = this.parseCookies(cookieString);
        
        for (const [name, value] of Object.entries(cookies)) {
            const cookieThreats = this.scanForXSS(value, `cookie:${name}`);
            threats.push(...cookieThreats);
        }
        
        return threats;
    }

    scanReferer(referer) {
        const threats = [];
        
        // Check for XSS in referer URL
        if (referer.includes('<') || referer.includes('javascript:')) {
            threats.push({
                pattern: 'suspicious_referer',
                location: 'referer',
                severity: 6,
                matched: referer
            });
        }
        
        return threats;
    }

    decodeInput(input) {
        try {
            // Try multiple decoding methods
            let decoded = input;
            
            // URL decode
            decoded = decodeURIComponent(decoded);
            
            // HTML entity decode (basic)
            decoded = decoded
                .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
                .replace(/&#(\d+);/gi, (_, dec) => String.fromCharCode(parseInt(dec, 10)));
            
            // Base64 decode if it looks like base64
            if (/^[A-Za-z0-9+/]+=*$/.test(decoded)) {
                try {
                    decoded = Buffer.from(decoded, 'base64').toString();
                } catch (e) {
                    // Not valid base64
                }
            }
            
            return decoded;
        } catch (error) {
            return input;
        }
    }

    parseCookies(cookieString) {
        const cookies = {};
        cookieString.split(';').forEach(cookie => {
            const [name, value] = cookie.trim().split('=');
            if (name && value) {
                cookies[name] = value;
            }
        });
        return cookies;
    }

    getPatternSeverity(patternIndex) {
        // Map pattern index to severity
        if (patternIndex <= 1) return this.severityMap.script_tag;
        if (patternIndex <= 3) return this.severityMap.event_handler;
        if (patternIndex <= 5) return this.severityMap.javascript_protocol;
        if (patternIndex <= 8) return this.severityMap.iframe;
        if (patternIndex <= 10) return this.severityMap.eval_function;
        if (patternIndex <= 12) return this.severityMap.encoded_attack;
        if (patternIndex <= 15) return this.severityMap.css_injection;
        if (patternIndex === 16) return this.severityMap.svg_attack;
        if (patternIndex === 17) return this.severityMap.meta_refresh;
        if (patternIndex === 18) return this.severityMap.base_tag;
        return 5;
    }

    calculateConfidence(threats) {
        if (threats.length === 0) return 0;
        if (threats.length === 1) return 0.6;
        if (threats.length === 2) return 0.8;
        if (threats.length >= 3) return 0.95;
        
        // Adjust based on severity
        const avgSeverity = threats.reduce((sum, t) => sum + t.severity, 0) / threats.length;
        return Math.min(0.95, (threats.length * 0.2) + (avgSeverity * 0.08));
    }
}

module.exports = XSSPlugin;