const PluginBase = require('../core/plugin-base');
const crypto = require('crypto');

class BotDetectionPlugin extends PluginBase {
    constructor(waf) {
        super(waf);
        this.name = 'bot-detection';
        this.version = '1.0.0';
        this.description = 'Advanced bot and crawler detection with fingerprinting';
        this.priority = 9;
        
        this.browserFingerprints = new Map();
        this.challengeTokens = new Map();
        
        // Known bot patterns
        this.botPatterns = {
            userAgents: [
                /bot/i, /crawler/i, /spider/i, /scraper/i, /curl/i, /wget/i,
                /python/i, /java/i, /ruby/i, /perl/i, /php/i, /go-http/i,
                /postman/i, /insomnia/i, /axios/i, /node-fetch/i, /request/i,
                /scanner/i, /nmap/i, /nikto/i, /sqlmap/i, /havij/i, /acunetix/i,
                /burp/i, /zap/i, /metasploit/i, /nuclei/i
            ],
            
            // Headless browser detection
            headless: [
                /headless/i, /phantomjs/i, /puppeteer/i, /playwright/i,
                /selenium/i, /webdriver/i, /chrome-lighthouse/i
            ],
            
            // Known bad bots
            malicious: [
                /masscan/i, /zgrab/i, /shodan/i, /censys/i, /netcraft/i,
                /project25499/i, /l9scan/i, /leakix/i, /stretchoid/i
            ]
        };
        
        // Browser fingerprinting checks
        this.fingerprintChecks = {
            // Canvas fingerprinting
            canvas: true,
            
            // WebGL fingerprinting
            webgl: true,
            
            // Audio context fingerprinting
            audio: true,
            
            // Font detection
            fonts: true,
            
            // Plugin detection
            plugins: true,
            
            // Screen resolution and color depth
            screen: true,
            
            // Timezone and language
            locale: true,
            
            // Hardware concurrency
            hardware: true,
            
            // WebRTC leak test
            webrtc: true
        };
        
        // Behavioral patterns
        this.behaviorPatterns = {
            mouseMovement: [],
            keystrokes: [],
            scrollPatterns: [],
            clickPatterns: [],
            timeOnPage: new Map()
        };
        
        // Challenge types
        this.challenges = {
            javascript: true,
            proof_of_work: true,
            captcha: false,
            behavioral: true
        };
    }
    
    async analyze(request, analysis) {
        const threats = [];
        const ip = analysis.ip;
        
        // User agent analysis
        const uaThreats = this.analyzeUserAgent(request);
        threats.push(...uaThreats);
        
        // Header analysis
        const headerThreats = this.analyzeHeaders(request);
        threats.push(...headerThreats);
        
        // Behavioral analysis
        const behaviorThreats = await this.analyzeBehavior(request, ip);
        threats.push(...behaviorThreats);
        
        // Fingerprint validation
        const fingerprintThreats = this.validateFingerprint(request);
        threats.push(...fingerprintThreats);
        
        // Rate and pattern analysis
        const patternThreats = this.analyzePatterns(request, ip);
        threats.push(...patternThreats);
        
        // Challenge verification
        const challengeThreats = this.verifyChallenge(request);
        threats.push(...challengeThreats);
        
        // TLS fingerprinting
        const tlsThreats = this.analyzeTLSFingerprint(request);
        threats.push(...tlsThreats);
        
        // TCP/IP fingerprinting
        const tcpThreats = this.analyzeTCPFingerprint(request);
        threats.push(...tcpThreats);
        
        this.updateStats('analyzed');
        
        if (threats.length > 0) {
            this.updateStats('threats');
            
            const maxSeverity = Math.max(...threats.map(t => t.severity));
            const botScore = this.calculateBotScore(threats);
            
            this.log('warn', 'Bot detected', {
                ip: analysis.ip,
                path: analysis.path,
                threats: threats.length,
                botScore,
                maxSeverity
            });
            
            return {
                threat: {
                    type: 'bot',
                    severity: maxSeverity,
                    details: {
                        vectors: threats,
                        botScore,
                        confidence: this.calculateConfidence(threats),
                        recommendation: this.getRecommendation(threats),
                        challenge: this.shouldChallenge(botScore) ? this.generateChallenge() : null
                    }
                }
            };
        }
        
        return { threat: null };
    }
    
    analyzeUserAgent(request) {
        const threats = [];
        const ua = request.headers?.['user-agent'] || '';
        
        // Missing user agent
        if (!ua) {
            threats.push({
                type: 'missing_user_agent',
                severity: 7,
                details: 'No User-Agent header present'
            });
            return threats;
        }
        
        // Check for bot patterns
        for (const [category, patterns] of Object.entries(this.botPatterns)) {
            for (const pattern of patterns) {
                if (pattern.test(ua)) {
                    threats.push({
                        type: `bot_${category}`,
                        severity: category === 'malicious' ? 10 : 8,
                        pattern: pattern.source,
                        matched: ua.match(pattern)?.[0],
                        details: `Detected ${category} bot pattern`
                    });
                }
            }
        }
        
        // Check for spoofed user agents
        const spoofIndicators = this.detectSpoofedUA(ua, request);
        if (spoofIndicators.length > 0) {
            threats.push({
                type: 'spoofed_user_agent',
                severity: 8,
                indicators: spoofIndicators,
                details: 'User-Agent appears to be spoofed'
            });
        }
        
        // Check for unusual user agents
        if (this.isUnusualUA(ua)) {
            threats.push({
                type: 'unusual_user_agent',
                severity: 6,
                userAgent: ua,
                details: 'Unusual or modified User-Agent'
            });
        }
        
        return threats;
    }
    
    analyzeHeaders(request) {
        const threats = [];
        const headers = request.headers || {};
        
        // Check for missing standard browser headers
        const requiredHeaders = ['accept', 'accept-encoding', 'accept-language'];
        const missingHeaders = requiredHeaders.filter(h => !headers[h]);
        
        if (missingHeaders.length > 0) {
            threats.push({
                type: 'missing_browser_headers',
                severity: 7,
                missing: missingHeaders,
                details: 'Missing standard browser headers'
            });
        }
        
        // Check for automation tool headers
        const automationHeaders = [
            'x-selenium', 'x-webdriver', 'x-puppeteer', 'x-playwright',
            'x-cypress', 'x-phantomjs', 'x-automation'
        ];
        
        const foundAutomation = automationHeaders.filter(h => headers[h]);
        if (foundAutomation.length > 0) {
            threats.push({
                type: 'automation_headers',
                severity: 9,
                headers: foundAutomation,
                details: 'Automation tool headers detected'
            });
        }
        
        // Check header order (bots often have different order)
        const headerOrder = Object.keys(headers);
        if (this.isAbnormalHeaderOrder(headerOrder)) {
            threats.push({
                type: 'abnormal_header_order',
                severity: 6,
                order: headerOrder.slice(0, 10),
                details: 'Abnormal HTTP header order'
            });
        }
        
        // Check for inconsistent headers
        const inconsistencies = this.checkHeaderConsistency(headers);
        if (inconsistencies.length > 0) {
            threats.push({
                type: 'inconsistent_headers',
                severity: 7,
                inconsistencies,
                details: 'Header values are inconsistent'
            });
        }
        
        return threats;
    }
    
    async analyzeBehavior(request, ip) {
        const threats = [];
        
        // Check for JavaScript execution
        if (!request.headers?.['x-requested-with'] && request.method === 'POST') {
            threats.push({
                type: 'no_javascript_execution',
                severity: 6,
                details: 'Request appears to bypass JavaScript'
            });
        }
        
        // Check for mouse/keyboard events (if tracked)
        const behaviorData = request.body?.behaviorData;
        if (behaviorData) {
            const behaviorAnalysis = this.analyzeBehaviorData(behaviorData);
            
            if (behaviorAnalysis.isBot) {
                threats.push({
                    type: 'bot_behavior',
                    severity: 8,
                    analysis: behaviorAnalysis,
                    details: 'Behavioral patterns indicate bot activity'
                });
            }
        } else if (request.method === 'POST' && request.path !== '/api') {
            // No behavior data on interactive request
            threats.push({
                type: 'missing_behavior_data',
                severity: 5,
                details: 'No behavioral data on interactive request'
            });
        }
        
        // Check request patterns
        const patterns = this.getRequestPatterns(ip);
        if (patterns.suspicious) {
            threats.push({
                type: 'suspicious_patterns',
                severity: 7,
                patterns: patterns.details,
                details: 'Request patterns indicate bot activity'
            });
        }
        
        return threats;
    }
    
    validateFingerprint(request) {
        const threats = [];
        const fingerprint = request.headers?.['x-fingerprint'];
        
        if (fingerprint) {
            const validation = this.validateBrowserFingerprint(fingerprint);
            
            if (!validation.valid) {
                threats.push({
                    type: 'invalid_fingerprint',
                    severity: 8,
                    reason: validation.reason,
                    details: 'Browser fingerprint validation failed'
                });
            }
            
            // Check for fingerprint spoofing
            if (validation.spoofed) {
                threats.push({
                    type: 'spoofed_fingerprint',
                    severity: 9,
                    indicators: validation.spoofIndicators,
                    details: 'Browser fingerprint appears spoofed'
                });
            }
        }
        
        return threats;
    }
    
    analyzePatterns(request, ip) {
        const threats = [];
        
        // Check for scanning patterns
        if (this.isScanning(ip)) {
            threats.push({
                type: 'scanning_behavior',
                severity: 8,
                details: 'IP is scanning for vulnerabilities'
            });
        }
        
        // Check for crawling patterns
        if (this.isCrawling(ip)) {
            threats.push({
                type: 'crawling_behavior',
                severity: 6,
                details: 'IP is crawling the website'
            });
        }
        
        // Check for API abuse patterns
        if (this.isAPIAbuse(request, ip)) {
            threats.push({
                type: 'api_abuse',
                severity: 8,
                details: 'Automated API abuse detected'
            });
        }
        
        return threats;
    }
    
    verifyChallenge(request) {
        const threats = [];
        const token = request.headers?.['x-challenge-token'];
        
        if (token) {
            const verification = this.verifyChallengeToken(token);
            
            if (!verification.valid) {
                threats.push({
                    type: 'invalid_challenge',
                    severity: 9,
                    reason: verification.reason,
                    details: 'Challenge verification failed'
                });
            }
        }
        
        return threats;
    }
    
    analyzeTLSFingerprint(request) {
        const threats = [];
        
        // TLS fingerprinting (JA3)
        const tlsInfo = request.connection?.getCipher?.();
        if (tlsInfo) {
            const ja3 = this.calculateJA3(request);
            
            if (this.isKnownBotJA3(ja3)) {
                threats.push({
                    type: 'bot_tls_fingerprint',
                    severity: 8,
                    ja3,
                    details: 'TLS fingerprint matches known bot'
                });
            }
        }
        
        return threats;
    }
    
    analyzeTCPFingerprint(request) {
        const threats = [];
        
        // TCP/IP stack fingerprinting
        const socket = request.socket;
        if (socket) {
            const tcpFingerprint = {
                windowSize: socket.bufferSize,
                ttl: this.extractTTL(socket),
                mss: this.extractMSS(socket),
                timestamps: socket.connecting
            };
            
            if (this.isAbnormalTCP(tcpFingerprint)) {
                threats.push({
                    type: 'abnormal_tcp',
                    severity: 7,
                    fingerprint: tcpFingerprint,
                    details: 'Abnormal TCP/IP characteristics'
                });
            }
        }
        
        return threats;
    }
    
    detectSpoofedUA(ua, request) {
        const indicators = [];
        
        // Check if Chrome UA but no Chrome-specific headers
        if (ua.includes('Chrome') && !request.headers?.['sec-ch-ua']) {
            indicators.push('Missing Chrome client hints');
        }
        
        // Check if mobile UA but desktop characteristics
        if (ua.includes('Mobile') && request.headers?.['sec-ch-ua-mobile'] === '?0') {
            indicators.push('Mobile UA but desktop client hint');
        }
        
        // Check version inconsistencies
        const versions = ua.match(/\d+\.\d+/g);
        if (versions && versions.length > 2) {
            // Check for impossible version combinations
            if (this.hasImpossibleVersions(versions)) {
                indicators.push('Impossible version combination');
            }
        }
        
        return indicators;
    }
    
    isUnusualUA(ua) {
        // Check for unusual patterns
        if (ua.length > 500) return true; // Too long
        if (ua.length < 10) return true; // Too short
        if (!/[a-zA-Z]/.test(ua)) return true; // No letters
        if (ua.split('/').length > 20) return true; // Too many components
        
        return false;
    }
    
    isAbnormalHeaderOrder(order) {
        // Normal browser header order patterns
        const normalPatterns = [
            ['host', 'connection', 'user-agent'],
            ['host', 'user-agent', 'accept'],
            ['host', 'cache-control', 'user-agent']
        ];
        
        const firstThree = order.slice(0, 3);
        
        return !normalPatterns.some(pattern => 
            pattern.every((h, i) => firstThree[i] === h)
        );
    }
    
    checkHeaderConsistency(headers) {
        const inconsistencies = [];
        
        // Check Accept vs User-Agent
        if (headers['user-agent']?.includes('Chrome') && 
            headers['accept'] && 
            !headers['accept'].includes('webp')) {
            inconsistencies.push('Chrome UA but no WebP support');
        }
        
        // Check encoding support
        if (headers['accept-encoding'] && 
            !headers['accept-encoding'].includes('gzip')) {
            inconsistencies.push('No gzip support (unusual)');
        }
        
        return inconsistencies;
    }
    
    analyzeBehaviorData(data) {
        const analysis = {
            isBot: false,
            confidence: 0,
            reasons: []
        };
        
        // Check mouse movement
        if (data.mouse) {
            const mouseAnalysis = this.analyzeMouseMovement(data.mouse);
            if (mouseAnalysis.isBot) {
                analysis.isBot = true;
                analysis.reasons.push('Abnormal mouse movement');
                analysis.confidence += mouseAnalysis.confidence;
            }
        }
        
        // Check keyboard dynamics
        if (data.keyboard) {
            const keyboardAnalysis = this.analyzeKeyboardDynamics(data.keyboard);
            if (keyboardAnalysis.isBot) {
                analysis.isBot = true;
                analysis.reasons.push('Abnormal keyboard patterns');
                analysis.confidence += keyboardAnalysis.confidence;
            }
        }
        
        // Check timing patterns
        if (data.timing) {
            const timingAnalysis = this.analyzeTimingPatterns(data.timing);
            if (timingAnalysis.isBot) {
                analysis.isBot = true;
                analysis.reasons.push('Suspicious timing patterns');
                analysis.confidence += timingAnalysis.confidence;
            }
        }
        
        analysis.confidence = Math.min(1, analysis.confidence);
        return analysis;
    }
    
    analyzeMouseMovement(mouseData) {
        // Check for linear movements (bots often move in straight lines)
        const movements = mouseData.movements || [];
        let linearCount = 0;
        
        for (let i = 2; i < movements.length; i++) {
            const angle1 = Math.atan2(
                movements[i - 1].y - movements[i - 2].y,
                movements[i - 1].x - movements[i - 2].x
            );
            const angle2 = Math.atan2(
                movements[i].y - movements[i - 1].y,
                movements[i].x - movements[i - 1].x
            );
            
            if (Math.abs(angle1 - angle2) < 0.1) {
                linearCount++;
            }
        }
        
        const linearRatio = linearCount / Math.max(1, movements.length - 2);
        
        return {
            isBot: linearRatio > 0.7,
            confidence: linearRatio
        };
    }
    
    analyzeKeyboardDynamics(keyboardData) {
        const dwellTimes = keyboardData.dwellTimes || [];
        const flightTimes = keyboardData.flightTimes || [];
        
        // Check for consistent timing (bots have regular patterns)
        const dwellVariance = this.calculateVariance(dwellTimes);
        const flightVariance = this.calculateVariance(flightTimes);
        
        const isRegular = dwellVariance < 10 && flightVariance < 10;
        
        return {
            isBot: isRegular,
            confidence: isRegular ? 0.8 : 0.2
        };
    }
    
    analyzeTimingPatterns(timingData) {
        const intervals = timingData.actionIntervals || [];
        
        // Check for regular intervals
        const variance = this.calculateVariance(intervals);
        const isRegular = variance < intervals.reduce((a, b) => a + b, 0) / intervals.length * 0.1;
        
        return {
            isBot: isRegular,
            confidence: isRegular ? 0.7 : 0.3
        };
    }
    
    calculateVariance(values) {
        if (values.length === 0) return 0;
        const mean = values.reduce((a, b) => a + b, 0) / values.length;
        const squaredDiffs = values.map(v => Math.pow(v - mean, 2));
        return squaredDiffs.reduce((a, b) => a + b, 0) / values.length;
    }
    
    getRequestPatterns(ip) {
        // Implementation for tracking request patterns
        return { suspicious: false, details: {} };
    }
    
    isScanning(ip) {
        // Implementation for detecting scanning behavior
        return false;
    }
    
    isCrawling(ip) {
        // Implementation for detecting crawling behavior
        return false;
    }
    
    isAPIAbuse(request, ip) {
        // Check for API-specific abuse patterns
        if (request.path.startsWith('/api/')) {
            // Check for rapid API calls, missing auth, etc.
            return false; // Placeholder
        }
        return false;
    }
    
    validateBrowserFingerprint(fingerprint) {
        // Implementation for fingerprint validation
        return { valid: true, spoofed: false };
    }
    
    calculateJA3(request) {
        // Simplified JA3 calculation
        return crypto.createHash('md5')
            .update(JSON.stringify(request.connection?.getCipher?.() || {}))
            .digest('hex');
    }
    
    isKnownBotJA3(ja3) {
        // Check against known bot JA3 fingerprints
        const knownBotJA3s = [
            // Add known bot JA3 hashes here
        ];
        return knownBotJA3s.includes(ja3);
    }
    
    extractTTL(socket) {
        // Extract TTL from socket if possible
        return 64; // Placeholder
    }
    
    extractMSS(socket) {
        // Extract Maximum Segment Size
        return 1460; // Placeholder
    }
    
    isAbnormalTCP(fingerprint) {
        // Check for abnormal TCP characteristics
        return false; // Placeholder
    }
    
    calculateBotScore(threats) {
        let score = 0;
        
        threats.forEach(threat => {
            score += threat.severity * 0.1;
        });
        
        return Math.min(1, score);
    }
    
    calculateConfidence(threats) {
        if (threats.length === 0) return 0;
        if (threats.length === 1) return 0.6;
        if (threats.length === 2) return 0.8;
        return 0.95;
    }
    
    shouldChallenge(botScore) {
        return botScore > 0.5;
    }
    
    generateChallenge() {
        const challengeType = 'proof_of_work';
        const challenge = {
            type: challengeType,
            token: crypto.randomBytes(32).toString('hex'),
            difficulty: 4,
            timestamp: Date.now(),
            expires: Date.now() + 300000 // 5 minutes
        };
        
        this.challengeTokens.set(challenge.token, challenge);
        
        return challenge;
    }
    
    verifyChallengeToken(token) {
        const challenge = this.challengeTokens.get(token);
        
        if (!challenge) {
            return { valid: false, reason: 'Unknown token' };
        }
        
        if (Date.now() > challenge.expires) {
            this.challengeTokens.delete(token);
            return { valid: false, reason: 'Token expired' };
        }
        
        // Verify proof of work or other challenge solution
        // Implementation depends on challenge type
        
        this.challengeTokens.delete(token);
        return { valid: true };
    }
    
    hasImpossibleVersions(versions) {
        // Check for impossible version combinations
        // Implementation would check against known valid combinations
        return false;
    }
    
    getRecommendation(threats) {
        const recommendations = [];
        
        if (threats.some(t => t.type === 'bot_malicious')) {
            recommendations.push('Block immediately - malicious bot detected');
        }
        
        if (threats.some(t => t.type === 'automation_headers')) {
            recommendations.push('Require CAPTCHA or proof-of-work challenge');
        }
        
        if (threats.some(t => t.type === 'scanning_behavior')) {
            recommendations.push('Rate limit and monitor closely');
        }
        
        return recommendations.length > 0 ? recommendations : ['Monitor and collect more data'];
    }
}

module.exports = BotDetectionPlugin;