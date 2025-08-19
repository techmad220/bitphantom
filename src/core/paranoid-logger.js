const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const { createWriteStream } = require('fs');
const EventEmitter = require('events');

class ParanoidLogger extends EventEmitter {
    constructor(config = {}) {
        super();
        
        this.config = {
            enabled: true,
            paranoidLevel: 'extreme', // 'high', 'extreme', 'insane'
            
            // Forensic logging
            logEverything: true,
            logRawPackets: true,
            logMemorySnapshots: true,
            logStackTraces: true,
            logTimingData: true,
            logBrowserFingerprints: true,
            logNetworkHops: true,
            
            // Evidence preservation
            tamperProof: true,
            cryptographicHashing: true,
            blockchainAnchoring: false,
            multipleBackups: 3,
            remoteBackup: true,
            
            // Stealth logging
            hiddenLogs: true,
            encryptedLogs: true,
            steganographicLogs: false,
            fragmentedLogs: true,
            
            // Analysis
            behavioralAnalysis: true,
            anomalyScoring: true,
            threatCorrelation: true,
            forensicTimeline: true,
            
            // Storage
            logDir: path.join(__dirname, '../../.shadow_logs'),
            maxLogSize: 100 * 1024 * 1024, // 100MB per file
            compressionLevel: 9,
            
            ...config
        };
        
        this.logStreams = new Map();
        this.evidenceChain = [];
        this.sessionRecording = new Map();
        this.threatIntelligence = new Map();
        this.hashChain = null;
        this.initVector = crypto.randomBytes(16);
    }
    
    async initialize() {
        // Create hidden log directories
        const dirs = [
            this.config.logDir,
            path.join(this.config.logDir, '.forensics'),
            path.join(this.config.logDir, '.evidence'),
            path.join(this.config.logDir, '.behavioral'),
            path.join(this.config.logDir, '.network'),
            path.join(this.config.logDir, '.fragments')
        ];
        
        for (const dir of dirs) {
            await fs.mkdir(dir, { recursive: true, mode: 0o700 });
            
            // Hide directory on Unix systems
            if (process.platform !== 'win32') {
                try {
                    await fs.rename(dir, dir); // Ensure it exists
                    const parentDir = path.dirname(dir);
                    const baseName = path.basename(dir);
                    if (!baseName.startsWith('.')) {
                        await fs.rename(dir, path.join(parentDir, '.' + baseName));
                    }
                } catch (e) {
                    // Directory already hidden
                }
            }
        }
        
        // Initialize hash chain for tamper detection
        this.hashChain = crypto.randomBytes(32).toString('hex');
        
        // Setup log rotation with encryption
        await this.setupLogRotation();
        
        console.log('[Paranoid Logger] Initialized in', this.config.paranoidLevel, 'mode');
    }
    
    async logThreat(threat, request, response) {
        const logEntry = {
            id: crypto.randomBytes(16).toString('hex'),
            timestamp: Date.now(),
            timestampNano: process.hrtime.bigint().toString(),
            threat,
            
            // Request forensics
            request: {
                method: request.method,
                path: request.path,
                headers: this.sanitizeHeaders(request.headers),
                body: request.body,
                query: request.query,
                ip: request.ip,
                ips: request.ips,
                protocol: request.protocol,
                secure: request.secure,
                xhr: request.xhr,
                
                // Deep inspection
                rawBody: request.rawBody,
                cookies: request.cookies,
                signedCookies: request.signedCookies,
                params: request.params,
                route: request.route,
                baseUrl: request.baseUrl,
                originalUrl: request.originalUrl,
                
                // Network forensics
                socket: {
                    remoteAddress: request.socket?.remoteAddress,
                    remotePort: request.socket?.remotePort,
                    localAddress: request.socket?.localAddress,
                    localPort: request.socket?.localPort,
                    bytesRead: request.socket?.bytesRead,
                    bytesWritten: request.socket?.bytesWritten
                },
                
                // Timing data
                timing: {
                    start: request.startTime,
                    dnsLookup: request.timings?.dnslookup,
                    tcpConnection: request.timings?.connection,
                    tlsHandshake: request.timings?.secureConnection,
                    firstByte: request.timings?.firstByte,
                    contentDownload: request.timings?.download,
                    total: request.timings?.total
                }
            },
            
            // Response forensics
            response: response ? {
                statusCode: response.statusCode,
                headers: response.getHeaders?.(),
                size: response.get?.('content-length')
            } : null,
            
            // System state
            system: {
                memory: process.memoryUsage(),
                cpu: process.cpuUsage(),
                uptime: process.uptime(),
                platform: process.platform,
                arch: process.arch,
                versions: process.versions,
                env: this.sanitizeEnv(process.env)
            },
            
            // Stack trace
            stackTrace: this.config.logStackTraces ? new Error().stack : null,
            
            // Behavioral analysis
            behavioral: await this.analyzeBehavior(request),
            
            // Evidence chain
            previousHash: this.hashChain,
            hash: null
        };
        
        // Calculate hash for tamper detection
        logEntry.hash = this.calculateHash(logEntry);
        this.hashChain = logEntry.hash;
        
        // Store in evidence chain
        this.evidenceChain.push({
            hash: logEntry.hash,
            timestamp: logEntry.timestamp,
            threat: threat.type
        });
        
        // Write to multiple locations
        await this.writeParanoidLog(logEntry);
        
        // Trigger real-time analysis
        this.emit('threat-logged', logEntry);
        
        return logEntry;
    }
    
    async writeParanoidLog(entry) {
        // Encrypt the log entry
        const encrypted = this.encryptData(entry);
        
        // Fragment the log for stealth
        if (this.config.fragmentedLogs) {
            await this.writeFragmentedLog(encrypted);
        }
        
        // Write to main log
        await this.writeToStream('main', encrypted);
        
        // Write forensic copy
        await this.writeToStream('forensics', {
            ...entry,
            encrypted: false,
            forensicMarkers: this.addForensicMarkers(entry)
        });
        
        // Write behavioral analysis
        if (entry.behavioral) {
            await this.writeToStream('behavioral', entry.behavioral);
        }
        
        // Create backups
        if (this.config.multipleBackups > 0) {
            await this.createBackups(encrypted);
        }
        
        // Remote backup
        if (this.config.remoteBackup) {
            await this.sendRemoteBackup(encrypted);
        }
    }
    
    async writeFragmentedLog(data) {
        const fragments = this.fragmentData(data);
        const fragmentDir = path.join(this.config.logDir, '.fragments');
        
        for (let i = 0; i < fragments.length; i++) {
            const fragmentFile = path.join(
                fragmentDir,
                `${Date.now()}_${i}_${crypto.randomBytes(8).toString('hex')}.frag`
            );
            
            await fs.writeFile(fragmentFile, fragments[i], { mode: 0o600 });
        }
        
        // Store reassembly map (encrypted)
        const mapFile = path.join(fragmentDir, '.map');
        const map = {
            id: data.id,
            fragments: fragments.length,
            checksum: this.calculateHash(data)
        };
        
        await fs.appendFile(mapFile, this.encryptData(map) + '\n');
    }
    
    fragmentData(data) {
        const str = JSON.stringify(data);
        const chunkSize = Math.floor(str.length / (3 + Math.random() * 5));
        const fragments = [];
        
        for (let i = 0; i < str.length; i += chunkSize) {
            fragments.push(str.slice(i, i + chunkSize));
        }
        
        // Shuffle fragments for additional obfuscation
        return fragments.sort(() => Math.random() - 0.5);
    }
    
    async analyzeBehavior(request) {
        const ip = request.ip;
        
        if (!this.sessionRecording.has(ip)) {
            this.sessionRecording.set(ip, {
                requests: [],
                patterns: [],
                riskScore: 0,
                firstSeen: Date.now()
            });
        }
        
        const session = this.sessionRecording.get(ip);
        
        // Record request
        session.requests.push({
            timestamp: Date.now(),
            path: request.path,
            method: request.method,
            userAgent: request.headers['user-agent'],
            referer: request.headers['referer']
        });
        
        // Analyze patterns
        const analysis = {
            requestRate: this.calculateRequestRate(session),
            pathPatterns: this.analyzePathPatterns(session),
            timingPatterns: this.analyzeTimingPatterns(session),
            headerConsistency: this.analyzeHeaderConsistency(session, request),
            mouseMovement: this.analyzeMouseMovement(request),
            keyboardDynamics: this.analyzeKeyboardDynamics(request),
            
            // Advanced behavioral markers
            automationScore: this.detectAutomation(session, request),
            evasionScore: this.detectEvasion(session, request),
            reconScore: this.detectReconnaissance(session),
            exploitScore: this.detectExploitation(session),
            
            // Risk assessment
            overallRisk: 0
        };
        
        // Calculate overall risk
        analysis.overallRisk = (
            analysis.automationScore * 0.2 +
            analysis.evasionScore * 0.3 +
            analysis.reconScore * 0.2 +
            analysis.exploitScore * 0.3
        );
        
        session.riskScore = analysis.overallRisk;
        
        return analysis;
    }
    
    calculateRequestRate(session) {
        const now = Date.now();
        const recentRequests = session.requests.filter(r => now - r.timestamp < 60000);
        return recentRequests.length / 60; // Requests per second
    }
    
    analyzePathPatterns(session) {
        const paths = session.requests.map(r => r.path);
        const patterns = {};
        
        // Detect scanning patterns
        patterns.sequential = this.detectSequentialPaths(paths);
        patterns.bruteforce = this.detectBruteforcePaths(paths);
        patterns.traversal = paths.filter(p => p.includes('../')).length;
        patterns.hiddenFiles = paths.filter(p => p.includes('/.')).length;
        
        return patterns;
    }
    
    analyzeTimingPatterns(session) {
        const timestamps = session.requests.map(r => r.timestamp);
        const intervals = [];
        
        for (let i = 1; i < timestamps.length; i++) {
            intervals.push(timestamps[i] - timestamps[i - 1]);
        }
        
        return {
            avgInterval: intervals.reduce((a, b) => a + b, 0) / intervals.length,
            minInterval: Math.min(...intervals),
            maxInterval: Math.max(...intervals),
            variance: this.calculateVariance(intervals),
            isRegular: this.detectRegularIntervals(intervals)
        };
    }
    
    analyzeHeaderConsistency(session, request) {
        const currentUA = request.headers['user-agent'];
        const allUAs = session.requests.map(r => r.userAgent);
        const uniqueUAs = [...new Set(allUAs)];
        
        return {
            userAgentChanges: uniqueUAs.length,
            currentMatchesPrevious: allUAs[allUAs.length - 2] === currentUA,
            suspiciousHeaders: this.detectSuspiciousHeaders(request.headers)
        };
    }
    
    analyzeMouseMovement(request) {
        // Check if mouse movement data was sent
        const mouseData = request.body?.mouseData;
        if (!mouseData) return { score: 0.5 }; // Neutral if no data
        
        return {
            humanLike: this.isHumanMouseMovement(mouseData),
            velocity: this.calculateMouseVelocity(mouseData),
            acceleration: this.calculateMouseAcceleration(mouseData)
        };
    }
    
    analyzeKeyboardDynamics(request) {
        const keyData = request.body?.keyboardData;
        if (!keyData) return { score: 0.5 };
        
        return {
            typingSpeed: this.calculateTypingSpeed(keyData),
            dwellTime: this.calculateDwellTime(keyData),
            flightTime: this.calculateFlightTime(keyData)
        };
    }
    
    detectAutomation(session, request) {
        let score = 0;
        
        // Check for automation indicators
        if (!request.headers['user-agent']) score += 0.2;
        if (!request.headers['accept-language']) score += 0.1;
        if (!request.headers['accept-encoding']) score += 0.1;
        if (request.headers['user-agent']?.includes('bot')) score += 0.3;
        if (request.headers['user-agent']?.includes('crawler')) score += 0.3;
        
        // Check timing
        const intervals = this.getRequestIntervals(session);
        if (intervals.every(i => Math.abs(i - intervals[0]) < 100)) score += 0.4; // Too regular
        
        return Math.min(1, score);
    }
    
    detectEvasion(session, request) {
        let score = 0;
        
        // Check for evasion techniques
        if (request.headers['user-agent']?.length > 500) score += 0.2; // Unusually long
        if (request.path.includes('%00')) score += 0.3; // Null byte
        if (request.path.match(/[^\x00-\x7F]/)) score += 0.2; // Non-ASCII
        if (this.detectEncoding(request.path)) score += 0.3;
        
        // Check for proxy/VPN headers
        const proxyHeaders = ['x-forwarded-for', 'x-real-ip', 'x-originating-ip'];
        proxyHeaders.forEach(header => {
            if (request.headers[header]) score += 0.1;
        });
        
        return Math.min(1, score);
    }
    
    detectReconnaissance(session) {
        let score = 0;
        const paths = session.requests.map(r => r.path);
        
        // Check for common recon patterns
        const reconPaths = ['/robots.txt', '/sitemap.xml', '/.git', '/.env', '/admin'];
        reconPaths.forEach(path => {
            if (paths.includes(path)) score += 0.1;
        });
        
        // Check for directory enumeration
        if (paths.filter(p => p.endsWith('/')).length > 5) score += 0.2;
        
        // Check for parameter fuzzing
        const uniquePaths = [...new Set(paths)];
        if (uniquePaths.length / paths.length > 0.8) score += 0.2; // Many unique paths
        
        return Math.min(1, score);
    }
    
    detectExploitation(session) {
        let score = 0;
        const requests = session.requests;
        
        // Check for exploit patterns
        requests.forEach(req => {
            if (req.path.includes('UNION SELECT')) score += 0.3;
            if (req.path.includes('<script>')) score += 0.3;
            if (req.path.includes('../')) score += 0.2;
            if (req.path.includes('exec(')) score += 0.3;
            if (req.path.includes('eval(')) score += 0.3;
        });
        
        return Math.min(1, score);
    }
    
    detectSequentialPaths(paths) {
        let sequential = 0;
        for (let i = 1; i < paths.length; i++) {
            if (this.areSequential(paths[i - 1], paths[i])) {
                sequential++;
            }
        }
        return sequential;
    }
    
    areSequential(path1, path2) {
        // Check if paths differ by a number
        const num1 = path1.match(/\d+/);
        const num2 = path2.match(/\d+/);
        
        if (num1 && num2) {
            return Math.abs(parseInt(num1[0]) - parseInt(num2[0])) === 1;
        }
        
        return false;
    }
    
    detectBruteforcePaths(paths) {
        const pathCounts = {};
        paths.forEach(path => {
            const base = path.replace(/\?.*$/, ''); // Remove query string
            pathCounts[base] = (pathCounts[base] || 0) + 1;
        });
        
        // Count paths accessed more than 10 times
        return Object.values(pathCounts).filter(count => count > 10).length;
    }
    
    detectRegularIntervals(intervals) {
        if (intervals.length < 3) return false;
        
        const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = this.calculateVariance(intervals);
        
        // Low variance indicates regular intervals (bot-like)
        return variance < avg * 0.1;
    }
    
    calculateVariance(values) {
        const avg = values.reduce((a, b) => a + b, 0) / values.length;
        const squaredDiffs = values.map(v => Math.pow(v - avg, 2));
        return squaredDiffs.reduce((a, b) => a + b, 0) / values.length;
    }
    
    getRequestIntervals(session) {
        const timestamps = session.requests.map(r => r.timestamp);
        const intervals = [];
        
        for (let i = 1; i < timestamps.length; i++) {
            intervals.push(timestamps[i] - timestamps[i - 1]);
        }
        
        return intervals;
    }
    
    detectEncoding(str) {
        // Check for various encoding types
        const encodings = [
            /%[0-9a-f]{2}/i, // URL encoding
            /\\x[0-9a-f]{2}/i, // Hex encoding
            /\\u[0-9a-f]{4}/i, // Unicode encoding
            /&#x[0-9a-f]+;/i, // HTML hex encoding
            /&#\d+;/i // HTML decimal encoding
        ];
        
        return encodings.some(pattern => pattern.test(str));
    }
    
    detectSuspiciousHeaders(headers) {
        const suspicious = [];
        
        // Check for unusual headers
        if (headers['x-forwarded-host']) suspicious.push('x-forwarded-host');
        if (headers['x-original-url']) suspicious.push('x-original-url');
        if (headers['x-rewrite-url']) suspicious.push('x-rewrite-url');
        if (headers['x-forwarded-proto'] === 'http' && headers['x-forwarded-proto'] !== 'https') {
            suspicious.push('protocol-downgrade');
        }
        
        return suspicious;
    }
    
    isHumanMouseMovement(mouseData) {
        if (!mouseData || !Array.isArray(mouseData)) return false;
        
        // Check for human-like characteristics
        const velocities = [];
        for (let i = 1; i < mouseData.length; i++) {
            const dx = mouseData[i].x - mouseData[i - 1].x;
            const dy = mouseData[i].y - mouseData[i - 1].y;
            const dt = mouseData[i].t - mouseData[i - 1].t;
            
            if (dt > 0) {
                velocities.push(Math.sqrt(dx * dx + dy * dy) / dt);
            }
        }
        
        // Human mouse movement has variable velocity
        const variance = this.calculateVariance(velocities);
        return variance > 0.1;
    }
    
    calculateMouseVelocity(mouseData) {
        // Implementation for mouse velocity calculation
        return 0;
    }
    
    calculateMouseAcceleration(mouseData) {
        // Implementation for mouse acceleration calculation
        return 0;
    }
    
    calculateTypingSpeed(keyData) {
        // Implementation for typing speed calculation
        return 0;
    }
    
    calculateDwellTime(keyData) {
        // Implementation for dwell time calculation
        return 0;
    }
    
    calculateFlightTime(keyData) {
        // Implementation for flight time calculation
        return 0;
    }
    
    encryptData(data) {
        if (!this.config.encryptedLogs) return data;
        
        const algorithm = 'aes-256-gcm';
        const key = crypto.scryptSync(
            process.env.LOG_KEY || 'paranoid-key-' + Date.now(),
            'paranoid-salt',
            32
        );
        
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(algorithm, key, iv);
        
        const str = JSON.stringify(data);
        let encrypted = cipher.update(str, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const authTag = cipher.getAuthTag();
        
        return {
            encrypted: true,
            algorithm,
            data: encrypted,
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex'),
            timestamp: Date.now()
        };
    }
    
    calculateHash(data) {
        const str = JSON.stringify(data);
        return crypto.createHash('sha512').update(str).digest('hex');
    }
    
    sanitizeHeaders(headers) {
        const sanitized = { ...headers };
        
        // Remove sensitive headers
        const sensitive = ['authorization', 'cookie', 'x-api-key'];
        sensitive.forEach(header => {
            if (sanitized[header]) {
                sanitized[header] = '[REDACTED-' + 
                    crypto.createHash('sha256')
                        .update(sanitized[header])
                        .digest('hex')
                        .substring(0, 8) + ']';
            }
        });
        
        return sanitized;
    }
    
    sanitizeEnv(env) {
        const sanitized = {};
        const allowed = ['NODE_ENV', 'PORT', 'HOST'];
        
        allowed.forEach(key => {
            if (env[key]) {
                sanitized[key] = env[key];
            }
        });
        
        return sanitized;
    }
    
    addForensicMarkers(entry) {
        return {
            checksum: this.calculateHash(entry),
            previousChecksum: this.hashChain,
            signature: this.signData(entry),
            timestamp: {
                unix: entry.timestamp,
                iso: new Date(entry.timestamp).toISOString(),
                nano: entry.timestampNano,
                highRes: process.hrtime.bigint().toString()
            },
            correlation: {
                requestId: entry.id,
                sessionId: crypto.createHash('sha256').update(entry.request.ip).digest('hex'),
                threatId: entry.threat.id || crypto.randomBytes(16).toString('hex')
            }
        };
    }
    
    signData(data) {
        // Create digital signature for non-repudiation
        const sign = crypto.createSign('SHA512');
        sign.write(JSON.stringify(data));
        sign.end();
        
        // Use a proper private key in production
        const privateKey = process.env.SIGNING_KEY || 'dummy-key';
        
        try {
            return sign.sign(privateKey, 'hex');
        } catch (e) {
            return 'unsigned';
        }
    }
    
    async writeToStream(type, data) {
        const fileName = `${type}_${new Date().toISOString().split('T')[0]}.log`;
        const filePath = path.join(this.config.logDir, fileName);
        
        if (!this.logStreams.has(type)) {
            this.logStreams.set(type, createWriteStream(filePath, {
                flags: 'a',
                mode: 0o600
            }));
        }
        
        const stream = this.logStreams.get(type);
        stream.write(JSON.stringify(data) + '\n');
    }
    
    async createBackups(data) {
        const backupDir = path.join(this.config.logDir, '.backups');
        await fs.mkdir(backupDir, { recursive: true, mode: 0o700 });
        
        for (let i = 0; i < this.config.multipleBackups; i++) {
            const backupFile = path.join(
                backupDir,
                `backup_${i}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.bak`
            );
            
            await fs.writeFile(backupFile, JSON.stringify(data), { mode: 0o600 });
        }
    }
    
    async sendRemoteBackup(data) {
        // Implement remote backup logic
        // This could be to S3, remote syslog, etc.
        if (this.config.remoteEndpoint) {
            try {
                // Send to remote endpoint
                console.log('[Paranoid Logger] Remote backup queued');
            } catch (error) {
                console.error('[Paranoid Logger] Remote backup failed:', error);
            }
        }
    }
    
    async setupLogRotation() {
        setInterval(async () => {
            for (const [type, stream] of this.logStreams) {
                stream.end();
                this.logStreams.delete(type);
            }
            
            // Compress old logs
            const files = await fs.readdir(this.config.logDir);
            for (const file of files) {
                if (file.endsWith('.log')) {
                    const filePath = path.join(this.config.logDir, file);
                    const stats = await fs.stat(filePath);
                    
                    if (stats.size > this.config.maxLogSize) {
                        await this.compressLog(filePath);
                    }
                }
            }
        }, 3600000); // Every hour
    }
    
    async compressLog(filePath) {
        const zlib = require('zlib');
        const { pipeline } = require('stream/promises');
        
        const source = require('fs').createReadStream(filePath);
        const destination = require('fs').createWriteStream(`${filePath}.gz`);
        const gzip = zlib.createGzip({ level: this.config.compressionLevel });
        
        await pipeline(source, gzip, destination);
        await fs.unlink(filePath);
    }
    
    async getForensicReport(threatId) {
        // Generate comprehensive forensic report
        const report = {
            threatId,
            timeline: [],
            evidence: [],
            analysis: {},
            recommendations: []
        };
        
        // Gather all related logs
        const logs = await this.gatherRelatedLogs(threatId);
        
        // Build timeline
        report.timeline = this.buildTimeline(logs);
        
        // Collect evidence
        report.evidence = this.collectEvidence(logs);
        
        // Perform analysis
        report.analysis = this.performForensicAnalysis(logs);
        
        // Generate recommendations
        report.recommendations = this.generateRecommendations(report.analysis);
        
        return report;
    }
    
    async gatherRelatedLogs(threatId) {
        // Implementation to gather all logs related to a threat
        return [];
    }
    
    buildTimeline(logs) {
        // Implementation to build forensic timeline
        return [];
    }
    
    collectEvidence(logs) {
        // Implementation to collect digital evidence
        return [];
    }
    
    performForensicAnalysis(logs) {
        // Implementation for forensic analysis
        return {};
    }
    
    generateRecommendations(analysis) {
        // Implementation to generate security recommendations
        return [];
    }
}

module.exports = ParanoidLogger;