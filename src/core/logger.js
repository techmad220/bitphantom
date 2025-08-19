const fs = require('fs').promises;
const path = require('path');
const { createWriteStream } = require('fs');
const EventEmitter = require('events');

class WAFLogger extends EventEmitter {
    constructor(config = {}) {
        super();
        
        this.config = {
            logDir: path.join(__dirname, '../../logs'),
            maxFileSize: 50 * 1024 * 1024, // 50MB
            maxFiles: 10,
            logLevel: 'info',
            console: true,
            file: true,
            remote: false,
            remoteEndpoint: null,
            remoteApiKey: null,
            bufferSize: 100,
            flushInterval: 5000,
            format: 'json', // 'json' or 'text'
            ...config
        };
        
        this.levels = {
            error: 0,
            warn: 1,
            info: 2,
            debug: 3
        };
        
        this.streams = new Map();
        this.buffer = [];
        this.stats = {
            totalLogs: 0,
            errorCount: 0,
            warnCount: 0,
            infoCount: 0,
            debugCount: 0
        };
    }

    async initialize() {
        // Create log directory
        await fs.mkdir(this.config.logDir, { recursive: true });
        
        // Initialize file streams
        await this.initializeStreams();
        
        // Start flush interval
        if (this.config.remote && this.config.remoteEndpoint) {
            this.flushInterval = setInterval(() => {
                this.flushRemote();
            }, this.config.flushInterval);
        }
        
        // Rotate logs on startup
        await this.rotateLogs();
        
        return true;
    }

    async initializeStreams() {
        const logTypes = ['access', 'error', 'security', 'performance'];
        
        for (const type of logTypes) {
            const fileName = `waf-${type}.log`;
            const filePath = path.join(this.config.logDir, fileName);
            
            const stream = createWriteStream(filePath, {
                flags: 'a',
                encoding: 'utf8'
            });
            
            this.streams.set(type, stream);
        }
    }

    log(level, message, data = {}) {
        if (this.levels[level] === undefined) {
            level = 'info';
        }
        
        if (this.levels[level] > this.levels[this.config.logLevel]) {
            return;
        }
        
        const logEntry = this.createLogEntry(level, message, data);
        
        // Update stats
        this.stats.totalLogs++;
        this.stats[`${level}Count`]++;
        
        // Console logging
        if (this.config.console) {
            this.logToConsole(logEntry);
        }
        
        // File logging
        if (this.config.file) {
            this.logToFile(logEntry);
        }
        
        // Buffer for remote logging
        if (this.config.remote) {
            this.buffer.push(logEntry);
            
            if (this.buffer.length >= this.config.bufferSize) {
                this.flushRemote();
            }
        }
        
        // Emit log event
        this.emit('log', logEntry);
    }

    createLogEntry(level, message, data) {
        return {
            timestamp: new Date().toISOString(),
            level,
            message,
            ...data,
            hostname: require('os').hostname(),
            pid: process.pid
        };
    }

    logToConsole(entry) {
        const colors = {
            error: '\x1b[31m',
            warn: '\x1b[33m',
            info: '\x1b[36m',
            debug: '\x1b[90m'
        };
        
        const reset = '\x1b[0m';
        const color = colors[entry.level] || reset;
        
        if (this.config.format === 'json') {
            console.log(JSON.stringify(entry));
        } else {
            console.log(`${color}[${entry.timestamp}] [${entry.level.toUpperCase()}] ${entry.message}${reset}`, 
                        entry.data ? JSON.stringify(entry.data) : '');
        }
    }

    async logToFile(entry) {
        const type = this.getLogType(entry);
        const stream = this.streams.get(type);
        
        if (stream) {
            const line = JSON.stringify(entry) + '\n';
            stream.write(line);
        }
    }

    getLogType(entry) {
        if (entry.level === 'error') return 'error';
        if (entry.threat || entry.blocked) return 'security';
        if (entry.performance || entry.latency) return 'performance';
        return 'access';
    }

    async flushRemote() {
        if (this.buffer.length === 0) return;
        
        const logs = [...this.buffer];
        this.buffer = [];
        
        try {
            const response = await this.sendLogsRemote(logs);
            
            if (!response.ok) {
                // Re-add logs to buffer if send failed
                this.buffer.unshift(...logs);
                this.log('error', 'Failed to send logs to remote endpoint', {
                    status: response.status,
                    logsCount: logs.length
                });
            }
        } catch (error) {
            // Re-add logs to buffer if send failed
            this.buffer.unshift(...logs);
            this.log('error', 'Error sending logs to remote endpoint', {
                error: error.message,
                logsCount: logs.length
            });
        }
    }

    async sendLogsRemote(logs) {
        // Implement remote logging based on endpoint type
        // This is a placeholder - implement based on your logging service
        const fetch = require('node-fetch');
        
        return fetch(this.config.remoteEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.config.remoteApiKey}`
            },
            body: JSON.stringify({
                logs,
                source: 'waf',
                timestamp: new Date().toISOString()
            })
        });
    }

    async rotateLogs() {
        for (const [type, stream] of this.streams) {
            const fileName = `waf-${type}.log`;
            const filePath = path.join(this.config.logDir, fileName);
            
            try {
                const stats = await fs.stat(filePath);
                
                if (stats.size > this.config.maxFileSize) {
                    // Close current stream
                    stream.end();
                    
                    // Rotate files
                    await this.rotateFile(filePath);
                    
                    // Create new stream
                    const newStream = createWriteStream(filePath, {
                        flags: 'a',
                        encoding: 'utf8'
                    });
                    
                    this.streams.set(type, newStream);
                }
            } catch (error) {
                // File doesn't exist yet
            }
        }
    }

    async rotateFile(filePath) {
        const dir = path.dirname(filePath);
        const basename = path.basename(filePath, '.log');
        
        // Shift existing rotated files
        for (let i = this.config.maxFiles - 1; i > 0; i--) {
            const oldPath = path.join(dir, `${basename}.${i}.log`);
            const newPath = path.join(dir, `${basename}.${i + 1}.log`);
            
            try {
                await fs.rename(oldPath, newPath);
            } catch (error) {
                // File doesn't exist
            }
        }
        
        // Rename current file to .1
        const rotatedPath = path.join(dir, `${basename}.1.log`);
        await fs.rename(filePath, rotatedPath);
        
        // Compress old file if needed
        if (this.config.compress) {
            await this.compressFile(rotatedPath);
        }
    }

    async compressFile(filePath) {
        const zlib = require('zlib');
        const { pipeline } = require('stream/promises');
        
        const source = require('fs').createReadStream(filePath);
        const destination = require('fs').createWriteStream(`${filePath}.gz`);
        const gzip = zlib.createGzip();
        
        await pipeline(source, gzip, destination);
        await fs.unlink(filePath);
    }

    logSecurity(threat) {
        this.log('warn', 'Security threat detected', {
            threat: threat.type,
            severity: threat.severity,
            details: threat.details,
            blocked: threat.blocked
        });
    }

    logAccess(request, response) {
        this.log('info', 'Request processed', {
            method: request.method,
            path: request.path,
            ip: request.ip,
            status: response.status,
            duration: response.duration,
            userAgent: request.headers?.['user-agent']
        });
    }

    logPerformance(metric, value, tags = {}) {
        this.log('info', 'Performance metric', {
            metric,
            value,
            tags,
            performance: true
        });
    }

    async getStats() {
        const files = await fs.readdir(this.config.logDir);
        const logFiles = files.filter(f => f.startsWith('waf-'));
        
        const fileSizes = await Promise.all(
            logFiles.map(async (file) => {
                const filePath = path.join(this.config.logDir, file);
                const stats = await fs.stat(filePath);
                return {
                    file,
                    size: stats.size,
                    modified: stats.mtime
                };
            })
        );
        
        return {
            ...this.stats,
            bufferSize: this.buffer.length,
            logFiles: fileSizes,
            totalSize: fileSizes.reduce((sum, f) => sum + f.size, 0)
        };
    }

    async searchLogs(query) {
        const results = [];
        const { type, level, startTime, endTime, limit = 100 } = query;
        
        const fileName = type ? `waf-${type}.log` : 'waf-access.log';
        const filePath = path.join(this.config.logDir, fileName);
        
        try {
            const content = await fs.readFile(filePath, 'utf8');
            const lines = content.split('\n').filter(line => line.trim());
            
            for (const line of lines) {
                try {
                    const entry = JSON.parse(line);
                    
                    // Apply filters
                    if (level && entry.level !== level) continue;
                    if (startTime && new Date(entry.timestamp) < new Date(startTime)) continue;
                    if (endTime && new Date(entry.timestamp) > new Date(endTime)) continue;
                    
                    results.push(entry);
                    
                    if (results.length >= limit) break;
                } catch (error) {
                    // Invalid JSON line
                }
            }
        } catch (error) {
            this.log('error', 'Error searching logs', { error: error.message });
        }
        
        return results;
    }

    async cleanup() {
        // Flush any remaining logs
        if (this.config.remote) {
            await this.flushRemote();
        }
        
        // Clear interval
        if (this.flushInterval) {
            clearInterval(this.flushInterval);
        }
        
        // Close all streams
        for (const stream of this.streams.values()) {
            stream.end();
        }
        
        this.streams.clear();
        this.buffer = [];
    }
}

module.exports = WAFLogger;