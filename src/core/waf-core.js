const EventEmitter = require('events');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

class WAFCore extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            enabled: true,
            mode: 'monitor', // 'monitor', 'block', 'learning'
            pluginDir: path.join(__dirname, '../plugins'),
            logDir: path.join(__dirname, '../../logs'),
            cacheSize: 1000,
            rateLimitWindow: 60000, // 1 minute
            rateLimitMax: 100,
            whitelistIPs: [],
            blacklistIPs: [],
            ...config
        };
        
        this.plugins = new Map();
        this.requestCache = new Map();
        this.rateLimitCache = new Map();
        this.stats = {
            totalRequests: 0,
            blockedRequests: 0,
            threats: new Map(),
            startTime: Date.now()
        };
    }

    async initialize() {
        await this.loadPlugins();
        await this.setupLogging();
        this.startCleanupInterval();
        this.emit('initialized', { plugins: Array.from(this.plugins.keys()) });
    }

    async loadPlugins() {
        try {
            const files = await fs.readdir(this.config.pluginDir);
            const pluginFiles = files.filter(f => f.endsWith('.plugin.js'));
            
            for (const file of pluginFiles) {
                const pluginPath = path.join(this.config.pluginDir, file);
                const Plugin = require(pluginPath);
                const plugin = new Plugin(this);
                
                if (plugin.validate()) {
                    this.plugins.set(plugin.name, plugin);
                    await plugin.initialize();
                    console.log(`[WAF] Plugin loaded: ${plugin.name} v${plugin.version}`);
                }
            }
        } catch (error) {
            console.error('[WAF] Plugin loading error:', error);
        }
    }

    async analyze(request) {
        const requestId = this.generateRequestId();
        const analysis = {
            id: requestId,
            timestamp: Date.now(),
            ip: request.ip || request.connection?.remoteAddress,
            method: request.method,
            path: request.path || request.url,
            headers: request.headers,
            body: request.body,
            query: request.query,
            threats: [],
            score: 0,
            blocked: false
        };

        // Check IP whitelist/blacklist
        if (this.isBlacklisted(analysis.ip)) {
            analysis.threats.push({ type: 'blacklist', severity: 10 });
            analysis.blocked = true;
            analysis.score = 100;
            return analysis;
        }

        if (this.isWhitelisted(analysis.ip)) {
            return analysis;
        }

        // Check rate limiting
        if (this.isRateLimited(analysis.ip)) {
            analysis.threats.push({ type: 'rate_limit', severity: 7 });
            analysis.score += 70;
        }

        // Run plugins
        for (const [name, plugin] of this.plugins) {
            if (!plugin.enabled) continue;
            
            try {
                const result = await plugin.analyze(request, analysis);
                if (result.threat) {
                    analysis.threats.push({
                        plugin: name,
                        ...result.threat
                    });
                    analysis.score += result.threat.severity * 10;
                }
            } catch (error) {
                console.error(`[WAF] Plugin error (${name}):`, error);
            }
        }

        // Determine if request should be blocked
        analysis.blocked = this.shouldBlock(analysis);
        
        // Update stats
        this.updateStats(analysis);
        
        // Emit events
        this.emit('request-analyzed', analysis);
        if (analysis.blocked) {
            this.emit('threat-detected', analysis);
        }

        // Store in cache
        this.requestCache.set(requestId, analysis);
        
        return analysis;
    }

    shouldBlock(analysis) {
        if (this.config.mode === 'monitor') return false;
        if (this.config.mode === 'learning') return false;
        return analysis.score >= 50;
    }

    isWhitelisted(ip) {
        return this.config.whitelistIPs.includes(ip);
    }

    isBlacklisted(ip) {
        return this.config.blacklistIPs.includes(ip);
    }

    isRateLimited(ip) {
        const now = Date.now();
        const windowStart = now - this.config.rateLimitWindow;
        
        if (!this.rateLimitCache.has(ip)) {
            this.rateLimitCache.set(ip, []);
        }
        
        const requests = this.rateLimitCache.get(ip);
        const recentRequests = requests.filter(t => t > windowStart);
        this.rateLimitCache.set(ip, recentRequests);
        
        recentRequests.push(now);
        return recentRequests.length > this.config.rateLimitMax;
    }

    updateStats(analysis) {
        this.stats.totalRequests++;
        if (analysis.blocked) {
            this.stats.blockedRequests++;
        }
        
        for (const threat of analysis.threats) {
            const key = threat.plugin || threat.type;
            this.stats.threats.set(key, (this.stats.threats.get(key) || 0) + 1);
        }
    }

    generateRequestId() {
        return crypto.randomBytes(16).toString('hex');
    }

    async setupLogging() {
        try {
            await fs.mkdir(this.config.logDir, { recursive: true });
        } catch (error) {
            console.error('[WAF] Log directory setup error:', error);
        }
    }

    startCleanupInterval() {
        setInterval(() => {
            // Clean old entries from cache
            const maxAge = 3600000; // 1 hour
            const now = Date.now();
            
            for (const [id, analysis] of this.requestCache) {
                if (now - analysis.timestamp > maxAge) {
                    this.requestCache.delete(id);
                }
            }
            
            // Limit cache size
            if (this.requestCache.size > this.config.cacheSize) {
                const entries = Array.from(this.requestCache.entries());
                entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
                const toDelete = entries.slice(0, entries.length - this.config.cacheSize);
                toDelete.forEach(([id]) => this.requestCache.delete(id));
            }
        }, 60000); // Run every minute
    }

    getStats() {
        return {
            ...this.stats,
            uptime: Date.now() - this.stats.startTime,
            cacheSize: this.requestCache.size,
            plugins: Array.from(this.plugins.keys()),
            mode: this.config.mode
        };
    }

    async reloadPlugin(pluginName) {
        const plugin = this.plugins.get(pluginName);
        if (plugin) {
            await plugin.cleanup();
            this.plugins.delete(pluginName);
        }
        
        // Reload the plugin
        const files = await fs.readdir(this.config.pluginDir);
        const pluginFile = files.find(f => f.includes(pluginName));
        if (pluginFile) {
            delete require.cache[require.resolve(path.join(this.config.pluginDir, pluginFile))];
            const Plugin = require(path.join(this.config.pluginDir, pluginFile));
            const newPlugin = new Plugin(this);
            if (newPlugin.validate()) {
                this.plugins.set(newPlugin.name, newPlugin);
                await newPlugin.initialize();
            }
        }
    }

    async cleanup() {
        for (const plugin of this.plugins.values()) {
            await plugin.cleanup();
        }
        this.removeAllListeners();
    }
}

module.exports = WAFCore;