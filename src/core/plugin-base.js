class PluginBase {
    constructor(waf, config = {}) {
        this.waf = waf;
        this.name = 'base-plugin';
        this.version = '1.0.0';
        this.description = 'Base plugin class';
        this.enabled = true;
        this.priority = 5;
        this.config = config;
        this.stats = {
            analyzed: 0,
            threats: 0
        };
    }

    async initialize() {
        // Override in child classes
        return true;
    }

    async analyze(request, analysis) {
        // Override in child classes
        // Should return { threat: { type, severity, details } } or { threat: null }
        return { threat: null };
    }

    validate() {
        return !!(this.name && this.version && typeof this.analyze === 'function');
    }

    async cleanup() {
        // Override in child classes for cleanup tasks
        return true;
    }

    log(level, message, data = {}) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            plugin: this.name,
            level,
            message,
            ...data
        };
        this.waf.emit('plugin-log', logEntry);
        console.log(`[${this.name}] ${level}: ${message}`, data);
    }

    updateStats(type = 'analyzed') {
        if (this.stats[type] !== undefined) {
            this.stats[type]++;
        }
    }

    getStats() {
        return { ...this.stats };
    }
}

module.exports = PluginBase;