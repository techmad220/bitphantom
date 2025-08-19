const express = require('express');
const http = require('http');
const path = require('path');
const WAFCore = require('./src/core/waf-core');
const WAFLogger = require('./src/core/logger');
const WebSocketMonitor = require('./src/core/websocket-monitor');
const AnomalyDetector = require('./src/ai/anomaly-detector');
const { WAFMiddleware } = require('./src/middleware/express-middleware');

class BitPhantomWAF {
    constructor(config = {}) {
        this.config = {
            port: process.env.WAF_PORT || 3001,
            wsPort: process.env.WS_PORT || 8080,
            mode: process.env.WAF_MODE || 'monitor',
            enableAI: true,
            enableWebSocket: true,
            enableDashboard: true,
            dashboardPath: '/waf-admin',
            clientScriptPath: '/waf-client.js',
            ...config
        };
        
        this.app = null;
        this.server = null;
        this.waf = null;
        this.logger = null;
        this.wsMonitor = null;
        this.aiDetector = null;
        this.middleware = null;
    }
    
    async initialize() {
        console.log('🚀 Initializing Bit Phantom WAF...');
        
        // Initialize core components
        this.logger = new WAFLogger(this.config.logging);
        await this.logger.initialize();
        
        this.waf = new WAFCore(this.config.waf);
        await this.waf.initialize();
        
        // Initialize AI if enabled
        if (this.config.enableAI) {
            try {
                this.aiDetector = new AnomalyDetector(this.config.ai);
                await this.aiDetector.initialize();
                
                // Add AI as a plugin
                this.waf.plugins.set('ai-anomaly', {
                    name: 'ai-anomaly',
                    version: '1.0.0',
                    enabled: true,
                    priority: 5,
                    analyze: async (request, analysis) => {
                        const result = await this.aiDetector.analyze(request);
                        if (result.isAnomaly) {
                            return {
                                threat: {
                                    type: 'ai-anomaly',
                                    severity: Math.round(result.score * 10),
                                    details: result
                                }
                            };
                        }
                        return { threat: null };
                    },
                    validate: () => true,
                    initialize: async () => true,
                    cleanup: async () => true
                });
            } catch (error) {
                console.error('⚠️ AI initialization failed:', error.message);
                console.log('Continuing without AI detection...');
            }
        }
        
        // Initialize WebSocket monitor
        if (this.config.enableWebSocket) {
            this.wsMonitor = new WebSocketMonitor(this.config.websocket);
            
            // Setup event forwarding
            this.setupEventForwarding();
        }
        
        // Initialize middleware
        this.middleware = new WAFMiddleware({
            ...this.config,
            waf: this.waf,
            logger: this.logger
        });
        await this.middleware.initialize();
        
        console.log('✅ WAF Core initialized');
        console.log(`📊 Mode: ${this.config.mode}`);
        console.log(`🔌 Plugins loaded: ${Array.from(this.waf.plugins.keys()).join(', ')}`);
    }
    
    setupEventForwarding() {
        // Forward WAF events to WebSocket
        this.waf.on('threat-detected', (threat) => {
            this.wsMonitor.broadcastThreat(threat);
        });
        
        this.waf.on('request-analyzed', (analysis) => {
            if (analysis.blocked) {
                this.wsMonitor.broadcastAlert({
                    type: 'request-blocked',
                    ...analysis
                });
            }
        });
        
        // Handle WebSocket requests
        this.wsMonitor.on('stats-request', (callback) => {
            Promise.all([
                this.waf.getStats(),
                this.logger.getStats(),
                this.aiDetector ? this.aiDetector.getStats() : null
            ]).then(([wafStats, loggerStats, aiStats]) => {
                callback({
                    waf: wafStats,
                    logger: loggerStats,
                    ai: aiStats
                });
            });
        });
        
        this.wsMonitor.on('config-request', (callback) => {
            callback(this.config);
        });
        
        this.wsMonitor.on('config-update', ({ client, config }) => {
            if (config.mode) {
                this.config.mode = config.mode;
                this.waf.config.mode = config.mode;
                this.middleware.config.mode = config.mode;
                
                this.logger.log('info', 'Configuration updated', {
                    client,
                    changes: config
                });
            }
        });
    }
    
    createExpressApp() {
        const app = express();
        
        // Body parsing middleware
        app.use(express.json({ limit: '10mb' }));
        app.use(express.urlencoded({ extended: true, limit: '10mb' }));
        
        // WAF middleware
        app.use(this.middleware.middleware());
        
        // Serve client script
        if (this.config.clientScriptPath) {
            app.get(this.config.clientScriptPath, (req, res) => {
                res.sendFile(path.join(__dirname, 'src/client/waf-client.js'));
            });
        }
        
        // Serve dashboard
        if (this.config.enableDashboard) {
            app.get(this.config.dashboardPath, (req, res) => {
                res.sendFile(path.join(__dirname, 'dashboard/index.html'));
            });
        }
        
        // WAF API endpoints
        app.get('/waf/stats', async (req, res) => {
            const stats = await this.getStats();
            res.json(stats);
        });
        
        app.post('/waf/report', (req, res) => {
            this.logger.log('info', 'Client report', req.body);
            res.json({ success: true });
        });
        
        app.get('/waf/config', (req, res) => {
            res.json({
                mode: this.config.mode,
                plugins: Array.from(this.waf.plugins.keys()),
                ai: this.config.enableAI
            });
        });
        
        app.post('/waf/config', (req, res) => {
            const { mode, plugins } = req.body;
            
            if (mode) {
                this.config.mode = mode;
                this.waf.config.mode = mode;
                this.middleware.config.mode = mode;
            }
            
            res.json({ success: true });
        });
        
        // Health check
        app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                uptime: process.uptime(),
                memory: process.memoryUsage()
            });
        });
        
        return app;
    }
    
    async start(app = null) {
        await this.initialize();
        
        // Use provided app or create new one
        this.app = app || this.createExpressApp();
        
        // Create HTTP server
        this.server = http.createServer(this.app);
        
        // Initialize WebSocket server
        if (this.config.enableWebSocket) {
            await this.wsMonitor.initialize(this.server);
        }
        
        // Start server
        return new Promise((resolve) => {
            this.server.listen(this.config.port, () => {
                console.log(`🛡️ Bit Phantom WAF running on port ${this.config.port}`);
                console.log(`📊 Dashboard: http://localhost:${this.config.port}${this.config.dashboardPath}`);
                console.log(`🔌 WebSocket: ws://localhost:${this.config.port}/waf-monitor`);
                resolve(this);
            });
        });
    }
    
    async getStats() {
        const [wafStats, loggerStats, aiStats, wsStats] = await Promise.all([
            this.waf.getStats(),
            this.logger.getStats(),
            this.aiDetector ? this.aiDetector.getStats() : null,
            this.wsMonitor ? this.wsMonitor.getMetrics() : null
        ]);
        
        return {
            waf: wafStats,
            logger: loggerStats,
            ai: aiStats,
            websocket: wsStats,
            system: {
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                cpu: process.cpuUsage()
            }
        };
    }
    
    getMiddleware() {
        if (!this.middleware) {
            throw new Error('WAF not initialized. Call initialize() first.');
        }
        return this.middleware.middleware();
    }
    
    async stop() {
        console.log('Shutting down WAF...');
        
        if (this.server) {
            await new Promise((resolve) => {
                this.server.close(resolve);
            });
        }
        
        if (this.wsMonitor) {
            await this.wsMonitor.cleanup();
        }
        
        if (this.aiDetector) {
            await this.aiDetector.cleanup();
        }
        
        if (this.waf) {
            await this.waf.cleanup();
        }
        
        if (this.logger) {
            await this.logger.cleanup();
        }
        
        console.log('WAF shut down complete');
    }
}

// Export for use as module
module.exports = BitPhantomWAF;

// Run standalone if executed directly
if (require.main === module) {
    const waf = new BitPhantomWAF({
        port: process.env.PORT || 3001,
        mode: process.env.WAF_MODE || 'monitor',
        enableAI: process.env.ENABLE_AI !== 'false',
        enableWebSocket: true,
        enableDashboard: true
    });
    
    waf.start().catch(error => {
        console.error('Failed to start WAF:', error);
        process.exit(1);
    });
    
    // Graceful shutdown
    process.on('SIGINT', async () => {
        await waf.stop();
        process.exit(0);
    });
    
    process.on('SIGTERM', async () => {
        await waf.stop();
        process.exit(0);
    });
}