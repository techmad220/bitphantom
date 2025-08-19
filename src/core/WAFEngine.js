const EventEmitter = require('events');
const PluginLoader = require('./PluginLoader');
const { Logger } = require('../utils/logger');
const RequestAnalyzer = require('./RequestAnalyzer');
const ResponseProcessor = require('./ResponseProcessor');
const ThreatIntelligence = require('./ThreatIntelligence');
const { performanceMonitor } = require('../utils/performance');

class WAFEngine extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = {
      mode: 'detect', // 'detect' | 'prevent' | 'learning'
      enableAI: true,
      enableWebSocket: true,
      maxRequestSize: 10 * 1024 * 1024, // 10MB
      timeout: 5000,
      ...config
    };
    
    this.logger = new Logger('WAFEngine');
    this.pluginLoader = new PluginLoader(config.plugins || {});
    this.requestAnalyzer = new RequestAnalyzer();
    this.responseProcessor = new ResponseProcessor();
    this.threatIntel = new ThreatIntelligence();
    
    this.stats = {
      totalRequests: 0,
      blockedRequests: 0,
      allowedRequests: 0,
      errors: 0,
      avgProcessingTime: 0,
      threats: new Map()
    };
    
    this.isInitialized = false;
  }

  async initialize() {
    try {
      this.logger.info('Initializing WAF Engine...');
      
      // Initialize components
      await this.pluginLoader.initialize();
      await this.requestAnalyzer.initialize();
      await this.responseProcessor.initialize();
      await this.threatIntel.initialize();
      
      // Set up event listeners
      this.setupEventListeners();
      
      // Start performance monitoring
      performanceMonitor.start();
      
      this.isInitialized = true;
      this.logger.info('WAF Engine initialized successfully');
      
      this.emit('engine:initialized');
      return this;
      
    } catch (error) {
      this.logger.error(`Failed to initialize WAF Engine: ${error.message}`);
      throw error;
    }
  }

  setupEventListeners() {
    // Plugin events
    this.pluginLoader.on('request:blocked', (data) => {
      this.stats.blockedRequests++;
      this.updateThreatStats(data);
      this.emit('threat:detected', data);
    });
    
    this.pluginLoader.on('plugin:error', (data) => {
      this.stats.errors++;
      this.emit('engine:error', data);
    });
    
    // Threat intelligence events
    this.threatIntel.on('threat:identified', (threat) => {
      this.emit('threat:identified', threat);
    });
  }

  async processRequest(req, res, next) {
    if (!this.isInitialized) {
      return next(new Error('WAF Engine not initialized'));
    }
    
    const startTime = Date.now();
    const requestId = this.generateRequestId();
    
    // Attach metadata to request
    req.waf = {
      id: requestId,
      startTime,
      threats: [],
      score: 0
    };
    
    try {
      this.stats.totalRequests++;
      
      // Step 1: Analyze request
      const analysis = await this.requestAnalyzer.analyze(req);
      req.waf.analysis = analysis;
      
      // Step 2: Check threat intelligence
      const threatInfo = await this.threatIntel.check(req);
      if (threatInfo.isThreat) {
        return this.blockRequest(req, res, threatInfo.reason);
      }
      
      // Step 3: Execute plugin hooks
      const hookResult = await this.pluginLoader.executeHook('onRequest', req, res);
      
      if (hookResult.blocked) {
        return this.blockRequest(req, res, hookResult.reason, hookResult.plugin);
      }
      
      // Step 4: Calculate threat score
      const threatScore = this.calculateThreatScore(req);
      req.waf.score = threatScore;
      
      if (threatScore > this.config.blockThreshold) {
        return this.blockRequest(req, res, 'High threat score');
      }
      
      // Request is clean, continue
      this.stats.allowedRequests++;
      
      // Monitor response
      this.monitorResponse(req, res);
      
      // Update processing time
      const processingTime = Date.now() - startTime;
      this.updateProcessingTime(processingTime);
      
      // Log if in learning mode
      if (this.config.mode === 'learning') {
        this.logLearningData(req);
      }
      
      next();
      
    } catch (error) {
      this.logger.error(`Error processing request: ${error.message}`);
      this.stats.errors++;
      
      if (this.config.mode === 'prevent') {
        return this.blockRequest(req, res, 'Processing error');
      }
      
      next();
    }
  }

  monitorResponse(req, res) {
    const originalSend = res.send;
    const originalJson = res.json;
    
    res.send = async function(data) {
      await this.processResponse(req, res, data);
      return originalSend.call(res, data);
    }.bind(this);
    
    res.json = async function(data) {
      await this.processResponse(req, res, JSON.stringify(data));
      return originalJson.call(res, data);
    }.bind(this);
  }

  async processResponse(req, res, body) {
    try {
      // Process response through plugins
      await this.pluginLoader.executeHook('onResponse', req, res, body);
      
      // Analyze response for data leakage
      const processed = await this.responseProcessor.process(body, req.waf);
      
      if (processed.modified) {
        return processed.body;
      }
      
      return body;
    } catch (error) {
      this.logger.error(`Error processing response: ${error.message}`);
      return body;
    }
  }

  blockRequest(req, res, reason, plugin = 'core') {
    const blockedInfo = {
      requestId: req.waf.id,
      reason,
      plugin,
      ip: req.ip,
      method: req.method,
      path: req.path,
      timestamp: new Date().toISOString()
    };
    
    this.logger.warn(`Request blocked: ${JSON.stringify(blockedInfo)}`);
    this.emit('request:blocked', blockedInfo);
    
    // Execute onBlock hooks
    this.pluginLoader.executeHook('onBlock', req, res, blockedInfo);
    
    if (this.config.mode === 'detect') {
      // In detect mode, log but don't actually block
      req.waf.wouldBlock = true;
      return;
    }
    
    // Send block response
    res.status(403).json({
      error: 'Request blocked by WAF',
      reason: this.config.verboseErrors ? reason : 'Security policy violation',
      requestId: req.waf.id
    });
  }

  calculateThreatScore(req) {
    let score = 0;
    
    // Base score from analysis
    if (req.waf.analysis) {
      score += req.waf.analysis.suspicionLevel * 10;
    }
    
    // Add scores from plugin detections
    if (req.waf.threats && req.waf.threats.length > 0) {
      req.waf.threats.forEach(threat => {
        switch (threat.severity) {
          case 'critical': score += 50; break;
          case 'high': score += 30; break;
          case 'medium': score += 15; break;
          case 'low': score += 5; break;
        }
      });
    }
    
    // Adjust based on request characteristics
    if (req.method === 'POST' || req.method === 'PUT') {
      score += 5;
    }
    
    if (req.path.includes('admin') || req.path.includes('api')) {
      score += 10;
    }
    
    return Math.min(score, 100);
  }

  updateThreatStats(data) {
    const key = `${data.plugin}:${data.reason}`;
    const current = this.stats.threats.get(key) || 0;
    this.stats.threats.set(key, current + 1);
  }

  updateProcessingTime(time) {
    const current = this.stats.avgProcessingTime;
    const total = this.stats.totalRequests;
    this.stats.avgProcessingTime = (current * (total - 1) + time) / total;
  }

  logLearningData(req) {
    // Log request data for ML training
    const learningData = {
      timestamp: new Date().toISOString(),
      method: req.method,
      path: req.path,
      headers: req.headers,
      score: req.waf.score,
      analysis: req.waf.analysis,
      wouldBlock: req.waf.wouldBlock || false
    };
    
    this.emit('learning:data', learningData);
  }

  generateRequestId() {
    return `waf-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  async updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    this.emit('config:updated', this.config);
    this.logger.info('Configuration updated');
  }

  getStats() {
    return {
      ...this.stats,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      plugins: this.pluginLoader.getStatus(),
      mode: this.config.mode,
      threats: Array.from(this.stats.threats.entries()).map(([key, count]) => ({
        type: key,
        count
      }))
    };
  }

  async destroy() {
    this.logger.info('Shutting down WAF Engine...');
    
    await this.pluginLoader.destroy();
    await this.requestAnalyzer.destroy();
    await this.responseProcessor.destroy();
    await this.threatIntel.destroy();
    
    performanceMonitor.stop();
    this.removeAllListeners();
    
    this.logger.info('WAF Engine shut down complete');
  }
}

module.exports = WAFEngine;