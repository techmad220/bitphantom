const EventEmitter = require('events');

class BasePlugin extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = config;
    this.enabled = config.enabled !== false;
    this.rules = [];
    this.context = null;
    this.stats = {
      processed: 0,
      blocked: 0,
      errors: 0,
      lastActivity: null
    };
  }

  // Required properties - must be overridden
  get name() {
    throw new Error('Plugin must define a name');
  }

  get version() {
    return '1.0.0';
  }

  get priority() {
    return 100;
  }

  get description() {
    return 'Base plugin';
  }

  // Lifecycle methods
  async init(context) {
    this.context = context;
    this.logger = context.logger;
    this.storage = context.storage;
    
    // Load rules
    await this.loadRules();
    
    // Initialize plugin-specific resources
    await this.onInit();
    
    this.logger.info(`${this.name} plugin initialized`);
  }

  async destroy() {
    await this.onDestroy();
    this.removeAllListeners();
    this.logger.info(`${this.name} plugin destroyed`);
  }

  // Hook methods - can be overridden
  async onRequest(req, res) {
    this.stats.processed++;
    this.stats.lastActivity = Date.now();
    
    try {
      // Check all rules
      for (const rule of this.rules) {
        if (!rule.enabled) continue;
        
        const result = await this.checkRule(rule, req);
        
        if (result.match) {
          this.stats.blocked++;
          
          this.logger.warn(`Rule ${rule.id} matched: ${result.reason}`);
          
          if (rule.action === 'block') {
            return {
              action: 'BLOCK',
              reason: result.reason || rule.message,
              rule: rule.id,
              severity: rule.severity,
              details: result.details
            };
          } else if (rule.action === 'log') {
            this.logThreat(req, rule, result);
          } else if (rule.action === 'challenge') {
            return {
              action: 'CHALLENGE',
              type: rule.challengeType || 'captcha',
              rule: rule.id
            };
          }
        }
      }
      
      // Run custom detection logic
      return await this.detect(req, res);
      
    } catch (error) {
      this.stats.errors++;
      this.logger.error(`Error in ${this.name} plugin: ${error.message}`);
      return null;
    }
  }

  async onResponse(req, res, body) {
    // Override in specific plugins
    return body;
  }

  async onError(error, req, res) {
    // Override in specific plugins
  }

  async onBlock(req, res, blockInfo) {
    // Override in specific plugins
  }

  // Rule management
  async loadRules() {
    // Load default rules
    this.rules = await this.getDefaultRules();
    
    // Load custom rules from config
    if (this.config.customRules) {
      this.rules.push(...this.config.customRules);
    }
    
    // Sort rules by priority
    this.rules.sort((a, b) => (a.priority || 100) - (b.priority || 100));
  }

  async checkRule(rule, req) {
    switch (rule.type) {
      case 'pattern':
        return this.checkPatternRule(rule, req);
      case 'behavior':
        return this.checkBehaviorRule(rule, req);
      case 'threshold':
        return this.checkThresholdRule(rule, req);
      case 'custom':
        return rule.check(req);
      default:
        return { match: false };
    }
  }

  checkPatternRule(rule, req) {
    const targets = this.getTargets(rule.targets || ['all'], req);
    
    for (const [key, value] of targets) {
      if (this.matchPattern(rule.pattern, value)) {
        return {
          match: true,
          reason: `Pattern matched in ${key}`,
          details: { key, value, pattern: rule.pattern.toString() }
        };
      }
    }
    
    return { match: false };
  }

  checkBehaviorRule(rule, req) {
    // Override in specific plugins
    return { match: false };
  }

  checkThresholdRule(rule, req) {
    const key = rule.key(req);
    const current = this.storage.get(key) || 0;
    
    if (current >= rule.threshold) {
      return {
        match: true,
        reason: `Threshold exceeded: ${current} >= ${rule.threshold}`,
        details: { key, current, threshold: rule.threshold }
      };
    }
    
    this.storage.set(key, current + 1);
    return { match: false };
  }

  matchPattern(pattern, value) {
    if (!value) return false;
    
    if (pattern instanceof RegExp) {
      return pattern.test(value);
    } else if (typeof pattern === 'function') {
      return pattern(value);
    } else {
      return value.includes(pattern);
    }
  }

  getTargets(targetSpec, req) {
    const targets = new Map();
    
    const specs = Array.isArray(targetSpec) ? targetSpec : [targetSpec];
    
    for (const spec of specs) {
      switch (spec) {
        case 'all':
          this.addTarget(targets, 'url', req.url);
          this.addTarget(targets, 'method', req.method);
          this.addHeaders(targets, req.headers);
          this.addBody(targets, req.body);
          this.addQuery(targets, req.query);
          this.addParams(targets, req.params);
          break;
        case 'headers':
          this.addHeaders(targets, req.headers);
          break;
        case 'body':
          this.addBody(targets, req.body);
          break;
        case 'query':
          this.addQuery(targets, req.query);
          break;
        case 'params':
          this.addParams(targets, req.params);
          break;
        case 'cookies':
          this.addCookies(targets, req.cookies);
          break;
        default:
          if (spec.startsWith('header:')) {
            const headerName = spec.substring(7);
            this.addTarget(targets, `header:${headerName}`, req.headers[headerName]);
          }
      }
    }
    
    return targets;
  }

  addTarget(targets, key, value) {
    if (value !== undefined && value !== null) {
      targets.set(key, String(value));
    }
  }

  addHeaders(targets, headers) {
    if (!headers) return;
    
    for (const [key, value] of Object.entries(headers)) {
      this.addTarget(targets, `header:${key}`, value);
    }
  }

  addBody(targets, body) {
    if (!body) return;
    
    if (typeof body === 'object') {
      const flatten = (obj, prefix = '') => {
        for (const [key, value] of Object.entries(obj)) {
          const newKey = prefix ? `${prefix}.${key}` : key;
          if (typeof value === 'object' && value !== null) {
            flatten(value, newKey);
          } else {
            this.addTarget(targets, `body:${newKey}`, value);
          }
        }
      };
      flatten(body);
    } else {
      this.addTarget(targets, 'body', body);
    }
  }

  addQuery(targets, query) {
    if (!query) return;
    
    for (const [key, value] of Object.entries(query)) {
      this.addTarget(targets, `query:${key}`, value);
    }
  }

  addParams(targets, params) {
    if (!params) return;
    
    for (const [key, value] of Object.entries(params)) {
      this.addTarget(targets, `param:${key}`, value);
    }
  }

  addCookies(targets, cookies) {
    if (!cookies) return;
    
    for (const [key, value] of Object.entries(cookies)) {
      this.addTarget(targets, `cookie:${key}`, value);
    }
  }

  logThreat(req, rule, result) {
    const threat = {
      timestamp: new Date().toISOString(),
      plugin: this.name,
      rule: rule.id,
      severity: rule.severity,
      ip: req.ip,
      method: req.method,
      path: req.path,
      reason: result.reason,
      details: result.details
    };
    
    this.emit('threat:detected', threat);
    this.context.emit('threat', threat);
  }

  // Methods to be overridden by specific plugins
  async getDefaultRules() {
    return [];
  }

  async detect(req, res) {
    // Custom detection logic
    return null;
  }

  async onInit() {
    // Plugin-specific initialization
  }

  async onDestroy() {
    // Plugin-specific cleanup
  }

  // Utility methods
  getStats() {
    return {
      ...this.stats,
      name: this.name,
      version: this.version,
      enabled: this.enabled,
      rulesCount: this.rules.length
    };
  }

  enable() {
    this.enabled = true;
    this.emit('enabled');
  }

  disable() {
    this.enabled = false;
    this.emit('disabled');
  }

  addRule(rule) {
    rule.id = rule.id || `${this.name}-${Date.now()}`;
    rule.enabled = rule.enabled !== false;
    this.rules.push(rule);
    this.rules.sort((a, b) => (a.priority || 100) - (b.priority || 100));
  }

  removeRule(ruleId) {
    this.rules = this.rules.filter(r => r.id !== ruleId);
  }

  updateRule(ruleId, updates) {
    const rule = this.rules.find(r => r.id === ruleId);
    if (rule) {
      Object.assign(rule, updates);
    }
  }
}

module.exports = BasePlugin;