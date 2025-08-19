const crypto = require('crypto');
const { Logger } = require('../utils/logger');

class RequestAnalyzer {
  constructor() {
    this.logger = new Logger('RequestAnalyzer');
    this.patterns = this.loadPatterns();
    this.anomalyBaseline = new Map();
    this.requestHistory = new Map();
    this.suspicionThresholds = {
      low: 0.3,
      medium: 0.5,
      high: 0.7,
      critical: 0.9
    };
  }

  async initialize() {
    // Load ML models if available
    try {
      this.loadAnomalyDetectionModel();
    } catch (e) {
      this.logger.warn('ML model not available, using rule-based detection');
    }
    return this;
  }

  async analyze(req) {
    const analysis = {
      suspicionLevel: 0,
      anomalies: [],
      patterns: [],
      entropy: {},
      timing: {},
      behavioral: {},
      fingerprint: this.generateRequestFingerprint(req)
    };

    // Layer 1: Pattern Analysis
    analysis.patterns = this.detectPatterns(req);
    
    // Layer 2: Entropy Analysis (detect obfuscation)
    analysis.entropy = this.analyzeEntropy(req);
    
    // Layer 3: Timing Analysis
    analysis.timing = this.analyzeTimingPatterns(req);
    
    // Layer 4: Behavioral Analysis
    analysis.behavioral = this.analyzeBehavior(req);
    
    // Layer 5: Anomaly Detection
    analysis.anomalies = await this.detectAnomalies(req);
    
    // Layer 6: Request Structure Analysis
    analysis.structure = this.analyzeRequestStructure(req);
    
    // Layer 7: Encoding Analysis
    analysis.encoding = this.analyzeEncoding(req);
    
    // Calculate overall suspicion level
    analysis.suspicionLevel = this.calculateSuspicionLevel(analysis);
    
    // Log paranoid level details
    this.logger.logRequest(req, { analysis });
    
    // Track request for behavioral analysis
    this.trackRequest(req, analysis);
    
    return analysis;
  }

  detectPatterns(req) {
    const detected = [];
    const targets = this.extractAllTargets(req);
    
    for (const [location, value] of targets) {
      // Check for SQL Injection patterns
      if (this.patterns.sql.some(p => p.test(value))) {
        detected.push({ type: 'sql', location, severity: 'high', value });
      }
      
      // Check for XSS patterns
      if (this.patterns.xss.some(p => p.test(value))) {
        detected.push({ type: 'xss', location, severity: 'high', value });
      }
      
      // Check for Command Injection
      if (this.patterns.command.some(p => p.test(value))) {
        detected.push({ type: 'command', location, severity: 'critical', value });
      }
      
      // Check for Path Traversal
      if (this.patterns.pathTraversal.some(p => p.test(value))) {
        detected.push({ type: 'pathTraversal', location, severity: 'high', value });
      }
      
      // Check for XXE patterns
      if (this.patterns.xxe.some(p => p.test(value))) {
        detected.push({ type: 'xxe', location, severity: 'high', value });
      }
      
      // Check for LDAP Injection
      if (this.patterns.ldap.some(p => p.test(value))) {
        detected.push({ type: 'ldap', location, severity: 'medium', value });
      }
      
      // Check for NoSQL Injection
      if (this.patterns.nosql.some(p => p.test(value))) {
        detected.push({ type: 'nosql', location, severity: 'high', value });
      }
      
      // Check for Template Injection
      if (this.patterns.template.some(p => p.test(value))) {
        detected.push({ type: 'template', location, severity: 'high', value });
      }
      
      // Check for suspicious encoding
      if (this.patterns.encoding.some(p => p.test(value))) {
        detected.push({ type: 'encoding', location, severity: 'medium', value });
      }
    }
    
    return detected;
  }

  analyzeEntropy(req) {
    const entropy = {};
    const targets = this.extractAllTargets(req);
    
    for (const [location, value] of targets) {
      const ent = this.calculateEntropy(value);
      
      // High entropy might indicate obfuscation or encryption
      if (ent > 4.5) {
        entropy[location] = {
          value: ent,
          suspicious: true,
          reason: 'High entropy - possible obfuscation'
        };
      } else if (ent < 1) {
        entropy[location] = {
          value: ent,
          suspicious: true,
          reason: 'Very low entropy - possible padding attack'
        };
      }
    }
    
    return entropy;
  }

  calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    
    const freq = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }
    
    let entropy = 0;
    const len = str.length;
    
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    
    return entropy;
  }

  analyzeTimingPatterns(req) {
    const ip = req.ip;
    const now = Date.now();
    const history = this.requestHistory.get(ip) || [];
    
    const timing = {
      requestRate: 0,
      avgInterval: 0,
      burstDetected: false,
      automated: false,
      pattern: 'normal'
    };
    
    if (history.length > 0) {
      const intervals = [];
      for (let i = 1; i < history.length; i++) {
        intervals.push(history[i].timestamp - history[i-1].timestamp);
      }
      
      if (intervals.length > 0) {
        timing.avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        timing.requestRate = 1000 / timing.avgInterval; // requests per second
        
        // Detect automated behavior (too regular intervals)
        const variance = this.calculateVariance(intervals);
        if (variance < 100 && timing.requestRate > 1) {
          timing.automated = true;
          timing.pattern = 'bot-like';
        }
        
        // Detect burst behavior
        if (timing.requestRate > 10) {
          timing.burstDetected = true;
          timing.pattern = 'burst';
        }
        
        // Detect scanning behavior
        if (this.detectScanningPattern(history)) {
          timing.pattern = 'scanning';
        }
      }
    }
    
    return timing;
  }

  calculateVariance(numbers) {
    const mean = numbers.reduce((a, b) => a + b, 0) / numbers.length;
    const squaredDiffs = numbers.map(n => Math.pow(n - mean, 2));
    return squaredDiffs.reduce((a, b) => a + b, 0) / numbers.length;
  }

  detectScanningPattern(history) {
    // Check if requests are incrementing/testing different paths
    const paths = history.map(h => h.path);
    const uniquePaths = new Set(paths);
    
    // High ratio of unique paths indicates scanning
    if (uniquePaths.size / paths.length > 0.8 && paths.length > 10) {
      return true;
    }
    
    // Check for sequential patterns
    const sequential = paths.some((path, i) => {
      if (i === 0) return false;
      return this.isSequential(paths[i-1], path);
    });
    
    return sequential;
  }

  isSequential(path1, path2) {
    // Check if paths follow a sequential pattern (e.g., /user/1, /user/2)
    const nums1 = path1.match(/\d+/g);
    const nums2 = path2.match(/\d+/g);
    
    if (nums1 && nums2 && nums1.length === nums2.length) {
      return nums1.some((n1, i) => {
        const n2 = nums2[i];
        return parseInt(n2) === parseInt(n1) + 1;
      });
    }
    
    return false;
  }

  analyzeBehavior(req) {
    const behavior = {
      suspicious: false,
      indicators: [],
      riskScore: 0
    };
    
    // Check for suspicious headers
    if (req.headers['x-forwarded-for'] && req.headers['x-forwarded-for'].split(',').length > 3) {
      behavior.indicators.push('Multiple proxy hops');
      behavior.riskScore += 10;
    }
    
    // Check for tools/scanners
    const userAgent = req.headers['user-agent'] || '';
    const scannerPatterns = [
      /sqlmap/i, /nikto/i, /nmap/i, /masscan/i, /metasploit/i,
      /burp/i, /zap/i, /acunetix/i, /nessus/i, /openvas/i,
      /curl/i, /wget/i, /python/i, /ruby/i, /perl/i, /go-http/i
    ];
    
    if (scannerPatterns.some(p => p.test(userAgent))) {
      behavior.indicators.push('Known scanning tool detected');
      behavior.riskScore += 30;
      behavior.suspicious = true;
    }
    
    // Check for missing headers that browsers always send
    if (!req.headers['accept'] || !req.headers['accept-language']) {
      behavior.indicators.push('Missing standard browser headers');
      behavior.riskScore += 15;
    }
    
    // Check for suspicious content types
    const contentType = req.headers['content-type'] || '';
    if (contentType.includes('multipart') && req.method === 'GET') {
      behavior.indicators.push('Multipart content in GET request');
      behavior.riskScore += 25;
      behavior.suspicious = true;
    }
    
    // Check for header anomalies
    if (req.headers['content-length'] && req.headers['transfer-encoding']) {
      behavior.indicators.push('Both Content-Length and Transfer-Encoding present');
      behavior.riskScore += 20;
    }
    
    behavior.suspicious = behavior.riskScore > 20;
    
    return behavior;
  }

  async detectAnomalies(req) {
    const anomalies = [];
    
    // Check against baseline
    const baseline = this.getBaseline(req.path);
    
    if (baseline) {
      // Check parameter count anomaly
      const paramCount = Object.keys(req.query || {}).length + Object.keys(req.body || {}).length;
      if (paramCount > baseline.avgParamCount * 2) {
        anomalies.push({
          type: 'param_count',
          severity: 'medium',
          details: `Unusual parameter count: ${paramCount} (baseline: ${baseline.avgParamCount})`
        });
      }
      
      // Check request size anomaly
      const size = JSON.stringify(req.body || {}).length;
      if (size > baseline.avgSize * 3) {
        anomalies.push({
          type: 'request_size',
          severity: 'medium',
          details: `Unusual request size: ${size} (baseline: ${baseline.avgSize})`
        });
      }
    }
    
    // Check for impossible travel (same session from different locations quickly)
    if (req.sessionID) {
      const sessionAnomaly = await this.checkSessionAnomaly(req);
      if (sessionAnomaly) {
        anomalies.push(sessionAnomaly);
      }
    }
    
    return anomalies;
  }

  analyzeRequestStructure(req) {
    const structure = {
      depth: 0,
      complexity: 0,
      suspicious: false,
      issues: []
    };
    
    // Analyze JSON depth and complexity
    if (req.body && typeof req.body === 'object') {
      structure.depth = this.getObjectDepth(req.body);
      structure.complexity = this.getObjectComplexity(req.body);
      
      if (structure.depth > 10) {
        structure.suspicious = true;
        structure.issues.push('Excessive nesting depth');
      }
      
      if (structure.complexity > 100) {
        structure.suspicious = true;
        structure.issues.push('Excessive complexity');
      }
    }
    
    // Check for potential billion laughs / XML bomb patterns
    const bodyStr = JSON.stringify(req.body || {});
    if (bodyStr.length > 1000000) {
      structure.suspicious = true;
      structure.issues.push('Potential payload bomb');
    }
    
    return structure;
  }

  analyzeEncoding(req) {
    const encoding = {
      suspicious: false,
      types: [],
      issues: []
    };
    
    const targets = this.extractAllTargets(req);
    
    for (const [location, value] of targets) {
      // Check for multiple encoding layers
      if (this.hasMultipleEncoding(value)) {
        encoding.suspicious = true;
        encoding.issues.push(`Multiple encoding detected in ${location}`);
      }
      
      // Check for uncommon encodings
      if (this.hasUncommonEncoding(value)) {
        encoding.types.push({ location, type: 'uncommon' });
      }
      
      // Check for null bytes
      if (value.includes('\x00') || value.includes('%00')) {
        encoding.suspicious = true;
        encoding.issues.push(`Null byte injection attempt in ${location}`);
      }
    }
    
    return encoding;
  }

  hasMultipleEncoding(value) {
    // Check if value has been encoded multiple times
    let decoded = value;
    let levels = 0;
    
    while (levels < 5) {
      const prev = decoded;
      
      // Try URL decoding
      try {
        decoded = decodeURIComponent(decoded);
        if (decoded !== prev) {
          levels++;
          continue;
        }
      } catch (e) {}
      
      // Try base64 decoding
      if (/^[A-Za-z0-9+/]+=*$/.test(decoded)) {
        try {
          decoded = Buffer.from(decoded, 'base64').toString();
          if (decoded !== prev) {
            levels++;
            continue;
          }
        } catch (e) {}
      }
      
      break;
    }
    
    return levels > 1;
  }

  hasUncommonEncoding(value) {
    // Check for uncommon but suspicious encodings
    const patterns = [
      /\\x[0-9a-f]{2}/i,  // Hex encoding
      /\\u[0-9a-f]{4}/i,  // Unicode encoding
      /&#x[0-9a-f]+;/i,   // HTML hex entities
      /&#\d+;/,           // HTML decimal entities
      /\${.*}/,           // Template injection
      /%\{.*\}/           // Another template pattern
    ];
    
    return patterns.some(p => p.test(value));
  }

  getObjectDepth(obj, currentDepth = 0) {
    if (typeof obj !== 'object' || obj === null) {
      return currentDepth;
    }
    
    let maxDepth = currentDepth;
    
    for (const value of Object.values(obj)) {
      if (typeof value === 'object' && value !== null) {
        const depth = this.getObjectDepth(value, currentDepth + 1);
        maxDepth = Math.max(maxDepth, depth);
      }
    }
    
    return maxDepth;
  }

  getObjectComplexity(obj) {
    let complexity = 0;
    
    const count = (o) => {
      if (typeof o !== 'object' || o === null) {
        return 1;
      }
      
      let c = 1;
      for (const value of Object.values(o)) {
        c += count(value);
      }
      return c;
    };
    
    return count(obj);
  }

  calculateSuspicionLevel(analysis) {
    let level = 0;
    
    // Weight different factors
    level += analysis.patterns.length * 0.15;
    level += Object.keys(analysis.entropy).filter(k => analysis.entropy[k].suspicious).length * 0.1;
    level += analysis.behavioral.riskScore / 100 * 0.3;
    level += analysis.anomalies.length * 0.1;
    level += (analysis.structure.suspicious ? 0.2 : 0);
    level += (analysis.encoding.suspicious ? 0.15 : 0);
    
    // Add timing factors
    if (analysis.timing.automated) level += 0.1;
    if (analysis.timing.burstDetected) level += 0.15;
    
    return Math.min(1, level);
  }

  extractAllTargets(req) {
    const targets = new Map();
    
    // URL and path
    targets.set('url', req.url || '');
    targets.set('path', req.path || '');
    
    // Headers
    for (const [key, value] of Object.entries(req.headers || {})) {
      targets.set(`header:${key}`, String(value));
    }
    
    // Query parameters
    for (const [key, value] of Object.entries(req.query || {})) {
      targets.set(`query:${key}`, String(value));
    }
    
    // Body parameters
    const flattenBody = (obj, prefix = '') => {
      for (const [key, value] of Object.entries(obj || {})) {
        const fullKey = prefix ? `${prefix}.${key}` : key;
        if (typeof value === 'object' && value !== null) {
          flattenBody(value, fullKey);
        } else {
          targets.set(`body:${fullKey}`, String(value));
        }
      }
    };
    
    if (req.body) {
      if (typeof req.body === 'object') {
        flattenBody(req.body);
      } else {
        targets.set('body', String(req.body));
      }
    }
    
    // Cookies
    for (const [key, value] of Object.entries(req.cookies || {})) {
      targets.set(`cookie:${key}`, String(value));
    }
    
    return targets;
  }

  generateRequestFingerprint(req) {
    const fingerprintData = {
      method: req.method,
      path: req.path,
      userAgent: req.headers['user-agent'],
      acceptLanguage: req.headers['accept-language'],
      acceptEncoding: req.headers['accept-encoding'],
      paramKeys: Object.keys(req.query || {}).sort().join(','),
      bodyKeys: req.body ? Object.keys(req.body).sort().join(',') : ''
    };
    
    return crypto.createHash('sha256')
      .update(JSON.stringify(fingerprintData))
      .digest('hex');
  }

  trackRequest(req, analysis) {
    const ip = req.ip;
    const history = this.requestHistory.get(ip) || [];
    
    history.push({
      timestamp: Date.now(),
      path: req.path,
      method: req.method,
      suspicionLevel: analysis.suspicionLevel,
      fingerprint: analysis.fingerprint
    });
    
    // Keep only last 100 requests per IP
    if (history.length > 100) {
      history.shift();
    }
    
    this.requestHistory.set(ip, history);
  }

  getBaseline(path) {
    return this.anomalyBaseline.get(path);
  }

  async checkSessionAnomaly(req) {
    // Check for impossible travel or session hijacking attempts
    // This would integrate with a session store in production
    return null;
  }

  loadPatterns() {
    return {
      sql: [
        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE|TRUNCATE|DECLARE|CAST)\b)/gi,
        /(\b(OR|AND)\b\s*[\(\)]*\s*[\'\"\d])/gi,
        /(\-\-|\/\*|\*\/|@@|@|char|nchar|varchar|nvarchar|alter|begin|cast|create|cursor|declare|delete|drop|end|exec|execute|fetch|insert|kill|select|sys|sysobjects|syscolumns|table|update)/gi,
        /(\bwaitfor\s+delay\s+)/gi,
        /(\bbenchmark\s*\()/gi,
        /(\bsleep\s*\()/gi,
        /([\'\"][\s\;]*(\b(OR|AND)\b)[\s\;]*[\'\"\d\=])/gi,
        /(\w*[\'\"][\)\;\s]*\b(OR|AND)\b[\s\(]*[\'\"\d]?\=[\'\"\d]?)/gi,
        /([\'\"][\s]*\b(OR|AND)\b[\s]*[\'\"]?[\d\w][\'\"]?[\s]*\=[\s]*[\'\"]?[\d\w])/gi
      ],
      xss: [
        /(<script[\s\S]*?>[\s\S]*?<\/script>)/gi,
        /(<iframe[\s\S]*?>[\s\S]*?<\/iframe>)/gi,
        /(javascript\s*:)/gi,
        /(on\w+\s*=\s*[\"\'])/gi,
        /(<img[^>]+src[\\s]*=[\\s]*[\"\']javascript:)/gi,
        /(<svg[^>]*>[\s\S]*?<\/svg>)/gi,
        /(<object[\s\S]*?>[\s\S]*?<\/object>)/gi,
        /(<embed[\s\S]*?>)/gi,
        /(<applet[\s\S]*?>[\s\S]*?<\/applet>)/gi,
        /(eval\s*\()/gi,
        /(expression\s*\()/gi,
        /(prompt\s*\()/gi,
        /(alert\s*\()/gi,
        /(confirm\s*\()/gi,
        /(console\.\w+\s*\()/gi,
        /(<[^>]+\s+style\s*=\s*[\"'][^\"']*expression)/gi
      ],
      command: [
        /(;|\||&|`|\$\(|\$\{|<\(|>\()/g,
        /(\b(cat|ls|wget|curl|bash|sh|cmd|powershell|nc|netcat|telnet|ssh)\b)/gi,
        /(\/etc\/passwd|\/etc\/shadow|\/windows\/system32)/gi,
        /(%0a|%0d|%00)/gi,
        /(\.\.[\/\\])/g
      ],
      pathTraversal: [
        /(\.\.\/|\.\.\\)/g,
        /(%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c)/gi,
        /(\/etc\/|\/proc\/|\/var\/|C:\\|file:\/\/)/gi,
        /(\.\.[\/\\]){2,}/g
      ],
      xxe: [
        /(<!DOCTYPE[^>]*\[)/gi,
        /(<!ENTITY)/gi,
        /(<\?xml[^>]*>)/gi,
        /(SYSTEM\s+[\"\'])/gi,
        /(PUBLIC\s+[\"\'])/gi
      ],
      ldap: [
        /(\*\|)/gi,
        /(\)\(|\|\()/gi,
        /([\w\s]*=\*)/gi
      ],
      nosql: [
        /(\$ne|\$eq|\$gt|\$gte|\$lt|\$lte|\$in|\$nin)/gi,
        /(\$or|\$and|\$not|\$nor)/gi,
        /(\$where|\$regex|\$text|\$expr)/gi,
        /(\/.*\/[gimsx]*)/g
      ],
      template: [
        /(\{\{[^}]*\}\})/g,
        /(\{%[^%]*%\})/g,
        /(\${[^}]*})/g,
        /(#{[^}]*})/g,
        /(@\{[^}]*\})/g
      ],
      encoding: [
        /(\\x[0-9a-f]{2})/gi,
        /(\\u[0-9a-f]{4})/gi,
        /(&#x[0-9a-f]+;)/gi,
        /(&#\d+;)/g,
        /(%[0-9a-f]{2})/gi
      ]
    };
  }

  loadAnomalyDetectionModel() {
    // This would load a real ML model in production
    // For now, using rule-based detection
  }

  async destroy() {
    this.requestHistory.clear();
    this.anomalyBaseline.clear();
  }
}

module.exports = RequestAnalyzer;