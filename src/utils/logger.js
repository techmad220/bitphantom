const winston = require('winston');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const rfs = require('rotating-file-stream');

class Logger {
  constructor(component = 'WAF') {
    this.component = component;
    this.logDir = path.join(__dirname, '../../logs');
    this.honeypotDir = path.join(this.logDir, 'honeypot');
    
    // Ensure log directories exist
    if (!fs.existsSync(this.logDir)) {
      fs.mkdirSync(this.logDir, { recursive: true });
    }
    if (!fs.existsSync(this.honeypotDir)) {
      fs.mkdirSync(this.honeypotDir, { recursive: true });
    }
    
    // Paranoid logging - log EVERYTHING
    this.logger = winston.createLogger({
      level: 'debug',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: { component: this.component },
      transports: [
        // Console output (disguised)
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          ),
          silent: process.env.STEALTH_MODE === 'true'
        }),
        // Main log file (encrypted)
        new winston.transports.File({
          filename: path.join(this.logDir, 'waf-encrypted.log'),
          maxsize: 100000000, // 100MB
          maxFiles: 100
        }),
        // Honeypot data collection
        new winston.transports.File({
          filename: path.join(this.honeypotDir, 'attack-data.json'),
          level: 'warn',
          format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.json()
          )
        })
      ]
    });
    
    // Forensic logger for ultra-detailed logging
    this.forensicLogger = winston.createLogger({
      level: 'debug',
      format: winston.format.json(),
      transports: [
        new winston.transports.File({
          filename: path.join(this.logDir, 'forensic.log'),
          maxsize: 500000000, // 500MB
          maxFiles: 50
        })
      ]
    });
    
    // Attack pattern collector for honeypot
    this.attackLogger = winston.createLogger({
      format: winston.format.json(),
      transports: [
        new winston.transports.File({
          filename: path.join(this.honeypotDir, `attacks-${new Date().toISOString().split('T')[0]}.json`)
        })
      ]
    });
  }

  // Paranoid logging methods
  logRequest(req, metadata = {}) {
    const requestData = {
      timestamp: new Date().toISOString(),
      id: crypto.randomBytes(16).toString('hex'),
      ip: this.getRealIP(req),
      ips: req.ips,
      method: req.method,
      url: req.url,
      path: req.path,
      query: req.query,
      params: req.params,
      headers: this.sanitizeHeaders(req.headers),
      body: this.sanitizeBody(req.body),
      cookies: req.cookies,
      sessionID: req.sessionID,
      protocol: req.protocol,
      hostname: req.hostname,
      userAgent: req.get('user-agent'),
      referer: req.get('referer'),
      contentType: req.get('content-type'),
      contentLength: req.get('content-length'),
      acceptLanguage: req.get('accept-language'),
      acceptEncoding: req.get('accept-encoding'),
      connection: req.get('connection'),
      socketInfo: {
        remoteAddress: req.socket?.remoteAddress,
        remotePort: req.socket?.remotePort,
        localAddress: req.socket?.localAddress,
        localPort: req.socket?.localPort
      },
      tlsInfo: req.socket?.encrypted ? {
        protocol: req.socket.getProtocol?.(),
        cipher: req.socket.getCipher?.()
      } : null,
      ...metadata
    };
    
    // Log to forensic file
    this.forensicLogger.debug('REQUEST', requestData);
    
    // Encrypt sensitive data for main log
    const encrypted = this.encryptData(requestData);
    this.logger.debug('Request received', { encrypted });
    
    return requestData;
  }

  logAttack(attackData) {
    const enrichedData = {
      ...attackData,
      timestamp: new Date().toISOString(),
      id: crypto.randomBytes(16).toString('hex'),
      fingerprint: this.generateAttackFingerprint(attackData),
      honeypotValue: this.calculateHoneypotValue(attackData)
    };
    
    // Log to honeypot collection
    this.attackLogger.info(enrichedData);
    
    // Log to main system
    this.logger.warn('ATTACK_DETECTED', enrichedData);
    
    // Store for selling
    this.storeHoneypotData(enrichedData);
    
    return enrichedData;
  }

  logSuspiciousActivity(activity) {
    const data = {
      timestamp: new Date().toISOString(),
      type: 'SUSPICIOUS',
      ...activity
    };
    
    this.forensicLogger.info('SUSPICIOUS_ACTIVITY', data);
    this.logger.info('Suspicious activity', data);
  }

  logAnomaly(anomaly) {
    const data = {
      timestamp: new Date().toISOString(),
      type: 'ANOMALY',
      ...anomaly
    };
    
    this.forensicLogger.warn('ANOMALY_DETECTED', data);
    this.attackLogger.info(data);
  }

  // Helper methods
  getRealIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] ||
           req.headers['x-real-ip'] ||
           req.connection?.remoteAddress ||
           req.socket?.remoteAddress ||
           req.connection?.socket?.remoteAddress ||
           req.ip;
  }

  sanitizeHeaders(headers) {
    const sanitized = { ...headers };
    // Keep everything for honeypot but mark sensitive fields
    const sensitive = ['authorization', 'cookie', 'x-api-key'];
    sensitive.forEach(key => {
      if (sanitized[key]) {
        sanitized[`${key}_hash`] = crypto.createHash('sha256')
          .update(sanitized[key])
          .digest('hex');
        sanitized[key] = '[REDACTED-SEE-HASH]';
      }
    });
    return sanitized;
  }

  sanitizeBody(body) {
    if (!body) return null;
    
    // Deep clone to avoid modifying original
    const sanitized = JSON.parse(JSON.stringify(body));
    
    // Patterns to detect sensitive data
    const sensitivePatterns = [
      /password/i,
      /passwd/i,
      /secret/i,
      /token/i,
      /api[_-]?key/i,
      /private[_-]?key/i,
      /credit[_-]?card/i,
      /ssn/i
    ];
    
    const sanitizeObject = (obj) => {
      for (const [key, value] of Object.entries(obj)) {
        if (sensitivePatterns.some(pattern => pattern.test(key))) {
          obj[`${key}_hash`] = crypto.createHash('sha256')
            .update(String(value))
            .digest('hex');
          obj[key] = '[REDACTED-SEE-HASH]';
        } else if (typeof value === 'object' && value !== null) {
          sanitizeObject(value);
        }
      }
    };
    
    if (typeof sanitized === 'object') {
      sanitizeObject(sanitized);
    }
    
    return sanitized;
  }

  encryptData(data) {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(process.env.LOG_ENCRYPTION_KEY || 'default-key', 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }

  generateAttackFingerprint(attackData) {
    // Create unique fingerprint for attack pattern
    const fingerprintData = {
      type: attackData.type,
      pattern: attackData.pattern,
      method: attackData.method,
      targetPath: attackData.path,
      userAgent: attackData.userAgent
    };
    
    return crypto.createHash('sha256')
      .update(JSON.stringify(fingerprintData))
      .digest('hex');
  }

  calculateHoneypotValue(attackData) {
    // Calculate the value of this attack data for selling
    let value = 1;
    
    // Novel attacks are more valuable
    if (attackData.novelty === 'high') value *= 5;
    
    // Zero-days are extremely valuable
    if (attackData.type === 'zero-day') value *= 10;
    
    // Complex attacks are valuable
    if (attackData.complexity === 'high') value *= 3;
    
    // Targeted attacks are valuable
    if (attackData.targeted) value *= 2;
    
    return value;
  }

  storeHoneypotData(data) {
    // Store in format ready for selling
    const filename = path.join(this.honeypotDir, `honeypot-${Date.now()}.json`);
    fs.writeFileSync(filename, JSON.stringify(data, null, 2));
  }

  // Standard logging methods
  info(message, meta = {}) {
    this.logger.info(message, meta);
  }

  warn(message, meta = {}) {
    this.logger.warn(message, meta);
  }

  error(message, meta = {}) {
    this.logger.error(message, meta);
  }

  debug(message, meta = {}) {
    this.logger.debug(message, meta);
  }
}

module.exports = { Logger };