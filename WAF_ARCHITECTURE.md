# BitPhantom WAF - Web Application Firewall Architecture

## System Overview

BitPhantom WAF is a modular, plugin-based web application firewall designed for React + Vite applications with the following characteristics:
- **Memory Footprint**: < 1GB RAM including AI model
- **Deployment**: Works as middleware, reverse proxy, or client-side injection
- **Real-time**: WebSocket-compatible with live monitoring
- **AI-Powered**: Lightweight ML for anomaly detection
- **Extensible**: Plugin architecture for custom rules

## Architecture Components

### 1. Core Engine
- **Plugin Loader**: Dynamic plugin loading system
- **Request Pipeline**: Multi-stage request processing
- **Response Pipeline**: Output filtering and modification
- **Event Bus**: Real-time event distribution
- **Memory Pool**: Efficient memory management

### 2. Plugin System
```
plugins/
├── core/           # Core security plugins
│   ├── xss/       # XSS detection & prevention
│   ├── sqli/      # SQL injection protection
│   ├── csrf/      # CSRF token validation
│   ├── ratelimit/ # Rate limiting
│   └── auth/      # Authentication checks
├── custom/         # User-defined plugins
└── ai/            # AI-powered plugins
```

### 3. Detection Methods

#### Pattern-Based Detection
- Regular expression matching
- Signature-based detection
- Blacklist/whitelist rules

#### Behavioral Analysis
- Request frequency analysis
- Path traversal detection
- Unusual parameter patterns

#### AI/ML Detection
- Anomaly detection using lightweight models
- Options:
  1. **TensorFlow.js Lite** (150-200MB)
  2. **ONNX Runtime Web** (100-150MB)
  3. **Custom Isolation Forest** (50-100MB)
  4. **Tiny BERT** for text analysis (90MB)

### 4. Deployment Modes

#### A. Middleware Mode (Express/Node.js)
```javascript
app.use(bitPhantomWAF({
  plugins: ['xss', 'sqli', 'csrf'],
  ai: true,
  logging: 'local'
}));
```

#### B. Reverse Proxy Mode (Nginx Integration)
```nginx
location / {
    proxy_pass http://localhost:3001;  # WAF port
    proxy_set_header X-Real-IP $remote_addr;
}
```

#### C. Client-Side Injection
```html
<script src="/bitphantom-client.js"></script>
```

### 5. Logging Architecture

#### Local Logging
- Structured JSON logs
- Rotating file system
- SQLite for quick queries

#### Remote Logging Ready
- Elasticsearch preparation
- Syslog protocol support
- Webhook notifications

### 6. Real-time Monitoring

#### WebSocket Server
- Live threat feed
- Active connection monitoring
- Performance metrics streaming

#### Dashboard Integration
- React components for visualization
- Chart.js for metrics
- Real-time alert system

## Plugin API Specification

### Plugin Structure
```javascript
module.exports = {
  name: 'plugin-name',
  version: '1.0.0',
  priority: 100,  // Execution order
  
  // Lifecycle hooks
  async init(context) {},
  async destroy() {},
  
  // Request processing
  async onRequest(req, res, next) {},
  async onResponse(req, res, body) {},
  
  // Detection rules
  rules: [],
  
  // AI model (optional)
  model: null,
  
  // Configuration
  config: {}
};
```

### Rule Definition
```javascript
{
  id: 'xss-001',
  type: 'pattern|behavior|ai',
  severity: 'critical|high|medium|low',
  pattern: /regex/,
  action: 'block|log|challenge',
  message: 'Attack detected'
}
```

## Performance Targets

### Memory Usage
- Core Engine: 50-100MB
- Plugin System: 20-50MB per plugin
- AI Model: 100-200MB
- Logging Buffer: 50MB
- **Total**: < 500MB typical, < 1GB maximum

### Latency
- Pattern matching: < 1ms
- AI inference: < 10ms
- Total added latency: < 15ms per request

### Throughput
- Target: 10,000+ requests/second
- WebSocket connections: 1,000+ concurrent

## Security Features

### Attack Prevention
1. **XSS (Cross-Site Scripting)**
   - Input sanitization
   - Output encoding
   - CSP header injection

2. **SQL Injection**
   - Query parameter validation
   - Prepared statement enforcement
   - Database-specific patterns

3. **CSRF (Cross-Site Request Forgery)**
   - Token validation
   - Referer checking
   - SameSite cookie enforcement

4. **DDoS Protection**
   - Rate limiting
   - Connection throttling
   - Captcha challenges

5. **Path Traversal**
   - Directory traversal blocking
   - File inclusion prevention

6. **XXE (XML External Entity)**
   - XML parsing protection
   - DTD blocking

### Additional Features
- IP reputation checking
- Geo-blocking capabilities
- Bot detection
- Session hijacking prevention
- Cookie security
- Header injection prevention

## Implementation Phases

### Phase 1: Core Engine (Week 1)
- Plugin loader
- Request/response pipeline
- Basic logging

### Phase 2: Core Plugins (Week 2)
- XSS, SQLi, CSRF plugins
- Rate limiting
- Basic rules engine

### Phase 3: AI Integration (Week 3)
- Model selection and training
- Anomaly detection plugin
- Performance optimization

### Phase 4: Monitoring & Dashboard (Week 4)
- WebSocket server
- React dashboard
- Alert system

### Phase 5: Production Hardening (Week 5)
- Performance tuning
- Memory optimization
- Stress testing

## Configuration Example

```yaml
# bitphantom.config.yaml
mode: middleware
port: 3001

plugins:
  enabled:
    - xss
    - sqli
    - csrf
    - ratelimit
    - ai-anomaly

ai:
  enabled: true
  model: isolation-forest
  threshold: 0.85

logging:
  level: info
  local:
    enabled: true
    path: /var/log/bitphantom
    rotation: daily
  remote:
    enabled: false
    endpoint: https://logs.example.com

monitoring:
  websocket:
    enabled: true
    port: 3002
  dashboard:
    enabled: true
    port: 3003

rules:
  custom:
    - pattern: "(?i)(union|select|insert|update|delete|drop)"
      action: block
      severity: high
```

## Technology Stack

### Core
- **Language**: Node.js (v18+)
- **Framework**: Express.js
- **WebSocket**: Socket.io

### AI/ML
- **Primary**: TensorFlow.js Lite
- **Alternative**: Custom Isolation Forest in pure JS

### Storage
- **Logs**: SQLite + JSON files
- **Cache**: Redis (optional) or in-memory

### Monitoring
- **Dashboard**: React + Vite
- **Charts**: Chart.js
- **Real-time**: WebSocket

### Development
- **Testing**: Jest + Supertest
- **Linting**: ESLint
- **Build**: Webpack/Rollup for plugins

## Security Considerations

1. **WAF Bypass Prevention**
   - Multiple encoding detection
   - Normalization before inspection
   - Context-aware filtering

2. **Performance Impact**
   - Async processing where possible
   - Worker threads for CPU-intensive tasks
   - Caching of rule results

3. **False Positive Reduction**
   - Whitelisting capabilities
   - Learning mode
   - Confidence scoring

4. **Secure Configuration**
   - Encrypted config files
   - Environment variable support
   - Secure defaults

## Next Steps

1. Initialize Node.js project structure
2. Implement core engine with plugin loader
3. Create base plugin template
4. Develop XSS detection plugin as proof of concept
5. Set up AI model training pipeline
6. Build monitoring dashboard
7. Create deployment scripts
8. Write comprehensive documentation