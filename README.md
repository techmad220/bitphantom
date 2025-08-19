# 🛡️ Bit Phantom WAF

A lightweight, modular, plugin-based Web Application Firewall with AI-powered anomaly detection designed to run on less than 1GB RAM.

## Features

### Core Protection
- **XSS Detection & Prevention** - Advanced pattern matching and context-aware filtering
- **SQL Injection Protection** - Multi-database support with encoded payload detection
- **CSRF Protection** - Token validation, origin checking, and double-submit cookies
- **Rate Limiting & DDoS Protection** - Intelligent rate limiting with burst detection
- **AI Anomaly Detection** - Lightweight ML models (Autoencoder, Isolation Forest, One-Class SVM)

### Architecture
- **Plugin System** - Modular design for easy extension
- **Multiple Integration Methods**:
  - Express/Node.js middleware
  - Reverse proxy mode
  - Client-side JavaScript injection
- **Real-time Monitoring** - WebSocket-based live threat feed
- **Comprehensive Logging** - Local and remote logging with rotation

### Performance
- Optimized for <1GB RAM usage
- Efficient pattern matching algorithms
- Lazy loading of AI models
- Connection pooling and caching

## Quick Start

### Installation

```bash
cd "/root/bit phantom"
npm install
```

### Basic Usage

#### As Express Middleware

```javascript
const express = require('express');
const BitPhantomWAF = require('bitphantom-waf');

const app = express();
const waf = new BitPhantomWAF({
    mode: 'block', // 'monitor', 'block', or 'learning'
    enableAI: true,
    enableWebSocket: true
});

// Initialize and get middleware
await waf.initialize();
app.use(waf.getMiddleware());

// Your routes
app.get('/', (req, res) => {
    res.send('Protected by Bit Phantom WAF');
});

app.listen(3000);
```

#### Standalone Server

```bash
npm start
```

This starts the WAF on port 3001 with:
- Dashboard: http://localhost:3001/waf-admin
- WebSocket Monitor: ws://localhost:3001/waf-monitor
- Client Script: http://localhost:3001/waf-client.js

### Configuration

```javascript
const waf = new BitPhantomWAF({
    port: 3001,
    mode: 'block', // 'monitor', 'block', 'learning'
    
    // Enable/disable features
    enableAI: true,
    enableWebSocket: true,
    enableDashboard: true,
    
    // Paths
    dashboardPath: '/waf-admin',
    clientScriptPath: '/waf-client.js',
    
    // WAF settings
    waf: {
        enabled: true,
        pluginDir: './src/plugins',
        logDir: './logs',
        rateLimitWindow: 60000,
        rateLimitMax: 100
    },
    
    // AI settings
    ai: {
        modelType: 'autoencoder', // 'autoencoder', 'isolation-forest', 'one-class-svm'
        threshold: 0.85,
        memoryLimit: 512 * 1024 * 1024, // 512MB
        updateInterval: 3600000 // 1 hour
    },
    
    // Logging
    logging: {
        logDir: './logs',
        maxFileSize: 50 * 1024 * 1024, // 50MB
        maxFiles: 10,
        logLevel: 'info',
        console: true,
        file: true,
        remote: false
    }
});
```

## Plugin Development

Create custom plugins by extending the PluginBase class:

```javascript
const PluginBase = require('./src/core/plugin-base');

class CustomPlugin extends PluginBase {
    constructor(waf) {
        super(waf);
        this.name = 'custom-plugin';
        this.version = '1.0.0';
        this.priority = 5;
    }
    
    async analyze(request, analysis) {
        // Your detection logic
        if (detectThreat(request)) {
            return {
                threat: {
                    type: 'custom-threat',
                    severity: 8,
                    details: { /* ... */ }
                }
            };
        }
        return { threat: null };
    }
}

module.exports = CustomPlugin;
```

## Client-Side Protection

Include the WAF client script in your HTML:

```html
<script src="/waf-client.js"></script>
<script>
    WAFClient.init({
        reportUri: '/waf/report',
        wsEndpoint: 'ws://localhost:3001/waf-monitor',
        protections: {
            xss: true,
            clickjacking: true,
            formProtection: true
        }
    });
</script>
```

## API Endpoints

- `GET /waf/stats` - Get current statistics
- `GET /waf/config` - Get current configuration
- `POST /waf/config` - Update configuration
- `POST /waf/report` - Client-side threat reporting
- `GET /health` - Health check

## WebSocket Events

Connect to the WebSocket endpoint for real-time monitoring:

```javascript
const ws = new WebSocket('ws://localhost:3001/waf-monitor?apiKey=YOUR_API_KEY');

ws.on('message', (data) => {
    const message = JSON.parse(data);
    switch(message.type) {
        case 'threat':
            console.log('Threat detected:', message.data);
            break;
        case 'stats-update':
            console.log('Stats:', message.data);
            break;
    }
});
```

## Memory Optimization

The WAF is optimized to run on systems with limited resources:

1. **Efficient Data Structures** - Uses Maps and Sets for O(1) lookups
2. **Streaming Processing** - Processes requests without loading entire payloads
3. **Garbage Collection** - Automatic cleanup of old data
4. **Lazy Loading** - AI models loaded on-demand
5. **Memory Limits** - Configurable memory limits for AI models

## Security Modes

### Monitor Mode
- Analyzes all requests
- Logs threats but doesn't block
- Ideal for initial deployment

### Block Mode
- Actively blocks detected threats
- Returns 403 responses for malicious requests
- Recommended for production

### Learning Mode
- Collects data for AI model training
- Doesn't block requests
- Builds baseline of normal behavior

## Dashboard

Access the admin dashboard at `http://localhost:3001/waf-admin` to:
- View real-time threat feed
- Monitor statistics
- Configure WAF settings
- Enable/disable plugins
- Train AI models
- View system metrics

## Deployment

### Docker

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3001 8080
CMD ["npm", "start"]
```

### PM2

```bash
pm2 start index.js --name "bitphantom-waf"
pm2 save
pm2 startup
```

### Systemd

```ini
[Unit]
Description=Bit Phantom WAF
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/bitphantom-waf
ExecStart=/usr/bin/node index.js
Restart=on-failure
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

## Performance Metrics

Typical resource usage with all features enabled:
- **RAM**: 200-400MB (without AI), 400-800MB (with AI)
- **CPU**: 5-15% on single core
- **Disk**: ~100MB for logs (with rotation)
- **Network**: Minimal overhead (<5ms latency)

## License

MIT

## Support

For issues, questions, or contributions, please visit the GitHub repository.