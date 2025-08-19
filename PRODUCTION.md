# BitPhantom WAF - Production Deployment Guide

## Production Checklist

### Pre-Deployment
- [ ] All tests passing (`npm test`)
- [ ] Security audit clean (`npm audit`)
- [ ] Linting passed (`npm run lint`)
- [ ] Environment variables configured
- [ ] SSL certificates ready
- [ ] Monitoring setup complete
- [ ] Backup strategy defined
- [ ] Rate limits configured
- [ ] Log rotation configured

### Security Hardening
- [ ] Non-root user configured
- [ ] Secrets in environment variables
- [ ] HTTPS only in production
- [ ] Security headers configured
- [ ] Input validation enabled
- [ ] Rate limiting active
- [ ] DDoS protection enabled
- [ ] WAF mode set to 'block'

## Deployment Options

### 1. Docker Deployment (Recommended)

```bash
# Build the image
docker build -t bitphantom-waf:latest .

# Run with docker-compose
docker-compose up -d

# Check logs
docker-compose logs -f waf

# Scale horizontally
docker-compose up -d --scale waf=3
```

### 2. PM2 Deployment

```bash
# Install PM2 globally
npm install -g pm2

# Start with ecosystem file
pm2 start ecosystem.config.js --env production

# Save PM2 configuration
pm2 save

# Setup startup script
pm2 startup

# Monitor
pm2 monit
```

### 3. Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bitphantom-waf
spec:
  replicas: 3
  selector:
    matchLabels:
      app: bitphantom-waf
  template:
    metadata:
      labels:
        app: bitphantom-waf
    spec:
      containers:
      - name: waf
        image: bitphantom-waf:latest
        ports:
        - containerPort: 3001
        env:
        - name: NODE_ENV
          value: "production"
        - name: WAF_MODE
          value: "block"
        resources:
          limits:
            memory: "1Gi"
            cpu: "1000m"
          requests:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 3001
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 3001
          initialDelaySeconds: 5
          periodSeconds: 5
```

## Configuration

### Environment Variables

```bash
# Required
NODE_ENV=production
WAF_MODE=block
JWT_SECRET=<generate-secure-secret>
API_KEY=<generate-secure-api-key>

# Optional but recommended
REDIS_HOST=redis
REDIS_PORT=6379
LOG_LEVEL=info
RATE_LIMIT_MAX=100
ENABLE_AI=true
```

### Nginx Reverse Proxy

```nginx
upstream waf_backend {
    least_conn;
    server localhost:3001 max_fails=3 fail_timeout=30s;
    server localhost:3002 max_fails=3 fail_timeout=30s;
    server localhost:3003 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name waf.example.com;

    ssl_certificate /etc/ssl/certs/waf.crt;
    ssl_certificate_key /etc/ssl/private/waf.key;

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://waf_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # WebSocket support
    location /waf-monitor {
        proxy_pass http://waf_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Monitoring

### Health Checks

The WAF exposes a `/health` endpoint that returns:
```json
{
  "status": "healthy",
  "uptime": 3600,
  "memory": {
    "rss": 134217728,
    "heapTotal": 73728000,
    "heapUsed": 45678900
  }
}
```

### Metrics Endpoint

Access metrics at `/waf/stats`:
```json
{
  "waf": {
    "totalRequests": 10000,
    "blockedRequests": 523,
    "threats": {
      "xss": 234,
      "sqli": 189,
      "csrf": 100
    }
  },
  "system": {
    "uptime": 3600,
    "memory": {...},
    "cpu": {...}
  }
}
```

### Prometheus Integration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'bitphantom-waf'
    static_configs:
      - targets: ['localhost:3001']
    metrics_path: '/metrics'
```

### Logging

Logs are stored in the `./logs` directory with automatic rotation:
- `waf.log` - General WAF logs
- `threats.log` - Detected threats
- `access.log` - Access logs
- `error.log` - Error logs

Configure log shipping to centralized logging:
```bash
# Filebeat configuration
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /app/logs/*.log
  json.keys_under_root: true
  json.add_error_key: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
```

## Performance Tuning

### Node.js Optimization

```bash
# Increase memory limit
NODE_OPTIONS="--max-old-space-size=1024"

# Enable cluster mode
pm2 start index.js -i max

# Use production mode
NODE_ENV=production
```

### Redis Caching

Configure Redis for session and rate limit storage:
```javascript
const redis = require('ioredis');
const client = new redis({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  lazyConnect: true
});
```

### Database Connection Pooling

```javascript
const pool = {
  min: 2,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
};
```

## Backup and Recovery

### Backup Strategy

```bash
#!/bin/bash
# backup.sh
BACKUP_DIR="/backups/waf"
DATE=$(date +%Y%m%d_%H%M%S)

# Backup configuration
cp -r /app/config $BACKUP_DIR/config_$DATE

# Backup logs
tar -czf $BACKUP_DIR/logs_$DATE.tar.gz /app/logs

# Backup Redis data
redis-cli --rdb $BACKUP_DIR/redis_$DATE.rdb

# Clean old backups (keep 30 days)
find $BACKUP_DIR -type f -mtime +30 -delete
```

### Recovery Procedure

1. Stop the WAF service
2. Restore configuration files
3. Restore Redis data if applicable
4. Start the WAF service
5. Verify functionality

## Troubleshooting

### Common Issues

1. **High Memory Usage**
   - Check for memory leaks: `node --inspect index.js`
   - Increase memory limit: `NODE_OPTIONS="--max-old-space-size=2048"`
   - Enable heap snapshots for analysis

2. **Performance Degradation**
   - Check CPU usage: `pm2 monit`
   - Review slow queries in logs
   - Enable caching for frequently accessed data

3. **False Positives**
   - Review threat logs
   - Adjust detection thresholds
   - Add exceptions for legitimate traffic

### Debug Mode

```bash
# Enable debug logging
LOG_LEVEL=debug npm start

# Enable Node.js debugging
node --inspect=0.0.0.0:9229 index.js

# Connect Chrome DevTools
chrome://inspect
```

## Security Considerations

1. **Regular Updates**
   - Keep dependencies updated: `npm update`
   - Monitor security advisories
   - Apply patches promptly

2. **Access Control**
   - Implement IP whitelisting for admin endpoints
   - Use strong API keys
   - Enable MFA for dashboard access

3. **Audit Logging**
   - Log all configuration changes
   - Monitor for suspicious patterns
   - Regular security audits

## Support

- Documentation: [README.md](README.md)
- Issues: GitHub Issues
- Security: Report to security@bitphantom.com

## License

MIT License - See LICENSE file for details