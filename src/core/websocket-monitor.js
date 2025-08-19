const WebSocket = require('ws');
const EventEmitter = require('events');
const crypto = require('crypto');

class WebSocketMonitor extends EventEmitter {
    constructor(config = {}) {
        super();
        
        this.config = {
            port: 8080,
            host: '0.0.0.0',
            path: '/waf-monitor',
            authentication: true,
            apiKey: process.env.WAF_API_KEY || crypto.randomBytes(32).toString('hex'),
            heartbeatInterval: 30000,
            maxClients: 100,
            compression: true,
            perMessageDeflate: {
                zlibDeflateOptions: {
                    chunkSize: 1024,
                    memLevel: 7,
                    level: 3
                },
                zlibInflateOptions: {
                    chunkSize: 10 * 1024
                }
            },
            ...config
        };
        
        this.wss = null;
        this.clients = new Map();
        this.metrics = {
            connections: 0,
            messagessSent: 0,
            messagesReceived: 0,
            bytessSent: 0,
            bytesReceived: 0
        };
        
        this.subscriptions = new Map();
        this.threatFeed = [];
        this.maxFeedSize = 1000;
    }

    async initialize(server = null) {
        if (server) {
            // Attach to existing server
            this.wss = new WebSocket.Server({
                server,
                path: this.config.path,
                perMessageDeflate: this.config.compression ? this.config.perMessageDeflate : false
            });
        } else {
            // Create standalone server
            this.wss = new WebSocket.Server({
                port: this.config.port,
                host: this.config.host,
                path: this.config.path,
                perMessageDeflate: this.config.compression ? this.config.perMessageDeflate : false
            });
        }
        
        this.setupWebSocketServer();
        this.startHeartbeat();
        
        console.log(`[WebSocket Monitor] Server started on ${this.config.host}:${this.config.port}${this.config.path}`);
        if (this.config.authentication) {
            console.log(`[WebSocket Monitor] API Key: ${this.config.apiKey}`);
        }
        
        return true;
    }

    setupWebSocketServer() {
        this.wss.on('connection', (ws, req) => {
            const clientId = this.generateClientId();
            const clientIp = this.getClientIp(req);
            
            // Authenticate if required
            if (this.config.authentication) {
                const apiKey = this.extractApiKey(req);
                if (apiKey !== this.config.apiKey) {
                    ws.send(JSON.stringify({
                        type: 'error',
                        message: 'Authentication failed'
                    }));
                    ws.close(1008, 'Authentication failed');
                    return;
                }
            }
            
            // Check max clients
            if (this.clients.size >= this.config.maxClients) {
                ws.send(JSON.stringify({
                    type: 'error',
                    message: 'Maximum clients reached'
                }));
                ws.close(1008, 'Maximum clients reached');
                return;
            }
            
            // Register client
            const client = {
                id: clientId,
                ws,
                ip: clientIp,
                connectedAt: Date.now(),
                subscriptions: new Set(),
                stats: {
                    messagesSent: 0,
                    messagesReceived: 0,
                    bytesSent: 0,
                    bytesReceived: 0
                }
            };
            
            this.clients.set(clientId, client);
            this.metrics.connections++;
            
            // Send welcome message
            this.sendToClient(client, {
                type: 'welcome',
                clientId,
                serverTime: Date.now(),
                config: {
                    heartbeatInterval: this.config.heartbeatInterval,
                    compression: this.config.compression
                }
            });
            
            // Send initial data
            this.sendInitialData(client);
            
            // Setup client handlers
            this.setupClientHandlers(client);
            
            this.emit('client-connected', { clientId, ip: clientIp });
        });
        
        this.wss.on('error', (error) => {
            console.error('[WebSocket Monitor] Server error:', error);
            this.emit('error', error);
        });
    }

    setupClientHandlers(client) {
        const ws = client.ws;
        
        ws.on('message', (data) => {
            try {
                const message = JSON.parse(data.toString());
                client.stats.messagesReceived++;
                client.stats.bytesReceived += data.length;
                this.metrics.messagesReceived++;
                this.metrics.bytesReceived += data.length;
                
                this.handleClientMessage(client, message);
            } catch (error) {
                console.error('[WebSocket Monitor] Message parse error:', error);
                this.sendToClient(client, {
                    type: 'error',
                    message: 'Invalid message format'
                });
            }
        });
        
        ws.on('pong', () => {
            client.lastPong = Date.now();
        });
        
        ws.on('close', (code, reason) => {
            this.handleClientDisconnect(client, code, reason);
        });
        
        ws.on('error', (error) => {
            console.error(`[WebSocket Monitor] Client ${client.id} error:`, error);
        });
    }

    handleClientMessage(client, message) {
        const { type, data } = message;
        
        switch (type) {
            case 'subscribe':
                this.handleSubscribe(client, data);
                break;
                
            case 'unsubscribe':
                this.handleUnsubscribe(client, data);
                break;
                
            case 'get-stats':
                this.sendStats(client);
                break;
                
            case 'get-threats':
                this.sendThreats(client, data);
                break;
                
            case 'get-config':
                this.sendConfig(client);
                break;
                
            case 'update-config':
                this.handleConfigUpdate(client, data);
                break;
                
            case 'ping':
                this.sendToClient(client, { type: 'pong', timestamp: Date.now() });
                break;
                
            default:
                this.emit('client-message', { client, message });
        }
    }

    handleSubscribe(client, data) {
        const { channels = [] } = data;
        
        for (const channel of channels) {
            client.subscriptions.add(channel);
            
            if (!this.subscriptions.has(channel)) {
                this.subscriptions.set(channel, new Set());
            }
            this.subscriptions.get(channel).add(client.id);
        }
        
        this.sendToClient(client, {
            type: 'subscribed',
            channels: Array.from(client.subscriptions)
        });
    }

    handleUnsubscribe(client, data) {
        const { channels = [] } = data;
        
        for (const channel of channels) {
            client.subscriptions.delete(channel);
            
            const channelSubs = this.subscriptions.get(channel);
            if (channelSubs) {
                channelSubs.delete(client.id);
                if (channelSubs.size === 0) {
                    this.subscriptions.delete(channel);
                }
            }
        }
        
        this.sendToClient(client, {
            type: 'unsubscribed',
            channels: Array.from(client.subscriptions)
        });
    }

    handleConfigUpdate(client, data) {
        // Emit config update event for WAF to handle
        this.emit('config-update', { client: client.id, config: data });
        
        this.sendToClient(client, {
            type: 'config-updated',
            success: true
        });
    }

    handleClientDisconnect(client, code, reason) {
        // Remove from all subscriptions
        for (const channel of client.subscriptions) {
            const channelSubs = this.subscriptions.get(channel);
            if (channelSubs) {
                channelSubs.delete(client.id);
                if (channelSubs.size === 0) {
                    this.subscriptions.delete(channel);
                }
            }
        }
        
        this.clients.delete(client.id);
        
        this.emit('client-disconnected', {
            clientId: client.id,
            code,
            reason: reason?.toString(),
            duration: Date.now() - client.connectedAt
        });
    }

    sendInitialData(client) {
        // Send recent threats
        this.sendToClient(client, {
            type: 'initial-data',
            threats: this.threatFeed.slice(-100),
            timestamp: Date.now()
        });
    }

    sendStats(client) {
        this.emit('stats-request', (stats) => {
            this.sendToClient(client, {
                type: 'stats',
                data: stats,
                timestamp: Date.now()
            });
        });
    }

    sendThreats(client, data) {
        const { limit = 100, offset = 0 } = data || {};
        
        const threats = this.threatFeed.slice(offset, offset + limit);
        
        this.sendToClient(client, {
            type: 'threats',
            data: threats,
            total: this.threatFeed.length,
            timestamp: Date.now()
        });
    }

    sendConfig(client) {
        this.emit('config-request', (config) => {
            this.sendToClient(client, {
                type: 'config',
                data: config,
                timestamp: Date.now()
            });
        });
    }

    // Broadcast methods
    broadcast(message, channel = null) {
        if (channel) {
            // Send to specific channel subscribers
            const subscribers = this.subscriptions.get(channel);
            if (subscribers) {
                for (const clientId of subscribers) {
                    const client = this.clients.get(clientId);
                    if (client) {
                        this.sendToClient(client, message);
                    }
                }
            }
        } else {
            // Send to all clients
            for (const client of this.clients.values()) {
                this.sendToClient(client, message);
            }
        }
    }

    broadcastThreat(threat) {
        // Add to threat feed
        this.threatFeed.push({
            ...threat,
            timestamp: Date.now()
        });
        
        // Limit feed size
        if (this.threatFeed.length > this.maxFeedSize) {
            this.threatFeed.shift();
        }
        
        // Broadcast to subscribers
        this.broadcast({
            type: 'threat',
            data: threat,
            timestamp: Date.now()
        }, 'threats');
    }

    broadcastStats(stats) {
        this.broadcast({
            type: 'stats-update',
            data: stats,
            timestamp: Date.now()
        }, 'stats');
    }

    broadcastAlert(alert) {
        this.broadcast({
            type: 'alert',
            data: alert,
            timestamp: Date.now()
        }, 'alerts');
    }

    sendToClient(client, message) {
        if (client.ws.readyState === WebSocket.OPEN) {
            const data = JSON.stringify(message);
            client.ws.send(data);
            
            client.stats.messagesSent++;
            client.stats.bytesSent += data.length;
            this.metrics.messagessSent++;
            this.metrics.bytessSent += data.length;
        }
    }

    startHeartbeat() {
        this.heartbeatInterval = setInterval(() => {
            const now = Date.now();
            
            for (const [clientId, client] of this.clients) {
                if (client.ws.readyState === WebSocket.OPEN) {
                    // Check if client is alive
                    if (client.lastPong && now - client.lastPong > this.config.heartbeatInterval * 2) {
                        // Client didn't respond to ping, disconnect
                        client.ws.terminate();
                        continue;
                    }
                    
                    // Send ping
                    client.ws.ping();
                }
            }
            
            // Broadcast heartbeat
            this.broadcast({
                type: 'heartbeat',
                timestamp: now,
                clients: this.clients.size
            }, 'system');
        }, this.config.heartbeatInterval);
    }

    getClientIp(req) {
        return req.headers['x-forwarded-for']?.split(',')[0].trim() ||
               req.connection?.remoteAddress ||
               req.socket?.remoteAddress;
    }

    extractApiKey(req) {
        // Check Authorization header
        const authHeader = req.headers.authorization;
        if (authHeader) {
            const [type, key] = authHeader.split(' ');
            if (type === 'Bearer') return key;
        }
        
        // Check query parameter
        const url = new URL(req.url, `http://${req.headers.host}`);
        return url.searchParams.get('apiKey');
    }

    generateClientId() {
        return crypto.randomBytes(16).toString('hex');
    }

    getMetrics() {
        return {
            ...this.metrics,
            activeClients: this.clients.size,
            subscriptions: this.subscriptions.size,
            threatFeedSize: this.threatFeed.length,
            uptime: process.uptime()
        };
    }

    async cleanup() {
        // Clear heartbeat
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
        }
        
        // Close all client connections
        for (const client of this.clients.values()) {
            client.ws.close(1000, 'Server shutting down');
        }
        
        // Close WebSocket server
        if (this.wss) {
            await new Promise((resolve) => {
                this.wss.close(resolve);
            });
        }
        
        this.clients.clear();
        this.subscriptions.clear();
        this.threatFeed = [];
    }
}

module.exports = WebSocketMonitor;