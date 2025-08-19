const express = require('express');
const request = require('supertest');
const BitPhantomWAF = require('../index');

describe('Express Middleware Integration', () => {
    let app;
    let waf;
    
    beforeEach(async () => {
        waf = new BitPhantomWAF({
            mode: 'block',
            enableAI: false, // Disable AI for faster tests
            enableWebSocket: false,
            enableDashboard: false
        });
        
        await waf.initialize();
        
        app = express();
        app.use(express.json());
        app.use(waf.getMiddleware());
        
        // Test endpoints
        app.post('/api/test', (req, res) => {
            res.json({ success: true, data: req.body });
        });
        
        app.get('/api/user/:id', (req, res) => {
            res.json({ id: req.params.id });
        });
    });
    
    afterEach(async () => {
        if (waf) {
            await waf.stop();
        }
    });
    
    describe('Attack Detection', () => {
        test('should block XSS attempts', async () => {
            const response = await request(app)
                .post('/api/test')
                .send({ data: '<script>alert(1)</script>' });
            
            expect(response.status).toBe(403);
            expect(response.body.error).toContain('blocked');
        });
        
        test('should block SQL injection', async () => {
            const response = await request(app)
                .get('/api/user/1; DROP TABLE users')
                .expect(403);
            
            expect(response.body.error).toBeDefined();
        });
        
        test('should allow legitimate requests', async () => {
            const response = await request(app)
                .post('/api/test')
                .send({ data: 'This is a normal message' })
                .expect(200);
            
            expect(response.body.success).toBe(true);
        });
    });
    
    describe('Rate Limiting', () => {
        test('should enforce rate limits', async () => {
            // Make multiple requests
            const requests = [];
            for (let i = 0; i < 150; i++) {
                requests.push(
                    request(app)
                        .get('/api/user/1')
                        .set('X-Forwarded-For', '192.168.1.1')
                );
            }
            
            const responses = await Promise.all(requests);
            const blockedCount = responses.filter(r => r.status === 429).length;
            
            expect(blockedCount).toBeGreaterThan(0);
        });
    });
    
    describe('Content Type Validation', () => {
        test('should validate JSON payloads', async () => {
            const response = await request(app)
                .post('/api/test')
                .set('Content-Type', 'application/json')
                .send('not json')
                .expect(400);
            
            expect(response.body.error).toBeDefined();
        });
    });
});