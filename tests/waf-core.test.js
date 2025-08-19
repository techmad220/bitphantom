const WAFCore = require('../src/core/waf-core');
const path = require('path');

describe('WAF Core', () => {
    let waf;
    
    beforeEach(async () => {
        waf = new WAFCore({
            mode: 'block',
            pluginDir: path.join(__dirname, '../src/plugins'),
            logDir: path.join(__dirname, '../logs'),
            rateLimitWindow: 60000,
            rateLimitMax: 100
        });
        await waf.initialize();
    });
    
    afterEach(async () => {
        if (waf) {
            await waf.cleanup();
        }
    });
    
    describe('Plugin Management', () => {
        test('should load plugins on initialization', () => {
            expect(waf.plugins.size).toBeGreaterThan(0);
        });
        
        test('should have essential security plugins', () => {
            const essentialPlugins = ['xss', 'sqli', 'csrf', 'ratelimit'];
            const loadedPlugins = Array.from(waf.plugins.keys());
            
            essentialPlugins.forEach(plugin => {
                expect(loadedPlugins.some(p => p.includes(plugin))).toBeTruthy();
            });
        });
    });
    
    describe('Request Analysis', () => {
        test('should detect XSS attacks', async () => {
            const maliciousRequest = {
                method: 'POST',
                url: '/api/test',
                headers: {},
                body: { data: '<script>alert(1)</script>' },
                query: {}
            };
            
            const result = await waf.analyzeRequest(maliciousRequest);
            expect(result.blocked).toBeTruthy();
            expect(result.threats).toHaveLength(1);
            expect(result.threats[0].type).toContain('xss');
        });
        
        test('should detect SQL injection', async () => {
            const maliciousRequest = {
                method: 'POST',
                url: '/api/login',
                headers: {},
                body: { username: "admin' OR '1'='1", password: 'test' },
                query: {}
            };
            
            const result = await waf.analyzeRequest(maliciousRequest);
            expect(result.blocked).toBeTruthy();
            expect(result.threats).toHaveLength(1);
            expect(result.threats[0].type).toContain('sqli');
        });
        
        test('should allow legitimate requests', async () => {
            const legitimateRequest = {
                method: 'POST',
                url: '/api/data',
                headers: {},
                body: { message: 'Hello, this is a normal message!' },
                query: {}
            };
            
            const result = await waf.analyzeRequest(legitimateRequest);
            expect(result.blocked).toBeFalsy();
            expect(result.threats).toHaveLength(0);
        });
    });
    
    describe('Mode Switching', () => {
        test('should not block in monitor mode', async () => {
            waf.config.mode = 'monitor';
            
            const maliciousRequest = {
                method: 'POST',
                url: '/api/test',
                headers: {},
                body: { data: '<script>alert(1)</script>' },
                query: {}
            };
            
            const result = await waf.analyzeRequest(maliciousRequest);
            expect(result.blocked).toBeFalsy();
            expect(result.threats.length).toBeGreaterThan(0);
        });
        
        test('should block in block mode', async () => {
            waf.config.mode = 'block';
            
            const maliciousRequest = {
                method: 'POST',
                url: '/api/test',
                headers: {},
                body: { data: '<script>alert(1)</script>' },
                query: {}
            };
            
            const result = await waf.analyzeRequest(maliciousRequest);
            expect(result.blocked).toBeTruthy();
        });
    });
    
    describe('Statistics', () => {
        test('should track request statistics', async () => {
            const request = {
                method: 'GET',
                url: '/api/test',
                headers: {},
                body: {},
                query: {}
            };
            
            await waf.analyzeRequest(request);
            const stats = await waf.getStats();
            
            expect(stats.totalRequests).toBe(1);
            expect(stats.blockedRequests).toBeDefined();
            expect(stats.threats).toBeDefined();
        });
    });
});