const XSSPlugin = require('../src/plugins/xss.plugin');
const SQLiPlugin = require('../src/plugins/sqli.plugin');
const CSRFPlugin = require('../src/plugins/csrf.plugin');

describe('Security Plugins', () => {
    describe('XSS Plugin', () => {
        let plugin;
        const mockWaf = {
            emit: jest.fn(),
            config: { mode: 'block' }
        };
        
        beforeEach(() => {
            plugin = new XSSPlugin(mockWaf);
            plugin.initialize();
        });
        
        test('should detect basic XSS', async () => {
            const request = {
                body: { data: '<script>alert(1)</script>' }
            };
            
            const result = await plugin.analyze(request, {});
            expect(result.threat).toBeDefined();
            expect(result.threat.type).toBe('xss');
        });
        
        test('should detect encoded XSS', async () => {
            const request = {
                body: { data: '%3Cscript%3Ealert(1)%3C/script%3E' }
            };
            
            const result = await plugin.analyze(request, {});
            expect(result.threat).toBeDefined();
        });
        
        test('should detect event handler XSS', async () => {
            const request = {
                body: { data: '<img src=x onerror=alert(1)>' }
            };
            
            const result = await plugin.analyze(request, {});
            expect(result.threat).toBeDefined();
        });
        
        test('should not flag legitimate HTML', async () => {
            const request = {
                body: { data: '<p>This is a paragraph</p>' }
            };
            
            const result = await plugin.analyze(request, {});
            expect(result.threat).toBeNull();
        });
    });
    
    describe('SQL Injection Plugin', () => {
        let plugin;
        const mockWaf = {
            emit: jest.fn(),
            config: { mode: 'block' }
        };
        
        beforeEach(() => {
            plugin = new SQLiPlugin(mockWaf);
            plugin.initialize();
        });
        
        test('should detect classic SQL injection', async () => {
            const request = {
                body: { username: "admin' OR '1'='1" }
            };
            
            const result = await plugin.analyze(request, {});
            expect(result.threat).toBeDefined();
            expect(result.threat.type).toBe('sqli');
        });
        
        test('should detect UNION-based injection', async () => {
            const request = {
                query: { id: '1 UNION SELECT * FROM users' }
            };
            
            const result = await plugin.analyze(request, {});
            expect(result.threat).toBeDefined();
        });
        
        test('should detect comment-based injection', async () => {
            const request = {
                body: { password: "password'; --" }
            };
            
            const result = await plugin.analyze(request, {});
            expect(result.threat).toBeDefined();
        });
        
        test('should allow legitimate SQL-like text', async () => {
            const request = {
                body: { comment: "I like to SELECT items and ORDER them" }
            };
            
            const result = await plugin.analyze(request, {});
            expect(result.threat).toBeNull();
        });
    });
    
    describe('CSRF Plugin', () => {
        let plugin;
        const mockWaf = {
            emit: jest.fn(),
            config: { mode: 'block' }
        };
        
        beforeEach(() => {
            plugin = new CSRFPlugin(mockWaf);
            plugin.initialize();
        });
        
        test('should block requests without CSRF token', async () => {
            const request = {
                method: 'POST',
                headers: {},
                body: { action: 'delete' }
            };
            
            const result = await plugin.analyze(request, {});
            expect(result.threat).toBeDefined();
            expect(result.threat.type).toBe('csrf');
        });
        
        test('should block requests with invalid origin', async () => {
            const request = {
                method: 'POST',
                headers: {
                    'Origin': 'http://evil.com',
                    'X-CSRF-Token': 'token123'
                },
                body: {}
            };
            
            const result = await plugin.analyze(request, {});
            expect(result.threat).toBeDefined();
        });
        
        test('should allow GET requests', async () => {
            const request = {
                method: 'GET',
                headers: {},
                query: {}
            };
            
            const result = await plugin.analyze(request, {});
            expect(result.threat).toBeNull();
        });
    });
});