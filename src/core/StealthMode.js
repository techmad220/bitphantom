const crypto = require('crypto');

class StealthMode {
  constructor() {
    this.responseVariations = this.initResponseVariations();
    this.timingProfiles = this.initTimingProfiles();
    this.serverHeaders = this.initServerHeaders();
    this.behaviorProfiles = this.initBehaviorProfiles();
    this.currentProfile = null;
    this.rotateProfile();
    
    // Rotate profile every 5-30 minutes randomly
    this.scheduleRotation();
  }

  initResponseVariations() {
    return {
      // Different ways to say "blocked" without revealing WAF presence
      blocked: [
        { status: 404, body: { error: 'Not Found' }},
        { status: 500, body: { error: 'Internal Server Error' }},
        { status: 503, body: { error: 'Service Temporarily Unavailable' }},
        { status: 400, body: { error: 'Bad Request' }},
        { status: 403, body: { error: 'Forbidden' }},
        { status: 429, body: { error: 'Too Many Requests' }},
        { status: 502, body: { error: 'Bad Gateway' }},
        // Mimic real application errors
        { status: 500, body: { error: 'Database connection failed' }},
        { status: 500, body: { error: 'Unable to process request' }},
        { status: 422, body: { error: 'Unprocessable Entity' }},
        // Timeout-like responses
        { status: 504, body: { error: 'Gateway Timeout' }},
        { status: 408, body: { error: 'Request Timeout' }},
        // Empty responses
        { status: 200, body: {} },
        { status: 204, body: null },
        // Redirect responses (honeypot)
        { status: 302, headers: { 'Location': '/login' }},
        { status: 301, headers: { 'Location': '/' }},
        // Fake success (honeypot)
        { status: 200, body: { success: true, data: this.generateFakeData() }}
      ],
      
      // Challenge responses that don't reveal security system
      challenge: [
        { status: 503, body: this.generateMaintenancePage() },
        { status: 429, body: this.generateRateLimitPage() },
        { status: 403, body: this.generateGenericErrorPage() }
      ]
    };
  }

  initTimingProfiles() {
    return [
      // Fast server profile
      { min: 5, max: 50, jitter: true, name: 'fast' },
      // Normal server profile  
      { min: 20, max: 200, jitter: true, name: 'normal' },
      // Slow server profile (makes WAF delays unnoticeable)
      { min: 100, max: 500, jitter: true, name: 'slow' },
      // Variable profile (completely random)
      { min: 5, max: 1000, jitter: true, name: 'variable' },
      // Mimics real processing time
      { min: 15, max: 150, jitter: true, pattern: 'gaussian', name: 'realistic' }
    ];
  }

  initServerHeaders() {
    // Different server signatures to rotate through
    return [
      { 'Server': 'nginx/1.18.0', 'X-Powered-By': undefined },
      { 'Server': 'Apache/2.4.41 (Ubuntu)', 'X-Powered-By': 'PHP/7.4.3' },
      { 'Server': 'Microsoft-IIS/10.0', 'X-Powered-By': 'ASP.NET' },
      { 'Server': undefined, 'X-Powered-By': 'Express' },
      { 'Server': 'cloudflare', 'X-Powered-By': undefined },
      { 'Server': 'AmazonS3', 'X-Powered-By': undefined },
      { 'Server': 'Google Frontend', 'X-Powered-By': undefined },
      { 'Server': 'Vercel', 'X-Powered-By': undefined },
      // No server header at all
      {},
      // Custom/fake servers
      { 'Server': 'CustomServer/1.0', 'X-Powered-By': 'Node.js' },
      { 'Server': 'LiteSpeed', 'X-Powered-By': undefined }
    ];
  }

  initBehaviorProfiles() {
    return [
      {
        name: 'strict',
        blockThreshold: 30,
        challengeThreshold: 20,
        logOnly: false,
        honeyPotMode: false
      },
      {
        name: 'moderate',
        blockThreshold: 50,
        challengeThreshold: 30,
        logOnly: false,
        honeyPotMode: false
      },
      {
        name: 'learning',
        blockThreshold: 70,
        challengeThreshold: 50,
        logOnly: true,
        honeyPotMode: false
      },
      {
        name: 'honeypot',
        blockThreshold: 90,
        challengeThreshold: 80,
        logOnly: false,
        honeyPotMode: true
      },
      {
        name: 'random',
        blockThreshold: Math.random() * 60 + 20,
        challengeThreshold: Math.random() * 40 + 10,
        logOnly: Math.random() > 0.7,
        honeyPotMode: Math.random() > 0.8
      }
    ];
  }

  rotateProfile() {
    // Randomly select new profiles
    this.currentProfile = {
      timing: this.timingProfiles[Math.floor(Math.random() * this.timingProfiles.length)],
      headers: this.serverHeaders[Math.floor(Math.random() * this.serverHeaders.length)],
      behavior: this.behaviorProfiles[Math.floor(Math.random() * this.behaviorProfiles.length)],
      sessionId: crypto.randomBytes(16).toString('hex')
    };
  }

  scheduleRotation() {
    // Random rotation between 5-30 minutes
    const delay = (Math.random() * 25 + 5) * 60 * 1000;
    setTimeout(() => {
      this.rotateProfile();
      this.scheduleRotation();
    }, delay);
  }

  async processResponse(req, res, decision) {
    // Add random delay based on current timing profile
    await this.addDelay();
    
    // Apply current server headers
    this.applyHeaders(res);
    
    if (decision.action === 'BLOCK') {
      return this.handleBlock(req, res, decision);
    } else if (decision.action === 'CHALLENGE') {
      return this.handleChallenge(req, res, decision);
    }
    
    // For allowed requests, sometimes add fake vulnerabilities (honeypot)
    if (this.currentProfile.behavior.honeyPotMode && Math.random() > 0.9) {
      this.addHoneypotMarkers(res);
    }
    
    return null;
  }

  async addDelay() {
    const profile = this.currentProfile.timing;
    let delay = Math.random() * (profile.max - profile.min) + profile.min;
    
    if (profile.pattern === 'gaussian') {
      // Gaussian distribution for more realistic delays
      delay = this.gaussianRandom(profile.min, profile.max);
    }
    
    if (profile.jitter) {
      // Add random jitter
      delay += (Math.random() - 0.5) * 10;
    }
    
    return new Promise(resolve => setTimeout(resolve, Math.max(0, delay)));
  }

  gaussianRandom(min, max) {
    // Box-Muller transform for gaussian distribution
    let u = 0, v = 0;
    while (u === 0) u = Math.random();
    while (v === 0) v = Math.random();
    
    const num = Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
    const normalized = (num + 3) / 6; // Normalize to 0-1
    
    return min + (max - min) * Math.max(0, Math.min(1, normalized));
  }

  applyHeaders(res) {
    const headers = this.currentProfile.headers;
    
    for (const [key, value] of Object.entries(headers)) {
      if (value !== undefined) {
        res.setHeader(key, value);
      } else {
        res.removeHeader(key);
      }
    }
    
    // Add random cache headers
    if (Math.random() > 0.5) {
      res.setHeader('Cache-Control', this.getRandomCacheControl());
    }
    
    // Add random security headers (but not WAF-specific)
    if (Math.random() > 0.3) {
      res.setHeader('X-Frame-Options', Math.random() > 0.5 ? 'DENY' : 'SAMEORIGIN');
    }
    
    if (Math.random() > 0.4) {
      res.setHeader('X-Content-Type-Options', 'nosniff');
    }
    
    // Sometimes add fake debug headers (honeypot)
    if (this.currentProfile.behavior.honeyPotMode && Math.random() > 0.95) {
      res.setHeader('X-Debug-Token', crypto.randomBytes(8).toString('hex'));
      res.setHeader('X-Request-Id', crypto.randomBytes(16).toString('hex'));
    }
  }

  getRandomCacheControl() {
    const options = [
      'no-cache',
      'no-store',
      'public, max-age=3600',
      'private, max-age=0',
      'must-revalidate',
      's-maxage=86400'
    ];
    return options[Math.floor(Math.random() * options.length)];
  }

  handleBlock(req, res, decision) {
    // Select random response from variations
    const responses = this.responseVariations.blocked;
    const response = responses[Math.floor(Math.random() * responses.length)];
    
    // Apply response
    res.status(response.status);
    
    if (response.headers) {
      for (const [key, value] of Object.entries(response.headers)) {
        res.setHeader(key, value);
      }
    }
    
    // Sometimes close connection abruptly (mimics real errors)
    if (Math.random() > 0.9) {
      res.destroy();
      return;
    }
    
    // Sometimes delay response significantly (mimics timeout)
    if (Math.random() > 0.85) {
      setTimeout(() => {
        if (!res.headersSent) {
          res.json(response.body || {});
        }
      }, 5000 + Math.random() * 10000);
      return;
    }
    
    res.json(response.body || {});
  }

  handleChallenge(req, res, decision) {
    const responses = this.responseVariations.challenge;
    const response = responses[Math.floor(Math.random() * responses.length)];
    
    res.status(response.status);
    
    // Send HTML page that doesn't reveal it's a challenge
    res.send(response.body);
  }

  addHoneypotMarkers(res) {
    // Add subtle markers that might attract attackers
    const markers = [
      () => res.setHeader('X-Debug-Mode', 'true'),
      () => res.setHeader('X-Admin-Access', 'false'),
      () => res.setHeader('X-API-Version', 'v1-deprecated'),
      () => res.setHeader('X-Development', '1'),
      () => res.setHeader('X-Test-Environment', 'staging')
    ];
    
    const marker = markers[Math.floor(Math.random() * markers.length)];
    marker();
  }

  generateFakeData() {
    // Generate realistic-looking fake data for honeypot responses
    const fakeData = [
      { users: Array(5).fill(null).map(() => ({ id: crypto.randomBytes(4).toString('hex'), name: 'User' })) },
      { token: crypto.randomBytes(32).toString('hex'), expires: Date.now() + 3600000 },
      { status: 'success', message: 'Operation completed' },
      { data: [], count: 0, page: 1 },
      { error: null, result: true }
    ];
    
    return fakeData[Math.floor(Math.random() * fakeData.length)];
  }

  generateMaintenancePage() {
    return `
      <!DOCTYPE html>
      <html>
      <head><title>Maintenance</title></head>
      <body>
        <h1>Scheduled Maintenance</h1>
        <p>We'll be back shortly.</p>
      </body>
      </html>
    `;
  }

  generateRateLimitPage() {
    return `
      <!DOCTYPE html>
      <html>
      <head><title>Too Many Requests</title></head>
      <body>
        <h1>Please slow down</h1>
        <p>You're making requests too quickly. Please wait a moment.</p>
      </body>
      </html>
    `;
  }

  generateGenericErrorPage() {
    return `
      <!DOCTYPE html>
      <html>
      <head><title>Error</title></head>
      <body>
        <h1>Something went wrong</h1>
        <p>Please try again later.</p>
      </body>
      </html>
    `;
  }

  shouldAllowThroughHoneypot(threatScore) {
    // Sometimes let attacks through to honeypot (for data collection)
    if (!this.currentProfile.behavior.honeyPotMode) {
      return false;
    }
    
    // Let through interesting attacks for honeypot
    if (threatScore > 30 && threatScore < 60 && Math.random() > 0.7) {
      return true;
    }
    
    return false;
  }

  mutateFingerprint() {
    // Change various characteristics to avoid fingerprinting
    this.rotateProfile();
    
    // Also mutate response variations
    this.responseVariations.blocked.sort(() => Math.random() - 0.5);
    this.responseVariations.challenge.sort(() => Math.random() - 0.5);
  }
}

module.exports = StealthMode;