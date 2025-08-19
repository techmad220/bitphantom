// Jest setup file for test environment configuration

// Set test environment
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error'; // Reduce noise in tests

// Mock console methods to reduce test output noise
global.console = {
    ...console,
    log: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    // Keep error for debugging
    error: console.error
};

// Set test timeout
jest.setTimeout(10000);

// Clean up after each test
afterEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
});

// Global teardown
afterAll(() => {
    // Close any open handles
    jest.clearAllTimers();
});