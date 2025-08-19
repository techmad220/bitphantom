const PluginBase = require('../core/plugin-base');
const path = require('path');

class PathTraversalPlugin extends PluginBase {
    constructor(waf) {
        super(waf);
        this.name = 'path-traversal-lfi-rfi';
        this.version = '1.0.0';
        this.description = 'Detects path traversal, LFI, and RFI attacks';
        this.priority = 9;
        
        // Attack patterns
        this.patterns = {
            // Path traversal patterns
            traversal: [
                /\.\./g,
                /\.\.%2f/gi,
                /\.\.%5c/gi,
                /\.\.\\/ 