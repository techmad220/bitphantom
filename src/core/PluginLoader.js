const fs = require('fs').promises;
const path = require('path');
const EventEmitter = require('events');
const { Logger } = require('../utils/logger');

class PluginLoader extends EventEmitter {
  constructor(config = {}) {
    super();
    this.plugins = new Map();
    this.config = config;
    this.logger = new Logger('PluginLoader');
    this.pluginPaths = [
      path.join(__dirname, '../plugins/core'),
      path.join(__dirname, '../plugins/custom'),
      path.join(__dirname, '../plugins/ai')
    ];
    this.loadOrder = [];
    this.hooks = {
      onRequest: [],
      onResponse: [],
      onError: [],
      onBlock: []
    };
  }

  async initialize() {
    this.logger.info('Initializing plugin loader...');
    
    // Load plugins from all paths
    for (const pluginPath of this.pluginPaths) {
      await this.loadPluginsFromPath(pluginPath);
    }
    
    // Sort plugins by priority
    this.sortPluginsByPriority();
    
    // Initialize plugins in order
    await this.initializePlugins();
    
    this.logger.info(`Loaded ${this.plugins.size} plugins successfully`);
    return this;
  }

  async loadPluginsFromPath(pluginPath) {
    try {
      const dirs = await fs.readdir(pluginPath);
      
      for (const dir of dirs) {
        const fullPath = path.join(pluginPath, dir);
        const stat = await fs.stat(fullPath);
        
        if (stat.isDirectory()) {
          await this.loadPlugin(fullPath);
        }
      }
    } catch (error) {
      this.logger.warn(`Could not load plugins from ${pluginPath}: ${error.message}`);
    }
  }

  async loadPlugin(pluginPath) {
    try {
      const indexPath = path.join(pluginPath, 'index.js');
      const configPath = path.join(pluginPath, 'config.json');
      
      // Check if plugin exists
      await fs.access(indexPath);
      
      // Load plugin module
      const PluginClass = require(indexPath);
      
      // Load plugin config if exists
      let pluginConfig = {};
      try {
        const configData = await fs.readFile(configPath, 'utf8');
        pluginConfig = JSON.parse(configData);
      } catch (e) {
        // Config file is optional
      }
      
      // Instantiate plugin
      const plugin = new PluginClass({
        ...pluginConfig,
        ...this.config[path.basename(pluginPath)]
      });
      
      // Validate plugin interface
      if (!this.validatePlugin(plugin)) {
        throw new Error(`Invalid plugin interface: ${plugin.name}`);
      }
      
      // Store plugin
      this.plugins.set(plugin.name, {
        instance: plugin,
        path: pluginPath,
        priority: plugin.priority || 100,
        enabled: plugin.enabled !== false
      });
      
      this.logger.info(`Loaded plugin: ${plugin.name} v${plugin.version}`);
      
    } catch (error) {
      this.logger.error(`Failed to load plugin from ${pluginPath}: ${error.message}`);
    }
  }

  validatePlugin(plugin) {
    // Check required properties
    if (!plugin.name || !plugin.version) {
      return false;
    }
    
    // Check required methods
    const requiredMethods = ['init', 'destroy'];
    for (const method of requiredMethods) {
      if (typeof plugin[method] !== 'function') {
        return false;
      }
    }
    
    return true;
  }

  sortPluginsByPriority() {
    this.loadOrder = Array.from(this.plugins.entries())
      .filter(([_, meta]) => meta.enabled)
      .sort((a, b) => a[1].priority - b[1].priority)
      .map(([name, _]) => name);
  }

  async initializePlugins() {
    for (const pluginName of this.loadOrder) {
      const { instance } = this.plugins.get(pluginName);
      
      try {
        await instance.init(this.createPluginContext(pluginName));
        
        // Register hooks
        this.registerPluginHooks(pluginName, instance);
        
        this.emit('plugin:initialized', pluginName);
      } catch (error) {
        this.logger.error(`Failed to initialize plugin ${pluginName}: ${error.message}`);
        this.plugins.get(pluginName).enabled = false;
      }
    }
  }

  createPluginContext(pluginName) {
    return {
      logger: new Logger(pluginName),
      config: this.config[pluginName] || {},
      emit: (event, data) => this.emit(`plugin:${pluginName}:${event}`, data),
      getPlugin: (name) => this.getPlugin(name),
      storage: this.createPluginStorage(pluginName)
    };
  }

  createPluginStorage(pluginName) {
    const storage = new Map();
    return {
      get: (key) => storage.get(key),
      set: (key, value) => storage.set(key, value),
      has: (key) => storage.has(key),
      delete: (key) => storage.delete(key),
      clear: () => storage.clear()
    };
  }

  registerPluginHooks(pluginName, plugin) {
    const hookMethods = ['onRequest', 'onResponse', 'onError', 'onBlock'];
    
    for (const hookName of hookMethods) {
      if (typeof plugin[hookName] === 'function') {
        this.hooks[hookName].push({
          name: pluginName,
          handler: plugin[hookName].bind(plugin),
          priority: plugin.priority || 100
        });
      }
    }
    
    // Sort hooks by priority
    for (const hookName of hookMethods) {
      this.hooks[hookName].sort((a, b) => a.priority - b.priority);
    }
  }

  async executeHook(hookName, ...args) {
    const hooks = this.hooks[hookName] || [];
    const results = [];
    
    for (const hook of hooks) {
      try {
        const plugin = this.plugins.get(hook.name);
        if (!plugin || !plugin.enabled) continue;
        
        const result = await hook.handler(...args);
        results.push(result);
        
        // If plugin returns BLOCK action, stop processing
        if (result && result.action === 'BLOCK') {
          this.emit('request:blocked', {
            plugin: hook.name,
            reason: result.reason,
            details: result
          });
          return { blocked: true, reason: result.reason, plugin: hook.name };
        }
      } catch (error) {
        this.logger.error(`Error in hook ${hookName} for plugin ${hook.name}: ${error.message}`);
        this.emit('plugin:error', { plugin: hook.name, error, hook: hookName });
      }
    }
    
    return { blocked: false, results };
  }

  getPlugin(name) {
    const plugin = this.plugins.get(name);
    return plugin ? plugin.instance : null;
  }

  async reloadPlugin(name) {
    const plugin = this.plugins.get(name);
    if (!plugin) {
      throw new Error(`Plugin ${name} not found`);
    }
    
    // Destroy old instance
    await plugin.instance.destroy();
    
    // Reload from disk
    delete require.cache[require.resolve(plugin.path)];
    await this.loadPlugin(plugin.path);
    
    // Re-sort and re-initialize
    this.sortPluginsByPriority();
    const newPlugin = this.plugins.get(name);
    if (newPlugin) {
      await newPlugin.instance.init(this.createPluginContext(name));
      this.registerPluginHooks(name, newPlugin.instance);
    }
    
    this.emit('plugin:reloaded', name);
  }

  async enablePlugin(name) {
    const plugin = this.plugins.get(name);
    if (plugin) {
      plugin.enabled = true;
      this.sortPluginsByPriority();
      this.emit('plugin:enabled', name);
    }
  }

  async disablePlugin(name) {
    const plugin = this.plugins.get(name);
    if (plugin) {
      plugin.enabled = false;
      this.sortPluginsByPriority();
      this.emit('plugin:disabled', name);
    }
  }

  async destroy() {
    // Destroy all plugins
    for (const [name, { instance }] of this.plugins) {
      try {
        await instance.destroy();
      } catch (error) {
        this.logger.error(`Error destroying plugin ${name}: ${error.message}`);
      }
    }
    
    this.plugins.clear();
    this.removeAllListeners();
  }

  getStatus() {
    const status = {
      totalPlugins: this.plugins.size,
      enabledPlugins: Array.from(this.plugins.values()).filter(p => p.enabled).length,
      plugins: {}
    };
    
    for (const [name, meta] of this.plugins) {
      status.plugins[name] = {
        enabled: meta.enabled,
        priority: meta.priority,
        version: meta.instance.version,
        path: meta.path
      };
    }
    
    return status;
  }
}

module.exports = PluginLoader;