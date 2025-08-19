module.exports = {
    apps: [{
        name: 'bitphantom-waf',
        script: './index.js',
        instances: 'max',
        exec_mode: 'cluster',
        env: {
            NODE_ENV: 'development',
            PORT: 3001
        },
        env_production: {
            NODE_ENV: 'production',
            PORT: 3001,
            WAF_MODE: 'block',
            ENABLE_AI: true
        },
        error_file: './logs/pm2-error.log',
        out_file: './logs/pm2-out.log',
        log_file: './logs/pm2-combined.log',
        time: true,
        max_memory_restart: '1G',
        min_uptime: '10s',
        max_restarts: 10,
        autorestart: true,
        watch: false,
        ignore_watch: ['node_modules', 'logs', '.git'],
        wait_ready: true,
        listen_timeout: 3000,
        kill_timeout: 5000
    }]
};