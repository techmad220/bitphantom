const PluginBase = require('../core/plugin-base');

class SQLInjectionPlugin extends PluginBase {
    constructor(waf) {
        super(waf);
        this.name = 'sql-injection-protection';
        this.version = '1.0.0';
        this.description = 'Detects and prevents SQL injection attacks';
        this.priority = 9;
        
        // SQL injection patterns
        this.patterns = [
            // Classic SQL injection
            /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|FROM|WHERE|ORDER BY|GROUP BY|HAVING)\b)/gi,
            
            // Union-based injection
            /UNION[\s\n]+SELECT/gi,
            /UNION[\s\n]+ALL[\s\n]+SELECT/gi,
            
            // Comment-based injection
            /--[\s\n]/g,
            /\/\*.*?\*\//g,
            /#.*$/gm,
            
            // Time-based blind injection
            /SLEEP\s*\(/gi,
            /BENCHMARK\s*\(/gi,
            /WAITFOR\s+DELAY/gi,
            /PG_SLEEP/gi,
            
            // Boolean-based blind injection
            /\bAND\b.*?=.*?\bAND\b/gi,
            /\bOR\b.*?=.*?\bOR\b/gi,
            /\b1\s*=\s*1\b/gi,
            /\b1\s*=\s*0\b/gi,
            /\'\s*OR\s*\'1\'\s*=\s*\'1/gi,
            
            // Stacked queries
            /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP)/gi,
            
            // System functions
            /\b(DATABASE|VERSION|USER|CURRENT_USER|SESSION_USER|@@VERSION|@@DATADIR)\s*\(/gi,
            
            // File operations
            /\b(LOAD_FILE|INTO OUTFILE|INTO DUMPFILE)\b/gi,
            
            // Common bypass techniques
            /\bCHAR\s*\(/gi,
            /\bCONCAT\s*\(/gi,
            /\bCONVERT\s*\(/gi,
            /\bCAST\s*\(/gi,
            
            // Hex encoding
            /0x[0-9a-fA-F]+/g,
            
            // Special characters that might indicate injection
            /['";\\]/g,
            
            // NoSQL injection patterns
            /\$ne|\$eq|\$gt|\$lt|\$gte|\$lte|\$in|\$nin/gi,
            /\$or|\$and|\$not|\$nor/gi,
            /\$where|\$regex|\$text|\$expr/gi,
            
            // LDAP injection
            /\(\s*\|\s*\(/gi,
            /\(\s*&\s*\(/gi,
            
            // XPath injection
            /\[\s*@/gi,
            /\[\s*position\s*\(\s*\)/gi
        ];

        // Context-specific dangerous keywords
        this.dangerousKeywords = {
            mysql: ['INFORMATION_SCHEMA', 'MYSQL', 'PERFORMANCE_SCHEMA'],
            postgresql: ['PG_CATALOG', 'PG_STAT', 'INFORMATION_SCHEMA'],
            mssql: ['SYSOBJECTS', 'SYSCOLUMNS', 'MASTER', 'TEMPDB'],
            oracle: ['ALL_TABLES', 'USER_TABLES', 'DBA_TABLES'],
            mongodb: ['$where', 'mapReduce', '$function'],
            general: ['XP_CMDSHELL', 'SP_', 'XP_', 'OLE']
        };

        // Severity mapping
        this.severityMap = {
            union_select: 10,
            stacked_query: 10,
            time_based: 9,
            boolean_blind: 8,
            file_operation: 10,
            system_function: 8,
            comment: 6,
            special_char: 4,
            nosql: 9,
            keyword: 7
        };
    }

    async analyze(request, analysis) {
        const threats = [];
        
        // Check all input vectors
        const inputVectors = [
            { data: this.stringifyData(request.query), type: 'query' },
            { data: this.stringifyData(request.body), type: 'body' },
            { data: request.path || '', type: 'path' },
            { data: this.getHeaderValues(request.headers), type: 'headers' }
        ];

        for (const vector of inputVectors) {
            if (!vector.data) continue;
            
            const sqlThreats = this.scanForSQLInjection(vector.data, vector.type);
            threats.push(...sqlThreats);
        }

        // Check for suspicious parameter names
        const suspiciousParams = this.checkParameterNames(request);
        threats.push(...suspiciousParams);

        // Check for encoded payloads
        const encodedThreats = this.checkEncodedPayloads(inputVectors);
        threats.push(...encodedThreats);

        this.updateStats('analyzed');

        if (threats.length > 0) {
            this.updateStats('threats');
            
            const maxSeverity = Math.max(...threats.map(t => t.severity));
            const confidence = this.calculateConfidence(threats);
            
            this.log('warn', 'SQL injection threat detected', {
                ip: analysis.ip,
                path: analysis.path,
                threats: threats.length,
                maxSeverity,
                confidence
            });

            return {
                threat: {
                    type: 'sql_injection',
                    severity: maxSeverity,
                    details: {
                        vectors: threats,
                        confidence,
                        recommendation: this.getRecommendation(threats)
                    }
                }
            };
        }

        return { threat: null };
    }

    scanForSQLInjection(input, inputType) {
        const threats = [];
        const normalizedInput = this.normalizeInput(input);
        
        // Check against SQL patterns
        for (const pattern of this.patterns) {
            const matches = normalizedInput.match(pattern);
            if (matches) {
                const threatType = this.identifyThreatType(pattern);
                threats.push({
                    pattern: pattern.source,
                    location: inputType,
                    severity: this.severityMap[threatType] || 5,
                    type: threatType,
                    matched: matches[0],
                    confidence: this.getPatternConfidence(pattern, matches)
                });
            }
            pattern.lastIndex = 0;
        }

        // Check for dangerous keywords
        for (const [db, keywords] of Object.entries(this.dangerousKeywords)) {
            for (const keyword of keywords) {
                if (normalizedInput.toUpperCase().includes(keyword)) {
                    threats.push({
                        pattern: `keyword:${keyword}`,
                        location: inputType,
                        severity: this.severityMap.keyword,
                        type: 'dangerous_keyword',
                        database: db,
                        matched: keyword
                    });
                }
            }
        }

        // Check for suspicious patterns
        threats.push(...this.checkSuspiciousPatterns(normalizedInput, inputType));

        return threats;
    }

    checkSuspiciousPatterns(input, inputType) {
        const threats = [];
        
        // Check for multiple SQL keywords in sequence
        const sqlKeywords = ['SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE'];
        let keywordCount = 0;
        for (const keyword of sqlKeywords) {
            if (input.toUpperCase().includes(keyword)) {
                keywordCount++;
            }
        }
        
        if (keywordCount >= 3) {
            threats.push({
                pattern: 'multiple_sql_keywords',
                location: inputType,
                severity: 8,
                type: 'suspicious_pattern',
                matched: `${keywordCount} SQL keywords detected`
            });
        }

        // Check for base64 encoded SQL
        const base64Pattern = /^[A-Za-z0-9+/]+=*$/;
        if (base64Pattern.test(input) && input.length > 20) {
            try {
                const decoded = Buffer.from(input, 'base64').toString();
                const decodedThreats = this.scanForSQLInjection(decoded, `${inputType}:base64`);
                threats.push(...decodedThreats);
            } catch (e) {
                // Not valid base64
            }
        }

        // Check for URL encoded SQL
        if (input.includes('%')) {
            try {
                const decoded = decodeURIComponent(input);
                if (decoded !== input) {
                    const decodedThreats = this.scanForSQLInjection(decoded, `${inputType}:urlencoded`);
                    threats.push(...decodedThreats);
                }
            } catch (e) {
                // Invalid URL encoding
            }
        }

        return threats;
    }

    checkParameterNames(request) {
        const threats = [];
        const suspiciousNames = ['id', 'user_id', 'userid', 'username', 'password', 'admin', 'login', 'token'];
        
        // Check query parameters
        if (request.query) {
            for (const param of Object.keys(request.query)) {
                if (suspiciousNames.includes(param.toLowerCase())) {
                    const value = request.query[param];
                    if (this.isSuspiciousValue(value)) {
                        threats.push({
                            pattern: 'suspicious_parameter',
                            location: `query:${param}`,
                            severity: 6,
                            type: 'suspicious_parameter',
                            matched: value
                        });
                    }
                }
            }
        }

        return threats;
    }

    checkEncodedPayloads(inputVectors) {
        const threats = [];
        
        for (const vector of inputVectors) {
            if (!vector.data) continue;
            
            // Check for double encoding
            const doubleDecoded = this.doubleUrlDecode(vector.data);
            if (doubleDecoded !== vector.data) {
                const doubleThreats = this.scanForSQLInjection(doubleDecoded, `${vector.type}:double_encoded`);
                threats.push(...doubleThreats);
            }
            
            // Check for unicode encoding
            const unicodeDecoded = this.decodeUnicode(vector.data);
            if (unicodeDecoded !== vector.data) {
                const unicodeThreats = this.scanForSQLInjection(unicodeDecoded, `${vector.type}:unicode`);
                threats.push(...unicodeThreats);
            }
        }
        
        return threats;
    }

    normalizeInput(input) {
        if (typeof input !== 'string') {
            input = String(input);
        }
        
        // Remove extra whitespace
        input = input.replace(/\s+/g, ' ');
        
        // Normalize quotes
        input = input.replace(/[''`´]/g, "'");
        
        return input;
    }

    stringifyData(data) {
        if (!data) return '';
        if (typeof data === 'string') return data;
        
        try {
            return JSON.stringify(data);
        } catch (e) {
            return String(data);
        }
    }

    getHeaderValues(headers) {
        if (!headers) return '';
        
        const relevantHeaders = ['user-agent', 'referer', 'x-forwarded-for', 'cookie'];
        const values = [];
        
        for (const header of relevantHeaders) {
            if (headers[header]) {
                values.push(headers[header]);
            }
        }
        
        return values.join(' ');
    }

    identifyThreatType(pattern) {
        const source = pattern.source.toUpperCase();
        
        if (source.includes('UNION') && source.includes('SELECT')) return 'union_select';
        if (source.includes('SLEEP') || source.includes('BENCHMARK') || source.includes('WAITFOR')) return 'time_based';
        if (source.includes('LOAD_FILE') || source.includes('OUTFILE')) return 'file_operation';
        if (source.includes('--') || source.includes('/*') || source.includes('#')) return 'comment';
        if (source.includes(';') && (source.includes('SELECT') || source.includes('INSERT'))) return 'stacked_query';
        if (source.includes('1=1') || source.includes('OR')) return 'boolean_blind';
        if (source.includes('DATABASE') || source.includes('VERSION')) return 'system_function';
        if (source.includes('$') && (source.includes('NE') || source.includes('OR'))) return 'nosql';
        if (source.includes("'") || source.includes('"')) return 'special_char';
        
        return 'unknown';
    }

    getPatternConfidence(pattern, matches) {
        // Higher confidence for more specific patterns
        const source = pattern.source;
        
        if (source.includes('UNION') && source.includes('SELECT')) return 0.95;
        if (source.includes('SLEEP') || source.includes('BENCHMARK')) return 0.9;
        if (source.includes('--') && matches[0].length > 3) return 0.7;
        if (source.includes("'") && matches.length > 2) return 0.6;
        
        return 0.5;
    }

    isSuspiciousValue(value) {
        if (!value) return false;
        
        const str = String(value);
        
        // Check for SQL keywords
        if (/\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b/i.test(str)) return true;
        
        // Check for special characters commonly used in injection
        if ((str.match(/['"`;]/g) || []).length > 2) return true;
        
        // Check for common injection patterns
        if (/\d+\s*(=|>|<)\s*\d+/.test(str)) return true;
        if (/\'\s*OR\s*\'/.test(str)) return true;
        
        return false;
    }

    doubleUrlDecode(input) {
        try {
            const once = decodeURIComponent(input);
            const twice = decodeURIComponent(once);
            return twice;
        } catch (e) {
            return input;
        }
    }

    decodeUnicode(input) {
        return input.replace(/\\u([0-9a-fA-F]{4})/g, (match, code) => {
            return String.fromCharCode(parseInt(code, 16));
        });
    }

    calculateConfidence(threats) {
        if (threats.length === 0) return 0;
        
        const weights = {
            union_select: 0.95,
            stacked_query: 0.9,
            time_based: 0.85,
            file_operation: 0.9,
            boolean_blind: 0.7,
            system_function: 0.75,
            dangerous_keyword: 0.6,
            suspicious_pattern: 0.5,
            comment: 0.4,
            special_char: 0.3
        };
        
        let totalWeight = 0;
        let weightedSum = 0;
        
        for (const threat of threats) {
            const weight = weights[threat.type] || 0.5;
            totalWeight += weight;
            weightedSum += weight * (threat.confidence || 0.5);
        }
        
        return totalWeight > 0 ? Math.min(0.99, weightedSum / totalWeight) : 0.5;
    }

    getRecommendation(threats) {
        const recommendations = [];
        
        const threatTypes = [...new Set(threats.map(t => t.type))];
        
        if (threatTypes.includes('union_select') || threatTypes.includes('stacked_query')) {
            recommendations.push('Use parameterized queries or prepared statements');
        }
        
        if (threatTypes.includes('special_char')) {
            recommendations.push('Implement proper input validation and escaping');
        }
        
        if (threatTypes.includes('dangerous_keyword')) {
            recommendations.push('Review database permissions and use least privilege principle');
        }
        
        if (threatTypes.includes('nosql')) {
            recommendations.push('Sanitize NoSQL queries and avoid string concatenation');
        }
        
        return recommendations.length > 0 ? recommendations : ['General input validation and parameterized queries recommended'];
    }
}

module.exports = SQLInjectionPlugin;