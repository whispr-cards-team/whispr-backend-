// ===================================================================
// WHISPR CARDS - ADAPTIVE LEARNING SECURITY SYSTEM
// Real-time threat learning and adaptation
// ===================================================================

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

class SecurityLearningEngine {
    constructor() {
        this.learningData = {
            attackPatterns: new Map(),
            ipReputations: new Map(),
            userAgentPatterns: new Map(),
            queryPatterns: new Map(),
            temporalPatterns: new Map(),
            adaptiveRules: []
        };
        
        this.thresholds = {
            suspiciousScore: 50,
            blockScore: 75,
            autoLearnThreshold: 10,
            patternConfidence: 0.8
        };
        
        this.logPath = path.join(__dirname, 'logs');
        this.rulesPath = path.join(__dirname, 'adaptive-rules.json');
        
        this.initializeLearning();
    }

    async initializeLearning() {
        try {
            // Create logs directory
            await fs.mkdir(this.logPath, { recursive: true });
            
            // Load existing rules
            await this.loadAdaptiveRules();
            
            // Start periodic learning
            this.startLearningCycle();
            
            console.log('🧠 Security Learning Engine initialized');
        } catch (error) {
            console.error('Error initializing learning engine:', error);
        }
    }

    // ===================================================================
    // REAL-TIME THREAT ANALYSIS
    // ===================================================================

    async analyzeRequest(req) {
        const analysis = {
            ip: this.getClientIP(req),
            userAgent: req.get('User-Agent') || '',
            url: req.url,
            method: req.method,
            query: req.query,
            body: req.body,
            headers: req.headers,
            timestamp: new Date(),
            score: 0,
            reasons: [],
            patterns: []
        };

        // Analyze different threat vectors
        await this.analyzeIP(analysis);
        await this.analyzeUserAgent(analysis);
        await this.analyzeURL(analysis);
        await this.analyzeQuery(analysis);
        await this.analyzeTemporal(analysis);
        await this.analyzeAdaptiveRules(analysis);

        // Log the analysis
        await this.logAnalysis(analysis);

        return analysis;
    }

    async analyzeIP(analysis) {
        const ipReputation = this.learningData.ipReputations.get(analysis.ip) || {
            requests: 0,
            blocked: 0,
            suspicious: 0,
            patterns: [],
            firstSeen: new Date(),
            lastSeen: new Date()
        };

        ipReputation.requests++;
        ipReputation.lastSeen = new Date();

        // Calculate IP risk score
        const blockRate = ipReputation.blocked / Math.max(ipReputation.requests, 1);
        const suspiciousRate = ipReputation.suspicious / Math.max(ipReputation.requests, 1);
        
        if (blockRate > 0.5) {
            analysis.score += 30;
            analysis.reasons.push('High block rate IP');
        }
        
        if (suspiciousRate > 0.3) {
            analysis.score += 20;
            analysis.reasons.push('Suspicious activity history');
        }

        // Check for rapid requests (possible bot)
        const timeDiff = new Date() - ipReputation.lastSeen;
        if (timeDiff < 1000 && ipReputation.requests > 10) {
            analysis.score += 25;
            analysis.reasons.push('Rapid requests detected');
        }

        this.learningData.ipReputations.set(analysis.ip, ipReputation);
    }

    async analyzeUserAgent(analysis) {
        const ua = analysis.userAgent.toLowerCase();
        
        // Check learned patterns
        for (const [pattern, data] of this.learningData.userAgentPatterns) {
            if (ua.includes(pattern) && data.maliciousScore > this.thresholds.patternConfidence) {
                analysis.score += data.maliciousScore * 50;
                analysis.reasons.push(`Learned malicious UA pattern: ${pattern}`);
                analysis.patterns.push(`ua:${pattern}`);
            }
        }

        // Dynamic learning - analyze UA characteristics
        const uaFeatures = this.extractUserAgentFeatures(ua);
        for (const feature of uaFeatures) {
            const existing = this.learningData.userAgentPatterns.get(feature) || {
                occurrences: 0,
                maliciousOccurrences: 0,
                maliciousScore: 0,
                lastSeen: new Date()
            };
            
            existing.occurrences++;
            existing.lastSeen = new Date();
            this.learningData.userAgentPatterns.set(feature, existing);
        }
    }

    extractUserAgentFeatures(ua) {
        const features = [];
        
        // Extract meaningful patterns
        const words = ua.split(/[\s\-\(\)\/]+/).filter(w => w.length > 2);
        features.push(...words);
        
        // Version patterns
        const versions = ua.match(/\d+\.\d+/g) || [];
        features.push(...versions);
        
        // Suspicious combinations
        if (ua.includes('bot') && !ua.includes('google')) features.push('suspicious_bot');
        if (ua.includes('curl') || ua.includes('wget')) features.push('command_line_tool');
        if (ua.length < 10) features.push('minimal_ua');
        if (ua.length > 500) features.push('oversized_ua');
        
        return features;
    }

    async analyzeURL(analysis) {
        const url = analysis.url.toLowerCase();
        
        // Check for learned malicious patterns
        for (const [pattern, data] of this.learningData.queryPatterns) {
            if (url.includes(pattern) && data.maliciousScore > this.thresholds.patternConfidence) {
                analysis.score += data.maliciousScore * 40;
                analysis.reasons.push(`Learned malicious URL pattern: ${pattern}`);
                analysis.patterns.push(`url:${pattern}`);
            }
        }

        // Extract and learn URL features
        const urlFeatures = this.extractURLFeatures(url);
        for (const feature of urlFeatures) {
            const existing = this.learningData.queryPatterns.get(feature) || {
                occurrences: 0,
                maliciousOccurrences: 0,
                maliciousScore: 0,
                lastSeen: new Date()
            };
            
            existing.occurrences++;
            existing.lastSeen = new Date();
            this.learningData.queryPatterns.set(feature, existing);
        }
    }

    extractURLFeatures(url) {
        const features = [];
        
        // SQL injection patterns
        if (url.match(/union.*select|select.*from|drop.*table/i)) features.push('sql_injection');
        
        // XSS patterns
        if (url.match(/script|javascript|onerror|onload/i)) features.push('xss_attempt');
        
        // Path traversal
        if (url.match(/\.\.\/|\.\.\\|%2e%2e/i)) features.push('path_traversal');
        
        // Admin endpoints
        if (url.match(/admin|login|wp-admin|phpmyadmin/i)) features.push('admin_probe');
        
        // File access attempts
        if (url.match(/etc\/passwd|boot\.ini|win\.ini/i)) features.push('file_access');
        
        // Command injection
        if (url.match(/cmd|exec|system|shell/i)) features.push('command_injection');
        
        // Encoded characters
        if (url.match(/%[0-9a-f]{2}/i)) features.push('url_encoded');
        
        // Long URLs (potential buffer overflow)
        if (url.length > 1000) features.push('oversized_url');
        
        return features;
    }

    async analyzeQuery(analysis) {
        const queryString = JSON.stringify(analysis.query).toLowerCase();
        
        // Similar pattern matching as URL but for query parameters
        const queryFeatures = this.extractQueryFeatures(queryString);
        for (const feature of queryFeatures) {
            const existing = this.learningData.queryPatterns.get(feature) || {
                occurrences: 0,
                maliciousOccurrences: 0,
                maliciousScore: 0,
                lastSeen: new Date()
            };
            
            existing.occurrences++;
            this.learningData.queryPatterns.set(feature, existing);
        }
    }

    extractQueryFeatures(queryString) {
        const features = [];
        
        // Look for suspicious query patterns
        if (queryString.includes('union') || queryString.includes('select')) features.push('query_sql');
        if (queryString.includes('script') || queryString.includes('javascript')) features.push('query_xss');
        if (queryString.includes('..') || queryString.includes('etc')) features.push('query_traversal');
        if (queryString.match(/[<>'"]/)) features.push('query_special_chars');
        
        return features;
    }

    async analyzeTemporal(analysis) {
        const hour = analysis.timestamp.getHours();
        const dayOfWeek = analysis.timestamp.getDay();
        const timeKey = `${dayOfWeek}-${hour}`;
        
        const temporal = this.learningData.temporalPatterns.get(timeKey) || {
            requests: 0,
            attacks: 0,
            normalTraffic: 0
        };
        
        temporal.requests++;
        this.learningData.temporalPatterns.set(timeKey, temporal);
        
        // Check if this is an unusual time for traffic
        const attackRate = temporal.attacks / Math.max(temporal.requests, 1);
        if (attackRate > 0.3) {
            analysis.score += 15;
            analysis.reasons.push('High attack rate for this time period');
        }
    }

    async analyzeAdaptiveRules(analysis) {
        for (const rule of this.learningData.adaptiveRules) {
            if (this.evaluateRule(rule, analysis)) {
                analysis.score += rule.score;
                analysis.reasons.push(`Adaptive rule: ${rule.description}`);
                analysis.patterns.push(`rule:${rule.id}`);
                
                // Update rule usage statistics
                rule.hits = (rule.hits || 0) + 1;
                rule.lastHit = new Date();
            }
        }
    }

    evaluateRule(rule, analysis) {
        try {
            // Safely evaluate rule conditions
            return rule.conditions.every(condition => {
                switch (condition.type) {
                    case 'ip_contains':
                        return analysis.ip.includes(condition.value);
                    case 'ua_contains':
                        return analysis.userAgent.toLowerCase().includes(condition.value);
                    case 'url_contains':
                        return analysis.url.toLowerCase().includes(condition.value);
                    case 'method_equals':
                        return analysis.method === condition.value;
                    case 'score_greater':
                        return analysis.score > condition.value;
                    default:
                        return false;
                }
            });
        } catch (error) {
            console.error('Error evaluating rule:', error);
            return false;
        }
    }

    // ===================================================================
    // LEARNING & ADAPTATION
    // ===================================================================

    async learnFromBlocked(analysis, reason) {
        // Mark this request as malicious and learn from it
        analysis.malicious = true;
        analysis.blockReason = reason;
        
        // Update IP reputation
        const ipReputation = this.learningData.ipReputations.get(analysis.ip);
        if (ipReputation) {
            ipReputation.blocked++;
            ipReputation.suspicious++;
        }
        
        // Learn from patterns
        for (const pattern of analysis.patterns) {
            const [type, value] = pattern.split(':');
            const patternMap = this.getPatternMap(type);
            const existing = patternMap.get(value);
            
            if (existing) {
                existing.maliciousOccurrences++;
                existing.maliciousScore = existing.maliciousOccurrences / existing.occurrences;
            }
        }
        
        // Update temporal patterns
        const hour = analysis.timestamp.getHours();
        const dayOfWeek = analysis.timestamp.getDay();
        const timeKey = `${dayOfWeek}-${hour}`;
        const temporal = this.learningData.temporalPatterns.get(timeKey);
        if (temporal) {
            temporal.attacks++;
        }
        
        // Generate new adaptive rules if patterns emerge
        await this.generateAdaptiveRules(analysis);
        
        await this.logLearning(analysis, 'blocked');
    }

    async learnFromSuspicious(analysis, reason) {
        analysis.suspicious = true;
        analysis.suspiciousReason = reason;
        
        const ipReputation = this.learningData.ipReputations.get(analysis.ip);
        if (ipReputation) {
            ipReputation.suspicious++;
        }
        
        await this.logLearning(analysis, 'suspicious');
    }

    async generateAdaptiveRules(analysis) {
        // Generate rules based on repeated malicious patterns
        for (const pattern of analysis.patterns) {
            const [type, value] = pattern.split(':');
            const patternMap = this.getPatternMap(type);
            const patternData = patternMap.get(value);
            
            if (patternData && 
                patternData.maliciousOccurrences >= this.thresholds.autoLearnThreshold &&
                patternData.maliciousScore >= this.thresholds.patternConfidence) {
                
                const ruleId = crypto.createHash('md5').update(`${type}:${value}`).digest('hex');
                
                // Check if rule already exists
                const existingRule = this.learningData.adaptiveRules.find(r => r.id === ruleId);
                if (!existingRule) {
                    const newRule = {
                        id: ruleId,
                        description: `Auto-generated rule for ${type}: ${value}`,
                        conditions: [{
                            type: this.getConditionType(type),
                            value: value
                        }],
                        score: Math.round(patternData.maliciousScore * 50),
                        confidence: patternData.maliciousScore,
                        created: new Date(),
                        hits: 0,
                        autoGenerated: true
                    };
                    
                    this.learningData.adaptiveRules.push(newRule);
                    await this.saveAdaptiveRules();
                    
                    console.log(`🧠 Generated new adaptive rule: ${newRule.description}`);
                }
            }
        }
    }

    getPatternMap(type) {
        switch (type) {
            case 'ua': return this.learningData.userAgentPatterns;
            case 'url': return this.learningData.queryPatterns;
            case 'query': return this.learningData.queryPatterns;
            default: return new Map();
        }
    }

    getConditionType(type) {
        switch (type) {
            case 'ua': return 'ua_contains';
            case 'url': return 'url_contains';
            case 'query': return 'url_contains';
            default: return 'url_contains';
        }
    }

    // ===================================================================
    // LOGGING & PERSISTENCE
    // ===================================================================

    async logAnalysis(analysis) {
        const logEntry = {
            timestamp: analysis.timestamp,
            ip: analysis.ip,
            userAgent: analysis.userAgent,
            url: analysis.url,
            method: analysis.method,
            score: analysis.score,
            reasons: analysis.reasons,
            patterns: analysis.patterns,
            malicious: analysis.malicious || false,
            suspicious: analysis.suspicious || false
        };
        
        const logFile = path.join(this.logPath, `security-${new Date().toISOString().split('T')[0]}.log`);
        const logLine = JSON.stringify(logEntry) + '\n';
        
        try {
            await fs.appendFile(logFile, logLine);
        } catch (error) {
            console.error('Error writing security log:', error);
        }
    }

    async logLearning(analysis, action) {
        const learningEntry = {
            timestamp: new Date(),
            action: action,
            ip: analysis.ip,
            patterns: analysis.patterns,
            score: analysis.score,
            reasons: analysis.reasons,
            adaptiveRulesCount: this.learningData.adaptiveRules.length
        };
        
        const logFile = path.join(this.logPath, `learning-${new Date().toISOString().split('T')[0]}.log`);
        const logLine = JSON.stringify(learningEntry) + '\n';
        
        try {
            await fs.appendFile(logFile, logLine);
        } catch (error) {
            console.error('Error writing learning log:', error);
        }
    }

    async loadAdaptiveRules() {
        try {
            const data = await fs.readFile(this.rulesPath, 'utf8');
            const rules = JSON.parse(data);
            this.learningData.adaptiveRules = rules.adaptiveRules || [];
            console.log(`📚 Loaded ${this.learningData.adaptiveRules.length} adaptive rules`);
        } catch (error) {
            console.log('📚 No existing adaptive rules found, starting fresh');
            this.learningData.adaptiveRules = [];
        }
    }

    async saveAdaptiveRules() {
        try {
            const data = {
                lastUpdated: new Date(),
                adaptiveRules: this.learningData.adaptiveRules,
                statistics: {
                    totalRules: this.learningData.adaptiveRules.length,
                    autoGenerated: this.learningData.adaptiveRules.filter(r => r.autoGenerated).length,
                    totalHits: this.learningData.adaptiveRules.reduce((sum, r) => sum + (r.hits || 0), 0)
                }
            };
            
            await fs.writeFile(this.rulesPath, JSON.stringify(data, null, 2));
        } catch (error) {
            console.error('Error saving adaptive rules:', error);
        }
    }

    startLearningCycle() {
        // Run learning analysis every 5 minutes
        setInterval(async () => {
            await this.analyzeLearningData();
        }, 5 * 60 * 1000);
        
        // Save rules every hour
        setInterval(async () => {
            await this.saveAdaptiveRules();
        }, 60 * 60 * 1000);
        
        // Cleanup old data every day
        setInterval(async () => {
            await this.cleanupOldData();
        }, 24 * 60 * 60 * 1000);
    }

    async analyzeLearningData() {
        // Analyze patterns and generate insights
        console.log('🧠 Running learning cycle...');
        
        // Update pattern scores based on recent data
        await this.updatePatternScores();
        
        // Remove ineffective rules
        await this.pruneRules();
        
        // Generate learning report
        await this.generateLearningReport();
    }

    async updatePatternScores() {
        // Recalculate malicious scores for all patterns
        for (const [pattern, data] of this.learningData.userAgentPatterns) {
            if (data.occurrences > 0) {
                data.maliciousScore = data.maliciousOccurrences / data.occurrences;
            }
        }
        
        for (const [pattern, data] of this.learningData.queryPatterns) {
            if (data.occurrences > 0) {
                data.maliciousScore = data.maliciousOccurrences / data.occurrences;
            }
        }
    }

    async pruneRules() {
        // Remove rules that haven't been effective
        const cutoffDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days ago
        
        this.learningData.adaptiveRules = this.learningData.adaptiveRules.filter(rule => {
            // Keep rule if it's recent or has been hit
            return rule.created > cutoffDate || (rule.hits && rule.hits > 0);
        });
    }

    async generateLearningReport() {
        const report = {
            timestamp: new Date(),
            statistics: {
                totalIPs: this.learningData.ipReputations.size,
                maliciousIPs: Array.from(this.learningData.ipReputations.values())
                    .filter(ip => ip.blocked > ip.requests * 0.5).length,
                totalPatterns: this.learningData.userAgentPatterns.size + this.learningData.queryPatterns.size,
                adaptiveRules: this.learningData.adaptiveRules.length,
                topThreats: this.getTopThreats()
            }
        };
        
        const reportFile = path.join(this.logPath, `learning-report-${new Date().toISOString().split('T')[0]}.json`);
        
        try {
            await fs.writeFile(reportFile, JSON.stringify(report, null, 2));
            console.log(`📊 Learning report generated: ${report.statistics.adaptiveRules} active rules`);
        } catch (error) {
            console.error('Error generating learning report:', error);
        }
    }

    getTopThreats() {
        const threats = [];
        
        // Top malicious IPs
        for (const [ip, data] of this.learningData.ipReputations) {
            if (data.blocked > 5) {
                threats.push({
                    type: 'ip',
                    value: ip,
                    score: data.blocked,
                    blockRate: data.blocked / data.requests
                });
            }
        }
        
        // Top malicious patterns
        for (const [pattern, data] of this.learningData.userAgentPatterns) {
            if (data.maliciousScore > 0.8 && data.maliciousOccurrences > 3) {
                threats.push({
                    type: 'user_agent',
                    value: pattern,
                    score: data.maliciousScore,
                    occurrences: data.maliciousOccurrences
                });
            }
        }
        
        return threats.sort((a, b) => b.score - a.score).slice(0, 10);
    }

    async cleanupOldData() {
        console.log('🧹 Cleaning up old learning data...');
        
        const cutoffDate = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000); // 90 days
        
        // Clean old IP data
        for (const [ip, data] of this.learningData.ipReputations) {
            if (data.lastSeen < cutoffDate && data.blocked === 0) {
                this.learningData.ipReputations.delete(ip);
            }
        }
        
        // Clean old pattern data
        for (const [pattern, data] of this.learningData.userAgentPatterns) {
            if (data.lastSeen < cutoffDate && data.maliciousOccurrences === 0) {
                this.learningData.userAgentPatterns.delete(pattern);
            }
        }
        
        for (const [pattern, data] of this.learningData.queryPatterns) {
            if (data.lastSeen < cutoffDate && data.maliciousOccurrences === 0) {
                this.learningData.queryPatterns.delete(pattern);
            }
        }
    }

    // ===================================================================
    // UTILITY METHODS
    // ===================================================================

    getClientIP(req) {
        return req.headers['x-forwarded-for']?.split(',')[0] || 
               req.headers['x-real-ip'] || 
               req.connection.remoteAddress || 
               req.socket.remoteAddress || 
               req.ip || 
               'unknown';
    }

    // Export learning data for Claude analysis
    async exportLearningData() {
        return {
            timestamp: new Date(),
            ipReputations: Object.fromEntries(this.learningData.ipReputations),
            userAgentPatterns: Object.fromEntries(this.learningData.userAgentPatterns),
            queryPatterns: Object.fromEntries(this.learningData.queryPatterns),
            temporalPatterns: Object.fromEntries(this.learningData.temporalPatterns),
            adaptiveRules: this.learningData.adaptiveRules,
            statistics: {
                totalRequests: Array.from(this.learningData.ipReputations.values())
                    .reduce((sum, ip) => sum + ip.requests, 0),
                totalBlocked: Array.from(this.learningData.ipReputations.values())
                    .reduce((sum, ip) => sum + ip.blocked, 0),
                adaptiveRulesGenerated: this.learningData.adaptiveRules.filter(r => r.autoGenerated).length
            }
        };
    }
}

module.exports = SecurityLearningEngine;