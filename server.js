const express = require('express');
const path = require('path');
const QRCode = require('qrcode');
const VCard = require('vcard-creator').VCard;
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
require('dotenv').config();

const database = require('./database/mysql');
const SecurityLearningEngine = require('./security-learning');

const app = express();
const PORT = process.env.PORT || 3001;

// Initialize learning engine
const securityLearning = new SecurityLearningEngine();

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
}));

app.use(cors());

// Enhanced rate limiting with learning
const createAdaptiveRateLimit = (windowMs, maxRequests, keyPrefix = '') => {
    return rateLimit({
        windowMs,
        max: async (req) => {
            // Adaptive rate limiting based on learned behavior
            const analysis = await securityLearning.analyzeRequest(req);
            
            if (analysis.score > securityLearning.thresholds.blockScore) {
                await securityLearning.learnFromBlocked(analysis, 'Rate limit exceeded');
                return 0; // Block completely
            } else if (analysis.score > securityLearning.thresholds.suspiciousScore) {
                await securityLearning.learnFromSuspicious(analysis, 'Suspicious rate limit behavior');
                return Math.max(1, Math.floor(maxRequests * 0.3)); // Severely limit
            }
            
            return maxRequests;
        },
        keyGenerator: (req) => {
            return keyPrefix + securityLearning.getClientIP(req);
        },
        message: async (req, res) => {
            const analysis = await securityLearning.analyzeRequest(req);
            await securityLearning.learnFromBlocked(analysis, 'Rate limit violation');
            return { error: 'Rate limit exceeded. Please slow down.' };
        },
        standardHeaders: true,
        legacyHeaders: false,
    });
};

// Apply adaptive rate limiting
const generalLimiter = createAdaptiveRateLimit(15 * 60 * 1000, 50, 'general-');
const createCardLimiter = createAdaptiveRateLimit(60 * 60 * 1000, 5, 'create-');
const viewLimiter = createAdaptiveRateLimit(5 * 60 * 1000, 30, 'view-');

app.use(generalLimiter);

// Body parsing with adaptive limits
app.use(express.json({ 
    limit: '10kb',
    verify: async (req, res, buf, encoding) => {
        // Analyze request body for suspicious content
        const analysis = await securityLearning.analyzeRequest(req);
        if (analysis.score > securityLearning.thresholds.blockScore) {
            const error = new Error('Suspicious request blocked');
            error.status = 403;
            throw error;
        }
    }
}));

app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static('public'));

// Learning-enhanced security middleware
async function adaptiveSecurityCheck(req, res, next) {
    try {
        const analysis = await securityLearning.analyzeRequest(req);
        
        // Add analysis to request for later use
        req.securityAnalysis = analysis;
        
        if (analysis.score > securityLearning.thresholds.blockScore) {
            await securityLearning.learnFromBlocked(analysis, 'Security check failed');
            await database.logSecurityEvent(analysis.ip, 'blocked', {
                score: analysis.score,
                reasons: analysis.reasons,
                patterns: analysis.patterns
            }, true);
            
            return res.status(403).json({ 
                error: 'Access denied due to suspicious activity',
                requestId: analysis.timestamp.getTime()
            });
        }
        
        if (analysis.score > securityLearning.thresholds.suspiciousScore) {
            await securityLearning.learnFromSuspicious(analysis, 'Elevated suspicious score');
            await database.logSecurityEvent(analysis.ip, 'suspicious_activity', {
                score: analysis.score,
                reasons: analysis.reasons
            }, false);
        }
        
        next();
    } catch (error) {
        console.error('Security check error:', error);
        // Fail secure - block on error
        return res.status(500).json({ error: 'Security check failed' });
    }
}

// Utility functions
function generateSlug() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < 8; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

function generateCaptcha() {
    const num1 = Math.floor(Math.random() * 10) + 1;
    const num2 = Math.floor(Math.random() * 10) + 1;
    return {
        question: `${num1} + ${num2}`,
        answer: num1 + num2
    };
}

// Enhanced spam detection with learning
function containsSpam(text, analysis) {
    if (!text) return false;
    
    const lowerText = text.toLowerCase();
    const baseSpamWords = ['viagra', 'casino', 'porn', 'xxx', 'bitcoin', 'crypto'];
    
    // Check base spam words
    const hasBaseSpam = baseSpamWords.some(word => lowerText.includes(word));
    if (hasBaseSpam) {
        analysis.patterns.push(`spam:${baseSpamWords.find(word => lowerText.includes(word))}`);
        return true;
    }
    
    // Check learned spam patterns
    for (const [pattern, data] of securityLearning.learningData.queryPatterns) {
        if (lowerText.includes(pattern) && data.maliciousScore > 0.7) {
            analysis.patterns.push(`learned_spam:${pattern}`);
            return true;
        }
    }
    
    return false;
}

// Routes with learning integration
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/analytics', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'analytics.html'));
});

// Learning dashboard for Claude analysis
app.get('/api/learning/dashboard', adaptiveSecurityCheck, async (req, res) => {
    try {
        const learningData = await securityLearning.exportLearningData();
        res.json(learningData);
    } catch (error) {
        console.error('Error getting learning dashboard:', error);
        res.status(500).json({ error: 'Failed to get learning data' });
    }
});

// Export learning data for Claude analysis
app.get('/api/learning/export', adaptiveSecurityCheck, async (req, res) => {
    try {
        const exportData = await securityLearning.exportLearningData();
        
        // Create detailed report for Claude
        const claudeReport = {
            ...exportData,
            recommendations: await generateSecurityRecommendations(exportData),
            threats: await identifyEmergingThreats(exportData),
            patterns: await analyzeAttackPatterns(exportData)
        };
        
        res.json(claudeReport);
    } catch (error) {
        console.error('Error exporting learning data:', error);
        res.status(500).json({ error: 'Failed to export learning data' });
    }
});

// Generate CAPTCHA with learning
app.get('/api/captcha', adaptiveSecurityCheck, (req, res) => {
    const captcha = generateCaptcha();
    const sessionId = Date.now().toString();
    
    global.captchaSessions = global.captchaSessions || {};
    global.captchaSessions[sessionId] = captcha.answer;
    
    // Learn from CAPTCHA requests
    if (req.securityAnalysis.score > securityLearning.thresholds.suspiciousScore) {
        securityLearning.learnFromSuspicious(req.securityAnalysis, 'Suspicious CAPTCHA request');
    }
    
    res.json({ 
        question: captcha.question,
        sessionId: sessionId
    });
});

// Enhanced card creation with learning
app.post('/api/cards', createCardLimiter, adaptiveSecurityCheck, async (req, res) => {
    try {
        const analysis = req.securityAnalysis;
        const { 
            firstName, lastName, title, function: jobFunction, 
            company, address, email, phone, expiry,
            captchaAnswer, captchaSession, honeypot 
        } = req.body;

        // Enhanced honeypot check with learning
        if (honeypot && honeypot.trim() !== '') {
            analysis.patterns.push('honeypot_triggered');
            await securityLearning.learnFromBlocked(analysis, 'Honeypot triggered');
            return res.status(400).json({ error: 'Invalid submission' });
        }

        // CAPTCHA verification with learning
        global.captchaSessions = global.captchaSessions || {};
        const expectedAnswer = global.captchaSessions[captchaSession];
        
        if (!expectedAnswer || parseInt(captchaAnswer) !== expectedAnswer) {
            analysis.patterns.push('captcha_failed');
            await securityLearning.learnFromBlocked(analysis, 'CAPTCHA failed');
            return res.status(400).json({ error: 'Invalid CAPTCHA. Please try again.' });
        }

        delete global.captchaSessions[captchaSession];

        // Enhanced input validation with learning
        if (!firstName || !lastName) {
            return res.status(400).json({ error: 'First name and last name are required' });
        }

        if (firstName.length < 2 || lastName.length < 2 || firstName.length > 50 || lastName.length > 50) {
            analysis.patterns.push('invalid_name_length');
            await securityLearning.learnFromSuspicious(analysis, 'Invalid name length');
            return res.status(400).json({ error: 'Names must be 2-50 characters' });
        }

        // Enhanced spam detection with learning
        const fieldsToCheck = [firstName, lastName, title, jobFunction, company, address];
        if (fieldsToCheck.some(field => containsSpam(field, analysis))) {
            await securityLearning.learnFromBlocked(analysis, 'Spam content detected');
            return res.status(400).json({ error: 'Content not allowed' });
        }

        // Enhanced IP abuse detection with learning
        const ip = securityLearning.getClientIP(req);
        const recentCards = await database.getCardsByIP(ip, 24);
        const ipReputation = securityLearning.learningData.ipReputations.get(ip);
        
        let maxCards = 3;
        if (ipReputation && ipReputation.blocked > 0) {
            maxCards = 1; // Reduce limit for previously blocked IPs
        }
        
        if (recentCards.length >= maxCards) {
            analysis.patterns.push('ip_abuse');
            await securityLearning.learnFromBlocked(analysis, 'Too many cards from IP');
            return res.status(429).json({ error: 'Too many cards from your location. Please try again later.' });
        }

        const slug = generateSlug();
        const expiryHours = Math.min(parseInt(expiry) || 24, 168);

        const cardData = {
            slug,
            firstName: firstName.trim(),
            lastName: lastName.trim(),
            title: title ? title.trim() : '',
            function: jobFunction ? jobFunction.trim() : '',
            company: company ? company.trim() : '',
            address: address ? address.trim() : '',
            email: email ? email.trim().toLowerCase() : '',
            phone: phone ? phone.trim() : '',
            expiryHours,
            createdIP: ip
        };

        const cardId = await database.createCard(cardData);
        
        if (cardId) {
            // Learn from successful card creation
            await securityLearning.logAnalysis(analysis);
            
            const baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`;
            res.json({ 
                success: true, 
                slug, 
                url: `${baseUrl}/${slug}`,
                expiryHours 
            });
        } else {
            res.status(500).json({ error: 'Failed to create card' });
        }
    } catch (error) {
        console.error('Error creating card:', error);
        if (req.securityAnalysis) {
            await securityLearning.learnFromSuspicious(req.securityAnalysis, 'Server error during card creation');
        }
        res.status(500).json({ error: 'Server error' });
    }
});

// Enhanced card viewing with learning
app.get('/:slug', viewLimiter, adaptiveSecurityCheck, async (req, res) => {
    try {
        const { slug } = req.params;
        const analysis = req.securityAnalysis;
        
        // Validate slug format
        if (!/^[a-zA-Z0-9]{8}$/.test(slug)) {
            analysis.patterns.push('invalid_slug_format');
            await securityLearning.learnFromSuspicious(analysis, 'Invalid slug format');
            return res.status(404).send('Card not found');
        }

        const card = await database.getCard(slug);

        if (!card) {
            analysis.patterns.push('card_not_found');
            await securityLearning.learnFromSuspicious(analysis, 'Card not found');
            return res.status(404).send('Card not found or expired');
        }

        const ip = securityLearning.getClientIP(req);
        await database.logAnalytics(card.id, 'view', ip, req.get('User-Agent'), analysis.score > securityLearning.thresholds.suspiciousScore);
        
        res.sendFile(path.join(__dirname, 'public', 'card.html'));
    } catch (error) {
        console.error('Error getting card:', error);
        res.status(500).send('Server error');
    }
});

// API endpoints with learning
app.get('/api/cards/:slug', viewLimiter, adaptiveSecurityCheck, async (req, res) => {
    try {
        const { slug } = req.params;
        
        if (!/^[a-zA-Z0-9]{8}$/.test(slug)) {
            return res.status(404).json({ error: 'Invalid card format' });
        }

        const card = await database.getCard(slug);
        if (!card) {
            return res.status(404).json({ error: 'Card not found or expired' });
        }

        delete card.createdIP;
        res.json(card);
    } catch (error) {
        console.error('Error getting card data:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// QR and vCard endpoints with learning
app.get('/api/qr/:slug', viewLimiter, adaptiveSecurityCheck, async (req, res) => {
    try {
        const { slug } = req.params;
        
        if (!/^[a-zA-Z0-9]{8}$/.test(slug)) {
            return res.status(404).json({ error: 'Invalid card format' });
        }

        const card = await database.getCard(slug);
        if (!card) {
            return res.status(404).json({ error: 'Card not found or expired' });
        }

        const baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`;
        const cardUrl = `${baseUrl}/${slug}`;
        
        const qrCodeDataURL = await QRCode.toDataURL(cardUrl, {
            width: 300,
            margin: 2,
            color: { dark: '#000000', light: '#FFFFFF' }
        });

        const ip = securityLearning.getClientIP(req);
        await database.logAnalytics(card.id, 'qr_scan', ip, req.get('User-Agent'), req.securityAnalysis.score > securityLearning.thresholds.suspiciousScore);
        
        res.json({ qrCode: qrCodeDataURL });
    } catch (error) {
        console.error('Error generating QR code:', error);
        res.status(500).json({ error: 'Failed to generate QR code' });
    }
});

app.get('/api/vcard/:slug', viewLimiter, adaptiveSecurityCheck, async (req, res) => {
    try {
        const { slug } = req.params;
        
        if (!/^[a-zA-Z0-9]{8}$/.test(slug)) {
            return res.status(404).json({ error: 'Invalid card format' });
        }

        const card = await database.getCard(slug);
        if (!card) {
            return res.status(404).json({ error: 'Card not found or expired' });
        }

        const vCard = new VCard();
        vCard.addName(card.lastName, card.firstName);
        
        if (card.title) vCard.addJobtitle(card.title);
        if (card.company) vCard.addCompany(card.company);
        if (card.function) vCard.addRole(card.function);
        if (card.email) vCard.addEmail(card.email);
        if (card.phone) vCard.addPhoneNumber(card.phone);
        if (card.address) vCard.addAddress(card.address);

        const vCardString = vCard.toString();

        const ip = securityLearning.getClientIP(req);
        await database.logAnalytics(card.id, 'vcard_download', ip, req.get('User-Agent'), req.securityAnalysis.score > securityLearning.thresholds.suspiciousScore);

        res.setHeader('Content-Type', 'text/vcard');
        res.setHeader('Content-Disposition', `attachment; filename="${card.firstName}_${card.lastName}.vcf"`);
        res.send(vCardString);
    } catch (error) {
        console.error('Error generating vCard:', error);
        res.status(500).json({ error: 'Failed to generate vCard' });
    }
});

// Analytics with learning insights
app.get('/api/analytics', generalLimiter, adaptiveSecurityCheck, async (req, res) => {
    try {
        const analytics = await database.getAnalytics();
        const securityStats = await database.getSecurityStats();
        const learningInsights = await securityLearning.exportLearningData();
        
        const enhancedAnalytics = analytics.map(item => {
            const { createdIP, ...safeData } = item;
            return safeData;
        });
        
        res.json({
            cards: enhancedAnalytics,
            security: securityStats,
            learning: {
                adaptiveRules: learningInsights.adaptiveRules.length,
                learnedPatterns: Object.keys(learningInsights.userAgentPatterns).length + Object.keys(learningInsights.queryPatterns).length,
                totalRequests: learningInsights.statistics.totalRequests,
                totalBlocked: learningInsights.statistics.totalBlocked
            }
        });
    } catch (error) {
        console.error('Error getting analytics:', error);
        res.status(500).json({ error: 'Failed to get analytics' });
    }
});

// Health check with learning status
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        security: 'enhanced',
        learning: {
            active: true,
            adaptiveRules: securityLearning.learningData.adaptiveRules.length,
            learnedPatterns: securityLearning.learningData.userAgentPatterns.size + securityLearning.learningData.queryPatterns.size
        }
    });
});

// Learning management endpoints
app.post('/api/learning/manual-rule', adaptiveSecurityCheck, async (req, res) => {
    try {
        const { description, conditions, score } = req.body;
        
        const newRule = {
            id: crypto.createHash('md5').update(`manual:${Date.now()}`).digest('hex'),
            description,
            conditions,
            score,
            confidence: 1.0,
            created: new Date(),
            hits: 0,
            autoGenerated: false,
            manual: true
        };
        
        securityLearning.learningData.adaptiveRules.push(newRule);
        await securityLearning.saveAdaptiveRules();
        
        res.json({ success: true, ruleId: newRule.id });
    } catch (error) {
        console.error('Error creating manual rule:', error);
        res.status(500).json({ error: 'Failed to create rule' });
    }
});

// Helper functions for Claude analysis
async function generateSecurityRecommendations(learningData) {
    const recommendations = [];
    
    // Analyze attack patterns
    const totalRequests = learningData.statistics.totalRequests;
    const totalBlocked = learningData.statistics.totalBlocked;
    const blockRate = totalBlocked / Math.max(totalRequests, 1);
    
    if (blockRate > 0.1) {
        recommendations.push({
            priority: 'high',
            type: 'security',
            message: `High block rate detected (${Math.round(blockRate * 100)}%). Consider implementing additional preventive measures.`,
            data: { blockRate, totalRequests, totalBlocked }
        });
    }
    
    // Analyze adaptive rules effectiveness
    const ineffectiveRules = learningData.adaptiveRules.filter(rule => 
        rule.autoGenerated && (rule.hits || 0) === 0 && 
        (new Date() - new Date(rule.created)) > 7 * 24 * 60 * 60 * 1000
    );
    
    if (ineffectiveRules.length > 10) {
        recommendations.push({
            priority: 'medium',
            type: 'optimization',
            message: `${ineffectiveRules.length} adaptive rules have no hits. Consider rule pruning.`,
            data: { ineffectiveRules: ineffectiveRules.length }
        });
    }
    
    return recommendations;
}

async function identifyEmergingThreats(learningData) {
    const threats = [];
    
    // Identify rapidly evolving patterns
    for (const [pattern, data] of Object.entries(learningData.userAgentPatterns)) {
        if (data.maliciousScore > 0.5 && data.occurrences > 5) {
            const threat = {
                type: 'user_agent_pattern',
                pattern,
                severity: data.maliciousScore,
                frequency: data.occurrences,
                confidence: data.maliciousScore
            };
            threats.push(threat);
        }
    }
    
    for (const [pattern, data] of Object.entries(learningData.queryPatterns)) {
        if (data.maliciousScore > 0.5 && data.occurrences > 5) {
            const threat = {
                type: 'query_pattern',
                pattern,
                severity: data.maliciousScore,
                frequency: data.occurrences,
                confidence: data.maliciousScore
            };
            threats.push(threat);
        }
    }
    
    return threats.sort((a, b) => b.severity - a.severity).slice(0, 20);
}

async function analyzeAttackPatterns(learningData) {
    const patterns = {
        temporal: {},
        geographical: {},
        behavioral: {}
    };
    
    // Analyze temporal patterns
    for (const [timeKey, data] of Object.entries(learningData.temporalPatterns)) {
        const attackRate = data.attacks / Math.max(data.requests, 1);
        if (attackRate > 0.2) {
            patterns.temporal[timeKey] = {
                attackRate,
                totalRequests: data.requests,
                totalAttacks: data.attacks
            };
        }
    }
    
    return patterns;
}

// Error handler with learning
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    
    // Learn from errors that might indicate attacks
    if (req.securityAnalysis) {
        securityLearning.learnFromSuspicious(req.securityAnalysis, `Server error: ${error.message}`);
    }
    
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler with learning
app.use(async (req, res) => {
    const analysis = await securityLearning.analyzeRequest(req);
    
    if (analysis.score > securityLearning.thresholds.suspiciousScore) {
        await securityLearning.learnFromSuspicious(analysis, '404 with suspicious patterns');
    }
    
    res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully');
    await securityLearning.saveAdaptiveRules();
    await database.close();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('SIGINT received, shutting down gracefully');
    await securityLearning.saveAdaptiveRules();
    await database.close();
    process.exit(0);
});

// Start server
app.listen(PORT, () => {
    console.log(`🃏 Whispr Cards server running on port ${PORT}`);
    console.log(`🔒 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🧠 Learning Engine: Active with ${securityLearning.learningData.adaptiveRules.length} adaptive rules`);
    console.log(`📊 Access learning dashboard at: /api/learning/dashboard`);
});

module.exports = app;