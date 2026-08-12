const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==================== STORAGE ====================
const userSessions = new Map();
const verifiedUsers = new Set();

// ==================== HELPER FUNCTIONS ====================

function getBrowserInfo(req) {
    const userAgent = req.headers['user-agent'] || '';
    let browser = 'Unknown';
    let os = 'Unknown';
    
    if (userAgent.includes('Chrome') && !userAgent.includes('Edg')) browser = 'Chrome';
    else if (userAgent.includes('Firefox')) browser = 'Firefox';
    else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) browser = 'Safari';
    else if (userAgent.includes('Edg')) browser = 'Edge';
    else if (userAgent.includes('Opera')) browser = 'Opera';
    
    if (userAgent.includes('Windows')) os = 'Windows';
    else if (userAgent.includes('Mac OS')) os = 'MacOS';
    else if (userAgent.includes('Linux')) os = 'Linux';
    else if (userAgent.includes('Android')) os = 'Android';
    else if (userAgent.includes('iOS')) os = 'iOS';
    
    return { browser: browser, os: os };
}

function parseUserData(initData) {
    try {
        const params = new URLSearchParams(initData);
        const userJson = params.get('user');
        if (userJson) {
            return JSON.parse(decodeURIComponent(userJson));
        }
        return null;
    } catch (error) {
        return null;
    }
}

function createWebhookResponse(userId, status, title, message, errorType, deviceInfo) {
    var webhookData = {
        userId: userId,
        status: status,
        title: title,
        message: message,
        timestamp: new Date().toISOString()
    };
    if (errorType) webhookData.errorType = errorType;
    if (deviceInfo) webhookData.deviceInfo = deviceInfo;
    console.log('Webhook Data:', JSON.stringify(webhookData, null, 2));
    return webhookData;
}

// ==================== API ROUTES ====================

// 1. Init Verification
app.post('/api/init-verification', async function(req, res) {
    try {
        var initData = req.body.initData;
        var botHash = req.body.botHash;
        var bot = req.body.bot;
        var browserInfo = getBrowserInfo(req);
        
        console.log('Init Verification Request:', { botHash: botHash, bot: bot, hasInitData: !!initData });
        
        if (!initData) {
            var webhookData = createWebhookResponse(
                'unknown',
                'error',
                'Missing Data',
                'No verification data found',
                'MISSING_INIT_DATA',
                browserInfo
            );
            return res.status(400).json({
                success: false,
                error: 'MISSING_INIT_DATA',
                title: 'Missing Data',
                message: 'Missing required data.',
                webhook: webhookData
            });
        }
        
        var user = parseUserData(initData);
        if (!user || !user.id) {
            var webhookData = createWebhookResponse(
                'unknown',
                'error',
                'Invalid User',
                'User data could not be parsed',
                'INVALID_USER_DATA',
                browserInfo
            );
            return res.status(400).json({
                success: false,
                error: 'INVALID_USER_DATA',
                title: 'Invalid User',
                message: 'Invalid user data.',
                webhook: webhookData
            });
        }
        
        console.log('User:', user.id, user.first_name);
        
        var userIdStr = user.id.toString();
        var isVerified = verifiedUsers.has(userIdStr);
        
        console.log('User ' + userIdStr + ' verified status: ' + isVerified);
        
        // =============================================
        // ✅ CHECK: If user is already verified
        // =============================================
        if (isVerified) {
            console.log('User already verified, sending info response');
            
            var webhookData = createWebhookResponse(
                userIdStr,
                'info',
                'Already Verified',
                'You are already verified in our system.',
                null,
                browserInfo
            );
            
            return res.status(200).json({
                success: true,
                status: 'already_verified',
                user: user,
                title: 'Already Verified',
                message: 'You are already verified in our system.',
                webhook: webhookData
            });
        }
        
        // =============================================
        // ✅ NEW USER - Create session
        // =============================================
        var sessionId = crypto.randomBytes(32).toString('hex');
        
        userSessions.set(sessionId, {
            userId: user.id,
            username: user.username || '',
            firstName: user.first_name || '',
            lastName: user.last_name || '',
            status: 'pending',
            createdAt: Date.now(),
            botHash: botHash || null,
            bot: bot || null,
            browser: browserInfo.browser,
            os: browserInfo.os
        });
        
        console.log('Session created:', sessionId);
        
        // Auto-verify after 5 seconds
        setTimeout(function() {
            if (userSessions.has(sessionId)) {
                var session = userSessions.get(sessionId);
                session.status = 'verified';
                userSessions.set(sessionId, session);
                verifiedUsers.add(userIdStr);
                
                var webhookData = createWebhookResponse(
                    userIdStr,
                    'success',
                    'Verification Complete',
                    'Device verified successfully!',
                    null,
                    browserInfo
                );
                console.log('User verified:', userIdStr);
                console.log('Webhook Response:', JSON.stringify(webhookData, null, 2));
            }
        }, 5000);
        
        var webhookData = createWebhookResponse(
            user.id,
            'pending',
            'Verification Started',
            'Your device verification has been started.',
            null,
            browserInfo
        );
        
        res.json({
            success: true,
            status: 'pending',
            sessionId: sessionId,
            userId: user.id,
            title: 'Verification Started',
            message: 'Your device verification has been started.',
            deviceInfo: {
                browser: browserInfo.browser,
                os: browserInfo.os
            },
            webhook: webhookData
        });
        
    } catch (error) {
        console.error('Init verification error:', error);
        var webhookData = createWebhookResponse(
            'unknown',
            'error',
            'Server Error',
            'Internal server error occurred',
            'INTERNAL_SERVER_ERROR',
            getBrowserInfo(req)
        );
        res.status(500).json({
            success: false,
            error: 'INTERNAL_SERVER_ERROR',
            title: 'Server Error',
            message: 'Server error. Please try again later.',
            webhook: webhookData
        });
    }
});

// 2. Check Status
app.get('/api/check-status/:sessionId', async function(req, res) {
    try {
        var sessionId = req.params.sessionId;
        
        console.log('Check Status:', sessionId);
        
        if (!sessionId || !userSessions.has(sessionId)) {
            return res.status(404).json({
                success: false,
                error: 'SESSION_NOT_FOUND',
                title: 'Session Not Found',
                message: 'Session not found.'
            });
        }
        
        var session = userSessions.get(sessionId);
        var userId = session.userId.toString();
        
        if (verifiedUsers.has(userId)) {
            session.status = 'verified';
            userSessions.set(sessionId, session);
        }
        
        res.json({
            success: true,
            status: session.status,
            userId: session.userId,
            username: session.username,
            firstName: session.firstName,
            lastName: session.lastName,
            isVerified: verifiedUsers.has(userId),
            title: 'Status Check',
            message: 'Verification status: ' + session.status,
            deviceInfo: {
                browser: session.browser,
                os: session.os
            }
        });
        
    } catch (error) {
        console.error('Check status error:', error);
        res.status(500).json({
            success: false,
            error: 'INTERNAL_SERVER_ERROR',
            title: 'Server Error',
            message: 'Server error.'
        });
    }
});

// 3. Complete Verification
app.post('/api/complete-verification', async function(req, res) {
    try {
        var userId = req.body.userId;
        var verified = req.body.verified;
        var browserInfo = getBrowserInfo(req);
        
        console.log('Complete Verification:', userId, verified);
        
        if (!userId) {
            return res.status(400).json({
                success: false,
                error: 'MISSING_USER_ID',
                title: 'Missing User ID',
                message: 'User ID required.'
            });
        }
        
        if (verified) {
            verifiedUsers.add(userId.toString());
            
            for (var [sid, session] of userSessions) {
                if (session.userId.toString() === userId.toString()) {
                    session.status = 'verified';
                    userSessions.set(sid, session);
                }
            }
            
            var webhookData = createWebhookResponse(
                userId,
                'success',
                'Verification Complete',
                'Device verified successfully!',
                null,
                browserInfo
            );
            
            res.json({
                success: true,
                status: 'success',
                verified: true,
                userId: userId,
                title: 'Verification Complete',
                message: 'Your device has been verified successfully!',
                webhook: webhookData
            });
        } else {
            var webhookData = createWebhookResponse(
                userId,
                'info',
                'Verification Cancelled',
                'User cancelled verification',
                null,
                browserInfo
            );
            res.json({
                success: true,
                status: 'cancelled',
                verified: false,
                userId: userId,
                title: 'Verification Cancelled',
                message: 'Verification cancelled.',
                webhook: webhookData
            });
        }
        
    } catch (error) {
        console.error('Complete verification error:', error);
        res.status(500).json({
            success: false,
            error: 'INTERNAL_SERVER_ERROR',
            title: 'Server Error',
            message: 'Server error.'
        });
    }
});

// 4. User Status
app.get('/api/user-status/:userId', async function(req, res) {
    try {
        var userId = req.params.userId;
        var isVerified = verifiedUsers.has(userId);
        
        res.json({
            success: true,
            userId: userId,
            isVerified: isVerified,
            status: isVerified ? 'verified' : 'not_verified',
            title: 'User Status',
            message: isVerified ? 'User is verified' : 'User is not verified'
        });
        
    } catch (error) {
        console.error('User status error:', error);
        res.status(500).json({
            success: false,
            error: 'INTERNAL_SERVER_ERROR',
            title: 'Server Error',
            message: 'Server error.'
        });
    }
});

// 5. Bot Register
app.get('/api/bot_register', function(req, res) {
    var botHash = req.query.botHash;
    var bot = req.query.bot;
    var webhook_url = req.query.webhook_url;
    var bot_token = req.query.bot_token;
    console.log('Bot Register:', { botHash: botHash, bot: bot, webhook_url: webhook_url, bot_token: bot_token ? '***' : 'missing' });
    
    res.json({
        success: true,
        message: 'Bot registered successfully',
        botHash: botHash,
        bot: bot,
        webhook_url: webhook_url
    });
});

// 6. Health Check
app.get('/api/health', function(req, res) {
    res.json({
        success: true,
        status: 'healthy',
        timestamp: new Date().toISOString(),
        verifiedCount: verifiedUsers.size,
        sessionCount: userSessions.size
    });
});

module.exports = app;
