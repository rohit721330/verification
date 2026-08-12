const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();

// CORS সেট করুন
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
    
    return { browser, os };
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

function createWebhookResponse(userId, status, title, message, errorType = null, deviceInfo = null) {
    const webhookData = {
        userId: userId,
        status: status,
        title: title,
        message: message,
        timestamp: new Date().toISOString()
    };
    if (errorType) webhookData.errorType = errorType;
    if (deviceInfo) webhookData.deviceInfo = deviceInfo;
    console.log('📡 Webhook Data:', JSON.stringify(webhookData, null, 2));
    return webhookData;
}

// ==================== API ROUTES (সঠিকভাবে /api/ দিয়ে) ====================

// 1. Init Verification
app.post('/api/init-verification', async (req, res) => {
    try {
        const { initData, botHash, bot } = req.body;
        const browserInfo = getBrowserInfo(req);
        
        console.log('📥 Init Verification Request:', { botHash, bot, hasInitData: !!initData });
        
        if (!initData) {
            const webhookData = createWebhookResponse(
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
        
        const user = parseUserData(initData);
        if (!user || !user.id) {
            const webhookData = createWebhookResponse(
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
        
        console.log('👤 User:', user.id, user.first_name);
        
        const userIdStr = user.id.toString();
        const isVerified = verifiedUsers.has(userIdStr);
        
        if (isVerified) {
            const webhookData = createWebhookResponse(
                userIdStr,
                'info',
                'Already Verified',
                'User is already verified in the system',
                null,
                browserInfo
            );
            return res.json({
                success: true,
                status: 'already_verified',
                user: user,
                title: 'Already Verified',
                message: 'You are already verified.',
                webhook: webhookData
            });
        }
        
        const sessionId = crypto.randomBytes(32).toString('hex');
        
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
        
        console.log('✅ Session created:', sessionId);
        
        // Auto-verify after 5 seconds (demo)
        setTimeout(async () => {
            if (userSessions.has(sessionId)) {
                const session = userSessions.get(sessionId);
                session.status = 'verified';
                userSessions.set(sessionId, session);
                verifiedUsers.add(userIdStr);
                
                const webhookData = createWebhookResponse(
                    userIdStr,
                    'success',
                    'Verification Complete',
                    'Device verified successfully!',
                    null,
                    browserInfo
                );
                console.log('✅ User verified:', userIdStr);
                console.log('📡 Webhook Response:', JSON.stringify(webhookData, null, 2));
            }
        }, 5000);
        
        const webhookData = createWebhookResponse(
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
        const webhookData = createWebhookResponse(
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
app.get('/api/check-status/:sessionId', async (req, res) => {
    try {
        const { sessionId } = req.params;
        
        console.log('📊 Check Status:', sessionId);
        
        if (!sessionId || !userSessions.has(sessionId)) {
            return res.status(404).json({
                success: false,
                error: 'SESSION_NOT_FOUND',
                title: 'Session Not Found',
                message: 'Session not found.'
            });
        }
        
        const session = userSessions.get(sessionId);
        const userId = session.userId.toString();
        
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
            message: `Verification status: ${session.status}`,
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
app.post('/api/complete-verification', async (req, res) => {
    try {
        const { userId, verified } = req.body;
        const browserInfo = getBrowserInfo(req);
        
        console.log('✅ Complete Verification:', userId, verified);
        
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
            
            for (const [sid, session] of userSessions) {
                if (session.userId.toString() === userId.toString()) {
                    session.status = 'verified';
                    userSessions.set(sid, session);
                }
            }
            
            const webhookData = createWebhookResponse(
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
            const webhookData = createWebhookResponse(
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
app.get('/api/user-status/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const isVerified = verifiedUsers.has(userId);
        
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
app.get('/api/bot_register', (req, res) => {
    const { botHash, bot, webhook_url, bot_token } = req.query;
    console.log('📝 Bot Register:', { botHash, bot, webhook_url, bot_token: bot_token ? '***' : 'missing' });
    
    res.json({
        success: true,
        message: 'Bot registered successfully',
        botHash: botHash,
        bot: bot,
        webhook_url: webhook_url
    });
});

// 6. Health Check
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        status: 'healthy',
        timestamp: new Date().toISOString(),
        verifiedCount: verifiedUsers.size,
        sessionCount: userSessions.size
    });
});

module.exports = app;
