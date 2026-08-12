const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const userSessions = new Map();
const verifiedUsers = new Set();

// ==================== HELPER FUNCTIONS ====================

function generateDeviceFingerprint(req) {
    const userAgent = req.headers['user-agent'] || '';
    const acceptLanguage = req.headers['accept-language'] || '';
    const acceptEncoding = req.headers['accept-encoding'] || '';
    const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || '';
    
    return crypto
        .createHash('sha256')
        .update(`${userAgent}|${acceptLanguage}|${acceptEncoding}|${ip}`)
        .digest('hex');
}

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

// ==================== SEND WEBHOOK TO BOT ====================

async function sendWebhookToBot(userId, status, title, message, errorType = null, deviceInfo = null) {
    try {
        // Get bot token from environment or use default
        const botToken = process.env.BOT_TOKEN;
        if (!botToken) {
            console.log('⚠️ No bot token available');
            return;
        }
        
        const webhookData = {
            userId: userId,
            status: status,
            title: title,
            message: message,
            timestamp: new Date().toISOString()
        };
        
        if (errorType) webhookData.errorType = errorType;
        if (deviceInfo) webhookData.deviceInfo = deviceInfo;
        
        console.log('📡 Sending Webhook:', webhookData);
        
        // Send to bot's webhook handler
        const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
        
        let statusEmoji = 'ℹ️';
        let statusText = 'INFO';
        
        if (status === 'success') {
            statusEmoji = '✅';
            statusText = 'SUCCESS';
        } else if (status === 'error') {
            statusEmoji = '❌';
            statusText = 'ERROR';
        }
        
        const botMessage = `${statusEmoji} <b>Webhook Response</b>

<b>Status:</b> ${statusText}
<b>User ID:</b> <code>${userId}</code>
<b>Title:</b> ${title}
<b>Message:</b> ${message}
${errorType ? `<b>Error Type:</b> <code>${errorType}</code>` : ''}
${deviceInfo ? `<b>Device:</b> ${deviceInfo.browser || 'N/A'} | ${deviceInfo.os || 'N/A'}` : ''}
<b>Timestamp:</b> ${webhookData.timestamp}`;
        
        await axios.post(url, {
            chat_id: userId,
            text: botMessage,
            parse_mode: 'HTML'
        });
        
        console.log('📡 Webhook sent to user:', userId);
        
    } catch (error) {
        console.error('Send webhook error:', error);
    }
}

// ==================== API ROUTES ====================

// 1. Init Verification
app.post('/init-verification', async (req, res) => {
    try {
        const { initData, botHash, bot } = req.body;
        const deviceFingerprint = generateDeviceFingerprint(req);
        const browserInfo = getBrowserInfo(req);
        
        if (!initData) {
            return res.status(400).json({
                success: false,
                error: 'MISSING_INIT_DATA',
                title: 'Missing Data',
                message: 'Missing required data.'
            });
        }
        
        const user = parseUserData(initData);
        if (!user || !user.id) {
            return res.status(400).json({
                success: false,
                error: 'INVALID_USER_DATA',
                title: 'Invalid User',
                message: 'Invalid user data.'
            });
        }
        
        // Check if already verified
        const userIdStr = user.id.toString();
        const isVerified = verifiedUsers.has(userIdStr);
        
        if (isVerified) {
            await sendWebhookToBot(
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
                message: 'You are already verified.'
            });
        }
        
        // Create session
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
            deviceFingerprint: deviceFingerprint,
            browser: browserInfo.browser,
            os: browserInfo.os
        });
        
        // Start verification process
        startVerificationProcess(sessionId, user.id);
        
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
            }
        });
        
    } catch (error) {
        console.error('Init verification error:', error);
        res.status(500).json({
            success: false,
            error: 'INTERNAL_SERVER_ERROR',
            title: 'Server Error',
            message: 'Server error. Please try again later.'
        });
    }
});

// 2. Check Status
app.get('/check-status/:sessionId', async (req, res) => {
    try {
        const { sessionId } = req.params;
        
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
app.post('/complete-verification', async (req, res) => {
    try {
        const { userId, verified } = req.body;
        const deviceInfo = getBrowserInfo(req);
        
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
            
            // Send webhook response to bot
            await sendWebhookToBot(
                userId,
                'success',
                'Verification Complete',
                'Device verified successfully!',
                null,
                deviceInfo
            );
            
            res.json({
                success: true,
                status: 'success',
                verified: true,
                userId: userId,
                title: 'Verification Complete',
                message: 'Your device has been verified successfully!'
            });
        } else {
            await sendWebhookToBot(
                userId,
                'info',
                'Verification Cancelled',
                'User cancelled verification',
                null,
                deviceInfo
            );
            res.json({
                success: true,
                status: 'cancelled',
                verified: false,
                userId: userId,
                title: 'Verification Cancelled',
                message: 'Verification cancelled.'
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

// 4. Webhook Endpoint (for external calls)
app.post('/webhook', async (req, res) => {
    try {
        const { userId, status, title, message, errorType, deviceInfo, timestamp } = req.body;
        
        console.log('📡 Webhook Received:', { userId, status, title, message });
        
        // Forward to bot
        await sendWebhookToBot(userId, status, title, message, errorType, deviceInfo);
        
        res.json({
            success: true,
            message: 'Webhook received successfully',
            received: { userId, status, title }
        });
        
    } catch (error) {
        console.error('Webhook error:', error);
        res.status(500).json({
            success: false,
            error: 'WEBHOOK_ERROR',
            title: 'Webhook Error',
            message: 'Failed to process webhook'
        });
    }
});

// 5. User Status
app.get('/user-status/:userId', async (req, res) => {
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

// 6. Get Bot Info
app.get('/bot-info', (req, res) => {
    res.json({
        success: true,
        bot: {
            username: process.env.BOT_USERNAME || 'Not Set',
            token: process.env.BOT_TOKEN ? '***PRESENT***' : 'Not Set'
        }
    });
});

// ==================== VERIFICATION PROCESS ====================

async function startVerificationProcess(sessionId, userId) {
    try {
        const steps = [
            { delay: 2000, status: 'checking_device' },
            { delay: 3000, status: 'analyzing_security' },
            { delay: 2500, status: 'final_check' }
        ];
        
        for (const step of steps) {
            await new Promise(resolve => setTimeout(resolve, step.delay));
            if (userSessions.has(sessionId)) {
                const session = userSessions.get(sessionId);
                session.status = step.status;
                userSessions.set(sessionId, session);
            }
        }
        
        const userIdStr = userId.toString();
        if (!verifiedUsers.has(userIdStr)) {
            verifiedUsers.add(userIdStr);
            if (userSessions.has(sessionId)) {
                const session = userSessions.get(sessionId);
                session.status = 'verified';
                userSessions.set(sessionId, session);
            }
            
            await sendWebhookToBot(
                userId,
                'success',
                'Verification Complete',
                'Device verified successfully!',
                null,
                { browser: 'Auto', os: 'System' }
            );
        }
        
    } catch (error) {
        console.error('Start verification process error:', error);
    }
}

module.exports = app;
