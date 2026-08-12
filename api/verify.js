const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const JWT_SECRET = process.env.JWT_SECRET || 'default_jwt_secret_key';
const JWT_VERIFICATION_EXPIRY = parseInt(process.env.JWT_VERIFICATION_EXPIRY) || 300;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'default_admin_secret';

const userSessions = new Map();
const verifiedUsers = new Set();
const deviceFingerprints = new Map();
const userBrowserHistory = new Map();
const vpnBlocklist = new Set();
const rateLimiter = new Map();

let botInfo = { token: null, username: null, hash: null };

function generateToken(userData, expiresIn = JWT_VERIFICATION_EXPIRY) {
    return jwt.sign(
        {
            userId: userData.id,
            username: userData.username || '',
            firstName: userData.first_name || '',
            lastName: userData.last_name || '',
            deviceFingerprint: userData.deviceFingerprint || null
        },
        JWT_SECRET,
        { expiresIn: expiresIn }
    );
}

function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ success: false, error: 'NO_TOKEN' });
    }
    
    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(403).json({ success: false, error: 'INVALID_TOKEN' });
    }
    
    req.user = decoded;
    next();
}

function generateDeviceFingerprint(req) {
    const userAgent = req.headers['user-agent'] || '';
    const acceptLanguage = req.headers['accept-language'] || '';
    const acceptEncoding = req.headers['accept-encoding'] || '';
    const secChUa = req.headers['sec-ch-ua'] || '';
    const secChUaPlatform = req.headers['sec-ch-ua-platform'] || '';
    const secChUaMobile = req.headers['sec-ch-ua-mobile'] || '';
    const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || '';
    
    return crypto
        .createHash('sha256')
        .update(`${userAgent}|${acceptLanguage}|${acceptEncoding}|${secChUa}|${secChUaPlatform}|${secChUaMobile}|${ip}`)
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
    else if (userAgent.includes('Brave')) browser = 'Brave';
    
    if (userAgent.includes('Windows')) os = 'Windows';
    else if (userAgent.includes('Mac OS')) os = 'MacOS';
    else if (userAgent.includes('Linux')) os = 'Linux';
    else if (userAgent.includes('Android')) os = 'Android';
    else if (userAgent.includes('iOS')) os = 'iOS';
    
    return { browser, os };
}

async function detectVPN(ipAddress) {
    try {
        if (vpnBlocklist.has(ipAddress)) return true;
        
        const datacenterRanges = [
            /^3\./, /^13\./, /^15\./, /^18\./, /^34\./, /^35\./,
            /^44\./, /^52\./, /^54\./, /^104\./, /^143\./, /^151\./,
            /^157\./, /^159\./, /^161\./, /^164\./, /^185\./, /^192\./, /^203\./
        ];
        
        for (const pattern of datacenterRanges) {
            if (pattern.test(ipAddress)) return true;
        }
        
        return false;
    } catch (error) {
        return false;
    }
}

function verifyTelegramHash(initData, botToken) {
    try {
        const params = new URLSearchParams(initData);
        const hash = params.get('hash');
        params.delete('hash');
        
        const sortedParams = Array.from(params.entries())
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([key, value]) => `${key}=${value}`)
            .join('\n');
        
        const secretKey = crypto.createHmac('sha256', 'WebAppData')
            .update(botToken)
            .digest();
        
        const calculatedHash = crypto.createHmac('sha256', secretKey)
            .update(sortedParams)
            .digest('hex');
        
        return calculatedHash === hash;
    } catch (error) {
        return false;
    }
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

function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

function checkRateLimit(userId, maxAttempts = 3, windowMs = 300000) {
    const key = `rate_${userId}`;
    const now = Date.now();
    
    if (!rateLimiter.has(key)) {
        rateLimiter.set(key, { attempts: 1, firstAttempt: now });
        return true;
    }
    
    const data = rateLimiter.get(key);
    
    if (now - data.firstAttempt > windowMs) {
        rateLimiter.set(key, { attempts: 1, firstAttempt: now });
        return true;
    }
    
    if (data.attempts >= maxAttempts) return false;
    
    data.attempts++;
    rateLimiter.set(key, data);
    return true;
}

// ===== SEND WEBHOOK TO BOT =====
async function sendWebhookToBot(userId, status, title, message, errorType = null, deviceInfo = null) {
    try {
        const botToken = botInfo.token;
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

// ===== MIDDLEWARE =====
app.use((req, res, next) => {
    const query = req.query || {};
    if (query.botToken) botInfo.token = query.botToken;
    if (query.bot) botInfo.username = query.bot;
    if (query.botHash) botInfo.hash = query.botHash;
    next();
});

// ===== API ROUTES =====

app.post('/init-verification', async (req, res) => {
    try {
        const { initData, botHash, bot, botToken } = req.body;
        const deviceFingerprint = generateDeviceFingerprint(req);
        const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || '';
        const browserInfo = getBrowserInfo(req);
        
        if (botToken) botInfo.token = botToken;
        if (bot) botInfo.username = bot;
        if (botHash) botInfo.hash = botHash;
        
        const isVPN = await detectVPN(ip);
        if (isVPN) {
            vpnBlocklist.add(ip);
            await sendWebhookToBot('unknown', 'error', 'VPN Detected', 'VPN usage detected', 'VPN_USAGE_DETECTED', browserInfo);
            return res.status(403).json({ success: false, error: 'VPN_USAGE_DETECTED', title: 'VPN Detected', message: 'VPN usage is not allowed.' });
        }
        
        if (!initData) {
            await sendWebhookToBot('unknown', 'error', 'Missing Data', 'No verification data found', 'MISSING_INIT_DATA', browserInfo);
            return res.status(400).json({ success: false, error: 'MISSING_INIT_DATA', title: 'Missing Data', message: 'Missing required data.' });
        }
        
        const botTokenToUse = botInfo.token || process.env.BOT_TOKEN;
        if (!botTokenToUse) {
            return res.status(400).json({ success: false, error: 'MISSING_BOT_TOKEN', title: 'Missing Bot Token', message: 'Bot token not found' });
        }
        
        const isValid = verifyTelegramHash(initData, botTokenToUse);
        if (!isValid) {
            await sendWebhookToBot('unknown', 'error', 'Invalid Hash', 'Hash verification failed', 'INVALID_HASH', browserInfo);
            return res.status(403).json({ success: false, error: 'INVALID_HASH', title: 'Invalid Hash', message: 'Security verification failed.' });
        }
        
        const user = parseUserData(initData);
        if (!user || !user.id) {
            await sendWebhookToBot('unknown', 'error', 'Invalid User', 'User data could not be parsed', 'INVALID_USER_DATA', browserInfo);
            return res.status(400).json({ success: false, error: 'INVALID_USER_DATA', title: 'Invalid User', message: 'Invalid user data.' });
        }
        
        if (!checkRateLimit(user.id)) {
            await sendWebhookToBot(user.id, 'error', 'Rate Limit Exceeded', 'Too many attempts', 'RATE_LIMIT_EXCEEDED', browserInfo);
            return res.status(429).json({ success: false, error: 'RATE_LIMIT_EXCEEDED', title: 'Too Many Attempts', message: 'Please wait 5 minutes.' });
        }
        
        if (verifiedUsers.has(user.id.toString())) {
            await sendWebhookToBot(user.id, 'info', 'Already Verified', 'User is already verified', null, browserInfo);
            const token = generateToken(user, 3600);
            return res.json({ success: true, status: 'already_verified', user: user, token: token, title: 'Already Verified', message: 'You are already verified.' });
        }
        
        // Different browser check
        if (userBrowserHistory.has(user.id.toString())) {
            const userBrowsers = userBrowserHistory.get(user.id.toString());
            const currentBrowserFingerprint = generateDeviceFingerprint(req);
            
            let isDifferentBrowser = true;
            for (const fingerprint of userBrowsers) {
                if (fingerprint === currentBrowserFingerprint) {
                    isDifferentBrowser = false;
                    break;
                }
            }
            
            if (isDifferentBrowser) {
                await sendWebhookToBot(user.id, 'error', 'Different Browser', `User already verified using ${browserInfo.browser}`, 'DIFFERENT_BROWSER_DETECTED', browserInfo);
                return res.status(403).json({ success: false, error: 'DIFFERENT_BROWSER_DETECTED', title: 'Different Browser', message: `You already verified using ${browserInfo.browser}.` });
            }
        }
        
        // Same device different user check
        if (deviceFingerprints.has(deviceFingerprint)) {
            const existingData = deviceFingerprints.get(deviceFingerprint);
            
            if (existingData.userId !== user.id.toString()) {
                await sendWebhookToBot(user.id, 'error', 'Different User', `Different user (ID: ${existingData.userId}) on same device`, 'DIFFERENT_USER_SAME_DEVICE', browserInfo);
                return res.status(403).json({ success: false, error: 'DIFFERENT_USER_SAME_DEVICE', title: 'Different User', message: `Different user already verified from this device.` });
            }
            
            if (existingData.browser !== browserInfo.browser) {
                await sendWebhookToBot(user.id, 'error', 'Different Browser', `Same device different browser`, 'SAME_DEVICE_DIFFERENT_BROWSER', browserInfo);
                return res.status(403).json({ success: false, error: 'SAME_DEVICE_DIFFERENT_BROWSER', title: 'Different Browser', message: `This device already verified using ${existingData.browser}.` });
            }
        }
        
        const sessionId = generateSessionId();
        
        deviceFingerprints.set(deviceFingerprint, {
            userId: user.id.toString(),
            browser: browserInfo.browser,
            os: browserInfo.os,
            ip: ip,
            timestamp: Date.now()
        });
        
        if (!userBrowserHistory.has(user.id.toString())) {
            userBrowserHistory.set(user.id.toString(), new Set());
        }
        userBrowserHistory.get(user.id.toString()).add(deviceFingerprint);
        
        userSessions.set(sessionId, {
            userId: user.id,
            username: user.username || '',
            firstName: user.first_name || '',
            lastName: user.last_name || '',
            status: 'pending',
            createdAt: Date.now(),
            bot: bot || botInfo.username || '',
            botHash: botHash || botInfo.hash || null,
            deviceFingerprint: deviceFingerprint,
            browser: browserInfo.browser,
            os: browserInfo.os,
            ip: ip
        });
        
        const token = generateToken({
            id: user.id,
            username: user.username,
            first_name: user.first_name,
            last_name: user.last_name,
            deviceFingerprint: deviceFingerprint
        });
        
        // Start verification process
        startVerificationProcess(sessionId, user.id);
        
        res.json({
            success: true,
            status: 'pending',
            sessionId: sessionId,
            userId: user.id,
            token: token,
            expiresIn: JWT_VERIFICATION_EXPIRY,
            title: 'Verification Started',
            message: 'Your device verification has been started.',
            deviceInfo: { browser: browserInfo.browser, os: browserInfo.os }
        });
        
    } catch (error) {
        console.error('Init verification error:', error);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', title: 'Server Error', message: 'Please try again later.' });
    }
});

app.get('/check-status/:sessionId', authenticateToken, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const deviceFingerprint = generateDeviceFingerprint(req);
        
        if (!sessionId || !userSessions.has(sessionId)) {
            return res.status(404).json({ success: false, error: 'SESSION_NOT_FOUND', title: 'Session Not Found', message: 'Session not found.' });
        }
        
        const session = userSessions.get(sessionId);
        const userId = session.userId.toString();
        
        if (session.deviceFingerprint !== deviceFingerprint) {
            return res.status(403).json({ success: false, error: 'DEVICE_MISMATCH', title: 'Device Mismatch', message: 'Device mismatch detected.' });
        }
        
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
            deviceInfo: { browser: session.browser, os: session.os }
        });
        
    } catch (error) {
        console.error('Check status error:', error);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', title: 'Server Error', message: 'Server error.' });
    }
});

app.post('/complete-verification', authenticateToken, async (req, res) => {
    try {
        const { userId, verified } = req.body;
        const userData = req.user;
        const deviceInfo = getBrowserInfo(req);
        
        if (!userId) {
            return res.status(400).json({ success: false, error: 'MISSING_USER_ID', title: 'Missing User ID', message: 'User ID required.' });
        }
        
        if (userData.userId !== userId) {
            return res.status(403).json({ success: false, error: 'USER_ID_MISMATCH', title: 'User Mismatch', message: 'User ID mismatch.' });
        }
        
        if (verified) {
            verifiedUsers.add(userId.toString());
            
            for (const [sid, session] of userSessions) {
                if (session.userId.toString() === userId.toString()) {
                    session.status = 'verified';
                    userSessions.set(sid, session);
                }
            }
            
            const newToken = generateToken({
                id: userId,
                username: userData.username || '',
                first_name: userData.firstName || '',
                last_name: userData.lastName || '',
                deviceFingerprint: userData.deviceFingerprint || ''
            }, 86400);
            
            await sendWebhookToBot(userId, 'success', 'Verification Complete', 'Device verified successfully!', null, deviceInfo);
            
            res.json({
                success: true,
                status: 'success',
                verified: true,
                userId: userId,
                token: newToken,
                expiresIn: 86400,
                title: 'Verification Complete',
                message: 'Your device has been verified successfully!'
            });
        } else {
            await sendWebhookToBot(userId, 'info', 'Verification Cancelled', 'User cancelled verification', null, deviceInfo);
            res.json({ success: true, status: 'cancelled', verified: false, userId: userId, title: 'Verification Cancelled', message: 'Verification cancelled.' });
        }
        
    } catch (error) {
        console.error('Complete verification error:', error);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', title: 'Server Error', message: 'Server error.' });
    }
});

app.get('/user-profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const isVerified = verifiedUsers.has(userId.toString());
        
        let userData = null;
        for (const [sid, session] of userSessions) {
            if (session.userId.toString() === userId.toString()) {
                userData = {
                    id: session.userId,
                    username: session.username,
                    firstName: session.firstName,
                    lastName: session.lastName,
                    status: session.status,
                    browser: session.browser,
                    os: session.os
                };
                break;
            }
        }
        
        res.json({ success: true, user: userData, isVerified: isVerified, title: 'User Profile', message: isVerified ? 'User is verified' : 'User is not verified' });
        
    } catch (error) {
        console.error('User profile error:', error);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', title: 'Server Error', message: 'Server error.' });
    }
});

app.get('/user-status/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const isVerified = verifiedUsers.has(userId);
        res.json({ success: true, userId: userId, isVerified: isVerified, status: isVerified ? 'verified' : 'not_verified', title: 'User Status', message: isVerified ? 'User is verified' : 'User is not verified' });
    } catch (error) {
        console.error('User status error:', error);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', title: 'Server Error', message: 'Server error.' });
    }
});

app.post('/admin/verify-user', async (req, res) => {
    try {
        const { userId, adminSecret } = req.body;
        const deviceInfo = getBrowserInfo(req);
        
        if (adminSecret !== ADMIN_SECRET) {
            return res.status(403).json({ success: false, error: 'UNAUTHORIZED', title: 'Unauthorized', message: 'Unauthorized access.' });
        }
        
        if (!userId) {
            return res.status(400).json({ success: false, error: 'MISSING_USER_ID', title: 'Missing User ID', message: 'User ID required.' });
        }
        
        verifiedUsers.add(userId.toString());
        
        for (const [sid, session] of userSessions) {
            if (session.userId.toString() === userId.toString()) {
                session.status = 'verified';
                userSessions.set(sid, session);
            }
        }
        
        await sendWebhookToBot(userId, 'success', 'Admin Verification', 'User verified by admin', null, deviceInfo);
        
        res.json({ success: true, userId: userId, status: 'verified', title: 'User Verified', message: 'User has been verified successfully.' });
        
    } catch (error) {
        console.error('Admin verify error:', error);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', title: 'Server Error', message: 'Server error.' });
    }
});

app.get('/admin/users', async (req, res) => {
    try {
        const users = [];
        for (const [sid, session] of userSessions) {
            users.push({
                sessionId: sid,
                userId: session.userId,
                username: session.username,
                firstName: session.firstName,
                lastName: session.lastName,
                status: session.status,
                browser: session.browser,
                os: session.os,
                createdAt: new Date(session.createdAt).toISOString(),
                isVerified: verifiedUsers.has(session.userId.toString())
            });
        }
        res.json({ success: true, totalUsers: users.length, verifiedCount: verifiedUsers.size, users: users, title: 'All Users', message: 'Users list retrieved successfully.' });
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', title: 'Server Error', message: 'Server error.' });
    }
});

app.delete('/admin/clear-data', async (req, res) => {
    try {
        const { adminSecret } = req.body;
        if (adminSecret !== ADMIN_SECRET) {
            return res.status(403).json({ success: false, error: 'UNAUTHORIZED', title: 'Unauthorized', message: 'Unauthorized access.' });
        }
        userSessions.clear();
        verifiedUsers.clear();
        deviceFingerprints.clear();
        userBrowserHistory.clear();
        vpnBlocklist.clear();
        rateLimiter.clear();
        res.json({ success: true, title: 'Data Cleared', message: 'All data cleared successfully.' });
    } catch (error) {
        console.error('Clear data error:', error);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', title: 'Server Error', message: 'Server error.' });
    }
});

app.delete('/admin/clear-sessions', async (req, res) => {
    try {
        const { adminSecret } = req.body;
        if (adminSecret !== ADMIN_SECRET) {
            return res.status(403).json({ success: false, error: 'UNAUTHORIZED', title: 'Unauthorized', message: 'Unauthorized access.' });
        }
        userSessions.clear();
        rateLimiter.clear();
        res.json({ success: true, title: 'Sessions Cleared', message: 'All sessions cleared.' });
    } catch (error) {
        console.error('Clear sessions error:', error);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', title: 'Server Error', message: 'Server error.' });
    }
});

app.get('/admin/tokens', async (req, res) => {
    try {
        const tokens = [];
        for (const [sid, session] of userSessions) {
            tokens.push({ userId: session.userId, sessionId: sid, status: session.status, createdAt: new Date(session.createdAt).toISOString() });
        }
        res.json({ success: true, totalTokens: tokens.length, tokens: tokens, title: 'Tokens List', message: 'Tokens retrieved successfully.' });
    } catch (error) {
        console.error('Admin tokens error:', error);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', title: 'Server Error', message: 'Server error.' });
    }
});

app.post('/webhook', async (req, res) => {
    try {
        const { userId, status, title, message, errorType, deviceInfo, timestamp } = req.body;
        console.log('📡 Webhook Received:', { userId, status, title, message });
        
        if (botInfo.token) {
            await sendWebhookToBot(userId, status, title, message, errorType, deviceInfo);
        }
        
        res.json({ success: true, message: 'Webhook received successfully', received: { userId, status, title } });
    } catch (error) {
        console.error('Webhook error:', error);
        res.status(500).json({ success: false, error: 'WEBHOOK_ERROR', title: 'Webhook Error', message: 'Failed to process webhook' });
    }
});

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
            await sendWebhookToBot(userId, 'success', 'Verification Complete', 'Device verified successfully!', null, { browser: 'Auto', os: 'System' });
        }
    } catch (error) {
        console.error('Start verification process error:', error);
    }
}

module.exports = app;
