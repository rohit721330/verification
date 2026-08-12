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
        return res.status(401).json({
            success: false,
            error: 'NO_TOKEN'
        });
    }
    
    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(403).json({
            success: false,
            error: 'INVALID_TOKEN'
        });
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
    
    const fingerprint = crypto
        .createHash('sha256')
        .update(`${userAgent}|${acceptLanguage}|${acceptEncoding}|${secChUa}|${secChUaPlatform}|${secChUaMobile}|${ip}`)
        .digest('hex');
    
    return fingerprint;
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

async function sendTelegramMessage(userId, message) {
    try {
        const BOT_TOKEN = process.env.BOT_TOKEN;
        if (!BOT_TOKEN || BOT_TOKEN === 'YOUR_BOT_TOKEN') {
            console.log('Bot token not configured.');
            return;
        }
        
        const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
        await axios.post(url, {
            chat_id: userId,
            text: message,
            parse_mode: 'HTML'
        });
    } catch (error) {
        console.error('Telegram message error:', error);
    }
}

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
            
            await sendTelegramMessage(userId, '✅ Your device has been verified successfully!');
        }
        
    } catch (error) {
        console.error('Start verification process error:', error);
    }
}

// ==================== API ROUTES ====================

app.post('/init-verification', async (req, res) => {
    try {
        const { initData, botHash, bot } = req.body;
        const deviceFingerprint = generateDeviceFingerprint(req);
        const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || '';
        const browserInfo = getBrowserInfo(req);
        
        const isVPN = await detectVPN(ip);
        if (isVPN) {
            vpnBlocklist.add(ip);
            return res.status(403).json({
                success: false,
                error: 'VPN_USAGE_DETECTED'
            });
        }
        
        if (!initData) {
            return res.status(400).json({
                success: false,
                error: 'MISSING_INIT_DATA'
            });
        }
        
        const botToken = process.env.BOT_TOKEN;
        const isValid = verifyTelegramHash(initData, botToken);
        if (!isValid) {
            return res.status(403).json({
                success: false,
                error: 'INVALID_HASH'
            });
        }
        
        const user = parseUserData(initData);
        if (!user || !user.id) {
            return res.status(400).json({
                success: false,
                error: 'INVALID_USER_DATA'
            });
        }
        
        if (!checkRateLimit(user.id)) {
            return res.status(429).json({
                success: false,
                error: 'RATE_LIMIT_EXCEEDED'
            });
        }
        
        if (verifiedUsers.has(user.id.toString())) {
            const token = generateToken(user, 3600);
            return res.json({
                success: true,
                status: 'already_verified',
                user: user,
                token: token
            });
        }
        
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
                return res.status(403).json({
                    success: false,
                    error: 'DIFFERENT_BROWSER_DETECTED'
                });
            }
        }
        
        if (deviceFingerprints.has(deviceFingerprint)) {
            const existingData = deviceFingerprints.get(deviceFingerprint);
            
            if (existingData.userId !== user.id.toString()) {
                return res.status(403).json({
                    success: false,
                    error: 'DIFFERENT_USER_SAME_DEVICE'
                });
            }
            
            if (existingData.browser !== browserInfo.browser) {
                return res.status(403).json({
                    success: false,
                    error: 'SAME_DEVICE_DIFFERENT_BROWSER'
                });
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
            bot: bot || process.env.BOT_USERNAME,
            botHash: botHash || null,
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
        
        startVerificationProcess(sessionId, user.id);
        
        res.json({
            success: true,
            status: 'pending',
            sessionId: sessionId,
            userId: user.id,
            token: token,
            expiresIn: JWT_VERIFICATION_EXPIRY,
            deviceInfo: {
                browser: browserInfo.browser,
                os: browserInfo.os
            }
        });
        
    } catch (error) {
        console.error('Init verification error:', error);
        res.status(500).json({
            success: false,
            error: 'INTERNAL_SERVER_ERROR'
        });
    }
});

app.get('/check-status/:sessionId', authenticateToken, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const deviceFingerprint = generateDeviceFingerprint(req);
        
        if (!sessionId || !userSessions.has(sessionId)) {
            return res.status(404).json({
                success: false,
                error: 'SESSION_NOT_FOUND'
            });
        }
        
        const session = userSessions.get(sessionId);
        const userId = session.userId.toString();
        
        if (session.deviceFingerprint !== deviceFingerprint) {
            return res.status(403).json({
                success: false,
                error: 'DEVICE_MISMATCH'
            });
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
            deviceInfo: {
                browser: session.browser,
                os: session.os
            }
        });
        
    } catch (error) {
        console.error('Check status error:', error);
        res.status(500).json({
            success: false,
            error: 'INTERNAL_SERVER_ERROR'
        });
    }
});

app.post('/complete-verification', authenticateToken, async (req, res) => {
    try {
        const { userId, verified } = req.body;
        const userData = req.user;
        
        if (!userId) {
            return res.status(400).json({
                success: false,
                error: 'MISSING_USER_ID'
            });
        }
        
        if (userData.userId !== userId) {
            return res.status(403).json({
                success: false,
                error: 'USER_ID_MISMATCH'
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
            
            const newToken = generateToken({
                id: userId,
                username: userData.username || '',
                first_name: userData.firstName || '',
                last_name: userData.lastName || '',
                deviceFingerprint: userData.deviceFingerprint || ''
            }, 86400);
            
            await sendTelegramMessage(userId, '✅ Your device has been verified successfully!');
            
            res.json({
                success: true,
                verified: true,
                userId: userId,
                token: newToken,
                expiresIn: 86400
            });
        } else {
            res.json({
                success: true,
                verified: false,
                userId: userId
            });
        }
        
    } catch (error) {
        console.error('Complete verification error:', error);
        res.status(500).json({
            success: false,
            error: 'INTERNAL_SERVER_ERROR'
        });
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
        
        res.json({
            success: true,
            user: userData,
            isVerified: isVerified
        });
        
    } catch (error) {
        console.error('User profile error:', error);
        res.status(500).json({
            success: false,
            error: 'INTERNAL_SERVER_ERROR'
        });
    }
});

app.get('/user-status/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const isVerified = verifiedUsers.has(userId);
        
        res.json({
            success: true,
            userId: userId,
            isVerified: isVerified,
            status: isVerified ? 'verified' : 'not_verified'
        });
        
    } catch (error) {
        console.error('User status error:', error);
        res.status(500).json({
            success: false,
            error: 'INTERNAL_SERVER_ERROR'
        });
    }
});

app.post('/admin/verify-user', async (req, res) => {
    try {
        const { userId, adminSecret } = req.body;
        
        if (adminSecret !== ADMIN_SECRET) {
            return res.status(403).json({
                success: false,
                error: 'UNAUTHORIZED'
            });
        }
        
        if (!userId) {
            return res.status(400).json({
                success: false,
                error: 'MISSING_USER_ID'
            });
        }
        
        verifiedUsers.add(userId.toString());
        
        for (const [sid, session] of userSessions) {
            if (session.userId.toString() === userId.toString()) {
                session.status = 'verified';
                userSessions.set(sid, session);
            }
        }
        
        await sendTelegramMessage(userId, '✅ Your account has been verified by admin!');
        
        res.json({
            success: true,
            userId: userId,
            status: 'verified'
        });
        
    } catch (error) {
        console.error('Admin verify error:', error);
        res.status(500).json({
            success: false,
            error: 'INTERNAL_SERVER_ERROR'
        });
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
        
        res.json({
            success: true,
            totalUsers: users.length,
            verifiedCount: verifiedUsers.size,
            users: users
        });
        
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({
            success: false,
            error: 'INTERNAL_SERVER_ERROR'
        });
    }
});

app.delete('/admin/clear-data', async (req, res) => {
    try {
        const { adminSecret } = req.body;
        
        if (adminSecret !== ADMIN_SECRET) {
            return res.status(403).json({
                success: false,
                error: 'UNAUTHORIZED'
            });
        }
        
        userSessions.clear();
        verifiedUsers.clear();
        deviceFingerprints.clear();
        userBrowserHistory.clear();
        vpnBlocklist.clear();
        rateLimiter.clear();
        
        res.json({
            success: true,
            message: 'All data cleared successfully'
        });
        
    } catch (error) {
        console.error('Clear data error:', error);
        res.status(500).json({
            success: false,
            error: 'INTERNAL_SERVER_ERROR'
        });
    }
});

app.delete('/admin/clear-sessions', async (req, res) => {
    try {
        const { adminSecret } = req.body;
        
        if (adminSecret !== ADMIN_SECRET) {
            return res.status(403).json({
                success: false,
                error: 'UNAUTHORIZED'
            });
        }
        
        userSessions.clear();
        rateLimiter.clear();
        
        res.json({
            success: true,
            message: 'All sessions cleared'
        });
        
    } catch (error) {
        console.error('Clear sessions error:', error);
        res.status(500).json({
            success: false,
            error: 'INTERNAL_SERVER_ERROR'
        });
    }
});

app.get('/admin/tokens', async (req, res) => {
    try {
        const tokens = [];
        for (const [sid, session] of userSessions) {
            tokens.push({
                userId: session.userId,
                sessionId: sid,
                status: session.status,
                createdAt: new Date(session.createdAt).toISOString()
            });
        }
        
        res.json({
            success: true,
            totalTokens: tokens.length,
            tokens: tokens
        });
        
    } catch (error) {
        console.error('Admin tokens error:', error);
        res.status(500).json({
            success: false,
            error: 'INTERNAL_SERVER_ERROR'
        });
    }
});

module.exports = app;
