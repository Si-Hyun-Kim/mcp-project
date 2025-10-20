// server.js - Express Server for Security Dashboard
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const axios = require('axios');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const app = express();
const PORT = process.env.PORT || 3000;
const MCP_SERVER_URL = process.env.MCP_SERVER_URL || 'http://localhost:8080';
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// WebSocket server for real-time updates
const wss = new WebSocket.Server({ port: 3001 });

// In-memory storage (use database in production)
const users = new Map();
const sessions = new Map();
const mfaSecrets = new Map();

// Initialize admin user
users.set('admin', {
    username: 'admin',
    password: crypto.createHash('sha256').update('admin').digest('hex'),
    role: 'admin',
    mfaEnabled: true
});

// Generate MFA secret for admin
const adminSecret = speakeasy.generateSecret({ name: 'SOC Dashboard (admin)' });
mfaSecrets.set('admin', adminSecret.base32);

// Serve the dashboard HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Authentication endpoints
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    
    const user = users.get(username);
    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    if (hashedPassword !== user.password) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // If MFA is enabled, require verification
    if (user.mfaEnabled) {
        const tempToken = jwt.sign({ username, requireMFA: true }, JWT_SECRET, { expiresIn: '5m' });
        return res.json({ requireMFA: true, tempToken });
    }
    
    // Generate session token
    const token = jwt.sign({ username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    sessions.set(token, { username, loginTime: new Date() });
    
    res.json({ token, user: { username, role: user.role } });
});

app.post('/api/auth/verify-mfa', async (req, res) => {
    const { tempToken, code } = req.body;
    
    try {
        const decoded = jwt.verify(tempToken, JWT_SECRET);
        if (!decoded.requireMFA) {
            return res.status(400).json({ error: 'Invalid token' });
        }
        
        const secret = mfaSecrets.get(decoded.username);
        const verified = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token: code,
            window: 2
        });
        
        // For demo, accept '123456' as valid code
        if (verified || code === '123456') {
            const user = users.get(decoded.username);
            const token = jwt.sign({ username: decoded.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
            sessions.set(token, { username: decoded.username, loginTime: new Date() });
            
            res.json({ token, user: { username: decoded.username, role: user.role } });
        } else {
            res.status(401).json({ error: 'Invalid MFA code' });
        }
    } catch (error) {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
});

app.get('/api/auth/mfa-qr', async (req, res) => {
    const { username } = req.query;
    const secret = mfaSecrets.get(username);
    
    if (!secret) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    const otpauth = speakeasy.otpauthURL({
        secret: secret,
        label: `SOC Dashboard (${username})`,
        issuer: 'Security Operations Center',
        encoding: 'base32'
    });
    
    const qrCode = await QRCode.toDataURL(otpauth);
    res.json({ qrCode, secret });
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// MCP Server proxy endpoints
app.post('/api/mcp/*', authenticateToken, async (req, res) => {
    try {
        const mcpPath = req.params[0];
        const response = await axios.post(`${MCP_SERVER_URL}/api/${mcpPath}`, req.body);
        res.json(response.data);
    } catch (error) {
        console.error('MCP Server error:', error.message);
        res.status(500).json({ error: 'MCP Server communication error' });
    }
});

// Dashboard API endpoints
app.get('/api/alerts', authenticateToken, async (req, res) => {
    try {
        const { count = 100, severity, timeRange } = req.query;
        
        const response = await axios.post(`${MCP_SERVER_URL}/api`, {
            method: 'get_alerts',
            params: { count: parseInt(count), severity }
        });
        
        let alerts = response.data.alerts || [];
        
        // Apply time filter
        if (timeRange) {
            const now = Date.now();
            const ranges = {
                '1h': 3600000,
                '24h': 86400000,
                '7d': 604800000,
                '30d': 2592000000
            };
            
            if (ranges[timeRange]) {
                alerts = alerts.filter(alert => {
                    const alertTime = new Date(alert.timestamp).getTime();
                    return now - alertTime < ranges[timeRange];
                });
            }
        }
        
        res.json({ alerts });
    } catch (error) {
        console.error('Error fetching alerts:', error);
        res.status(500).json({ error: 'Failed to fetch alerts' });
    }
});

app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const response = await axios.post(`${MCP_SERVER_URL}/api`, {
            method: 'get_stats',
            params: {}
        });
        
        res.json(response.data);
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ error: 'Failed to fetch statistics' });
    }
});

app.post('/api/block-ip', authenticateToken, async (req, res) => {
    const { ip, reason } = req.body;
    
    try {
        const response = await axios.post(`${MCP_SERVER_URL}/api`, {
            method: 'block_ip',
            params: { ip, reason }
        });
        
        // Broadcast to WebSocket clients
        broadcast({
            type: 'ip_blocked',
            data: { ip, reason, timestamp: new Date() }
        });
        
        res.json(response.data);
    } catch (error) {
        console.error('Error blocking IP:', error);
        res.status(500).json({ error: 'Failed to block IP' });
    }
});

app.get('/api/rules', authenticateToken, async (req, res) => {
    try {
        const response = await axios.post(`${MCP_SERVER_URL}/api`, {
            method: 'get_rules',
            params: {}
        });
        
        res.json(response.data);
    } catch (error) {
        console.error('Error fetching rules:', error);
        res.status(500).json({ error: 'Failed to fetch rules' });
    }
});

app.post('/api/rules/toggle', authenticateToken, async (req, res) => {
    const { sid } = req.body;
    
    try {
        const response = await axios.post(`${MCP_SERVER_URL}/api`, {
            method: 'toggle_rule',
            params: { sid }
        });
        
        res.json(response.data);
    } catch (error) {
        console.error('Error toggling rule:', error);
        res.status(500).json({ error: 'Failed to toggle rule' });
    }
});

app.post('/api/reports/generate', authenticateToken, async (req, res) => {
    const { type, startDate, endDate, format } = req.body;
    
    try {
        const response = await axios.post(`${MCP_SERVER_URL}/api`, {
            method: 'generate_report',
            params: { type, start_date: startDate, end_date: endDate }
        });
        
        res.json(response.data);
    } catch (error) {
        console.error('Error generating report:', error);
        res.status(500).json({ error: 'Failed to generate report' });
    }
});

app.get('/api/comparison', authenticateToken, async (req, res) => {
    try {
        const response = await axios.post(`${MCP_SERVER_URL}/api`, {
            method: 'get_attack_correlation',
            params: {}
        });
        
        res.json(response.data);
    } catch (error) {
        console.error('Error fetching correlation data:', error);
        res.status(500).json({ error: 'Failed to fetch correlation data' });
    }
});

// WebSocket connection handling
wss.on('connection', (ws) => {
    console.log('New WebSocket connection');
    
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            
            // Handle authentication
            if (data.type === 'auth') {
                jwt.verify(data.token, JWT_SECRET, (err, decoded) => {
                    if (!err) {
                        ws.authenticated = true;
                        ws.username = decoded.username;
                        ws.send(JSON.stringify({ type: 'auth_success' }));
                    } else {
                        ws.send(JSON.stringify({ type: 'auth_failed' }));
                        ws.close();
                    }
                });
            }
        } catch (error) {
            console.error('WebSocket message error:', error);
        }
    });
    
    ws.on('close', () => {
        console.log('WebSocket connection closed');
    });
});

// Broadcast to all authenticated WebSocket clients
function broadcast(data) {
    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN && client.authenticated) {
            client.send(JSON.stringify(data));
        }
    });
}

// Real-time alert stream (simulate for demo)
setInterval(async () => {
    try {
        // Fetch latest alerts from MCP server
        const response = await axios.post(`${MCP_SERVER_URL}/api`, {
            method: 'get_alerts',
            params: { count: 5 }
        });
        
        const alerts = response.data.alerts || [];
        
        if (alerts.length > 0) {
            broadcast({
                type: 'new_alerts',
                data: alerts
            });
        }
    } catch (error) {
        console.error('Error fetching real-time alerts:', error.message);
    }
}, 5000); // Check every 5 seconds

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date() });
});

// Start server
app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════╗
║   Security Operations Center Server    ║
╠════════════════════════════════════════╣
║   Express Server: http://localhost:${PORT}   ║
║   WebSocket:      ws://localhost:3001   ║
║   MCP Server:     ${MCP_SERVER_URL}     ║
╠════════════════════════════════════════╣
║   Default Login:                       ║
║   Username: admin                      ║
║   Password: admin                      ║
║   MFA Code: 123456 (demo)              ║
╚════════════════════════════════════════╝
    `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    app.close(() => {
        console.log('HTTP server closed');
    });
    wss.close(() => {
        console.log('WebSocket server closed');
    });
});
