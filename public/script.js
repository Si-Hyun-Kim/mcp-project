// Global variables
let currentUser = null;
let mockData = {
    alerts: [],
    rules: [],
    reports: []
};

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    initializeMockData();
    setupEventListeners();
    
    // Auto-update every 5 seconds
    setInterval(updateDashboard, 5000);
});

// Setup event listeners
function setupEventListeners() {
    // Login form
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    
    // MFA inputs
    document.querySelectorAll('.mfa-input').forEach((input, index) => {
        input.addEventListener('input', function(e) {
            if (e.target.value) {
                if (index < 5) {
                    document.querySelectorAll('.mfa-input')[index + 1].focus();
                } else {
                    verifyMFA();
                }
            }
        });
        
        input.addEventListener('keydown', function(e) {
            if (e.key === 'Backspace' && !e.target.value && index > 0) {
                document.querySelectorAll('.mfa-input')[index - 1].focus();
            }
        });
    });
    
    // Navigation tabs
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.addEventListener('click', function() {
            switchPage(this.dataset.page);
        });
    });
    
    // Chart time range buttons
    document.querySelectorAll('.chart-option').forEach(btn => {
        btn.addEventListener('click', function() {
            document.querySelectorAll('.chart-option').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            updateChart(this.dataset.range);
        });
    });
}

// Login handler
function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    // Simple validation (in production, this would be server-side)
    if (username === 'admin' && password === 'admin') {
        document.getElementById('mfaContainer').style.display = 'block';
        document.querySelectorAll('.mfa-input')[0].focus();
        showToast('Enter verification code', 'success');
    } else {
        showToast('Invalid credentials', 'error');
    }
}

// MFA verification
function verifyMFA() {
    const code = Array.from(document.querySelectorAll('.mfa-input'))
        .map(input => input.value)
        .join('');
    
    // Simple MFA check (in production, this would be server-side)
    if (code === '123456') {
        currentUser = 'admin';
        document.getElementById('loginContainer').style.display = 'none';
        document.getElementById('dashboard').style.display = 'block';
        initializeDashboard();
        showToast('Welcome to Security Operations Center', 'success');
    } else {
        showToast('Invalid verification code', 'error');
        document.querySelectorAll('.mfa-input').forEach(input => input.value = '');
        document.querySelectorAll('.mfa-input')[0].focus();
    }
}

// Initialize dashboard
function initializeDashboard() {
    updateStats();
    initializeCharts();
    loadAlerts();
    loadRules();
    loadReports();
    loadComparison();
}

// Initialize mock data
function initializeMockData() {
    // Generate mock alerts
    const attackTypes = ['SQL Injection', 'XSS Attack', 'DDoS', 'Port Scan', 'Brute Force', 'Malware', 'Data Exfiltration'];
    const severities = ['critical', 'high', 'medium', 'low'];
    
    for (let i = 0; i < 100; i++) {
        const timestamp = new Date(Date.now() - Math.random() * 86400000 * 7);
        mockData.alerts.push({
            id: i + 1,
            timestamp: timestamp,
            sourceIP: `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
            destIP: `192.168.1.${Math.floor(Math.random() * 256)}`,
            port: Math.floor(Math.random() * 65535),
            protocol: Math.random() > 0.5 ? 'TCP' : 'UDP',
            attackType: attackTypes[Math.floor(Math.random() * attackTypes.length)],
            severity: severities[Math.floor(Math.random() * severities.length)],
            count: Math.floor(Math.random() * 50) + 1,
            blocked: Math.random() > 0.3
        });
    }
    
    // Generate mock rules
    const ruleCategories = ['Network', 'Application', 'Malware', 'Exploit', 'Policy'];
    for (let i = 0; i < 20; i++) {
        mockData.rules.push({
            id: 2000000 + i,
            name: `ET ${ruleCategories[Math.floor(Math.random() * ruleCategories.length)]} Rule ${i + 1}`,
            description: `Detects suspicious ${attackTypes[Math.floor(Math.random() * attackTypes.length)]} activity`,
            category: ruleCategories[Math.floor(Math.random() * ruleCategories.length)],
            hits: Math.floor(Math.random() * 1000),
            enabled: Math.random() > 0.2,
            lastModified: new Date(Date.now() - Math.random() * 86400000 * 30)
        });
    }
    
    // Generate mock reports
    const reportTypes = ['executive', 'technical', 'incident', 'compliance'];
    for (let i = 0; i < 10; i++) {
        mockData.reports.push({
            id: i + 1,
            name: `Security_Report_${new Date().toISOString().split('T')[0]}_${i + 1}`,
            type: reportTypes[Math.floor(Math.random() * reportTypes.length)],
            startDate: new Date(Date.now() - Math.random() * 86400000 * 30),
            endDate: new Date(),
            generatedAt: new Date(Date.now() - Math.random() * 86400000 * 7),
            size: `${(Math.random() * 5 + 0.5).toFixed(2)} MB`,
            format: ['pdf', 'excel', 'json'][Math.floor(Math.random() * 3)]
        });
    }
}

// Update dashboard stats
function updateStats() {
    const now = Date.now();
    const last24h = mockData.alerts.filter(a => now - a.timestamp < 86400000);
    const blocked = last24h.filter(a => a.blocked);
    const critical = last24h.filter(a => a.severity === 'critical');
    const activeRules = mockData.rules.filter(r => r.enabled);
    
    document.getElementById('totalAlerts').textContent = last24h.length.toLocaleString();
    document.getElementById('blockedAttacks').textContent = blocked.length.toLocaleString();
    document.getElementById('criticalThreats').textContent = critical.length.toLocaleString();
    document.getElementById('activeRules').textContent = activeRules.length.toLocaleString();
}

// Initialize charts
let attackChart, comparisonChart;

function initializeCharts() {
    // Attack Timeline Chart
    const ctx1 = document.getElementById('attackChart').getContext('2d');
    attackChart = new Chart(ctx1, {
        type: 'line',
        data: {
            labels: generateTimeLabels(24),
            datasets: [{
                label: 'Attacks',
                data: generateRandomData(24, 10, 100),
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                tension: 0.4
            }, {
                label: 'Blocked',
                data: generateRandomData(24, 5, 80),
                borderColor: '#10b981',
                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#e2e8f0' }
                }
            },
            scales: {
                x: {
                    grid: { color: '#2a3142' },
                    ticks: { color: '#94a3b8' }
                },
                y: {
                    grid: { color: '#2a3142' },
                    ticks: { color: '#94a3b8' }
                }
            }
        }
    });
    
    // Comparison Chart
    const ctx2 = document.getElementById('comparisonChart');
    if (ctx2) {
        comparisonChart = new Chart(ctx2.getContext('2d'), {
            type: 'bar',
            data: {
                labels: ['SQL Injection', 'XSS', 'DDoS', 'Port Scan', 'Brute Force'],
                datasets: [{
                    label: 'Attempted',
                    data: [45, 38, 52, 41, 35],
                    backgroundColor: '#ef4444'
                }, {
                    label: 'Blocked',
                    data: [42, 35, 48, 38, 33],
                    backgroundColor: '#10b981'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#e2e8f0' }
                    }
                },
                scales: {
                    x: {
                        grid: { color: '#2a3142' },
                        ticks: { color: '#94a3b8' }
                    },
                    y: {
                        grid: { color: '#2a3142' },
                        ticks: { color: '#94a3b8' }
                    }
                }
            }
        });
    }
}

// Load alerts
function loadAlerts() {
    const tbody = document.getElementById('recentAlertsTable');
    const fullTbody = document.getElementById('alertsTable');
    
    if (tbody) {
        tbody.innerHTML = mockData.alerts.slice(0, 5).map(alert => `
            <tr>
                <td>${alert.timestamp.toLocaleTimeString()}</td>
                <td>${alert.sourceIP}</td>
                <td>${alert.attackType}</td>
                <td><span class="severity-badge severity-${alert.severity}">${alert.severity.toUpperCase()}</span></td>
                <td>${alert.blocked ? '🟢 Blocked' : '🔴 Detected'}</td>
                <td><button class="action-btn" onclick="blockIP('${alert.sourceIP}')">Block IP</button></td>
            </tr>
        `).join('');
    }
    
    if (fullTbody) {
        fullTbody.innerHTML = mockData.alerts.map(alert => `
            <tr>
                <td>${alert.timestamp.toLocaleString()}</td>
                <td>${alert.sourceIP}</td>
                <td>${alert.destIP}</td>
                <td>${alert.port}</td>
                <td>${alert.protocol}</td>
                <td>${alert.attackType}</td>
                <td><span class="severity-badge severity-${alert.severity}">${alert.severity.toUpperCase()}</span></td>
                <td>${alert.count}</td>
                <td>
                    ${alert.blocked ? 
                        '<span style="color: #10b981">✓ Blocked</span>' : 
                        `<button class="action-btn" onclick="blockIP('${alert.sourceIP}')">Block</button>`
                    }
                </td>
            </tr>
        `).join('');
    }
}

// Load IPS rules
function loadRules() {
    const container = document.getElementById('rulesGrid');
    if (container) {
        container.innerHTML = mockData.rules.map(rule => `
            <div class="rule-card">
                <div class="rule-info">
                    <div class="rule-name">SID:${rule.id} - ${rule.name}</div>
                    <div class="rule-description">${rule.description}</div>
                    <div class="rule-meta">
                        <span>Category: ${rule.category}</span>
                        <span>Hits: ${rule.hits}</span>
                        <span>Modified: ${rule.lastModified.toLocaleDateString()}</span>
                    </div>
                </div>
                <div class="rule-status">
                    <div class="toggle-switch ${rule.enabled ? 'active' : ''}" onclick="toggleRule(${rule.id})">
                        <div class="toggle-slider"></div>
                    </div>
                </div>
            </div>
        `).join('');
    }
}

// Load reports
function loadReports() {
    const tbody = document.getElementById('reportsTable');
    if (tbody) {
        tbody.innerHTML = mockData.reports.map(report => `
            <tr>
                <td>${report.name}</td>
                <td>${report.type.charAt(0).toUpperCase() + report.type.slice(1)}</td>
                <td>${report.startDate.toLocaleDateString()} - ${report.endDate.toLocaleDateString()}</td>
                <td>${report.generatedAt.toLocaleString()}</td>
                <td>${report.size}</td>
                <td>
                    <button class="action-btn" onclick="downloadReport(${report.id})">Download</button>
                </td>
            </tr>
        `).join('');
    }
}

// Load comparison timeline
function loadComparison() {
    const defenseTimeline = document.getElementById('defenseTimeline');
    const attackTimeline = document.getElementById('attackTimeline');
    
    if (defenseTimeline) {
        const defenseEvents = [
            { time: '10:23:45', event: 'IPS Rule triggered: SQL Injection attempt blocked' },
            { time: '10:24:12', event: 'Automatic firewall rule added for IP 203.0.113.45' },
            { time: '10:25:03', event: 'Port scan detection activated' },
            { time: '10:26:18', event: 'DDoS mitigation enabled' },
            { time: '10:27:41', event: 'Malware signature updated' }
        ];
        
        defenseTimeline.innerHTML = defenseEvents.map(event => `
            <div class="timeline-event">
                <div class="timeline-time">${event.time}</div>
                <div class="timeline-content">${event.event}</div>
            </div>
        `).join('');
    }
    
    if (attackTimeline) {
        const attackEvents = [
            { time: '10:23:40', event: 'HexStrike AI: SQL injection payload generated' },
            { time: '10:24:05', event: 'Attack vector modified: Encoding bypass attempted' },
            { time: '10:24:58', event: 'Port scanning initiated on range 1-65535' },
            { time: '10:26:10', event: 'DDoS amplification attack launched' },
            { time: '10:27:35', event: 'Polymorphic malware variant deployed' }
        ];
        
        attackTimeline.innerHTML = attackEvents.map(event => `
            <div class="timeline-event">
                <div class="timeline-time">${event.time}</div>
                <div class="timeline-content">${event.event}</div>
            </div>
        `).join('');
    }
}

// Helper functions
function generateTimeLabels(hours) {
    const labels = [];
    for (let i = hours - 1; i >= 0; i--) {
        const time = new Date(Date.now() - i * 3600000);
        labels.push(time.getHours() + ':00');
    }
    return labels;
}

function generateRandomData(count, min, max) {
    return Array.from({ length: count }, () => Math.floor(Math.random() * (max - min + 1)) + min);
}

function switchPage(page) {
    // Update nav tabs
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.page === page);
    });
    
    // Update pages
    document.querySelectorAll('.page').forEach(p => {
        p.classList.toggle('active', p.id === `page-${page}`);
    });
    
    // Initialize page-specific content
    if (page === 'comparison' && !comparisonChart) {
        setTimeout(() => {
            initializeCharts();
            loadComparison();
        }, 100);
    }
}

function updateChart(range) {
    let hours = 1;
    switch(range) {
        case '1h': hours = 1; break;
        case '24h': hours = 24; break;
        case '7d': hours = 168; break;
        case '30d': hours = 720; break;
    }
    
    if (attackChart) {
        attackChart.data.labels = generateTimeLabels(Math.min(hours, 24));
        attackChart.data.datasets[0].data = generateRandomData(Math.min(hours, 24), 10, 100);
        attackChart.data.datasets[1].data = generateRandomData(Math.min(hours, 24), 5, 80);
        attackChart.update();
    }
}

function blockIP(ip) {
    showToast(`Blocking IP: ${ip}`, 'success');
    setTimeout(() => {
        showToast(`IP ${ip} has been blocked successfully`, 'success');
        loadAlerts(); // Refresh the alerts table
    }, 1000);
}

function toggleRule(ruleId) {
    const rule = mockData.rules.find(r => r.id === ruleId);
    if (rule) {
        rule.enabled = !rule.enabled;
        loadRules();
        showToast(`Rule ${ruleId} ${rule.enabled ? 'enabled' : 'disabled'}`, 'success');
    }
}

function generateReport() {
    const type = document.getElementById('reportType').value;
    const startDate = document.getElementById('reportStart').value;
    const endDate = document.getElementById('reportEnd').value;
    const format = document.getElementById('reportFormat').value;
    
    if (!startDate || !endDate) {
        showToast('Please select date range', 'error');
        return;
    }
    
    showToast('Generating report...', 'success');
    
    setTimeout(() => {
        const newReport = {
            id: mockData.reports.length + 1,
            name: `Security_Report_${new Date().toISOString().split('T')[0]}_${mockData.reports.length + 1}`,
            type: type,
            startDate: new Date(startDate),
            endDate: new Date(endDate),
            generatedAt: new Date(),
            size: `${(Math.random() * 5 + 0.5).toFixed(2)} MB`,
            format: format
        };
        
        mockData.reports.unshift(newReport);
        loadReports();
        showToast('Report generated successfully', 'success');
    }, 2000);
}

function downloadReport(reportId) {
    const report = mockData.reports.find(r => r.id === reportId);
    if (report) {
        showToast(`Downloading ${report.name}.${report.format}...`, 'success');
        // In production, this would trigger actual file download
    }
}

function applyFilters() {
    const search = document.getElementById('alertSearch').value.toLowerCase();
    const severity = document.getElementById('severityFilter').value;
    const timeRange = document.getElementById('timeFilter').value;
    
    let filtered = [...mockData.alerts];
    
    if (search) {
        filtered = filtered.filter(alert => 
            alert.sourceIP.includes(search) ||
            alert.destIP.includes(search) ||
            alert.attackType.toLowerCase().includes(search) ||
            alert.port.toString().includes(search)
        );
    }
    
    if (severity) {
        filtered = filtered.filter(alert => alert.severity === severity);
    }
    
    // Apply time filter
    const now = Date.now();
    const timeMap = {
        '1h': 3600000,
        '24h': 86400000,
        '7d': 604800000,
        '30d': 2592000000
    };
    
    if (timeRange && timeMap[timeRange]) {
        filtered = filtered.filter(alert => now - alert.timestamp < timeMap[timeRange]);
    }
    
    // Update table
    const tbody = document.getElementById('alertsTable');
    if (tbody) {
        tbody.innerHTML = filtered.map(alert => `
            <tr>
                <td>${alert.timestamp.toLocaleString()}</td>
                <td>${alert.sourceIP}</td>
                <td>${alert.destIP}</td>
                <td>${alert.port}</td>
                <td>${alert.protocol}</td>
                <td>${alert.attackType}</td>
                <td><span class="severity-badge severity-${alert.severity}">${alert.severity.toUpperCase()}</span></td>
                <td>${alert.count}</td>
                <td>
                    ${alert.blocked ? 
                        '<span style="color: #10b981">✓ Blocked</span>' : 
                        `<button class="action-btn" onclick="blockIP('${alert.sourceIP}')">Block</button>`
                    }
                </td>
            </tr>
        `).join('');
    }
    
    showToast(`Showing ${filtered.length} alerts`, 'success');
}

function addNewRule() {
    showToast('Rule editor would open here', 'success');
    // In production, this would open a modal for creating new rules
}

function updateDashboard() {
    // Simulate real-time updates
    if (Math.random() > 0.7) {
        const newAlert = {
            id: mockData.alerts.length + 1,
            timestamp: new Date(),
            sourceIP: `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
            destIP: `192.168.1.${Math.floor(Math.random() * 256)}`,
            port: Math.floor(Math.random() * 65535),
            protocol: Math.random() > 0.5 ? 'TCP' : 'UDP',
            attackType: ['SQL Injection', 'XSS Attack', 'DDoS', 'Port Scan'][Math.floor(Math.random() * 4)],
            severity: ['critical', 'high', 'medium', 'low'][Math.floor(Math.random() * 4)],
            count: Math.floor(Math.random() * 50) + 1,
            blocked: Math.random() > 0.3
        };
        
        mockData.alerts.unshift(newAlert);
        
        if (newAlert.severity === 'critical') {
            showToast(`⚠️ Critical threat detected from ${newAlert.sourceIP}`, 'error');
        }
    }
    
    updateStats();
    loadAlerts();
}

function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    const toastMessage = document.getElementById('toastMessage');
    
    toast.className = `toast show toast-${type}`;
    toastMessage.textContent = message;
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function logout() {
    if (confirm('Are you sure you want to logout?')) {
        currentUser = null;
        document.getElementById('loginContainer').style.display = 'flex';
        document.getElementById('dashboard').style.display = 'none';
        document.getElementById('username').value = '';
        document.getElementById('password').value = '';
        document.querySelectorAll('.mfa-input').forEach(input => input.value = '');
        document.getElementById('mfaContainer').style.display = 'none';
        showToast('Logged out successfully', 'success');
    }
}