let currentAttackData = null;
let investigationPanelOpen = false;

// DOM Content Loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    setupEventListeners();
    loadInitialData();
});

// Initialize Charts
function initializeCharts() {
    // Attack Type Chart
    const attackTypeCtx = document.getElementById('attackTypeChart');
    if (attackTypeCtx) {
        new Chart(attackTypeCtx, {
            type: 'doughnut',
            data: {
                labels: ['Brute Force', 'DDoS', 'Phishing', 'Malware', 'Port Scan'],
                datasets: [{
                    data: [24, 8, 16, 5, 12],
                    backgroundColor: [
                        '#e74c3c',
                        '#f39c12',
                        '#3498db',
                        '#9b59b6',
                        '#2ecc71'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    // Severity Chart
    const severityCtx = document.getElementById('severityChart');
    if (severityCtx) {
        new Chart(severityCtx, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    label: 'Number of Attacks',
                    data: [5, 8, 12, 20],
                    backgroundColor: [
                        '#e74c3c',
                        '#f39c12',
                        '#3498db',
                        '#2ecc71'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }

    // Attack Trend Chart
    const attackTrendCtx = document.getElementById('attackChart');
    if (attackTrendCtx) {
        new Chart(attackTrendCtx, {
            type: 'line',
            data: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                datasets: [
                    {
                        label: 'Brute Force',
                        data: [12, 19, 15, 17, 14, 16, 24],
                        borderColor: '#e74c3c',
                        tension: 0.1,
                        fill: false
                    },
                    {
                        label: 'DDoS',
                        data: [5, 8, 4, 6, 9, 7, 8],
                        borderColor: '#f39c12',
                        tension: 0.1,
                        fill: false
                    },
                    {
                        label: 'Phishing',
                        data: [8, 12, 10, 11, 13, 10, 16],
                        borderColor: '#3498db',
                        tension: 0.1,
                        fill: false
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Attacks This Week'
                    }
                }
            }
        });
    }

    // Bot Chart
    const botCtx = document.getElementById('botChart');
    if (botCtx) {
        new Chart(botCtx, {
            type: 'doughnut',
            data: {
                labels: ['Honeypots Active', 'Traps Triggered', 'Data Collected'],
                datasets: [{
                    data: [15, 8, 24],
                    backgroundColor: [
                        '#3498db',
                        '#2ecc71',
                        '#f39c12'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }
}

// Setup Event Listeners
function setupEventListeners() {
    // Menu navigation
    const menuItems = document.querySelectorAll('.menu-item');
    menuItems.forEach(item => {
        item.addEventListener('click', function() {
            const targetPage = this.id.replace('-link', '') + '.html';
            window.location.href = targetPage;
        });
    });

    // Investigation buttons
    const investigateButtons = document.querySelectorAll('.investigate-btn');
    investigateButtons.forEach(button => {
        button.addEventListener('click', function() {
            const attackId = this.getAttribute('data-attack-id');
            openInvestigationPanel(attackId);
        });
    });

    // Close investigation panel
    const closePanelBtn = document.getElementById('close-panel');
    if (closePanelBtn) {
        closePanelBtn.addEventListener('click', closeInvestigationPanel);
    }

    // Overlay click to close panel
    const overlay = document.getElementById('overlay');
    if (overlay) {
        overlay.addEventListener('click', closeInvestigationPanel);
    }

    // View transaction details
    const viewDetailsButtons = document.querySelectorAll('.view-details');
    viewDetailsButtons.forEach(button => {
        button.addEventListener('click', function() {
            const txId = this.getAttribute('data-tx');
            showTransactionDetails(txId);
        });
    });

    // Escape key to close panel
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && investigationPanelOpen) {
            closeInvestigationPanel();
        }
    });
}

// Load Initial Data
function loadInitialData() {
    // Simulate loading data from API
    setTimeout(() => {
        updateStats();
        updateRecentAttacks();
    }, 1000);
}

// Update Stats
function updateStats() {
    // In a real app, this would fetch from /api/stats
    console.log('Updating stats...');
}

// Update Recent Attacks
function updateRecentAttacks() {
    // In a real app, this would fetch from /api/attacks
    console.log('Updating recent attacks...');
}

// Open Investigation Panel
function openInvestigationPanel(attackId) {
    const panel = document.getElementById('investigation-panel');
    const overlay = document.getElementById('overlay');
    
    if (panel && overlay) {
        // Load attack data (simulated)
        loadAttackData(attackId);
        
        panel.classList.add('active');
        overlay.classList.add('active');
        investigationPanelOpen = true;
        
        // Prevent body scrolling
        document.body.style.overflow = 'hidden';
    }
}

// Close Investigation Panel
function closeInvestigationPanel() {
    const panel = document.getElementById('investigation-panel');
    const overlay = document.getElementById('overlay');
    
    if (panel && overlay) {
        panel.classList.remove('active');
        overlay.classList.remove('active');
        investigationPanelOpen = false;
        
        // Allow body scrolling
        document.body.style.overflow = 'auto';
    }
}

// Load Attack Data
function loadAttackData(attackId) {
    // Simulated attack data
    const attackData = {
        'attack-1': {
            type: 'Brute Force',
            ip: '192.168.23.45',
            time: '2023-10-05 14:32:18',
            severity: 'Critical'
        },
        'attack-2': {
            type: 'DDoS',
            ip: '103.216.184.72',
            time: '2023-10-05 13:15:42',
            severity: 'High'
        },
        'attack-3': {
            type: 'Phishing',
            ip: '89.238.162.134',
            time: '2023-10-05 11:42:05',
            severity: 'Medium'
        }
    };
    
    const attack = attackData[attackId];
    if (attack) {
        document.getElementById('investigation-type').textContent = attack.type;
        document.getElementById('investigation-ip').textContent = attack.ip;
        document.getElementById('investigation-time').textContent = attack.time;
        document.getElementById('investigation-severity').textContent = attack.severity;
    }
}

// Show Transaction Details
function showTransactionDetails(txId) {
    // Simulated transaction data
    const transactions = {
        'tx1': {
            hash: '0x4a3b...c89d',
            block: '#12345',
            from: '0x742d...a89b',
            to: '0x893c...d72e',
            value: '0.05 ETH',
            gas: '21,000',
            time: '2023-10-05 14:32:18'
        },
        'tx2': {
            hash: '0x5c2d...f76a',
            block: '#12344',
            from: '0x893c...d72e',
            to: '0x742d...a89b',
            value: '0.02 ETH',
            gas: '18,500',
            time: '2023-10-05 13:15:42'
        },
        'tx3': {
            hash: '0x6e1f...a54b',
            block: '#12343',
            from: '0xa45e...c39f',
            to: '0x893c...d72e',
            value: '0.01 ETH',
            gas: '19,200',
            time: '2023-10-05 11:42:05'
        }
    };
    
    const tx = transactions[txId];
    if (tx) {
        document.getElementById('detail-hash').textContent = tx.hash;
        document.getElementById('detail-block').textContent = tx.block;
        document.getElementById('detail-from').textContent = tx.from;
        document.getElementById('detail-to').textContent = tx.to;
        document.getElementById('detail-value').textContent = tx.value;
        document.getElementById('detail-gas').textContent = tx.gas;
        document.getElementById('detail-time').textContent = tx.time;
        
        document.getElementById('transaction-details').classList.add('show');
    }
}

// Export Data
function exportData(format) {
    console.log(`Exporting data in ${format} format...`);
    // In a real app, this would trigger a download
    alert(`Data exported as ${format.toUpperCase()}`);
}

// Block Source
function blockSource(ip) {
    console.log(`Blocking source IP: ${ip}`);
    // In a real app, this would send a request to the backend
    alert(`IP ${ip} has been blocked.`);
}

// Simulate Real-time Updates
function simulateRealTimeUpdates() {
    setInterval(() => {
        // Randomly update stats
        const statCards = document.querySelectorAll('.stat-value');
        statCards.forEach(card => {
            const currentValue = parseInt(card.textContent);
            const newValue = currentValue + Math.floor(Math.random() * 5);
            card.textContent = newValue;
        });
    }, 30000); // Update every 30 seconds
}

// Start simulation when page loads
if (document.getElementById('dashboard-link')) {
    simulateRealTimeUpdates();
}
