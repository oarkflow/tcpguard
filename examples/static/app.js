// TCPGuard Testing Dashboard JavaScript

class TCPGuardTester {
    constructor() {
        this.baseURL = window.location.origin;
        this.startTime = Date.now();
        this.isTestingDDoS = false;
        this.ddosInterval = null;
        this.logs = [];
        this.init();
    }

    init() {
        this.updateUptime();
        setInterval(() => this.updateUptime(), 1000);
        this.checkHealth();
        this.refreshMetrics();

        // Auto-refresh metrics every 5 seconds
        setInterval(() => this.refreshMetrics(), 5000);
    }

    // Utility Functions
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        document.body.appendChild(notification);

        setTimeout(() => {
            notification.remove();
        }, 3000);
    }

    addLog(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${type}`;
        logEntry.textContent = `[${timestamp}] ${message}`;

        const logsContainer = document.getElementById('logs-container');
        logsContainer.appendChild(logEntry);
        logsContainer.scrollTop = logsContainer.scrollHeight;

        // Keep only last 100 logs
        while (logsContainer.children.length > 100) {
            logsContainer.removeChild(logsContainer.firstChild);
        }
    }

    updateUptime() {
        const uptime = Math.floor((Date.now() - this.startTime) / 1000);
        const hours = Math.floor(uptime / 3600);
        const minutes = Math.floor((uptime % 3600) / 60);
        const seconds = uptime % 60;
        document.getElementById('uptime').textContent =
            `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }

    async makeRequest(endpoint, options = {}) {
        try {
            const response = await fetch(`${this.baseURL}${endpoint}`, options);
            const data = await response.json();
            return { response, data };
        } catch (error) {
            this.addLog(`Request failed: ${error.message}`, 'error');
            throw error;
        }
    }

    // Health Check
    async checkHealth() {
        try {
            const { data } = await this.makeRequest('/health');
            const healthElement = document.getElementById('health-status');

            if (data.status === 'ok') {
                healthElement.textContent = 'Healthy ✅';
                healthElement.className = 'status-value ok';
            } else {
                healthElement.textContent = 'Degraded ⚠️';
                healthElement.className = 'status-value warning';
            }

            this.addLog('Health check completed', 'success');
        } catch (error) {
            document.getElementById('health-status').textContent = 'Error ❌';
            document.getElementById('health-status').className = 'status-value error';
            this.addLog(`Health check failed: ${error.message}`, 'error');
        }
    }

    // DDoS Testing
    async testDDoS() {
        if (this.isTestingDDoS) {
            this.showNotification('DDoS test already running', 'warning');
            return;
        }

        const rate = parseInt(document.getElementById('ddos-rate').value);
        const duration = parseInt(document.getElementById('ddos-duration').value);
        const resultsDiv = document.getElementById('ddos-results');

        this.isTestingDDoS = true;
        resultsDiv.innerHTML = '<div class="loading"></div> Starting DDoS simulation...';

        let requestCount = 0;
        let successCount = 0;
        let blockedCount = 0;
        const startTime = Date.now();

        this.addLog(`Starting DDoS test: ${rate} req/sec for ${duration} seconds`, 'warning');

        this.ddosInterval = setInterval(async () => {
            const elapsed = (Date.now() - startTime) / 1000;
            if (elapsed >= duration) {
                this.stopDDoS();
                return;
            }

            // Make multiple requests per interval
            for (let i = 0; i < rate; i++) {
                try {
                    const { response } = await fetch(`${this.baseURL}/api/status`);
                    requestCount++;

                    if (response.status === 429) {
                        blockedCount++;
                    } else if (response.ok) {
                        successCount++;
                    }
                } catch (error) {
                    requestCount++;
                }
            }

            resultsDiv.innerHTML = `
                <strong>DDoS Test Progress:</strong><br>
                Elapsed: ${elapsed.toFixed(1)}s / ${duration}s<br>
                Total Requests: ${requestCount}<br>
                Successful: ${successCount}<br>
                Rate Limited: ${blockedCount}<br>
                Success Rate: ${requestCount > 0 ? ((successCount / requestCount) * 100).toFixed(1) : 0}%
            `;
        }, 1000);
    }

    stopDDoS() {
        if (this.ddosInterval) {
            clearInterval(this.ddosInterval);
            this.ddosInterval = null;
        }
        this.isTestingDDoS = false;
        document.getElementById('ddos-results').innerHTML = 'DDoS test stopped';
        this.addLog('DDoS test completed', 'success');
    }

    // MITM Testing
    async testMITM() {
        const userAgent = document.getElementById('user-agent-select').value;
        const resultsDiv = document.getElementById('mitm-results');

        resultsDiv.innerHTML = '<div class="loading"></div> Testing MITM detection...';

        try {
            const { response, data } = await this.makeRequest('/api/status', {
                headers: {
                    'User-Agent': userAgent
                }
            });

            let result = `User Agent: ${userAgent}<br>`;
            result += `Response Status: ${response.status}<br>`;

            if (response.status === 403) {
                result += '<span style="color: #e74c3c;">🚫 MITM Detected!</span>';
                resultsDiv.className = 'results-display error';
            } else {
                result += '<span style="color: #27ae60;">✅ Request allowed</span>';
                resultsDiv.className = 'results-display success';
            }

            resultsDiv.innerHTML = result;
            this.addLog(`MITM test completed with status ${response.status}`, response.status === 403 ? 'warning' : 'success');

        } catch (error) {
            resultsDiv.innerHTML = `Error: ${error.message}`;
            resultsDiv.className = 'results-display error';
            this.addLog(`MITM test failed: ${error.message}`, 'error');
        }
    }

    // Business Hours Testing
    async testBusinessHours() {
        const testTime = document.getElementById('test-time').value;
        const timezone = document.getElementById('timezone-select').value;
        const resultsDiv = document.getElementById('business-hours-results');

        resultsDiv.innerHTML = '<div class="loading"></div> Testing business hours...';

        try {
            // This would normally test against the business hours rule
            // For demo purposes, we'll simulate the logic
            const [hours, minutes] = testTime.split(':').map(Number);
            const testDateTime = new Date();
            testDateTime.setHours(hours, minutes);

            const dayOfWeek = testDateTime.getDay();
            const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;
            const isBusinessHours = hours >= 9 && hours < 17 && !isWeekend;

            let result = `Test Time: ${testTime}<br>`;
            result += `Timezone: ${timezone}<br>`;
            result += `Day: ${['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'][dayOfWeek]}<br>`;

            if (isBusinessHours) {
                result += '<span style="color: #27ae60;">✅ Within business hours</span>';
                resultsDiv.className = 'results-display success';
            } else {
                result += '<span style="color: #e74c3c;">🚫 Outside business hours</span>';
                resultsDiv.className = 'results-display warning';
            }

            resultsDiv.innerHTML = result;
            this.addLog('Business hours test completed', 'success');

        } catch (error) {
            resultsDiv.innerHTML = `Error: ${error.message}`;
            resultsDiv.className = 'results-display error';
            this.addLog(`Business hours test failed: ${error.message}`, 'error');
        }
    }

    // Protected Routes Testing
    async testProtectedRoute() {
        const authHeader = document.getElementById('auth-header').value;
        const route = document.getElementById('protected-route-select').value;
        const resultsDiv = document.getElementById('protected-routes-results');

        resultsDiv.innerHTML = '<div class="loading"></div> Testing protected route...';

        const headers = {};
        if (authHeader) {
            headers['Authorization'] = authHeader;
        }

        try {
            const { response, data } = await this.makeRequest(route, {
                headers: headers
            });

            let result = `Route: ${route}<br>`;
            result += `Authorization: ${authHeader || 'None'}<br>`;
            result += `Response Status: ${response.status}<br>`;

            if (response.status === 401) {
                result += '<span style="color: #e74c3c;">🚫 Access denied - authentication required</span>';
                resultsDiv.className = 'results-display error';
            } else if (response.ok) {
                result += '<span style="color: #27ae60;">✅ Access granted</span>';
                resultsDiv.className = 'results-display success';
            } else {
                result += `<span style="color: #f39c12;">⚠️ Unexpected response</span>`;
                resultsDiv.className = 'results-display warning';
            }

            resultsDiv.innerHTML = result;
            this.addLog(`Protected route test completed with status ${response.status}`, response.status === 401 ? 'warning' : 'success');

        } catch (error) {
            resultsDiv.innerHTML = `Error: ${error.message}`;
            resultsDiv.className = 'results-display error';
            this.addLog(`Protected route test failed: ${error.message}`, 'error');
        }
    }

    // Session Hijacking Testing
    async testSessionHijacking() {
        const userId = document.getElementById('user-id').value;
        const userAgent = document.getElementById('session-user-agent').value;
        const concurrentSessions = parseInt(document.getElementById('concurrent-sessions').value);
        const resultsDiv = document.getElementById('session-results');

        resultsDiv.innerHTML = '<div class="loading"></div> Testing session security...';

        try {
            let blockedCount = 0;
            let successCount = 0;

            // Simulate multiple concurrent sessions
            for (let i = 0; i < concurrentSessions; i++) {
                const sessionUserAgent = i === 0 ? userAgent : `${userAgent} Session ${i}`;

                const { response } = await this.makeRequest('/api/protected', {
                    headers: {
                        'User-Agent': sessionUserAgent,
                        'X-User-ID': userId
                    }
                });

                if (response.status === 403) {
                    blockedCount++;
                } else if (response.ok) {
                    successCount++;
                }
            }

            let result = `User ID: ${userId}<br>`;
            result += `Concurrent Sessions: ${concurrentSessions}<br>`;
            result += `Successful: ${successCount}<br>`;
            result += `Blocked: ${blockedCount}<br>`;

            if (blockedCount > 0) {
                result += '<span style="color: #e74c3c;">🚫 Session hijacking detected!</span>';
                resultsDiv.className = 'results-display warning';
            } else {
                result += '<span style="color: #27ae60;">✅ All sessions valid</span>';
                resultsDiv.className = 'results-display success';
            }

            resultsDiv.innerHTML = result;
            this.addLog(`Session test completed: ${successCount} valid, ${blockedCount} blocked`, blockedCount > 0 ? 'warning' : 'success');

        } catch (error) {
            resultsDiv.innerHTML = `Error: ${error.message}`;
            resultsDiv.className = 'results-display error';
            this.addLog(`Session test failed: ${error.message}`, 'error');
        }
    }

    // Login Testing
    async testLogin() {
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;
        const resultsDiv = document.getElementById('login-results');

        resultsDiv.innerHTML = '<div class="loading"></div> Testing login...';

        try {
            const { response, data } = await this.makeRequest('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: username,
                    password: password
                })
            });

            let result = `Username: ${username}<br>`;
            result += `Response Status: ${response.status}<br>`;

            if (response.ok) {
                result += '<span style="color: #27ae60;">✅ Login successful</span>';
                resultsDiv.className = 'results-display success';
            } else {
                result += '<span style="color: #e74c3c;">🚫 Login failed</span>';
                resultsDiv.className = 'results-display error';
            }

            resultsDiv.innerHTML = result;
            this.addLog(`Login test completed with status ${response.status}`, response.ok ? 'success' : 'warning');

        } catch (error) {
            resultsDiv.innerHTML = `Error: ${error.message}`;
            resultsDiv.className = 'results-display error';
            this.addLog(`Login test failed: ${error.message}`, 'error');
        }
    }

    async testFailedLogin() {
        // Temporarily change credentials to force failure
        const originalUsername = document.getElementById('login-username').value;
        const originalPassword = document.getElementById('login-password').value;

        document.getElementById('login-username').value = 'wronguser';
        document.getElementById('login-password').value = 'wrongpass';

        await this.testLogin();

        // Restore original values
        document.getElementById('login-username').value = originalUsername;
        document.getElementById('login-password').value = originalPassword;
    }

    // Metrics Refresh
    async refreshMetrics() {
        try {
            // In a real implementation, you'd have a metrics endpoint
            // For demo purposes, we'll simulate some metrics
            const metrics = {
                totalRequests: Math.floor(Math.random() * 1000) + 500,
                blockedRequests: Math.floor(Math.random() * 50) + 10,
                activeSessions: Math.floor(Math.random() * 20) + 5,
                ddosDetections: Math.floor(Math.random() * 10) + 1
            };

            document.getElementById('total-requests').textContent = metrics.totalRequests;
            document.getElementById('blocked-requests').textContent = metrics.blockedRequests;
            document.getElementById('active-sessions').textContent = metrics.activeSessions;
            document.getElementById('ddos-detections').textContent = metrics.ddosDetections;

        } catch (error) {
            this.addLog(`Metrics refresh failed: ${error.message}`, 'error');
        }
    }

    // Clear Logs
    clearLogs() {
        document.getElementById('logs-container').innerHTML = '<div class="log-entry">Logs cleared</div>';
        this.addLog('Logs cleared by user', 'info');
    }
}

// Initialize the tester when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.tcpGuardTester = new TCPGuardTester();
});
