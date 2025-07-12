// Web Vulnerability Scanner UI Script
class VulnerabilityScannerUI {
    constructor() {
        this.initializeEventListeners();
        this.pollInterval = null;
    }

    initializeEventListeners() {
        const scanForm = document.getElementById('scanForm');
        if (scanForm) {
            scanForm.addEventListener('submit', (e) => this.handleScanSubmit(e));
        }
    }

    async handleScanSubmit(e) {
        e.preventDefault();
        
        const url = document.getElementById('url').value;
        const scanButton = document.getElementById('scanButton');
        const loading = document.getElementById('loading');
        const results = document.getElementById('results');
        const error = document.getElementById('error');
        
        if (!url) {
            this.showError('Please enter a valid URL');
            return;
        }

        // Show loading with progress
        scanButton.disabled = true;
        loading.style.display = '';
        results.style.display = 'none';
        error.style.display = 'none';
        this.updateProgressBar(0, 'Initializing scan...');

        try {
            // Start scan and get scanId
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            const data = await response.json();
            if (!data.success) throw new Error(data.error || 'Scan failed');
            const scanId = data.scanId;
            // Poll for progress
            await this.pollProgress(scanId);
        } catch (err) {
            this.showError(`Error: ${err.message}`);
            scanButton.disabled = false;
            loading.style.display = 'none';
        }
    }

    async pollProgress(scanId) {
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');
        const scanButton = document.getElementById('scanButton');
        const loading = document.getElementById('loading');
        const results = document.getElementById('results');
        const error = document.getElementById('error');
        let done = false;
        while (!done) {
            try {
                const res = await fetch(`/api/progress?scanId=${encodeURIComponent(scanId)}`);
                const data = await res.json();
                this.updateProgressBar(data.progress, data.step);
                done = data.done;
                if (done) break;
                await new Promise(r => setTimeout(r, 500));
            } catch (err) {
                this.showError('Lost connection to server.');
                scanButton.disabled = false;
                loading.style.display = 'none';
                return;
            }
        }
        // Fetch results
        let resultsData = null;
        for (let i = 0; i < 10; i++) {
            const res = await fetch(`/api/results?scanId=${encodeURIComponent(scanId)}`);
            if (res.status === 202) {
                await new Promise(r => setTimeout(r, 500));
                continue;
            }
            const data = await res.json();
            if (data.success) {
                resultsData = data.results;
                break;
            }
        }
        scanButton.disabled = false;
        loading.style.display = 'none';
        if (resultsData) {
            this.displayResults(resultsData);
        } else {
            this.showError('Failed to fetch scan results.');
        }
    }

    updateProgressBar(progress, step) {
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');
        if (progressBar) progressBar.style.width = `${progress}%`;
        if (progressText) progressText.textContent = step + ` (${progress}%)`;
    }

    showError(message) {
        const error = document.getElementById('error');
        if (error) {
            error.textContent = message;
            error.style.display = '';
        }
    }

    displayResults(results) {
        if (!results || typeof results !== 'object') {
            this.showError('Scan failed or returned no results.');
            return;
        }
        const vulnerabilities = Array.isArray(results.vulnerabilities) ? results.vulnerabilities : [];
        const info = Array.isArray(results.info) ? results.info : [];
        const warnings = Array.isArray(results.warnings) ? results.warnings : [];
        const resultsDiv = document.getElementById('results');
        const summaryGrid = document.getElementById('summaryGrid');
        if (!resultsDiv || !summaryGrid) return;
        // Display summary
        const summary = {
            critical: vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
            high: vulnerabilities.filter(v => v.severity === 'HIGH').length,
            medium: vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
            low: vulnerabilities.filter(v => v.severity === 'LOW').length,
            info: info.length,
            warnings: warnings.length
        };
        summaryGrid.innerHTML = `
            <div class="summary-item critical">Critical<br><span>${summary.critical}</span></div>
            <div class="summary-item high">High<br><span>${summary.high}</span></div>
            <div class="summary-item medium">Medium<br><span>${summary.medium}</span></div>
            <div class="summary-item low">Low<br><span>${summary.low}</span></div>
            <div class="summary-item info">Info<br><span>${summary.info}</span></div>
            <div class="summary-item warning">Warnings<br><span>${summary.warnings}</span></div>
        `;
        this.displaySection('vulnerabilitiesSection', 'vulnerabilitiesList', vulnerabilities, 'vuln-item');
        this.displaySection('warningsSection', 'warningsList', warnings, 'vuln-item warning');
        this.displaySection('infoSection', 'infoList', info, 'vuln-item info');
        resultsDiv.style.display = '';
    }

    displaySection(sectionId, listId, items, className) {
        const section = document.getElementById(sectionId);
        const list = document.getElementById(listId);
        if (!section || !list) return;
        if (items.length > 0) {
            list.innerHTML = items.map(item => `
                <div class="${className}">
                    <div class="vuln-title">${item.type} <span style="font-size:0.8em;opacity:0.7;">(${item.severity})</span></div>
                    <div class="vuln-desc">${item.description}</div>
                    ${item.details ? `<div class="vuln-details">${typeof item.details === 'object' ? JSON.stringify(item.details) : item.details}</div>` : ''}
                    ${item.recommendation ? `<div class="vuln-recommendation">💡 ${item.recommendation}</div>` : ''}
                </div>
            `).join('');
            section.style.display = '';
        } else {
            section.style.display = 'none';
        }
    }
}

// Initialize the UI when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new VulnerabilityScannerUI();
}); 