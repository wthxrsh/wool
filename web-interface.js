#!/usr/bin/env node

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const WebVulnerabilityScanner = require('./scanner');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

// In-memory store for scan progress and results
const scanStore = {};

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Serve the main HTML page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API endpoint for scanning (async, with progress tracking)
app.post('/api/scan', async (req, res) => {
    try {
        const { url, options = {} } = req.body;
        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }
        const scanId = uuidv4();
        scanStore[scanId] = { progress: 0, step: 'Initializing scan...', done: false, results: null };
        // Start scan in background
        (async () => {
            const scanner = new WebVulnerabilityScanner();
            const scanResults = await scanner.scan(url, options, (progressObj) => {
                scanStore[scanId].progress = progressObj.progress;
                scanStore[scanId].step = progressObj.step;
            });
            scanStore[scanId].progress = 100;
            scanStore[scanId].step = 'Scan complete!';
            scanStore[scanId].done = true;
            scanStore[scanId].results = scanResults;
        })();
        res.json({ success: true, scanId });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// API endpoint for polling scan progress
app.get('/api/progress', (req, res) => {
    const { scanId } = req.query;
    if (!scanId || !scanStore[scanId]) {
        return res.status(404).json({ error: 'Scan not found' });
    }
    const { progress, step, done } = scanStore[scanId];
    res.json({ progress, step, done });
});

// API endpoint for getting scan results
app.get('/api/results', (req, res) => {
    const { scanId } = req.query;
    if (!scanId || !scanStore[scanId]) {
        return res.status(404).json({ error: 'Scan not found' });
    }
    if (!scanStore[scanId].done) {
        return res.status(202).json({ error: 'Scan not complete' });
    }
    res.json({ success: true, results: scanStore[scanId].results });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
    console.log(`🌐 Web Vulnerability Scanner running on http://localhost:${PORT}`);
    console.log(`📊 API available at http://localhost:${PORT}/api/scan`);
});

module.exports = app; 