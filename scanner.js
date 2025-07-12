#!/usr/bin/env node

const axios = require('axios');
const cheerio = require('cheerio');
const chalk = require('chalk');
const { Command } = require('commander');
const ora = require('ora').default;
const { createTable } = require('table');
const https = require('https');
const http = require('http');
const url = require('url');
const fs = require('fs');

class WebVulnerabilityScanner {
    constructor() {
        this.results = [];
        this.spinner = null;
        this.config = {
            timeout: 10000,
            maxRedirects: 5,
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        };
    }

    async scan(targetUrl, options = {}, progressCallback = null) {
        console.log(chalk.blue.bold('\n🔍 Web Vulnerability Scanner Starting...\n'));
        console.log(chalk.yellow(`Target: ${targetUrl}\n`));

        this.spinner = ora('Initializing scan...').start();

        try {
            // Normalize URL
            const normalizedUrl = this.normalizeUrl(targetUrl);
            
            // Perform comprehensive scan with progress callback
            const scanResults = await this.performComprehensiveScan(normalizedUrl, options, progressCallback);
            
            this.spinner.succeed('Scan completed!');
            
            // Display results
            this.displayResults(scanResults);
            
            return scanResults;
        } catch (error) {
            this.spinner.fail('Scan failed!');
            console.error(chalk.red('Error:'), error.message);
            return null;
        }
    }

    normalizeUrl(urlString) {
        if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
            urlString = 'https://' + urlString;
        }
        return urlString;
    }

    async performComprehensiveScan(targetUrl, options, progressCallback = null) {
        const results = {
            target: targetUrl,
            timestamp: new Date().toISOString(),
            vulnerabilities: [],
            info: [],
            warnings: []
        };
        const steps = [
            { fn: this.checkSSLSecurity, label: 'Checking SSL/TLS security...' },
            { fn: this.checkSecurityHeaders, label: 'Analyzing security headers...' },
            { fn: this.checkXSSVulnerabilities, label: 'Testing for XSS vulnerabilities...' },
            { fn: this.checkSQLInjection, label: 'Checking SQL injection...' },
            { fn: this.checkDirectoryTraversal, label: 'Scanning for directory traversal...' },
            { fn: this.checkInformationDisclosure, label: 'Checking information disclosure...' },
            { fn: this.checkCSRFVulnerabilities, label: 'Testing CSRF protection...' },
            { fn: this.checkOpenRedirects, label: 'Analyzing open redirects...' },
            { fn: this.checkServerInformation, label: 'Checking server information...' },
            { fn: this.checkCSP, label: 'Verifying Content Security Policy...' }
        ];
        for (let i = 0; i < steps.length; i++) {
            if (progressCallback) {
                progressCallback({
                    progress: Math.round((i / steps.length) * 100),
                    step: steps[i].label
                });
            }
            await steps[i].fn.call(this, targetUrl, results);
        }
        if (progressCallback) {
            progressCallback({ progress: 100, step: 'Finalizing results...' });
        }
        return results;
    }

    async checkSSLSecurity(targetUrl, results) {
        this.spinner.text = 'Checking SSL/TLS security...';
        
        try {
            const urlObj = new URL(targetUrl);
            if (urlObj.protocol === 'https:') {
                const agent = new https.Agent({
                    rejectUnauthorized: false
                });

                const response = await axios.get(targetUrl, {
                    httpsAgent: agent,
                    timeout: this.config.timeout,
                    maxRedirects: this.config.maxRedirects
                });

                const cert = response.request.socket.getPeerCertificate();
                
                if (cert && cert.raw) {
                    results.info.push({
                        type: 'SSL Certificate',
                        severity: 'INFO',
                        description: 'SSL certificate is present',
                        details: {
                            issuer: cert.issuer?.CN || 'Unknown',
                            validFrom: cert.valid_from,
                            validTo: cert.valid_to
                        }
                    });
                } else {
                    results.warnings.push({
                        type: 'SSL Certificate',
                        severity: 'WARNING',
                        description: 'SSL certificate details not available'
                    });
                }
            } else {
                results.vulnerabilities.push({
                    type: 'HTTP Protocol',
                    severity: 'HIGH',
                    description: 'Site is using HTTP instead of HTTPS',
                    recommendation: 'Upgrade to HTTPS for secure communication'
                });
            }
        } catch (error) {
            results.warnings.push({
                type: 'SSL Check',
                severity: 'WARNING',
                description: 'Could not verify SSL certificate',
                details: error.message
            });
        }
    }

    async checkSecurityHeaders(targetUrl, results) {
        this.spinner.text = 'Checking security headers...';
        
        try {
            const response = await axios.get(targetUrl, {
                timeout: this.config.timeout,
                maxRedirects: this.config.maxRedirects,
                headers: {
                    'User-Agent': this.config.userAgent
                }
            });

            const headers = response.headers;
            const securityHeaders = {
                'Strict-Transport-Security': 'HSTS',
                'X-Content-Type-Options': 'Content Type Options',
                'X-Frame-Options': 'Frame Options',
                'X-XSS-Protection': 'XSS Protection',
                'Referrer-Policy': 'Referrer Policy',
                'Content-Security-Policy': 'CSP',
                'Permissions-Policy': 'Permissions Policy'
            };

            for (const [header, name] of Object.entries(securityHeaders)) {
                if (!headers[header.toLowerCase()]) {
                    results.vulnerabilities.push({
                        type: `Missing ${name} Header`,
                        severity: 'MEDIUM',
                        description: `${header} security header is not set`,
                        recommendation: `Implement ${header} header for better security`
                    });
                } else {
                    results.info.push({
                        type: `${name} Header`,
                        severity: 'INFO',
                        description: `${header} is properly configured`,
                        details: headers[header.toLowerCase()]
                    });
                }
            }
        } catch (error) {
            results.warnings.push({
                type: 'Security Headers',
                severity: 'WARNING',
                description: 'Could not check security headers',
                details: error.message
            });
        }
    }

    async checkXSSVulnerabilities(targetUrl, results) {
        this.spinner.text = 'Checking for XSS vulnerabilities...';
        
        try {
            const response = await axios.get(targetUrl, {
                timeout: this.config.timeout,
                maxRedirects: this.config.maxRedirects,
                headers: {
                    'User-Agent': this.config.userAgent
                }
            });

            const $ = cheerio.load(response.data);
            
            // Check for reflected XSS in URL parameters
            const urlParams = new URL(targetUrl).searchParams;
            const xssPayloads = [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                'javascript:alert("XSS")',
                '"><img src=x onerror=alert("XSS")>'
            ];

            for (const [param, value] of urlParams) {
                for (const payload of xssPayloads) {
                    const testUrl = new URL(targetUrl);
                    testUrl.searchParams.set(param, payload);
                    
                    try {
                        const testResponse = await axios.get(testUrl.toString(), {
                            timeout: this.config.timeout,
                            headers: {
                                'User-Agent': this.config.userAgent
                            }
                        });
                        
                        if (testResponse.data.includes(payload)) {
                            results.vulnerabilities.push({
                                type: 'Reflected XSS',
                                severity: 'HIGH',
                                description: `Potential XSS vulnerability in parameter: ${param}`,
                                details: `Payload reflected: ${payload}`,
                                recommendation: 'Implement proper input validation and output encoding'
                            });
                            break;
                        }
                    } catch (error) {
                        // Continue with next payload
                    }
                }
            }

            // Check for stored XSS in forms
            const forms = $('form');
            forms.each((i, form) => {
                const action = $(form).attr('action');
                const method = $(form).attr('method') || 'GET';
                
                if (action && !action.startsWith('http')) {
                    results.info.push({
                        type: 'Form Analysis',
                        severity: 'INFO',
                        description: `Form found with action: ${action}, method: ${method}`,
                        recommendation: 'Verify form handling for XSS vulnerabilities'
                    });
                }
            });

        } catch (error) {
            results.warnings.push({
                type: 'XSS Check',
                severity: 'WARNING',
                description: 'Could not perform XSS vulnerability check',
                details: error.message
            });
        }
    }

    async checkSQLInjection(targetUrl, results) {
        this.spinner.text = 'Checking for SQL injection vulnerabilities...';
        
        const sqlPayloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT * FROM users--",
            "admin'--"
        ];

        const urlParams = new URL(targetUrl).searchParams;
        
        for (const [param, value] of urlParams) {
            for (const payload of sqlPayloads) {
                const testUrl = new URL(targetUrl);
                testUrl.searchParams.set(param, payload);
                
                try {
                    const response = await axios.get(testUrl.toString(), {
                        timeout: this.config.timeout,
                        headers: {
                            'User-Agent': this.config.userAgent
                        }
                    });
                    
                    // Check for common SQL error messages
                    const errorPatterns = [
                        /sql syntax/i,
                        /mysql error/i,
                        /oracle error/i,
                        /postgresql error/i,
                        /sql server error/i,
                        /syntax error/i
                    ];
                    
                    for (const pattern of errorPatterns) {
                        if (pattern.test(response.data)) {
                            results.vulnerabilities.push({
                                type: 'SQL Injection',
                                severity: 'CRITICAL',
                                description: `Potential SQL injection in parameter: ${param}`,
                                details: `Error pattern detected: ${pattern}`,
                                recommendation: 'Implement parameterized queries and input validation'
                            });
                            break;
                        }
                    }
                } catch (error) {
                    // Continue with next payload
                }
            }
        }
    }

    async checkDirectoryTraversal(targetUrl, results) {
        this.spinner.text = 'Checking for directory traversal vulnerabilities...';
        
        const traversalPayloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ];

        const baseUrl = new URL(targetUrl);
        
        for (const payload of traversalPayloads) {
            try {
                const testUrl = `${baseUrl.origin}/${payload}`;
                const response = await axios.get(testUrl, {
                    timeout: this.config.timeout,
                    headers: {
                        'User-Agent': this.config.userAgent
                    }
                });
                
                // Check for common file contents
                if (response.data.includes('root:') || response.data.includes('localhost')) {
                    results.vulnerabilities.push({
                        type: 'Directory Traversal',
                        severity: 'CRITICAL',
                        description: 'Potential directory traversal vulnerability detected',
                        details: `Payload: ${payload}`,
                        recommendation: 'Implement proper path validation and access controls'
                    });
                    break;
                }
            } catch (error) {
                // Continue with next payload
            }
        }
    }

    async checkInformationDisclosure(targetUrl, results) {
        this.spinner.text = 'Checking for information disclosure...';
        
        const sensitivePaths = [
            '/robots.txt',
            '/sitemap.xml',
            '/.git/config',
            '/.env',
            '/config.php',
            '/wp-config.php',
            '/phpinfo.php',
            '/server-status',
            '/.htaccess',
            '/web.config'
        ];

        const baseUrl = new URL(targetUrl);
        
        for (const path of sensitivePaths) {
            try {
                const testUrl = `${baseUrl.origin}${path}`;
                const response = await axios.get(testUrl, {
                    timeout: this.config.timeout,
                    headers: {
                        'User-Agent': this.config.userAgent
                    }
                });
                
                if (response.status === 200) {
                    results.warnings.push({
                        type: 'Information Disclosure',
                        severity: 'MEDIUM',
                        description: `Sensitive file accessible: ${path}`,
                        recommendation: 'Remove or protect sensitive files from public access'
                    });
                }
            } catch (error) {
                // File not accessible, which is good
            }
        }
    }

    async checkCSRFVulnerabilities(targetUrl, results) {
        this.spinner.text = 'Checking for CSRF vulnerabilities...';
        
        try {
            const response = await axios.get(targetUrl, {
                timeout: this.config.timeout,
                maxRedirects: this.config.maxRedirects,
                headers: {
                    'User-Agent': this.config.userAgent
                }
            });

            const $ = cheerio.load(response.data);
            const forms = $('form');
            
            forms.each((i, form) => {
                const hasCSRFToken = $(form).find('input[name*="csrf"], input[name*="token"], input[name*="nonce"]').length > 0;
                
                if (!hasCSRFToken) {
                    results.vulnerabilities.push({
                        type: 'CSRF Vulnerability',
                        severity: 'MEDIUM',
                        description: 'Form found without CSRF protection',
                        details: `Form ${i + 1} lacks CSRF token`,
                        recommendation: 'Implement CSRF tokens for all forms'
                    });
                }
            });
        } catch (error) {
            results.warnings.push({
                type: 'CSRF Check',
                severity: 'WARNING',
                description: 'Could not check CSRF vulnerabilities',
                details: error.message
            });
        }
    }

    async checkOpenRedirects(targetUrl, results) {
        this.spinner.text = 'Checking for open redirect vulnerabilities...';
        
        const redirectPayloads = [
            'https://evil.com',
            '//evil.com',
            'javascript:alert("redirect")',
            'data:text/html,<script>alert("redirect")</script>'
        ];

        const urlParams = new URL(targetUrl).searchParams;
        
        for (const [param, value] of urlParams) {
            if (param.toLowerCase().includes('redirect') || param.toLowerCase().includes('url') || param.toLowerCase().includes('next')) {
                for (const payload of redirectPayloads) {
                    const testUrl = new URL(targetUrl);
                    testUrl.searchParams.set(param, payload);
                    
                    try {
                        const response = await axios.get(testUrl.toString(), {
                            timeout: this.config.timeout,
                            maxRedirects: 0, // Don't follow redirects
                            headers: {
                                'User-Agent': this.config.userAgent
                            }
                        });
                        
                        if (response.headers.location && response.headers.location.includes(payload)) {
                            results.vulnerabilities.push({
                                type: 'Open Redirect',
                                severity: 'MEDIUM',
                                description: `Potential open redirect in parameter: ${param}`,
                                details: `Redirects to: ${response.headers.location}`,
                                recommendation: 'Implement proper redirect validation'
                            });
                            break;
                        }
                    } catch (error) {
                        // Continue with next payload
                    }
                }
            }
        }
    }

    async checkServerInformation(targetUrl, results) {
        this.spinner.text = 'Checking server information...';
        
        try {
            const response = await axios.get(targetUrl, {
                timeout: this.config.timeout,
                maxRedirects: this.config.maxRedirects,
                headers: {
                    'User-Agent': this.config.userAgent
                }
            });

            const headers = response.headers;
            
            // Check for server information disclosure
            if (headers.server) {
                results.info.push({
                    type: 'Server Information',
                    severity: 'INFO',
                    description: 'Server header reveals technology',
                    details: headers.server,
                    recommendation: 'Consider hiding server information'
                });
            }

            if (headers['x-powered-by']) {
                results.warnings.push({
                    type: 'Technology Disclosure',
                    severity: 'LOW',
                    description: 'X-Powered-By header reveals technology',
                    details: headers['x-powered-by'],
                    recommendation: 'Remove X-Powered-By header'
                });
            }

        } catch (error) {
            results.warnings.push({
                type: 'Server Information',
                severity: 'WARNING',
                description: 'Could not check server information',
                details: error.message
            });
        }
    }

    async checkCSP(targetUrl, results) {
        this.spinner.text = 'Checking Content Security Policy...';
        
        try {
            const response = await axios.get(targetUrl, {
                timeout: this.config.timeout,
                maxRedirects: this.config.maxRedirects,
                headers: {
                    'User-Agent': this.config.userAgent
                }
            });

            const cspHeader = response.headers['content-security-policy'] || response.headers['x-content-security-policy'];
            
            if (!cspHeader) {
                results.vulnerabilities.push({
                    type: 'Missing CSP',
                    severity: 'MEDIUM',
                    description: 'Content Security Policy header is not set',
                    recommendation: 'Implement CSP to prevent XSS attacks'
                });
            } else {
                results.info.push({
                    type: 'CSP Configuration',
                    severity: 'INFO',
                    description: 'Content Security Policy is configured',
                    details: cspHeader
                });
            }
        } catch (error) {
            results.warnings.push({
                type: 'CSP Check',
                severity: 'WARNING',
                description: 'Could not check CSP configuration',
                details: error.message
            });
        }
    }

    displayResults(results) {
        console.log(chalk.blue.bold('\n📊 Scan Results\n'));
        console.log(chalk.cyan(`Target: ${results.target}`));
        console.log(chalk.cyan(`Timestamp: ${results.timestamp}\n`));

        // Display vulnerabilities
        if (results.vulnerabilities.length > 0) {
            console.log(chalk.red.bold('🚨 VULNERABILITIES FOUND:\n'));
            results.vulnerabilities.forEach((vuln, index) => {
                console.log(chalk.red(`${index + 1}. ${vuln.type} (${vuln.severity})`));
                console.log(chalk.white(`   Description: ${vuln.description}`));
                if (vuln.details) console.log(chalk.gray(`   Details: ${vuln.details}`));
                if (vuln.recommendation) console.log(chalk.yellow(`   Recommendation: ${vuln.recommendation}`));
                console.log('');
            });
        } else {
            console.log(chalk.green.bold('✅ No vulnerabilities detected!\n'));
        }

        // Display warnings
        if (results.warnings.length > 0) {
            console.log(chalk.yellow.bold('⚠️  WARNINGS:\n'));
            results.warnings.forEach((warning, index) => {
                console.log(chalk.yellow(`${index + 1}. ${warning.type} (${warning.severity})`));
                console.log(chalk.white(`   Description: ${warning.description}`));
                if (warning.details) console.log(chalk.gray(`   Details: ${warning.details}`));
                if (warning.recommendation) console.log(chalk.yellow(`   Recommendation: ${warning.recommendation}`));
                console.log('');
            });
        }

        // Display info
        if (results.info.length > 0) {
            console.log(chalk.blue.bold('ℹ️  INFORMATION:\n'));
            results.info.forEach((info, index) => {
                console.log(chalk.blue(`${index + 1}. ${info.type} (${info.severity})`));
                console.log(chalk.white(`   Description: ${info.description}`));
                if (info.details) console.log(chalk.gray(`   Details: ${info.details}`));
                if (info.recommendation) console.log(chalk.yellow(`   Recommendation: ${info.recommendation}`));
                console.log('');
            });
        }

        // Summary
        console.log(chalk.blue.bold('📈 SUMMARY:'));
        console.log(chalk.red(`   Vulnerabilities: ${results.vulnerabilities.length}`));
        console.log(chalk.yellow(`   Warnings: ${results.warnings.length}`));
        console.log(chalk.blue(`   Information: ${results.info.length}`));
        console.log('');

        // Save results to file
        this.saveResults(results);
    }

    saveResults(results) {
        const filename = `scan_results_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
        fs.writeFileSync(filename, JSON.stringify(results, null, 2));
        console.log(chalk.green(`💾 Results saved to: ${filename}`));
    }
}

// CLI Interface
const program = new Command();

program
    .name('web-vulnerability-scanner')
    .description('A comprehensive web vulnerability scanner')
    .version('1.0.0');

program
    .argument('<url>', 'Target URL to scan')
    .option('-o, --output <file>', 'Output file for results')
    .option('-v, --verbose', 'Verbose output')
    .action(async (url, options) => {
        const scanner = new WebVulnerabilityScanner();
        await scanner.scan(url, options);
    });

if (require.main === module) {
    program.parse();
}

module.exports = WebVulnerabilityScanner; 