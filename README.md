# Web Vulnerability Scanner

A comprehensive web vulnerability scanner built with Node.js that detects various security vulnerabilities in web applications.

## Features

### 🔍 Vulnerability Detection
- **XSS (Cross-Site Scripting)** - Detects reflected and stored XSS vulnerabilities
- **SQL Injection** - Tests for SQL injection vulnerabilities with various payloads
- **CSRF (Cross-Site Request Forgery)** - Checks for missing CSRF protection
- **Directory Traversal** - Tests for path traversal vulnerabilities
- **Open Redirects** - Detects potential redirect vulnerabilities
- **Information Disclosure** - Checks for sensitive file exposure

### 🛡️ Security Headers Analysis
- **HSTS (HTTP Strict Transport Security)**
- **X-Content-Type-Options**
- **X-Frame-Options**
- **X-XSS-Protection**
- **Content Security Policy (CSP)**
- **Referrer Policy**
- **Permissions Policy**

### 🔐 SSL/TLS Security
- SSL certificate validation
- HTTPS enforcement
- Certificate information analysis

### 📊 Comprehensive Reporting
- Color-coded output with severity levels
- Detailed vulnerability descriptions
- Security recommendations
- JSON export functionality

## Installation

1. **Clone or download the project**
   ```bash
   git clone <repository-url>
   cd web-vulnerability-scanner
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Verify installation**
   ```bash
   node scanner.js --help
   ```

## Usage

### Basic Usage
```bash
# Scan a single website
node scanner.js https://example.com

# Scan with custom options
node scanner.js https://example.com --verbose --output results.json
```

### Command Line Options
```bash
Options:
  -o, --output <file>    Output file for results
  -v, --verbose          Verbose output
  -h, --help            Display help information
  -V, --version         Display version information
```

### Examples

#### Scan a website for vulnerabilities
```bash
node scanner.js https://example.com
```

#### Save results to a file
```bash
node scanner.js https://example.com --output scan_results.json
```

#### Verbose scanning
```bash
node scanner.js https://example.com --verbose
```

## Output Format

The scanner provides detailed output with the following structure:

### Severity Levels
- **CRITICAL** - Immediate security risks
- **HIGH** - Significant security vulnerabilities
- **MEDIUM** - Moderate security issues
- **LOW** - Minor security concerns
- **INFO** - Informational findings

### Output Categories
- **Vulnerabilities** - Actual security issues found
- **Warnings** - Potential issues or configuration problems
- **Information** - General findings and recommendations

### JSON Export
Results are automatically saved to a JSON file with the following structure:
```json
{
  "target": "https://example.com",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "vulnerabilities": [...],
  "warnings": [...],
  "info": [...]
}
```

## Security Features

### XSS Detection
- Tests for reflected XSS in URL parameters
- Analyzes form inputs for potential vulnerabilities
- Checks for proper output encoding

### SQL Injection Testing
- Uses various SQL injection payloads
- Detects common SQL error messages
- Tests parameter-based vulnerabilities

### Security Headers Analysis
- Comprehensive header checking
- Recommendations for missing headers
- Best practices implementation

### SSL/TLS Analysis
- Certificate validation
- Protocol security assessment
- HTTPS enforcement checking

## Ethical Usage

⚠️ **Important: This tool is for educational and authorized security testing purposes only.**

- Only scan websites you own or have explicit permission to test
- Respect robots.txt and rate limiting
- Do not use for malicious purposes
- Follow responsible disclosure practices

## Legal Disclaimer

This tool is provided for educational and authorized security testing purposes. Users are responsible for ensuring they have proper authorization before scanning any website. The authors are not responsible for any misuse of this tool.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

For issues, questions, or contributions, please open an issue on the repository.

---

**Built with ❤️ for web security** # wool
