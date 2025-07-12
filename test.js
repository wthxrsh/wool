#!/usr/bin/env node

const WebVulnerabilityScanner = require('./scanner');

async function runTests() {
    console.log('🧪 Running Vulnerability Scanner Tests\n');
    
    const scanner = new WebVulnerabilityScanner();
    
    // Test with a safe, well-known website
    const testTargets = [
        'https://httpbin.org',  // Safe test target
        'https://example.com'   // Another safe test target
    ];
    
    for (const target of testTargets) {
        console.log(`\n🔍 Testing: ${target}`);
        console.log('=' .repeat(50));
        
        try {
            await scanner.scan(target, { verbose: true });
        } catch (error) {
            console.error(`❌ Error testing ${target}:`, error.message);
        }
        
        console.log('\n' + '=' .repeat(50));
    }
    
    console.log('\n✅ Tests completed!');
}

// Run tests if this file is executed directly
if (require.main === module) {
    runTests().catch(console.error);
}

module.exports = { runTests }; 