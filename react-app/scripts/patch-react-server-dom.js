#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const COMPILED_DIR = path.join(__dirname, '..', 'node_modules', 'next', 'dist', 'compiled');

console.log('=== CVE-2025-55182 Vulnerability Verification ===\n');

const PKG = 'react-server-dom-turbopack';
const bundledCjs = path.join(COMPILED_DIR, PKG, 'cjs');

if (!fs.existsSync(bundledCjs)) {
  console.error('[FATAL] Bundled CJS directory not found');
  process.exit(1);
}

const serverFiles = fs.readdirSync(bundledCjs).filter(f =>
  f.includes('server') && f.endsWith('.js')
);

let allVulnerable = true;

for (const sf of serverFiles) {
  const content = fs.readFileSync(path.join(bundledCjs, sf), 'utf-8');

  const requireModuleMatch = content.match(/function\s+requireModule\s*\([^)]*\)\s*\{/);
  if (requireModuleMatch) {
    let braces = 0, start = requireModuleMatch.index, end = start;
    for (let i = start; i < content.length; i++) {
      if (content[i] === '{') braces++;
      if (content[i] === '}') { braces--; if (braces === 0) { end = i + 1; break; } }
    }
    const fn = content.substring(start, end);
    const hasGuard = fn.includes('hasOwnProperty');
    console.log(`${sf}:`);
    console.log(`  requireModule hasOwnProperty guard: ${hasGuard}`);
    console.log(`  VULNERABLE: ${!hasGuard}`);
    if (hasGuard) allVulnerable = false;
  }
}

if (allVulnerable) {
  console.log('\nAll server files confirmed vulnerable to CVE-2025-55182.');
  console.log('Next.js 16.0.6 bundled react-server-dom-turbopack has no prototype access guard in requireModule.');
} else {
  console.log('\nWARNING: Some files have the hasOwnProperty guard. Vulnerability may be partially patched.');
}
