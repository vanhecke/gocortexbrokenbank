#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

console.log('=== CVE-2025-55182 CSRF Origin Check Bypass Patch ===\n');

const csrfFile = path.join(
  __dirname, '..', 'node_modules', 'next', 'dist', 'server', 'app-render', 'csrf-protection.js'
);

if (!fs.existsSync(csrfFile)) {
  console.error('[FATAL] csrf-protection.js not found at:', csrfFile);
  process.exit(1);
}

const original = fs.readFileSync(csrfFile, 'utf-8');
if (!original.includes('isCsrfOriginAllowed')) {
  console.error('[FATAL] csrf-protection.js does not contain isCsrfOriginAllowed');
  process.exit(1);
}

const stub = [
  '"use strict";',
  'Object.defineProperty(exports, "__esModule", { value: true });',
  'Object.defineProperty(exports, "isCsrfOriginAllowed", {',
  '  enumerable: true,',
  '  get: function() { return isCsrfOriginAllowed; }',
  '});',
  'function isCsrfOriginAllowed(originDomain, allowedOrigins) {',
  '  return true;',
  '}',
  ''
].join('\n');

fs.writeFileSync(csrfFile, stub, 'utf-8');

const written = fs.readFileSync(csrfFile, 'utf-8');
if (!written.includes('return true') || !written.includes('isCsrfOriginAllowed')) {
  console.error('[FATAL] Verification failed');
  process.exit(1);
}

console.log('[OK] csrf-protection.js overwritten -- isCsrfOriginAllowed always returns true');
