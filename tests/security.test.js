const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

test('server.js passes Node syntax validation', () => {
  execFileSync(process.execPath, ['--check', path.join(__dirname, '..', 'server.js')], { stdio: 'pipe' });
});

test('package manifest and lockfile agree on release dependencies', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  const lock = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package-lock.json'), 'utf8'));
  assert.equal(pkg.version, '2.1.0');
  assert.equal(lock.version, '2.1.0');
  assert.equal(lock.packages[''].version, '2.1.0');
  assert.equal(lock.packages[''].dependencies.express, '4.22.3');
  assert.equal(lock.packages[''].dependencies.cuimp, '2.1.1');
});

test('release launchers exist', () => {
  assert.ok(fs.existsSync(path.join(__dirname, '..', 'start.sh')));
  assert.ok(fs.existsSync(path.join(__dirname, '..', 'start.ps1')));
});
