const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync, spawn } = require('node:child_process');
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

test('local server serves the UI and blocks direct private targets', async () => {
  const port = 18000 + Math.floor(Math.random() * 1000);
  const child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, HOST: '127.0.0.1', PORT: String(port), PROXY_TOKEN: '' },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('server startup timeout')), 10000);
      child.stdout.on('data', chunk => {
        if (chunk.toString().includes('[LIVE]')) {
          clearTimeout(timer);
          resolve();
        }
      });
      child.on('error', reject);
      child.on('exit', code => {
        if (code !== null) reject(new Error('server exited before startup: ' + code));
      });
    });

    const ui = await fetch('http://127.0.0.1:' + port + '/');
    assert.equal(ui.status, 200);
    assert.match(await ui.text(), /Rook Crawler/i);

    const blocked = await fetch('http://127.0.0.1:' + port + '/?url=' + encodeURIComponent('http://127.0.0.1:9/'));
    assert.equal(blocked.status, 403);
  } finally {
    child.kill('SIGTERM');
    await new Promise(resolve => child.once('exit', resolve));
  }
});

test('non-loopback bind requires authentication', () => {
  const result = require('node:child_process').spawnSync(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, HOST: '0.0.0.0', PORT: '18099', PROXY_TOKEN: '' },
    encoding: 'utf8'
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr + result.stdout, /PROXY_TOKEN|non-loopback/i);
});
