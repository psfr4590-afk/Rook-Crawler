const express = require('express');
const fs = require('fs');
const path = require('path');
const net = require('net');
const crypto = require('crypto');
const https = require('https');
const dns = require('dns').promises;
const { URL } = require('url');
const cuimp = require('cuimp');

const app = express();
const PORT = Number.parseInt(process.env.PORT || '8010', 10);
const HOST = process.env.HOST || '127.0.0.1';
const MAX_RESPONSE_BYTES = Number.parseInt(process.env.MAX_RESPONSE_BYTES || String(10 * 1024 * 1024), 10);
const MAX_REDIRECTS = Number.parseInt(process.env.MAX_REDIRECTS || '5', 10);
const REQUEST_TIMEOUT_MS = Number.parseInt(process.env.REQUEST_TIMEOUT_MS || '15000', 10);
const CORS_ALLOW_ORIGINS = new Set(
    (process.env.CORS_ALLOW_ORIGINS || `http://127.0.0.1:${PORT},http://localhost:${PORT}`)
        .split(',').map(v => v.trim()).filter(Boolean)
);
const INDEX_FILE = path.join(__dirname, 'index.html');
const PROXIES_FILE = path.join(__dirname, 'proxies.txt');
const TOKEN_FILE = path.join(__dirname, 'token.txt');
const TOR_CONFIG_FILE = path.join(__dirname, 'tor.json');
const DOH_CONFIG_FILE = path.join(__dirname, 'doh.json');
const FINGERPRINTS_FILE = path.join(__dirname, 'fingerprints.json');
const INTELLIGENCE_FILE = path.join(__dirname, 'crawler-intelligence.json');

app.disable('x-powered-by');
app.use(express.raw({ type: '*/*', limit: '10mb' }));

// State
let proxyPool = [];
let currentProxyIndex = 0;
let currentFingerprintIndex = 0;
let PROXY_TOKEN = '';
let torConfig = { enabled: false, mode: 'local', socksPort: 9050, controlPort: 9051, password: '', autoLaunch: false };
let dohConfig = { enabled: true, provider: 'cloudflare', providers: {}, timeout: 5000, cache: true, cacheMaxSize: 1000 };
let fingerprintProfiles = { browser_profiles: {} };
let crawlerIntelligence = { enabled: true, strategies: {}, response_analysis: {}, memory: {} };

// In-memory storage for intelligence
const dnsCache = new Map();
const responseMemory = new Map();
const blacklist = new Map();

const ALLOWED_PROXY_SCHEMES = ['http:', 'https:', 'socks4:', 'socks5:'];
const TOR_PATTERNS = /^tor:\/\/|\.onion$/i;

// ---- Config Loaders ----
function loadToken() {
    if (process.env.PROXY_TOKEN && process.env.PROXY_TOKEN.trim()) {
        PROXY_TOKEN = process.env.PROXY_TOKEN.trim();
    } else {
        try {
            PROXY_TOKEN = fs.existsSync(TOKEN_FILE)
                ? (fs.readFileSync(TOKEN_FILE, 'utf8').split('\n').map(l => l.trim())
                    .find(l => l.length > 0 && !l.startsWith('#')) || '')
                : '';
        } catch (err) {
            console.error('[ERROR] token.txt:', err.message);
            PROXY_TOKEN = '';
        }
    }
    console.log(PROXY_TOKEN
        ? '[SECURITY] Token auth ENABLED.'
        : '[SECURITY] WARNING: no token set - proxy is OPEN.');
}

function loadTorConfig() {
    try {
        if (fs.existsSync(TOR_CONFIG_FILE)) {
            torConfig = JSON.parse(fs.readFileSync(TOR_CONFIG_FILE, 'utf8'));
            if (torConfig.enabled) {
                console.log(`[TOR] Mode: ${torConfig.mode}, SOCKS: 127.0.0.1:${torConfig.socksPort}`);
                if (torConfig.autoLaunch && torConfig.browserPath) {
                    console.log(`[TOR] Auto-launch enabled: ${torConfig.browserPath}`);
                }
            }
        } else {
            const defaultConfig = {
                enabled: false,
                mode: 'local',
                socksPort: 9050,
                controlPort: 9051,
                password: '',
                browserPath: '',
                autoLaunch: false,
                circuitIsolation: true,
                circuitRotationInterval: 300000
            };
            fs.writeFileSync(TOR_CONFIG_FILE, JSON.stringify(defaultConfig, null, 2), 'utf8');
            torConfig = defaultConfig;
            console.log('[TOR] Created tor.json (disabled by default)');
        }
    } catch (err) {
        console.error('[ERROR] tor.json:', err.message);
        torConfig = { enabled: false, mode: 'local', socksPort: 9050 };
    }
}

function loadDoHConfig() {
    try {
        if (fs.existsSync(DOH_CONFIG_FILE)) {
            dohConfig = JSON.parse(fs.readFileSync(DOH_CONFIG_FILE, 'utf8'));
            console.log(`[DOH] Provider: ${dohConfig.provider}, Cache: ${dohConfig.cache}`);
        } else {
            const defaultConfig = {
                enabled: true,
                provider: 'cloudflare',
                providers: {
                    cloudflare: 'https://1.1.1.1/dns-query',
                    google: 'https://dns.google/dns-query',
                    quad9: 'https://dns.quad9.net/dns-query'
                },
                timeout: 5000,
                cache: true,
                cacheMaxSize: 1000,
                cacheTTL: 3600
            };
            fs.writeFileSync(DOH_CONFIG_FILE, JSON.stringify(defaultConfig, null, 2), 'utf8');
            dohConfig = defaultConfig;
            console.log('[DOH] Created doh.json');
        }
    } catch (err) {
        console.error('[ERROR] doh.json:', err.message);
        dohConfig = { enabled: true, provider: 'cloudflare' };
    }
}

function loadFingerprintProfiles() {
    try {
        if (fs.existsSync(FINGERPRINTS_FILE)) {
            fingerprintProfiles = JSON.parse(fs.readFileSync(FINGERPRINTS_FILE, 'utf8'));
            const count = Object.keys(fingerprintProfiles.browser_profiles || {}).length;
            console.log(`[FINGERPRINTS] Loaded ${count} browser profiles`);
        } else {
            const defaultProfiles = {
                browser_profiles: {
                    chrome_latest: { name: 'Chrome Latest', browser: 'chrome', version: 'latest' },
                    firefox_latest: { name: 'Firefox Latest', browser: 'firefox', version: 'latest' },
                    edge_windows: { name: 'Edge Windows', browser: 'edge', version: 'latest' },
                    safari_mac: { name: 'Safari macOS', browser: 'safari', version: 'latest' }
                }
            };
            fs.writeFileSync(FINGERPRINTS_FILE, JSON.stringify(defaultProfiles, null, 2), 'utf8');
            fingerprintProfiles = defaultProfiles;
            console.log('[FINGERPRINTS] Created fingerprints.json');
        }
    } catch (err) {
        console.error('[ERROR] fingerprints.json:', err.message);
        fingerprintProfiles = { browser_profiles: {} };
    }
}

function loadCrawlerIntelligence() {
    try {
        if (fs.existsSync(INTELLIGENCE_FILE)) {
            crawlerIntelligence = JSON.parse(fs.readFileSync(INTELLIGENCE_FILE, 'utf8'));
            console.log(`[INTELLIGENCE] Loaded with ${Object.keys(crawlerIntelligence.strategies || {}).length} strategies`);
        } else {
            const defaultIntelligence = {
                enabled: true,
                strategies: {
                    adaptive_delay: { enabled: true },
                    anti_bot_detection: { enabled: true },
                    cookie_persistence: { enabled: true },
                    dynamic_ua_rotation: { enabled: true }
                },
                response_analysis: {
                    status_codes: {
                        429: 'Rate limited - increase delay',
                        403: 'Forbidden - try different proxy',
                        503: 'Service unavailable - backoff'
                    }
                },
                memory: { learnFromErrors: true }
            };
            fs.writeFileSync(INTELLIGENCE_FILE, JSON.stringify(defaultIntelligence, null, 2), 'utf8');
            crawlerIntelligence = defaultIntelligence;
            console.log('[INTELLIGENCE] Created crawler-intelligence.json');
        }
    } catch (err) {
        console.error('[ERROR] crawler-intelligence.json:', err.message);
        crawlerIntelligence = { enabled: false, strategies: {} };
    }
}

// ---- DNS over HTTPS (DoH) ----
async function resolveViaDoh(hostname) {
    if (!dohConfig.enabled) return null;

    const cacheKey = `dns:${hostname}`;
    if (dohConfig.cache && dnsCache.has(cacheKey)) {
        const cached = dnsCache.get(cacheKey);
        if (Date.now() < cached.expires) {
            console.log(`[DOH] Cache hit for ${hostname}`);
            return cached.ips;
        }
        dnsCache.delete(cacheKey);
    }

    try {
        const provider = dohConfig.providers[dohConfig.provider];
        if (!provider) return null;

        const dohUrl = `${provider}?name=${encodeURIComponent(hostname)}&type=A`;
        const response = await new Promise((resolve, reject) => {
            const request = https.get(dohUrl, {
                timeout: Math.min(Number(dohConfig.timeout) || 5000, 10000),
                headers: { Accept: 'application/dns-json' }
            }, (res) => {
                let data = '';
                res.on('data', chunk => {
                    data += chunk;
                    if (data.length > 1024 * 1024) request.destroy(new Error('DoH response too large'));
                });
                res.on('end', () => {
                    if (res.statusCode !== 200) return reject(new Error(`DoH HTTP ${res.statusCode}`));
                    try { resolve(JSON.parse(data)); } catch (err) { reject(err); }
                });
            });
            request.on('timeout', () => request.destroy(new Error('DoH request timed out')));
            request.on('error', reject);
        });

        const ips = (response.Answer || []).filter(a => a.type === 1 || a.type === 28).map(a => a.data).filter(ip => net.isIP(ip));
        if (ips.some(isBlockedHost)) throw new Error('DoH resolved target to a blocked/private address');
        if (ips.length > 0 && dohConfig.cache) {
            dnsCache.set(cacheKey, {
                ips,
                expires: Date.now() + (dohConfig.cacheTTL * 1000)
            });
            console.log(`[DOH] Resolved ${hostname}: ${ips.join(', ')}`);
        }
        return ips.length > 0 ? ips : null;
    } catch (err) {
        console.error(`[DOH] Resolution failed for ${hostname}:`, err.message);
        return null;
    }
}

// ---- Proxy Pool with Tor ----
function loadProxies() {
    try {
        if (fs.existsSync(PROXIES_FILE)) {
            const lines = fs.readFileSync(PROXIES_FILE, 'utf8').split('\n')
                .map(l => l.trim())
                .filter(l => l.length > 0 && !l.startsWith('#'));

            proxyPool = lines.filter(l => {
                if (TOR_PATTERNS.test(l)) {
                    if (torConfig.enabled) {
                        console.log('[TOR] Entry detected in proxies.txt');
                        return true;
                    } else {
                        console.warn('[TOR] Skipping Tor entry: disabled in tor.json');
                        return false;
                    }
                }

                try {
                    return ALLOWED_PROXY_SCHEMES.includes(new URL(l).protocol);
                } catch {
                    console.warn(`[PROXY] Skipping malformed: ${l}`);
                    return false;
                }
            });

            console.log(`[SYSTEM] Loaded ${proxyPool.length} proxies from proxies.txt`);
        } else {
            fs.writeFileSync(PROXIES_FILE,
                '# Paste your proxies here, one per line.\n# Supports HTTP, HTTPS, SOCKS5, and Tor (tor://)\n# Example:\n# http://user:pass@host:8000\n# socks5://127.0.0.1:1080\n# tor://\n',
                'utf8');
            console.log('[SYSTEM] Created proxies.txt');
            proxyPool = [];
        }
    } catch (err) {
        console.error('[ERROR] proxies.txt:', err.message);
    }
}

function getNextProxy() {
    if (proxyPool.length === 0) return null;
    const p = proxyPool[currentProxyIndex];
    currentProxyIndex = (currentProxyIndex + 1) % proxyPool.length;
    return p;
}

function getNextFingerprint() {
    const profiles = Object.values(fingerprintProfiles.browser_profiles || {});
    if (profiles.length === 0) return { browser: 'chrome', version: 'latest' };
    const fp = profiles[currentFingerprintIndex];
    currentFingerprintIndex = (currentFingerprintIndex + 1) % profiles.length;
    return fp;
}

function maskProxy(s) {
    if (TOR_PATTERNS.test(s)) return 'tor://';
    try {
        const u = new URL(s);
        return `${u.protocol}//${u.host}`;
    } catch {
        return s.includes('@') ? s.split('@').pop() : s;
    }
}

function resolveProxyForUrl(proxyEntry, targetUrl) {
    if (TOR_PATTERNS.test(proxyEntry) || TOR_PATTERNS.test(targetUrl)) {
        if (!torConfig.enabled) {
            throw new Error('Tor is not enabled in tor.json');
        }
        return `socks5://127.0.0.1:${torConfig.socksPort}`;
    }
    return proxyEntry;
}

// ---- Crawler Intelligence: Response Analysis ----
function analyzeResponse(statusCode, contentType, contentLength) {
    const analysis = {
        statusCode,
        isError: statusCode >= 400,
        isRateLimited: statusCode === 429,
        isBlocked: statusCode === 403,
        isServerError: statusCode >= 500,
        contentValid: contentLength > (crawlerIntelligence.response_analysis?.content_signals?.min_content_length || 100)
    };

    if (crawlerIntelligence.enabled && crawlerIntelligence.memory?.learnFromErrors) {
        const memKey = `status:${statusCode}`;
        const mem = responseMemory.get(memKey) || { count: 0, lastSeen: 0 };
        mem.count++;
        mem.lastSeen = Date.now();
        responseMemory.set(memKey, mem);

        if (analysis.isRateLimited || analysis.isBlocked) {
            console.log(`[INTELLIGENCE] Recorded ${statusCode} error for learning`);
        }
    }

    return analysis;
}

// ---- SSRF Guard ----
function isLoopbackBind(host) {
    return host === '127.0.0.1' || host === 'localhost' || host === '::1';
}

function isBlockedHost(hostname) {
    const host = hostname.toLowerCase();
    if (host.endsWith('.onion')) return false;

    if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal')) return true;
    if (net.isIP(host) === 4) {
        const p = host.split('.').map(Number);
        if (p[0] === 127 || p[0] === 10 || p[0] === 0) return true;
        if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
        if (p[0] === 192 && p[1] === 168) return true;
        if (p[0] === 169 && p[1] === 254) return true;
    }
    if (net.isIP(host) === 6) {
        const normalized = host.replace(/^\[|\]$/g, '').toLowerCase();
        if (normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd') ||
            normalized.startsWith('fe80') || normalized.startsWith('::ffff:127.') ||
            normalized.startsWith('::ffff:10.') || normalized.startsWith('::ffff:192.168.') ||
            normalized.startsWith('::ffff:169.254.')) return true;
    }
    return false;
}

function safeEqual(a, b) {
    const ab = Buffer.from(String(a)), bb = Buffer.from(String(b));
    if (ab.length !== bb.length) return false;
    return crypto.timingSafeEqual(ab, bb);
}

// ---- Network Safety ----
async function validateTargetNetwork(hostname) {
    if (isBlockedHost(hostname)) throw new Error('Target host is blocked by SSRF guard.');
    if (net.isIP(hostname)) return;

    if (dohConfig.enabled) {
        const ips = await resolveViaDoh(hostname);
        if (!ips || ips.length === 0) throw new Error('Target DNS resolution failed.');
        if (ips.some(isBlockedHost)) throw new Error('Target resolves to a blocked/private address.');
        return;
    }

    const records = await dns.lookup(hostname, { all: true, verbatim: true });
    if (!records.length || records.some(record => isBlockedHost(record.address))) {
        throw new Error('Target resolves to a blocked/private address.');
    }
}

function corsOriginAllowed(origin) {
    if (!origin) return true;
    return CORS_ALLOW_ORIGINS.has(origin);
}

// ---- Cuimp Wrapper ----
function fetchViaCuimp(method, targetUrl, options) {
    if (typeof cuimp.createCuimpHttp !== 'function') {
        throw new Error('cuimp.createCuimpHttp not available. Install: npm install cuimp');
    }

    const m = method.toUpperCase();
    let client;

    try {
        const fp = options.fingerprint || { browser: 'chrome', version: 'latest' };
        client = cuimp.createCuimpHttp({
            descriptor: {
                browser: fp.browser,
                version: fp.version
            },
            autoDownload: false
        });
    } catch (err) {
        throw new Error(`Failed to create cuimp client: ${err.message}`);
    }

    const reqOptions = {
        ...options,
        headers: options.headers || {}
    };

    if (options.proxy) {
        reqOptions.proxy = options.proxy;
    }

    delete reqOptions.browser;
    delete reqOptions.fingerprint;

    try {
        if (typeof client[m.toLowerCase()] === 'function') {
            return client[m.toLowerCase()](targetUrl, reqOptions);
        }

        if (typeof client.request === 'function') {
            return client.request({
                ...reqOptions,
                url: targetUrl,
                method: m
            });
        }

        throw new Error(`cuimp has no handler for '${method}'`);
    } catch (err) {
        throw new Error(`cuimp request failed: ${err.message}`);
    }
}

// ---- Target Resolution ----
function resolveTarget(req) {
    if (req.query && typeof req.query.url === 'string' && req.query.url.trim()) return req.query.url.trim();
    const raw = req.originalUrl.replace(/^\/+/, '');
    return /^https?:\/\//i.test(raw) ? raw : null;
}

// ---- Initialize ----
loadTorConfig();
loadDoHConfig();
loadFingerprintProfiles();
loadCrawlerIntelligence();
loadProxies();
loadToken();

fs.watchFile(PROXIES_FILE, () => {
    try {
        console.log('[SYSTEM] proxies.txt changed, reloading...');
        loadProxies();
        currentProxyIndex = 0;
    } catch (err) {
        console.error('[ERROR] Failed to reload proxies.txt:', err.message);
    }
});

fs.watchFile(TOKEN_FILE, () => {
    try {
        console.log('[SYSTEM] token.txt changed, reloading...');
        loadToken();
    } catch (err) {
        console.error('[ERROR] Failed to reload token.txt:', err.message);
    }
});

fs.watchFile(TOR_CONFIG_FILE, () => {
    try {
        loadTorConfig();
    } catch (err) {
        console.error('[ERROR] Failed to reload tor.json:', err.message);
    }
});

fs.watchFile(DOH_CONFIG_FILE, () => {
    try {
        loadDoHConfig();
        dnsCache.clear();
        console.log('[DOH] DNS cache cleared after config reload');
    } catch (err) {
        console.error('[ERROR] Failed to reload doh.json:', err.message);
    }
});

fs.watchFile(FINGERPRINTS_FILE, () => {
    try {
        loadFingerprintProfiles();
    } catch (err) {
        console.error('[ERROR] Failed to reload fingerprints.json:', err.message);
    }
});

fs.watchFile(INTELLIGENCE_FILE, () => {
    try {
        loadCrawlerIntelligence();
    } catch (err) {
        console.error('[ERROR] Failed to reload crawler-intelligence.json:', err.message);
    }
});

// ---- Main Handler ----
app.use(async (req, res) => {
    const target = resolveTarget(req);

    const origin = req.headers.origin;
    if (!corsOriginAllowed(origin)) return res.status(403).send('Origin not allowed.');
    if (origin) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Proxy-Token');
    res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (req.method === 'OPTIONS') return res.sendStatus(204);

    if (!target) {
        if (req.method === 'GET') {
            if (fs.existsSync(INDEX_FILE)) return res.sendFile(INDEX_FILE);
            return res.status(404).send('index.html not found');
        }
        return res.status(400).send('No target. Use /?url=<encoded> or /<http...>.');
    }
    if (!/^https?:\/\//i.test(target)) return res.status(400).send('Invalid target URL.');

    let parsed;
    try {
        parsed = new URL(target);
    } catch {
        return res.status(400).send('Malformed target URL.');
    }

    // Token validation
    let token = req.headers['x-proxy-token'] || (req.query && req.query.token) || null;
    if (PROXY_TOKEN && !token && parsed.searchParams.has('token')) {
        token = parsed.searchParams.get('token');
        parsed.searchParams.delete('token');
    }
    if (PROXY_TOKEN && (!token || !safeEqual(token, PROXY_TOKEN))) {
        return res.status(401).send('Unauthorized: invalid proxy token.');
    }

    try { await validateTargetNetwork(parsed.hostname); }
    catch (error) { return res.status(403).send(error.message); }

    let targetUrl = parsed.toString();
    let lastError;
    let response;

    for (let redirect = 0; redirect <= MAX_REDIRECTS; redirect++) {
        let currentUrl;
        try {
            currentUrl = new URL(targetUrl);
            if (!['http:', 'https:'].includes(currentUrl.protocol)) throw new Error('Only HTTP and HTTPS targets are allowed.');
            await validateTargetNetwork(currentUrl.hostname);
        } catch (error) {
            return res.status(403).send(error.message);
        }

        const fingerprint = crawlerIntelligence.enabled && crawlerIntelligence.strategies?.dynamic_ua_rotation?.enabled
            ? getNextFingerprint() : { browser: 'chrome', version: 'latest' };
        const hasBody = Buffer.isBuffer(req.body) && req.body.length > 0;
        const baseOptions = {
            fingerprint,
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                ...(req.headers['content-type'] ? { 'Content-Type': req.headers['content-type'] } : {})
            },
            timeout: REQUEST_TIMEOUT_MS, maxRedirects: 0,
            ...(hasBody ? { data: req.body } : {})
        };

        const attempts = proxyPool.length > 0 ? Math.min(proxyPool.length, 3) : 1;
        let attemptError;
        for (let i = 0; i < attempts; i++) {
            const proxyEntry = getNextProxy();
            const fetchOptions = { ...baseOptions };
            try {
                if (proxyEntry) {
                    fetchOptions.proxy = resolveProxyForUrl(proxyEntry, targetUrl);
                    console.log(`[FETCH] ${maskProxy(proxyEntry)} -> ${req.method} ${currentUrl.hostname}`);
                } else {
                    console.log(`[FETCH] direct -> ${req.method} ${currentUrl.hostname}`);
                }
                response = await fetchViaCuimp(req.method, targetUrl, fetchOptions);
                attemptError = null;
                break;
            } catch (error) {
                attemptError = error;
                console.error(`[PROXY ERROR] attempt ${i + 1}/${attempts}: ${error.message}`);
                if (error.response) { response = error.response; attemptError = null; break; }
            }
        }

        if (attemptError) { lastError = attemptError; break; }

        const status = response.status || 200;
        const location = response.headers?.location || response.headers?.Location;
        if (status >= 300 && status < 400 && location) {
            if (redirect === MAX_REDIRECTS) return res.status(508).send('Redirect limit exceeded.');
            try {
                const nextUrl = new URL(location, targetUrl);
                if (!['http:', 'https:'].includes(nextUrl.protocol)) return res.status(403).send('Redirect target protocol is not allowed.');
                await validateTargetNetwork(nextUrl.hostname);
                targetUrl = nextUrl.toString();
                continue;
            } catch (error) {
                return res.status(403).send(`Redirect blocked: ${error.message}`);
            }
        }

        const body = response.data;
        const size = Buffer.isBuffer(body) ? body.length : Buffer.byteLength(String(body ?? ''));
        if (size > MAX_RESPONSE_BYTES) return res.status(413).send('Upstream response exceeds configured size limit.');
        analyzeResponse(status, response.headers?.['content-type'] || response.headers?.['Content-Type'], size);
        const ct = response.headers?.['content-type'] || response.headers?.['Content-Type'];
        if (ct) res.setHeader('Content-Type', ct);
        return res.status(status).send(body);
    }

    res.status(502).send(`Routing failed: ${lastError ? lastError.message : 'all proxies failed'}`);
});

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) throw new Error('PORT must be an integer between 1 and 65535.');
if (!isLoopbackBind(HOST) && !PROXY_TOKEN) throw new Error('Refusing non-loopback bind without PROXY_TOKEN. Set HOST=127.0.0.1 for local-only mode.');

const server = app.listen(PORT, HOST, () => {
    console.log(`\n============================================================`);
    console.log(`[LIVE] Rook Crawler + Stealth Proxy (Advanced)`);
    console.log(`[OPEN] http://${HOST === '::' ? '[::1]' : HOST}:${PORT}/`);
    console.log(`[AUTH] ${PROXY_TOKEN ? 'ENABLED' : 'LOCAL-ONLY'}`);
    console.log(`[PROXY] ${proxyPool.length} proxies loaded`);
    console.log(`[TOR] ${torConfig.enabled ? 'ENABLED' : 'disabled'}`);
    console.log(`[DOH] ${dohConfig.enabled ? `ENABLED (${dohConfig.provider})` : 'disabled'}`);
    console.log(`[FINGERPRINTS] ${Object.keys(fingerprintProfiles.browser_profiles || {}).length} profiles`);
    console.log(`[INTELLIGENCE] ${crawlerIntelligence.enabled ? 'ENABLED' : 'disabled'}`);
    console.log(`============================================================\n`);
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`[ERROR] Port ${PORT} in use. Try: PORT=8011 npm start`);
    } else {
        console.error(`[ERROR] ${err.message}`);
    }
    process.exit(1);
});

function shutdown(signal) {
    console.log(`[SYSTEM] ${signal} received; shutting down gracefully...`);
    server.close(() => {
        console.log('[SYSTEM] Server closed');
        process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

