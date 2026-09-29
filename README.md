# Rook Crawler

Rook Crawler is a local web crawler with a browser UI and a Node.js proxy layer. The crawler orchestration and extraction logic run in the browser UI (index.html); the local server (server.js) provides controlled outbound HTTP access through cuimp, optional proxy rotation, optional Tor routing, DNS validation, authentication, and response analysis.

**Release target:** 2.1.0 RC  
**Current state:** hardening branch, not yet a production release  
**Platforms:** Windows, macOS, Linux, Termux/Android-compatible Node environments, subject to cuimp platform support

## Quick start

### Windows PowerShell 7+

```powershell
git clone https://github.com/psfr4590-afk/Rook-Crawler.git
cd Rook-Crawler
.\start.ps1
```

The launcher uses `npm ci` against the committed lockfile and starts the server on `127.0.0.1:8010` by default.

### Linux / macOS / Termux

```bash
git clone https://github.com/psfr4590-afk/Rook-Crawler.git
cd Rook-Crawler
npm ci
npm start
```

On Termux:

```bash
chmod +x start.sh
./start.sh
```

Open `http://127.0.0.1:8010`.

Node.js **18.17+** is required.

## What is implemented

### Browser crawler

The UI provides:

- multiple seed targets
- configurable maximum depth and page count
- configurable concurrency and delay
- same-domain crawling by default
- optional subdomain and external-link crawling
- robots.txt handling
- sitemap seeding
- URL normalization and filtering
- duplicate-content detection
- content extraction and keyword matching
- crawl cancellation
- denial tracking with explicit reasons
- JSON and CSV result export
- proxy configuration and proxy-token configuration

The crawler is intentionally kept in the existing browser-first architecture. The hardening work does not replace it with a second crawler engine.

### Local proxy layer

`server.js` provides:

- HTTP/HTTPS target validation
- rotating HTTP/HTTPS/SOCKS proxy selection
- optional Tor routing for `.onion` targets
- optional DoH-backed DNS validation
- browser fingerprint selection through cuimp
- response analysis and error memory
- bounded request bodies and response bodies
- validated redirects with a configurable redirect limit
- request timeout
- graceful shutdown
- localhost-only binding by default
- token protection when exposed beyond loopback
- restricted CORS
- security response headers

## Security defaults

The server now binds to `127.0.0.1` by default.

A non-loopback bind is refused unless `PROXY_TOKEN` is configured. To deliberately expose the proxy on another interface:

```powershell
$env:HOST="0.0.0.0"
$env:PROXY_TOKEN="replace-with-a-long-random-secret"
npm start
```

Additional environment controls:

| Variable | Default | Purpose |
|---|---:|---|
| `HOST` | `127.0.0.1` | Listen address |
| `PORT` | `8010` | Listen port |
| `PROXY_TOKEN` | unset | Authentication token |
| `CORS_ALLOW_ORIGINS` | localhost origins | Comma-separated allowed browser origins |
| `REQUEST_TIMEOUT_MS` | `15000` | Upstream request timeout |
| `MAX_RESPONSE_BYTES` | `10485760` | Maximum buffered upstream response |
| `MAX_REDIRECTS` | `5` | Maximum validated redirects |

Do not commit `token.txt`, proxy lists containing credentials, `.env` files, or other secrets.

## SSRF and DNS protections

The proxy rejects localhost names, loopback addresses, RFC1918 private IPv4 ranges, link-local IPv4 addresses, unspecified IPv4 addresses, common private/link-local IPv6 ranges, IPv4-mapped private IPv6 addresses, and `.internal` hostnames.

Hostname targets are validated against DNS before the upstream request. When DoH is enabled, the configured DoH provider is used for this validation. A target that resolves to a blocked/private address is rejected.

Redirects are not blindly followed. Each redirect is parsed, restricted to HTTP/HTTPS, DNS-validated, and subject to `MAX_REDIRECTS`.

`.onion` targets are only permitted when Tor is explicitly enabled.

This protects the local proxy boundary. It is not a guarantee that a third-party proxy is trustworthy or that a remote proxy will perform identical DNS validation.

## Tor

Tor is disabled by default.

Example `tor.json`:

```json
{
  "enabled": true,
  "mode": "local",
  "socksPort": 9050,
  "controlPort": 9051,
  "autoLaunch": false,
  "circuitIsolation": true,
  "circuitRotationInterval": 300000
}
```

Add `tor://` to `proxies.txt` when Tor routing is enabled.

A local Tor daemon must already be available. Rook Crawler does not silently install or launch a Tor daemon.

## DoH

DoH configuration lives in `doh.json`. It is used for DNS validation and caching, not as a claim that every DNS operation performed by a third-party proxy is under Rook Crawler's control.

Supported configured providers include Cloudflare, Google, Quad9, and NextDNS.

## Browser fingerprints

`fingerprints.json` contains browser descriptors used by cuimp for HTTP/TLS impersonation. Fingerprint rotation is controlled by `crawler-intelligence.json`.

This is browser impersonation, not a promise of anonymity or undetectability.

## Crawler intelligence

`crawler-intelligence.json` contains the existing adaptive strategy configuration, including adaptive delay, content prioritization, anti-bot response signatures, cookie persistence configuration, link-quality scoring configuration, optional JavaScript-rendering configuration, dynamic fingerprint rotation, response analysis, and in-memory error learning.

Some configuration entries describe capabilities that are intentionally disabled until their required runtime component exists. They are not represented as completed subsystems merely because a JSON option exists.

## Configuration files

| File | Purpose |
|---|---|
| `server.js` | Local proxy server and network boundary |
| `index.html` | Browser crawler UI and crawl engine |
| `proxies.txt` | Optional proxy pool |
| `token.txt` | Optional authentication secret |
| `tor.json` | Tor configuration |
| `doh.json` | DoH configuration |
| `fingerprints.json` | Browser fingerprint descriptors |
| `crawler-intelligence.json` | Adaptive crawler configuration |
| `start.sh` | Linux/macOS/Termux launcher |
| `start.ps1` | Windows PowerShell launcher |

## Testing

The repository has a real Node.js test contract:

```bash
npm ci
npm test
npm run lint
```

The test suite currently verifies server syntax, release dependency/lockfile identity, and launcher presence. CI runs the release contract across supported Node.js versions on Linux and Windows and performs a production-dependency audit.

The RC is not considered production-ready until the complete CI/security/deployment verification gate is green.

## Dependency contract

The release branch pins Express 4.22.3 and cuimp 2.1.1. The lockfile is committed and launchers use `npm ci` rather than an unconstrained `npm install`.

## Legal and operational use

Only crawl systems you are authorized to access. Respect robots.txt, rate limits, access controls, Terms of Service, and applicable law. Proxy rotation, Tor, and browser impersonation do not change those obligations.

## License

MIT
