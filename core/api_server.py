"""
VulcanX Local API Server
Replaces selenium-wire's request interceptor for handling widget API calls.
Runs as a background HTTP server on a random free port (localhost only).
Works on any Python version including 3.14+.

Also hosts /api/proxy_status which is polled by the VulcanX Chrome Extension
to dynamically change Chrome's proxy settings without restarting the browser.
"""

import http.server
import threading
import socket
import json
import os
import tempfile
import urllib.parse
import urllib.request


def find_free_port():
    """Find a free port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def create_proxy_extension(api_port: int) -> str:
    """
    Dynamically generates a Chrome extension that can change Chrome's proxy
    settings mid-session by polling the VulcanX API server.
    Returns the path to the extension directory.
    """
    ext_dir = os.path.join(tempfile.gettempdir(), 'vulcanx_proxy_ext')
    os.makedirs(ext_dir, exist_ok=True)

    manifest = {
        "manifest_version": 3,
        "name": "VulcanX Proxy Controller",
        "version": "1.0",
        "description": "Dynamically routes Chrome traffic through Tor or a custom proxy for VulcanX.",
        "permissions": ["proxy", "storage"],
        "host_permissions": [
            "http://127.0.0.1:*/",
            "<all_urls>"
        ],
        "background": {
            "service_worker": "background.js"
        }
    }

    background_js = f"""
// VulcanX Proxy Controller - Background Service Worker
// Polls the VulcanX API server and applies proxy settings to Chrome.

const API_BASE = 'http://127.0.0.1:{api_port}';

let currentMode = 'direct';

async function applyProxy(status) {{
    const mode = status.mode || 'direct';
    if (mode === currentMode) return;
    currentMode = mode;

    if (mode === 'tor') {{
        chrome.proxy.settings.set({{
            value: {{
                mode: "fixed_servers",
                rules: {{
                    singleProxy: {{
                        scheme: "socks5",
                        host: "127.0.0.1",
                        port: 9050
                    }},
                    bypassList: ["localhost", "127.0.0.1"]
                }}
            }},
            scope: 'regular'
        }}, () => {{
            console.log('[VulcanX] Proxy set to Tor (SOCKS5 127.0.0.1:9050)');
        }});
    }} else if (mode === 'custom') {{
        const scheme = status.scheme || 'http';
        const host   = status.host   || '127.0.0.1';
        const port   = status.port   || 8080;
        chrome.proxy.settings.set({{
            value: {{
                mode: "fixed_servers",
                rules: {{
                    singleProxy: {{ scheme, host, port }},
                    bypassList: ["localhost", "127.0.0.1"]
                }}
            }},
            scope: 'regular'
        }}, () => {{
            console.log(`[VulcanX] Proxy set to ${{scheme}}://${{host}}:${{port}}`);
        }});
    }} else {{
        // direct — remove proxy
        chrome.proxy.settings.set({{
            value: {{ mode: "direct" }},
            scope: 'regular'
        }}, () => {{
            console.log('[VulcanX] Proxy disabled — direct connection.');
        }});
    }}
}}

async function pollProxyStatus() {{
    try {{
        const resp = await fetch(API_BASE + '/api/proxy_status', {{ signal: AbortSignal.timeout(3000) }});
        if (resp.ok) {{
            const data = await resp.json();
            await applyProxy(data);
        }}
    }} catch (e) {{
        // API server not ready yet, skip silently
    }}
}}

// Poll every 2 seconds
setInterval(pollProxyStatus, 2000);
// Run immediately on startup
pollProxyStatus();
"""

    with open(os.path.join(ext_dir, 'manifest.json'), 'w') as f:
        json.dump(manifest, f, indent=2)

    with open(os.path.join(ext_dir, 'background.js'), 'w') as f:
        f.write(background_js)

    return ext_dir


class VulcanXAPIHandler(http.server.BaseHTTPRequestHandler):
    """
    Lightweight HTTP request handler for the VulcanX widget API.
    The interceptor instance is set via the class variable `interceptor`.
    Proxy state is tracked in the class variable `proxy_state`.
    """
    interceptor = None   # Set to LiveBrowserInterceptor instance after start
    proxy_state  = {     # Current proxy configuration — read by the Chrome extension
        'mode':   'direct',  # 'direct' | 'tor' | 'custom'
        'scheme': 'socks5',
        'host':   '127.0.0.1',
        'port':   9050
    }

    def log_message(self, format, *args):
        pass  # Suppress noisy HTTP logs from the console

    # ─── CORS preflight ────────────────────────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(200)
        self._add_cors_headers()
        self.end_headers()

    # ─── GET endpoints ─────────────────────────────────────────────────────────
    def do_GET(self):
        path = self.path.split('?')[0]
        ix = self.interceptor

        # ── /api/proxy_status  (polled by the Chrome extension) ────────────
        if path == '/api/proxy_status':
            self._send_json(self.__class__.proxy_state)
            return

        # ── /api/report ─────────────────────────────────────────────────────
        if path == '/api/report':
            try:
                from core.report import generate_html_report
                html = generate_html_report(ix.analyzer.findings if ix else [])
                data = html.encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self._add_cors_headers()
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self._send_json({'status': 'error', 'error': str(e)}, 500)
            return

        self._send_json({'status': 'error', 'error': 'Not found'}, 404)

    # ─── POST endpoints ────────────────────────────────────────────────────────
    def do_POST(self):
        path = self.path.split('?')[0]
        ix = self.interceptor

        # Read body
        content_length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(content_length) if content_length > 0 else b''
        try:
            data = json.loads(raw_body.decode('utf-8')) if raw_body else {}
        except Exception:
            data = {}

        if ix is None:
            self._send_json({'status': 'error', 'error': 'Interceptor not ready'}, 503)
            return

        # ── /api/clear_traffic ──────────────────────────────────────────────
        if path == '/api/clear_traffic':
            ix.live_traffic.clear()
            ix.processed_requests.clear()
            ix.analyzer.scanned_urls = set()
            self._send_json({'status': 'ok'})

        # ── /api/clear_findings ─────────────────────────────────────────────
        elif path == '/api/clear_findings':
            ix.live_findings.clear()
            ix.live_hypotheses.clear()
            from core.correlate import CorrelationEngine
            ix.correlator = CorrelationEngine()
            ix.analyzer.findings = []
            ix.analyzer.scanned_urls = set()
            self._send_json({'status': 'ok'})

        # ── /api/vpn ────────────────────────────────────────────────────────
        elif path == '/api/vpn':
            action = data.get('action')

            if action == 'check_ip':
                try:
                    # If Tor is active, try fetching IP through it
                    ip = urllib.request.urlopen(
                        'https://checkip.amazonaws.com', timeout=10
                    ).read().decode('utf-8').strip()
                    mode = self.__class__.proxy_state.get('mode', 'direct')
                    self._send_json({'status': 'ok', 'ip': ip, 'mode': mode})
                except Exception as e:
                    self._send_json({'status': 'error', 'error': str(e)})

            elif action == 'enable_tor':
                self.__class__.proxy_state = {
                    'mode': 'tor',
                    'scheme': 'socks5',
                    'host': '127.0.0.1',
                    'port': 9050
                }
                ix.tor_enabled = True
                self._send_json({
                    'status': 'ok',
                    'message': 'Tor proxy enabled. Chrome will route all traffic through SOCKS5 127.0.0.1:9050 within ~2 seconds.'
                })

            elif action == 'disable_tor':
                self.__class__.proxy_state = {'mode': 'direct'}
                ix.tor_enabled = False
                self._send_json({'status': 'ok', 'message': 'Proxy disabled. Chrome is back to direct connection.'})

            elif action == 'enable_custom':
                # Custom proxy: {action, scheme, host, port}
                scheme = data.get('scheme', 'http')
                host   = data.get('host', '127.0.0.1')
                port   = int(data.get('port', 8080))
                self.__class__.proxy_state = {
                    'mode': 'custom',
                    'scheme': scheme,
                    'host': host,
                    'port': port
                }
                self._send_json({
                    'status': 'ok',
                    'message': f'Custom proxy set to {scheme}://{host}:{port}. Chrome will update within ~2 seconds.'
                })

            else:
                self._send_json({'status': 'error', 'error': 'Unknown VPN action'})

        # ── /api/update_scope ───────────────────────────────────────────────
        elif path == '/api/update_scope':
            hosts = data.get('hosts', [])
            if ix.scope:
                ix.scope.extra_hosts = hosts
            self._send_json({'status': 'ok'})

        # ── /api/repeater ───────────────────────────────────────────────────
        elif path == '/api/repeater':
            try:
                import requests as req_lib
                method  = data.get('method', 'GET')
                url     = data.get('url', '')
                headers = data.get('headers', {})
                body    = data.get('body', '')
                resp = req_lib.request(method, url, headers=headers, data=body, timeout=15, verify=False)
                self._send_json({
                    'status': 'ok',
                    'status_code': resp.status_code,
                    'headers': dict(resp.headers),
                    'body': resp.text[:50000]
                })
            except Exception as e:
                self._send_json({'status': 'error', 'error': str(e)})

        # ── /api/spider ─────────────────────────────────────────────────────
        elif path == '/api/spider':
            action = data.get('action', 'start')
            if action == 'start':
                url        = data.get('url') or (ix.current_url or ix.analyzer.target_url if hasattr(ix.analyzer,'target_url') else '')
                max_depth  = int(data.get('max_depth', 4))
                max_urls   = int(data.get('max_urls', 400))
                delay      = float(data.get('delay', 0.4))
                threads    = int(data.get('threads', 5))

                if not url:
                    self._send_json({'status': 'error', 'error': 'No URL provided and no current page URL available.'})
                    return

                # Stop any existing spider first
                if ix.spider and ix.spider.stats.get('running'):
                    ix.spider.stop()

                from core.spider import WebSpider
                ix.spider = WebSpider(
                    interceptor=ix,
                    start_url=url,
                    max_depth=max_depth,
                    max_urls=max_urls,
                    delay=delay,
                    threads=threads,
                )
                ix.spider.start()
                self._send_json({'status': 'ok', 'message': f'Spider started from {url}', 'stats': ix.spider.stats})

            elif action == 'stop':
                if ix.spider:
                    ix.spider.stop()
                    self._send_json({'status': 'ok', 'message': 'Spider stopped.'})
                else:
                    self._send_json({'status': 'ok', 'message': 'No spider running.'})

            elif action == 'status':
                if ix.spider:
                    self._send_json({'status': 'ok', 'stats': ix.spider.stats})
                else:
                    self._send_json({'status': 'ok', 'stats': {'running': False, 'visited': 0, 'queued': 0, 'total_found': 0}})
            else:
                self._send_json({'status': 'error', 'error': f'Unknown spider action: {action}'})

        # ── /api/ai_assist ──────────────────────────────────────────────────
        elif path == '/api/ai_assist':
            self._send_json({'status': 'ok', 'response': 'AI assistance requires OpenAI API key configuration.'})

        else:
            self._send_json({'status': 'error', 'error': f'Unknown endpoint: {path}'}, 404)

    # ─── Helpers ───────────────────────────────────────────────────────────────
    def _add_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self._add_cors_headers()
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class VulcanXAPIServer:
    """Manages the lifecycle of the local API HTTP server."""

    def __init__(self):
        self.port = find_free_port()
        self._server = None
        self._thread = None

    def start(self, interceptor_instance):
        """Start the API server in a background daemon thread."""
        VulcanXAPIHandler.interceptor = interceptor_instance
        self._server = http.server.HTTPServer(('127.0.0.1', self.port), VulcanXAPIHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.port

    def stop(self):
        if self._server:
            self._server.shutdown()
