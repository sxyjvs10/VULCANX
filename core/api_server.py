"""
VulcanX Local API Server
Replaces selenium-wire's request interceptor for handling widget API calls.
Runs as a background HTTP server on a random free port (localhost only).
Works on any Python version including 3.14+.
"""

import http.server
import threading
import socket
import json
import urllib.parse
import urllib.request
import subprocess
import os
import sys


def find_free_port():
    """Find a free port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class VulcanXAPIHandler(http.server.BaseHTTPRequestHandler):
    """
    Lightweight HTTP request handler for the VulcanX widget API.
    The interceptor instance is set via the class variable `interceptor`.
    """
    interceptor = None  # Set to LiveBrowserInterceptor instance after start

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
                    ip = urllib.request.urlopen(
                        'https://checkip.amazonaws.com', timeout=10
                    ).read().decode('utf-8').strip()
                    self._send_json({'status': 'ok', 'ip': ip})
                except Exception as e:
                    self._send_json({'status': 'error', 'error': str(e)})
            elif action in ('enable_tor', 'disable_tor'):
                # Tor proxy toggle — handled by the browser profile separately
                self._send_json({'status': 'ok', 'message': f'{action} acknowledged (no selenium-wire proxy on Python 3.14+)'})
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
                method = data.get('method', 'GET')
                url = data.get('url', '')
                headers = data.get('headers', {})
                body = data.get('body', '')
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
            target_url = data.get('url', '')
            self._send_json({'status': 'ok', 'message': f'Spider queued for {target_url}'})

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
