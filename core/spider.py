"""
VulcanX Web Spider
==================
Recursive BFS crawler that expands like a spider-web from a seed URL.
For every page it visits it:
  1. Extracts ALL reachable URLs (anchors, forms, scripts, inline-JS paths)
  2. Runs the full VulcanX security analysis on response headers + body
  3. Queues newly-found in-scope URLs for the next BFS level
  4. Reports live progress back through the LiveBrowserInterceptor

Works independently of Selenium — uses the requests library so it keeps
crawling even when the browser is idle or the user is on a different tab.
"""

import threading
import time
import datetime
import re
import urllib.parse
from collections import deque


class SpiderNode:
    """Represents one crawled URL in the spider's graph."""
    __slots__ = ('url', 'parent', 'depth', 'status_code', 'content_type',
                 'links_found', 'findings_count', 'error', 'crawled_at')

    def __init__(self, url, parent=None, depth=0):
        self.url           = url
        self.parent        = parent
        self.depth         = depth
        self.status_code   = 0
        self.content_type  = ''
        self.links_found   = 0
        self.findings_count = 0
        self.error         = None
        self.crawled_at    = None


class WebSpider:
    """
    BFS recursive web spider.

    Usage:
        spider = WebSpider(interceptor, start_url, max_depth=4, max_urls=400)
        spider.start()
        ...
        spider.stop()
    """

    SKIP_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp4', '.mp3', '.avi', '.mov', '.webm',
        '.pdf', '.zip', '.rar', '.tar', '.gz',
        '.exe', '.msi', '.dmg', '.deb',
        '.css',  # skip stylesheets — not security-relevant for body scan
    }

    REQUEST_HEADERS = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/124.0.0.0 Safari/537.36'
        ),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    }

    def __init__(self, interceptor, start_url,
                 max_depth=4, max_urls=400, delay=0.4, threads=5):
        self.interceptor = interceptor
        self.start_url   = start_url
        self.max_depth   = max_depth
        self.max_urls    = max_urls
        self.delay       = delay        # seconds between requests per thread
        self.num_threads = threads

        # BFS state
        self._queue   = deque()
        self._visited = set()           # URLs already queued/crawled
        self._lock    = threading.Lock()

        # Graph of SpiderNodes (url → node)
        self.graph = {}

        # Live stats (read by API server)
        self.stats = {
            'running':     False,
            'visited':     0,
            'queued':      0,
            'total_found': 0,
            'errors':      0,
            'start_time':  None,
            'current_urls': [],        # URLs currently being fetched
            'depth_counts': {},        # depth → count
        }

        self._stop_event = threading.Event()

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def start(self):
        """Start the spider in a pool of background threads."""
        if self.stats['running']:
            return
        self._stop_event.clear()
        self.stats['running']    = True
        self.stats['start_time'] = datetime.datetime.now().isoformat()

        # Seed the queue
        self._enqueue(self.start_url, parent=None, depth=0)

        # Launch worker threads
        for _ in range(self.num_threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()

        print(f"[*] Spider started: {self.start_url}  |  max_depth={self.max_depth}  "
              f"|  max_urls={self.max_urls}  |  threads={self.num_threads}")

    def stop(self):
        """Gracefully stop the spider."""
        self._stop_event.set()
        self.stats['running'] = False
        print("[*] Spider stopped.")

    # ─────────────────────────────────────────────────────────────────────────
    # Internal
    # ─────────────────────────────────────────────────────────────────────────

    def _enqueue(self, url, parent, depth):
        """Add a URL to the BFS queue (thread-safe, dedup)."""
        url = self._normalize(url)
        if not url:
            return
        with self._lock:
            if url in self._visited:
                return
            if len(self._visited) >= self.max_urls:
                return
            self._visited.add(url)
            node = SpiderNode(url, parent=parent, depth=depth)
            self.graph[url] = node
            self._queue.append(node)
            self.stats['queued']      = len(self._queue)
            self.stats['total_found'] = len(self._visited)
            self.stats['depth_counts'][depth] = \
                self.stats['depth_counts'].get(depth, 0) + 1

    def _worker(self):
        """BFS worker — runs until queue is empty or stop requested."""
        import requests
        session = requests.Session()
        session.headers.update(self.REQUEST_HEADERS)
        session.verify = False

        while not self._stop_event.is_set():
            node = None
            with self._lock:
                if self._queue:
                    node = self._queue.popleft()
                    self.stats['queued'] = len(self._queue)

            if node is None:
                # Queue empty — wait briefly then check again
                time.sleep(0.3)
                # If still empty and visited all — stop
                with self._lock:
                    if not self._queue and self.stats['visited'] >= self.stats['total_found']:
                        break
                continue

            # Update current URL tracker
            with self._lock:
                self.stats['current_urls'].append(node.url)
                if len(self.stats['current_urls']) > self.num_threads:
                    self.stats['current_urls'] = self.stats['current_urls'][-self.num_threads:]

            self._crawl_node(session, node)

            with self._lock:
                self.stats['visited'] += 1
                try:
                    self.stats['current_urls'].remove(node.url)
                except ValueError:
                    pass

            time.sleep(self.delay)

        self.stats['running'] = False

    def _crawl_node(self, session, node):
        """Fetch a single URL, analyze it, and enqueue discovered links."""
        url = node.url

        # Skip non-web schemes and unwanted extensions
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return
        ext = '.' + url.split('.')[-1].split('?')[0].lower() if '.' in url.split('/')[-1] else ''
        if ext in self.SKIP_EXTENSIONS:
            return

        try:
            resp = session.get(url, timeout=12, allow_redirects=True,
                               stream=False)
            node.status_code  = resp.status_code
            node.content_type = resp.headers.get('Content-Type', '')
            node.crawled_at   = datetime.datetime.now().strftime('%H:%M:%S')

            # ── Add to Interceptor's live traffic ──────────────────────────
            self._report_traffic(node, resp)

            # ── Security analysis (headers + body) ─────────────────────────
            findings = self._analyze(url, resp)
            node.findings_count = len(findings)

            # ── Extract links from HTML response ───────────────────────────
            ctype = node.content_type.lower()
            if 'text/html' in ctype and node.depth < self.max_depth:
                child_links = self._extract_links(url, resp.text)
                node.links_found = len(child_links)
                for link in child_links:
                    self._enqueue(link, parent=url, depth=node.depth + 1)

        except Exception as exc:
            node.error = str(exc)[:120]
            with self._lock:
                self.stats['errors'] += 1

    def _report_traffic(self, node, resp):
        """Push the crawled entry into the interceptor's live_traffic list."""
        ix = self.interceptor
        if ix is None:
            return
        display_url = node.url[:150] + '...' if len(node.url) > 150 else node.url
        entry = {
            'id':          f'spider_{hash(node.url) & 0xFFFFFF}',
            'method':      'SPIDER',
            'url':         node.url,
            'display_url': display_url,
            'status_code': node.status_code,
            'time':        node.crawled_at or '',
            'req_headers': {},
            'req_body':    '',
            'depth':       node.depth,
            'parent':      node.parent or '',
        }
        # Update existing entry if already added as DISCOVERED
        for e in ix.live_traffic:
            if e.get('url') == node.url:
                e.update(entry)
                return
        ix.live_traffic.append(entry)
        if len(ix.live_traffic) > 1000:
            ix.live_traffic.pop(0)

    def _analyze(self, url, resp):
        """Run VulcanX security analysis on this response."""
        ix = self.interceptor
        if ix is None:
            return []
        all_findings = []

        # ── Header analysis ────────────────────────────────────────────────
        try:
            ix._analyze_cdp_response(url, resp.status_code, dict(resp.headers))
        except Exception:
            pass

        # ── Body analysis ──────────────────────────────────────────────────
        ctype = resp.headers.get('Content-Type', '').lower()
        if any(t in ctype for t in ('text/html', 'javascript', 'json', 'text/plain', 'xml')):
            try:
                body = resp.text[:300000]
                if body:
                    findings = ix.analyzer.scan({url: body}, set())
                    for f in findings:
                        f.setdefault('source', 'SPIDER')
                        ix._inject_ui_alert(f)
                        all_findings.append(f)
            except Exception:
                pass

        return all_findings

    def _extract_links(self, base_url, html):
        """Extract all in-scope URLs from an HTML page."""
        links = set()

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')

            # Anchor + link tags
            for tag in soup.find_all(['a', 'link'], href=True):
                try:
                    href = tag.get('href', '').strip()
                    if href and not href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                        links.add(urllib.parse.urljoin(base_url, href))
                except Exception:
                    pass

            # Forms
            for form in soup.find_all('form', action=True):
                try:
                    action = form.get('action', '').strip()
                    if action:
                        links.add(urllib.parse.urljoin(base_url, action))
                except Exception:
                    pass

            # Script src
            for tag in soup.find_all('script', src=True):
                try:
                    links.add(urllib.parse.urljoin(base_url, tag['src']))
                except Exception:
                    pass

            # Inline JS path strings  e.g.  '/api/v1/users'
            for script in soup.find_all('script', src=False):
                blob = script.string or ''
                for m in re.finditer(r"""['"]([/][a-zA-Z0-9_.~!*:@,;+?=$&%#\-/]+)['"]""", blob):
                    try:
                        candidate = urllib.parse.urljoin(base_url, m.group(1))
                        links.add(candidate)
                    except Exception:
                        pass

        except ImportError:
            # Fallback: simple regex if BeautifulSoup not available
            for m in re.finditer(r'href=["\']([^"\'#\s]+)["\']', html, re.I):
                try:
                    links.add(urllib.parse.urljoin(base_url, m.group(1)))
                except Exception:
                    pass

        # Filter to in-scope only
        scope = self.interceptor.scope if self.interceptor else None
        if scope:
            links = {l for l in links if scope.in_scope(l)}

        return links

    @staticmethod
    def _normalize(url):
        """Normalize a URL — remove fragment, collapse whitespace."""
        url = url.strip()
        if not url or url.startswith(('javascript:', 'mailto:', 'tel:', 'data:', 'blob:')):
            return None
        # Strip fragment
        url = url.split('#')[0]
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ('http', 'https'):
                return None
            return urllib.parse.urlunparse(parsed)
        except Exception:
            return None
