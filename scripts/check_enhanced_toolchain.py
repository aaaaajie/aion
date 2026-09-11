"""Run inside the release with --network none; only loopback fixtures are used."""
import asyncio
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import threading

import httpx
from tools.browser.wrapper import BrowserTools, BrowserOpenArguments, BrowserActionArguments, BrowserOutputArguments, BrowserExportArguments, BrowserSessionArguments
from tools.binaries.layout import toolchain_for


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, body, status=200, content_type='text/html', headers=()):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/api':
            self.reply(json.dumps({'authenticated': 'session=fixture' in self.headers.get('Cookie', '')}).encode(), content_type='application/json')
        elif self.path == '/download':
            self.reply(b'local export', headers=[('Content-Disposition', 'attachment; filename=export.txt')])
        else:
            self.reply(b'''<input id="username"><button id="login" onclick="fetch('/login',{method:'POST',body:document.querySelector('#username').value}).then(()=>fetch('/api')).then(r=>r.json()).then(r=>document.querySelector('#result').textContent=JSON.stringify(r))">Login</button><p id="result"></p><input type="file" id="upload"><button id="send" onclick="let f=new FormData();f.append('file',document.querySelector('#upload').files[0]);fetch('/upload',{method:'POST',body:f})">Upload</button><a id="download" href="/download">Export</a>''')

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.reply(b'{}', content_type='application/json', headers=[('Set-Cookie', 'session=fixture; HttpOnly; Path=/')])


async def check_browser(root, url):
    owner = root / 'owner'; other = root / 'other'
    owner.mkdir(); other.mkdir()
    tracked = []
    async def track(pid):
        tracked.append(pid)
    browser, isolated = BrowserTools(owner, on_process_started=track), BrowserTools(other)
    try:
        opened = await browser.open(BrowserOpenArguments(url=url))
        sid = opened['session_id']
        await browser.action(BrowserActionArguments(session_id=sid, action='fill', selector='#username', value='fixture'))
        await browser.action(BrowserActionArguments(session_id=sid, action='click', selector='#login'))
        await browser.sessions[sid]['page'].wait_for_function("document.querySelector('#result').textContent.includes('true')")
        await browser.action(BrowserActionArguments(session_id=sid, action='screenshot'))
        upload = owner / 'upload.txt'; upload.write_text('local fixture')
        await browser.action(BrowserActionArguments(session_id=sid, action='upload', selector='#upload', value='upload.txt'))
        async with browser.sessions[sid]['page'].expect_response('**/upload'):
            await browser.action(BrowserActionArguments(session_id=sid, action='click', selector='#send'))
        await browser.action(BrowserActionArguments(session_id=sid, action='click', selector='#download'))
        await browser.close_session(BrowserSessionArguments(session_id=sid))
        evidence = await browser.output(BrowserOutputArguments(session_id=sid, limit=100))
        assert evidence['state'] == 'closed'
        assert tracked, 'browser processes must have an owner'
        assert evidence['downloads'] and Path(evidence['screenshot_path']).is_file()
        api = next(r for r in evidence['requests'] if r['url'].endswith('/api'))
        request = await browser.export_request(BrowserExportArguments(session_id=sid, request_id=api['request_id']))
        async with httpx.AsyncClient() as client:
            response = await client.get(request['arguments']['url'], headers=request['arguments']['headers'])
        assert response.json()['authenticated'] is True
        multipart = next(r for r in evidence['requests'] if r['url'].endswith('/upload'))
        assert multipart['replayable'] is False
        try:
            await isolated.output(BrowserOutputArguments(session_id=sid))
        except Exception:
            pass
        else:
            raise AssertionError('cross-Agent evidence accepted')
        second = await isolated.open(BrowserOpenArguments(url=url + 'api'))
        assert 'session=fixture' not in str(await isolated.context.cookies())
        await isolated.close()
        # A fresh provider sees durable evidence but never resumes old pages.
        await browser.close()
        restarted = BrowserTools(owner)
        assert (await restarted.output(BrowserOutputArguments(session_id=sid)))['state'] == 'closed'
        await restarted.close()
        return {'passed': True, 'captured_requests': len(evidence['requests']), 'isolated_session': bool(second)}
    finally:
        await browser.close()
        await isolated.close()


def check_source(root):
    source = root / 'src'; source.mkdir()
    (source / 'sample.py').write_text('def read(path):\n    return open(path).read()\n')
    (source / 'sample.php').write_text('<?php function read_path($path) { return file_get_contents($path); }')
    (source / 'sample.ts').write_text('function read(path: string) { return fs.readFileSync(path); }')
    (source / 'clean.py').write_text('def add(a, b):\n    return a + b\n')
    result = subprocess.run([sys.executable, '-m', 'tools.source.scan', str(source)], cwd=root, capture_output=True, text=True)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    report = json.loads(result.stdout)
    files = {Path(f['file']).name for f in report['findings']}
    assert files == {'sample.py', 'sample.php', 'sample.ts'}, report
    clean = root / 'clean'; clean.mkdir(); (clean / 'clean.py').write_text('answer = 1 + 2\n')
    empty = subprocess.run([sys.executable, '-m', 'tools.source.scan', str(clean)], cwd=root, capture_output=True, text=True, check=True)
    assert json.loads(empty.stdout)['total_findings'] == 0
    return {'passed': True, 'languages': sorted(files), 'findings': report['total_findings']}


def main():
    assert platform.system() == 'Linux' and platform.machine() == 'x86_64'
    assert sys.version_info[:2] == (3, 11)
    bundle = toolchain_for().root
    assets = json.loads((bundle / 'enhanced-assets.sha256.json').read_text())
    for name, expected in assets.items():
        assert hashlib.sha256((bundle.parent / name).read_bytes()).hexdigest() == expected, name
    with tempfile.TemporaryDirectory(prefix='aion-enhanced-') as temp:
        root = Path(temp)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            browser = asyncio.run(check_browser(root, f'http://127.0.0.1:{server.server_port}/'))
            source = check_source(root)
        finally:
            server.shutdown(); server.server_close()
    print(json.dumps({'passed': True, 'platform': 'linux-x86_64-python3.11',
                      'assets_verified': len(assets), 'browser': browser, 'source': source,
                      'versions': {name: importlib.metadata.version(name) for name in ('playwright', 'semgrep')}}, indent=2))


if __name__ == '__main__':
    main()
