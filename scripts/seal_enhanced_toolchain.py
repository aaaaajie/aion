"""Seal build-time browser, Python wheels and rule assets into the release."""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1] / 'tools' / 'binaries'
manifest_path = root / 'manifest.json'
manifest = json.loads(manifest_path.read_text())
from playwright.sync_api import sync_playwright
with sync_playwright() as playwright:
    executable = Path(playwright.chromium.executable_path)
assert executable.is_relative_to(root)
version = subprocess.check_output([str(executable), '--version'], text=True).strip()
manifest['system_binaries']['chromium'] = {
    'version': version.split()[1], 'path': str(executable.relative_to(root)),
    'sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
    'asset_directory': 'playwright-browsers',
    'version_args': ['--version'], 'required': True, 'purpose': 'Headless business request capture'}
for name in ('playwright', 'semgrep'):
    manifest['python_packages'][name] = {'version': importlib.metadata.version(name),
        'package': name, 'required': True, 'purpose': 'Offline browser and source review'}
manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
lock = subprocess.check_output([sys.executable, '-m', 'pip', 'freeze'], text=True)
(root / 'enhanced-requirements.lock').write_text(lock)
(root / 'system-packages.lock').write_text(subprocess.check_output(['dpkg-query', '-W', '-f=${Package}=${Version}\n'], text=True))
assets = {}
for folder in (root / 'playwright-browsers', root.parent / 'source' / 'rules', root / 'cyberchef'):
    for path in sorted(folder.rglob('*')):
        if path.is_file():
            assets[str(path.relative_to(root.parent))] = hashlib.sha256(path.read_bytes()).hexdigest()
(root / 'enhanced-assets.sha256.json').write_text(json.dumps(assets, indent=2) + '\n')
