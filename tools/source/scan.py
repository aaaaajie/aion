"""Subprocess entrypoint; all scanning stays inside the owned shell task."""
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid


def main():
    root = Path(sys.argv[1]).resolve(strict=True)
    out = Path.cwd() / 'source-reviews' / uuid.uuid4().hex
    out.mkdir(parents=True, mode=0o700)
    artifact = out / 'semgrep.json'
    rules = Path(__file__).with_name('rules')
    env = dict(os.environ, SEMGREP_SEND_METRICS='off', SEMGREP_ENABLE_VERSION_CHECK='0',
               SEMGREP_SETTINGS_FILE=str(out / 'settings.yml'))
    env.pop('SEMGREP_APP_TOKEN', None)
    command = [str(Path(sys.executable).with_name('semgrep')), 'scan', '--config', str(rules),
               '--json', '--output', str(artifact), '--metrics=off', '--disable-version-check',
               '--no-git-ignore', '--max-target-bytes', '1000000', '--timeout', '10']
    for pattern in ('.git', 'node_modules', 'vendor', '.venv', 'venv', 'dist', 'build', 'source-reviews'):
        command.extend(['--exclude', pattern])
    command.append(str(root))
    result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        report = json.loads(artifact.read_text())
    except (OSError, ValueError):
        print(json.dumps({'state': 'tool_failed', 'exit_code': result.returncode,
                          'error': result.stderr.decode(errors='replace')[-2000:]}))
        return 1
    findings = []
    for item in report.get('results', []):
        path = Path(item['path']).resolve()
        snippet = ''
        if path.is_relative_to(root) and path.is_file() and path.stat().st_size <= 1000000:
            lines = path.read_text(errors='replace').splitlines()
            start = item['start']['line'] - 1
            snippet = '\n'.join(lines[start:min(item['end']['line'], start + 5)])[:2000]
        findings.append({'rule_id': item['check_id'], 'file': item['path'],
                         'line': item['start']['line'], 'snippet': snippet,
                         'classification': 'review_lead'})
    errors = report.get('errors', [])
    state = 'partial' if errors and (findings or result.returncode == 0) else 'tool_failed' if result.returncode else 'completed'
    print(json.dumps({'state': state, 'findings': findings[:100], 'total_findings': len(findings),
                      'truncated': len(findings) > 100, 'errors': errors[:10],
                      'artifact_path': str(artifact)}, ensure_ascii=False))
    return 1 if state == 'tool_failed' else 0


if __name__ == '__main__':
    raise SystemExit(main())
