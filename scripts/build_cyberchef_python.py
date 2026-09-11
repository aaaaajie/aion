"""Generate the small CyberChef operation assets from the Python registry."""
from __future__ import annotations

import json
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_spec = importlib.util.spec_from_file_location('aion_cyberchef_engine', ROOT / 'tools/cyberchef/engine.py')
_engine = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = _engine
_spec.loader.exec_module(_engine)


DEST = ROOT / 'tools' / 'binaries' / 'cyberchef'


def main() -> None:
    DEST.mkdir(parents=True, exist_ok=True)
    config = _engine.operation_config()
    (DEST / 'operations.json').write_text(json.dumps(list(config), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (DEST / 'operation-config.json').write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    provenance = {
        'component': 'aion-cyberchef-python',
        'version': '11.2.0-aion-python',
        'source': 'tools/cyberchef/engine.py',
        'runtime': 'AION Python 3.11 image',
        'network': 'none',
    }
    (DEST / 'provenance.json').write_text(json.dumps(provenance, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
