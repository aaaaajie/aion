# Offline Linux toolchain

This directory is part of the release boundary. `wheelhouse/` contains the
Python 3.11 Linux x86_64 artifacts; `offline-requirements.lock` is the complete
runtime lock. `bin/` must contain the exact Linux x86_64 system tools declared
in `manifest.json`.

The repository intentionally does not accept a developer machine's macOS or
Homebrew executables as release assets. On the connected Linux build host,
stage the approved tools and run:

```bash
python scripts/package_linux_toolchain.py --source /absolute/path/to/bin
python scripts/package_linux_toolchain.py --check
```

The second command must pass before the release is uploaded. The competition
runtime has no package-manager or network fallback.
