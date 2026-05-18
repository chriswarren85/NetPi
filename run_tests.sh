#!/usr/bin/env bash
# Run the NetPi regression test suite on Linux/macOS (Pi)
set -euo pipefail
cd "$(dirname "$0")"
python3 -m pytest "$@"
