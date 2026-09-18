#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${ROOT}/../fase3b-red-teaming/custom_detectors/spanish_firewall.py"
VERSION="$(python -c 'from importlib.metadata import version; print(version("garak"))')"

if [[ "${VERSION}" != "0.16.0" ]]; then
  printf '%s\n' "Expected garak 0.16.0, found ${VERSION}. Refusing to patch a different release." >&2
  exit 1
fi

TARGET_DIR="$(python -c 'import pathlib, garak; print(pathlib.Path(garak.__file__).parent / "detectors")')"
install -m 0644 "${SOURCE}" "${TARGET_DIR}/spanish_firewall.py"
python -c 'from garak.detectors.spanish_firewall import SpanishMitigationBypass; print(SpanishMitigationBypass.__name__)'
