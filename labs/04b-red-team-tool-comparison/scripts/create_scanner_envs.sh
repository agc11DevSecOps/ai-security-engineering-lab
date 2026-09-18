#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3.12}"

"${PYTHON_BIN}" --version
for tool in garak giskard pyrit; do
  env_dir="${ROOT}/.venv-${tool}"
  "${PYTHON_BIN}" -m venv "${env_dir}"
  "${env_dir}/bin/python" -m pip install --upgrade pip
  "${env_dir}/bin/python" -m pip install -r "${ROOT}/requirements/${tool}.txt"
done

printf '%s\n' "Scanner environments created under ${ROOT}."
