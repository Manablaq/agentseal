#!/usr/bin/env bash
set -euo pipefail

echo "===== AGENTSEAL BACKEND BASELINE ====="
echo "PWD=$PWD"
echo "PYTHON=$(python --version 2>&1)"
echo "PYTHON_PATH=$(command -v python)"
echo "PIP=$(python -m pip --version)"
echo "PYTEST=$(python -m pytest --version)"
echo "GENVM_LINT_PATH=$(command -v genvm-lint)"
echo "FRONTEND_DIRECTORY_EXISTS=$([ -d frontend ] && echo YES || echo NO)"
echo "======================================"
