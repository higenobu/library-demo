#!/usr/bin/env bash
set -euo pipefail

# Usage: ./run-venv.sh
VE_DIR=".venv"

echo "Creating virtualenv in ${VE_DIR} (if not exists)..."
python3 -m venv "${VE_DIR}"
# shellcheck source=/dev/null
. "${VE_DIR}/bin/activate"

echo "Upgrading pip/setuptools/wheel..."
pip install --upgrade pip setuptools wheel

echo "Pre-installing a few runtime deps to avoid build-time issues..."
pip install --no-cache-dir flask-login psycopg2-binary || true

if [ ! -f requirements.txt ]; then
  echo "No requirements.txt found in project root - skipping requirements install."
  exit 0
fi

echo "Attempting to install from requirements.txt..."
if pip install --no-cache-dir -r requirements.txt; then
  echo "Installed requirements from requirements.txt"
  exit 0
fi

echo "pip install failed. Creating a cleaned requirements file to strip local file:// or croot paths..."
CLEAN="./requirements.clean.txt"
grep -v -E '^\\s*$|^\\s*#|^/|^file:|file://|@\\s*file://|/croot|^-e |^\\.\\.?/' requirements.txt > "${CLEAN}" || true

if [ ! -s "${CLEAN}" ]; then
  echo "requirements.clean.txt is empty after cleaning. Please open requirements.removed.txt to inspect removed lines."
  exit 1
fi

echo "Cleaned requirements written to ${CLEAN}. Installing from it..."
pip install --no-cache-dir -r "${CLEAN}"

echo "Done. Virtualenv at ${VE_DIR} is ready. Activate it with: source ${VE_DIR}/bin/activate"
