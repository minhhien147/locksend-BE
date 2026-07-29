#!/usr/bin/env bash
# A06 – Vulnerable & Outdated Components
# Chạy pip-audit + npm audit để kiểm tra dependency vulnerabilities.
# Dùng trong CI hoặc local: bash backend/scripts/security_audit.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "========================================"
echo " LockSend Security Audit — A06 Check"
echo "========================================"

# ── Backend: pip-audit ────────────────────────────────────────────────────────
echo ""
echo "[1/2] Backend Python dependencies (pip-audit)..."
cd "$REPO_ROOT/backend"

if ! command -v pip-audit &>/dev/null; then
    echo "  pip-audit chưa cài. Đang cài..."
    pip install pip-audit --quiet
fi

pip-audit -r requirements.txt --format=columns || {
    echo "  ⚠️  Phát hiện vulnerabilities trong backend dependencies!"
    EXIT_CODE=1
}

if [ -f requirements-ai.txt ]; then
    pip-audit -r requirements-ai.txt --format=columns || {
        echo "  ⚠️  Phát hiện vulnerabilities trong requirements-ai.txt!"
        EXIT_CODE=1
    }
fi

# ── Frontend: npm audit ───────────────────────────────────────────────────────
echo ""
echo "[2/2] Frontend npm dependencies (npm audit)..."
cd "$REPO_ROOT/frontend"

if [ -f package.json ]; then
    npm audit --audit-level=moderate || {
        echo "  ⚠️  Phát hiện vulnerabilities trong frontend dependencies!"
        EXIT_CODE=1
    }
fi

# ── locksend-ai ───────────────────────────────────────────────────────────────
if [ -f "$REPO_ROOT/locksend-ai/requirements.txt" ]; then
    echo ""
    echo "[+] locksend-ai dependencies (pip-audit)..."
    pip-audit -r "$REPO_ROOT/locksend-ai/requirements.txt" --format=columns || {
        echo "  ⚠️  Phát hiện vulnerabilities trong locksend-ai dependencies!"
        EXIT_CODE=1
    }
fi

echo ""
if [ "${EXIT_CODE:-0}" -eq 0 ]; then
    echo "✅  Không phát hiện vulnerability nghiêm trọng."
else
    echo "❌  Cần cập nhật dependencies trước khi deploy!"
    exit 1
fi
