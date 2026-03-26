#!/usr/bin/env bash
# setup-hooks.sh – Configures Git to use the project's .githooks directory
# so every developer gets the pre-commit gitleaks check automatically.

set -euo pipefail

HOOK_DIR=".githooks"

echo "⚙️  Setting core.hooksPath to ${HOOK_DIR} ..."
git config core.hooksPath "${HOOK_DIR}"

# Ensure the hook is executable (relevant on Unix/macOS/WSL)
chmod +x "${HOOK_DIR}/pre-commit" 2>/dev/null || true

echo "✅  Git hooks configured. The pre-commit gitleaks check is now active."
echo ""
echo "ℹ️   Make sure gitleaks is installed:"
echo "     https://github.com/gitleaks/gitleaks#installing"