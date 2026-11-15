#!/usr/bin/env bash
# setup/setup_parallel_project.sh
# Sets up a clean, isolated git worktree for the OpenA2A + WIMSE (AI2II) + AEP joint project.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${REPO_ROOT}/../opena2a-wimse-aep"
BRANCH_NAME="feature/opena2a-wimse-aep"

echo "==> Creating isolated git worktree at ${TARGET_DIR}..."
if [ -d "${TARGET_DIR}" ]; then
  echo "Directory ${TARGET_DIR} already exists. Skipping worktree add."
else
  git -C "${REPO_ROOT}" worktree add "${TARGET_DIR}" -b "${BRANCH_NAME}"
fi

echo "==> Setting up directories and copying spec & assets..."
mkdir -p "${TARGET_DIR}/specs" "${TARGET_DIR}/assets"
cp "${REPO_ROOT}/specs/OPENA2A_WIMSE_AEP_SPEC.md" "${TARGET_DIR}/specs/OPENA2A_WIMSE_AEP_SPEC.md"
if [ -f "${REPO_ROOT}/assets/opena2a-wimse-aep-architecture.jpg" ]; then
  cp "${REPO_ROOT}/assets/opena2a-wimse-aep-architecture.jpg" "${TARGET_DIR}/assets/opena2a-wimse-aep-architecture.jpg"
fi

echo "==> Done!"
echo "To begin working in the parallel project:"
echo "  cd ${TARGET_DIR}"
echo "  agy"
echo "Prompt the agent with:"
echo "  \"Read specs/OPENA2A_WIMSE_AEP_SPEC.md and build the WIMSE AI2II cross-domain bridge and file-exchange harness for Scenario 1 and Scenario 2.\""
