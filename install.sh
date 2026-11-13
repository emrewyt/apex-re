#!/usr/bin/env bash
# Install apex-re for Claude Code, Codex, Antigravity 2.0, Gemini CLI, Cursor.
# Usage: ./install.sh [--target claude|codex|antigravity|gemini|cursor|all] [--scope user|project]
set -euo pipefail

TARGET="all"
SCOPE="user"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target|-t) TARGET="$2"; shift 2 ;;
    --scope|-s)  SCOPE="$2";  shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/skills/apex-re"

if [[ ! -d "${SRC}" ]]; then
  echo "Error: Skill folder not found: ${SRC}" >&2
  exit 1
fi

get_dest() {
  local t="$1"
  if [[ "${SCOPE}" == "project" ]]; then
    case "$t" in
      claude)      echo ".claude/skills" ;;
      codex)       echo ".codex/skills" ;;
      antigravity) echo ".agents/skills" ;;
      gemini)      echo ".gemini/skills" ;;
      cursor)      echo ".cursor/skills" ;;
    esac
  else
    case "$t" in
      claude)      echo "${HOME}/.claude/skills" ;;
      codex)       echo "${HOME}/.codex/skills" ;;
      antigravity) echo "${HOME}/.gemini/config/skills" ;;
      gemini)      echo "${HOME}/.gemini/skills" ;;
      cursor)      echo "${HOME}/.cursor/skills" ;;
    esac
  fi
}

install_one() {
  local t="$1"
  local dest
  dest="$(get_dest "$t")"
  mkdir -p "${dest}"
  local target="${dest}/apex-re"
  rm -rf "${target}"
  cp -R "${SRC}" "${target}"
  echo " [OK] Installed apex-re for $t -> ${target}"
}

if [[ "${TARGET}" == "all" ]]; then
  for t in claude codex antigravity gemini cursor; do
    install_one "$t"
  done
else
  install_one "${TARGET}"
fi
