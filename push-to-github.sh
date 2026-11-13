#!/usr/bin/env bash
# Apex-RE: GitHub Push & Repository Setup Automation (Bash)

set -e

OWNER="${1:-emrewyt}"
REPO_NAME="${2:-apex-re}"
DESCRIPTION="Master-Tier Autonomous Reverse Engineering Skill for AI Agents. Covers Unreal Engine 4-5, Unity (IL2CPP), Godot, .NET 3-10 / NativeAOT, Electron, Tauri, MSVC C++, Python, VMProtect/OLLVM devirtualization, memory diffing, pattern scanning, and round-trip verification."

echo "[*] Apex-RE GitHub Deployment Setup"
echo "    Target: ${OWNER}/${REPO_NAME}"

if command -v gh &> /dev/null && gh auth status &> /dev/null; then
    echo "[+] GitHub CLI authenticated."
    if ! gh repo view "${OWNER}/${REPO_NAME}" &> /dev/null; then
        echo "[*] Creating repository ${OWNER}/${REPO_NAME} on GitHub..."
        gh repo create "${OWNER}/${REPO_NAME}" --public --description "${DESCRIPTION}" --source . --remote origin
    else
        gh repo edit "${OWNER}/${REPO_NAME}" --description "${DESCRIPTION}"
    fi

    TOPICS=(
        "reverse-engineering" "ai-agent" "antigravity" "claude-code" "codex"
        "cursor" "unreal-engine" "unity-il2cpp" "godot" "dotnet" "nativeaot"
        "memory-forensics" "kaitai-struct" "ollvm-deobfuscator" "signature-scanner"
        "devirtualization" "ghidra" "ida-pro"
    )
    for topic in "${TOPICS[@]}"; do
        gh repo edit "${OWNER}/${REPO_NAME}" --add-topic "${topic}" || true
    done

    git push -u origin main
    echo "[+] Repository published: https://github.com/${OWNER}/${REPO_NAME}"
    exit 0
fi

REMOTE_URL="https://github.com/${OWNER}/${REPO_NAME}.git"
echo "[*] Configuring git remote origin -> ${REMOTE_URL}"
git remote remove origin 2>/dev/null || true
git remote add origin "${REMOTE_URL}"
echo "[*] Execute to push:"
echo "    git push -u origin main"
