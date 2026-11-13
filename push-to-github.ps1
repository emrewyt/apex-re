# Apex-RE: GitHub Push & Repository Setup Automation (PowerShell)
# Usage: .\push-to-github.ps1 [-Owner "emrewyt"] [-Public]

param(
    [string]$Owner = "emrewyt",
    [string]$RepoName = "apex-re",
    [switch]$Public = $true
)

$Description = "Master-Tier Autonomous Reverse Engineering Skill for AI Agents. Covers Unreal Engine 4-5, Unity (IL2CPP), Godot, .NET 3-10 / NativeAOT, Electron, Tauri, MSVC C++, Python, VMProtect/OLLVM devirtualization, memory diffing, pattern scanning, and round-trip verification."
$Topics = @(
    "reverse-engineering",
    "ai-agent",
    "antigravity",
    "claude-code",
    "codex",
    "cursor",
    "unreal-engine",
    "unity-il2cpp",
    "godot",
    "dotnet",
    "nativeaot",
    "memory-forensics",
    "kaitai-struct",
    "ollvm-deobfuscator",
    "signature-scanner",
    "devirtualization",
    "ghidra",
    "ida-pro"
)

Write-Host "[*] Apex-RE GitHub Deployment Setup" -ForegroundColor Cyan
Write-Host "    Target: $Owner/$RepoName" -ForegroundColor Gray

# Check gh CLI
$ghCli = Get-Command gh -ErrorAction SilentlyContinue
if ($ghCli) {
    Write-Host "[+] GitHub CLI (gh) detected." -ForegroundColor Green
    $authCheck = gh auth status 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] GitHub CLI is authenticated." -ForegroundColor Green
        
        # Check if repo exists
        gh repo view "$Owner/$RepoName" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[*] Creating repository $Owner/$RepoName on GitHub..." -ForegroundColor Yellow
            $visibility = if ($Public) { "--public" } else { "--private" }
            gh repo create "$Owner/$RepoName" $visibility --description $Description --source . --remote origin
        } else {
            Write-Host "[+] Remote repository exists. Setting description..." -ForegroundColor Green
            gh repo edit "$Owner/$RepoName" --description $Description
        }

        # Set topics
        Write-Host "[*] Setting repository SEO topic tags..." -ForegroundColor Cyan
        foreach ($t in $Topics) {
            gh repo edit "$Owner/$RepoName" --add-topic $t
        }

        # Push branch
        Write-Host "[*] Pushing 'main' branch to origin..." -ForegroundColor Cyan
        git push -u origin main
        Write-Host "[+] Repository published successfully at https://github.com/$Owner/$RepoName" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "[!] GitHub CLI is not logged in. Run 'gh auth login' or enter a GitHub Personal Access Token." -ForegroundColor Yellow
    }
}

# Standard Git fallback
$remoteUrl = "https://github.com/$Owner/$RepoName.git"
Write-Host "[*] Configuring git remote origin -> $remoteUrl" -ForegroundColor Cyan
git remote remove origin 2>$null
git remote add origin $remoteUrl

Write-Host "[*] Ready to push. Run:" -ForegroundColor Cyan
Write-Host "    git push -u origin main" -ForegroundColor Yellow
Write-Host ""
Write-Host "If prompted for password, use your GitHub Personal Access Token (PAT)." -ForegroundColor Gray
