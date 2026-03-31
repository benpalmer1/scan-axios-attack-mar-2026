# =============================================================================
# Axios Supply Chain Attack Scanner (Windows - PowerShell 5.1+)
# =============================================================================
# Scans for compromised axios versions (1.14.1, 0.30.4) and the malicious
# plain-crypto-js payload package from the 30-31 March 2026 npm supply-chain
# compromise.
#
# Attack summary:
#   - Hijacked maintainer npm account used to publish poisoned axios releases
#   - axios@1.14.1 and axios@0.30.4 inject plain-crypto-js@4.2.1 as a
#     dependency whose postinstall hook drops a cross-platform remote access
#     trojan (RAT) targeting macOS, Windows, and Linux
#   - Ref: https://github.com/axios/axios/issues/10604
#   - Ref: https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
#
# Usage: .\scan-axios-attack.ps1
#        .\scan-axios-attack.ps1 -SearchRoot "D:\Projects"
# =============================================================================
# Keep this script ASCII-only for maximum Windows PowerShell compatibility.

[CmdletBinding()]
param(
    [string]$SearchRoot = "$($env:SystemDrive)\"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# --- Configuration -----------------------------------------------------------
$CompromisedVersions = @("1.14.1", "0.30.4")
$MaliciousPkg = "plain-crypto-js"
$SkipDirs = @("AppData\Local\Temp", "AppData\Local\Microsoft", "AppData\Local\Google\Chrome\User Data")

# --- State -------------------------------------------------------------------
$TotalAxiosFound = 0
$CompromisedFound = 0
$MaliciousPkgFound = 0
$OtherMaliciousPkgHits = 0
$SecurityHolderPkgFound = 0
$RatArtifactsFound = 0
$Findings = [System.Collections.ArrayList]::new()

# --- Helpers -----------------------------------------------------------------
function Write-Banner($text) {
    Write-Host ""
    Write-Host "  ===========================================================" -ForegroundColor Blue
    Write-Host "    $text" -ForegroundColor White -NoNewline; Write-Host ""
    Write-Host "  ===========================================================" -ForegroundColor Blue
}

function Write-Ok($text)   { Write-Host "    [OK]   " -ForegroundColor Green -NoNewline; Write-Host $text }
function Write-Warn($text) { Write-Host "    [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host $text }
function Write-Fail($text) { Write-Host "    [FAIL] " -ForegroundColor Red -NoNewline; Write-Host $text }
function Write-Info($text) { Write-Host "    [INFO] " -ForegroundColor Cyan -NoNewline; Write-Host $text }

function Test-ShouldSkip($path) {
    foreach ($skip in $SkipDirs) {
        if ($path -like "*\$skip\*") { return $true }
    }
    return $false
}

function Get-AxiosVersion($packageJsonPath) {
    try {
        $json = Get-Content $packageJsonPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $json.version -or [string]::IsNullOrWhiteSpace([string]$json.version)) {
            return "unknown"
        }
        return [string]$json.version
    } catch {
        return "unknown"
    }
}

function Get-ShortPath($fullPath) {
    return $fullPath.Replace($SearchRoot, "~")
}

function Get-FileText($path, [switch]$Binary) {
    try {
        if ($Binary) {
            return [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($path))
        }
        return Get-Content $path -Raw -ErrorAction Stop
    } catch {
        return ""
    }
}

function Get-LockfileText($path) {
    if ($path -like "*.lockb") {
        return Get-FileText -path $path -Binary
    }
    return Get-FileText -path $path
}

function Get-PackageVersionCategory($version) {
    if ($null -eq $version -or [string]::IsNullOrWhiteSpace([string]$version)) {
        return "unknown"
    }

    switch ([string]$version) {
        "4.2.1" { return "malicious" }
        "0.0.1-security.0" { return "security" }
        "unknown" { return "unknown" }
        default { return "other" }
    }
}

function Get-DependencySpecFromJson($content, $packageName) {
    if ([string]::IsNullOrWhiteSpace($content)) { return $null }
    $pattern = '"' + [regex]::Escape($packageName) + '"\s*:\s*"([^"]+)"'
    $match = [regex]::Match($content, $pattern)
    if ($match.Success) {
        return $match.Groups[1].Value
    }
    return $null
}

function Test-LockfileHasPackageVersion($content, $packageName, $version) {
    if ([string]::IsNullOrWhiteSpace($content)) { return $false }

    $pkg = [regex]::Escape($packageName)
    $v = [regex]::Escape($version)
    $patterns = @(
        "(?s)""node_modules/$pkg""\s*:\s*\{.{0,1200}?""version""\s*:\s*""$v""",
        "(?s)""$pkg""\s*:\s*\{.{0,1200}?""version""\s*:\s*""$v""",
        "(?s)(?:^|\n)$pkg@.*?(?:\r?\n).{0,400}?version\s+""$v""",
        "(?m)(?:^|\n)\s*/?$pkg@$v(?:\(|:|$)"
    )

    foreach ($pattern in $patterns) {
        if ([regex]::IsMatch($content, $pattern)) {
            return $true
        }
    }

    return $false
}

# =============================================================================
Write-Host ""
Write-Host "  +=========================================================+" -ForegroundColor Red
Write-Host "  |         AXIOS SUPPLY CHAIN ATTACK SCANNER                |" -ForegroundColor Red
Write-Host "  |     npm supply-chain compromise / RAT dropper            |" -ForegroundColor Red
Write-Host "  |      30-31 Mar 2026 - axios 1.14.1 / 0.30.4             |" -ForegroundColor Red
Write-Host "  |      https://github.com/axios/axios/issues/10604        |" -ForegroundColor Red
Write-Host "  +=========================================================+" -ForegroundColor Red
Write-Host ""
Write-Info "Search root: $SearchRoot"
Write-Info "Date:        $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Info "Host:        $env:COMPUTERNAME"
Write-Info "User:        $env:USERNAME"

# =============================================================================
# 1. Installed axios in node_modules
# =============================================================================
Write-Banner "1/7  Scanning node_modules for axios installations"

$axiosInstalls = Get-ChildItem -Path $SearchRoot -Recurse -Filter "package.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "\\node_modules\\axios\\package\.json$" -and !(Test-ShouldSkip $_.FullName) }

foreach ($install in $axiosInstalls) {
    $version = Get-AxiosVersion $install.FullName
    $location = Split-Path $install.FullName -Parent
    $TotalAxiosFound++

    if ($CompromisedVersions -contains $version) {
        $CompromisedFound++
        Write-Fail "COMPROMISED axios@$version"
        Write-Fail "  Location: $location"
        [void]$Findings.Add("CRITICAL: Compromised axios@$version at $location")
    } else {
        Write-Ok "axios@$version (safe) - $(Get-ShortPath $location)"
    }
}

if ($TotalAxiosFound -eq 0) {
    Write-Ok "No axios installations found in any node_modules"
}

# =============================================================================
# 2. axios in dependency files
# =============================================================================
Write-Banner "2/7  Scanning dependency manifests and lockfiles"

$depFileHits = 0

# package.json files (non-node_modules)
$packageJsonFiles = Get-ChildItem -Path $SearchRoot -Recurse -Filter "package.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch "\\node_modules\\" -and !(Test-ShouldSkip $_.FullName) }

foreach ($pj in $packageJsonFiles) {
    $content = Get-Content $pj.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -match '"axios"') {
        $depFileHits++
        if ($content -match '"axios"\s*:\s*"([^"]+)"') {
            Write-Info "package.json declares axios@$($Matches[1]) - $(Get-ShortPath $pj.FullName)"
        } else {
            Write-Info "axios referenced in $(Get-ShortPath $pj.FullName)"
        }
    }
}

# Lockfiles
$lockfileNames = @("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")
foreach ($lockName in $lockfileNames) {
    $lockfiles = Get-ChildItem -Path $SearchRoot -Recurse -Filter $lockName -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch "\\node_modules\\" -and !(Test-ShouldSkip $_.FullName) }

    foreach ($lf in $lockfiles) {
        $content = Get-LockfileText $lf.FullName
        if ($content -match "axios") {
            $depFileHits++

            foreach ($cv in $CompromisedVersions) {
                if (Test-LockfileHasPackageVersion $content "axios" $cv) {
                    $CompromisedFound++
                    Write-Fail "COMPROMISED version $cv referenced - $(Get-ShortPath $lf.FullName)"
                    [void]$Findings.Add("CRITICAL: Lockfile references compromised axios@$cv at $($lf.FullName)")
                }
            }

            if ($lockName -like "bun.lock*") {
                Write-Warn "axios referenced in bun lockfile - $(Get-ShortPath $lf.FullName)"
            } else {
                Write-Info "axios referenced in $lockName - $(Get-ShortPath $lf.FullName)"
            }
        }
    }
}

if ($depFileHits -eq 0) {
    Write-Ok "No axios references in any dependency manifests or lockfiles"
}

# =============================================================================
# 3. Malicious plain-crypto-js package
# =============================================================================
Write-Banner "3/7  Scanning for malicious $MaliciousPkg package"

# Check node_modules
$maliciousDirs = Get-ChildItem -Path $SearchRoot -Recurse -Directory -Filter $MaliciousPkg -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "\\node_modules\\$MaliciousPkg$" }

foreach ($md in $maliciousDirs) {
    $pkgVersion = Get-AxiosVersion (Join-Path $md.FullName "package.json")
    $pkgCategory = Get-PackageVersionCategory $pkgVersion

    switch ($pkgCategory) {
        "malicious" {
            $MaliciousPkgFound++
            Write-Fail "CONFIRMED MALICIOUS PACKAGE: $MaliciousPkg@$pkgVersion at $($md.FullName)"
            [void]$Findings.Add("CRITICAL: Confirmed malicious $MaliciousPkg@$pkgVersion found at $($md.FullName)")
        }
        "security" {
            $SecurityHolderPkgFound++
            Write-Ok "$MaliciousPkg@$pkgVersion security-holder package installed at $(Get-ShortPath $md.FullName)"
        }
        "unknown" {
            $OtherMaliciousPkgHits++
            Write-Warn "$MaliciousPkg found at $(Get-ShortPath $md.FullName), but its version could not be parsed"
            [void]$Findings.Add("WARNING: $MaliciousPkg found at $($md.FullName), but its version could not be parsed")
        }
        default {
            $OtherMaliciousPkgHits++
            Write-Warn "$MaliciousPkg@$pkgVersion found at $(Get-ShortPath $md.FullName) - not the confirmed malicious 4.2.1 release"
            [void]$Findings.Add("WARNING: $MaliciousPkg@$pkgVersion found at $($md.FullName) - review whether this package/version is expected")
        }
    }
}

# Check all dependency files for references
$allDepFiles = Get-ChildItem -Path $SearchRoot -Recurse -Include "package.json","package-lock.json","npm-shrinkwrap.json","yarn.lock","pnpm-lock.yaml","bun.lock","bun.lockb" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch "\\node_modules\\" -and !(Test-ShouldSkip $_.FullName) }

foreach ($df in $allDepFiles) {
    $content = Get-LockfileText $df.FullName
    if ($content -match [regex]::Escape($MaliciousPkg)) {
        if ($df.Name -eq "package.json") {
            $pkgSpec = Get-DependencySpecFromJson $content $MaliciousPkg
            if ($null -eq $pkgSpec -or [string]::IsNullOrWhiteSpace([string]$pkgSpec)) {
                $OtherMaliciousPkgHits++
                Write-Warn "$MaliciousPkg referenced in $(Get-ShortPath $df.FullName) (version unclear)"
                [void]$Findings.Add("WARNING: $MaliciousPkg referenced in $($df.FullName) with version unclear")
            } elseif ($pkgSpec -eq "4.2.1") {
                $MaliciousPkgFound++
                Write-Fail "CONFIRMED MALICIOUS REFERENCE in $(Get-ShortPath $df.FullName): $MaliciousPkg@4.2.1"
                [void]$Findings.Add("CRITICAL: Dependency manifest references confirmed malicious $MaliciousPkg@4.2.1 at $($df.FullName)")
            } elseif ($pkgSpec -eq "0.0.1-security.0") {
                $SecurityHolderPkgFound++
                Write-Ok "$MaliciousPkg@0.0.1-security.0 referenced in $(Get-ShortPath $df.FullName)"
            } else {
                $OtherMaliciousPkgHits++
                Write-Warn "$MaliciousPkg@$pkgSpec referenced in $(Get-ShortPath $df.FullName) - not the confirmed malicious 4.2.1 release"
                [void]$Findings.Add("WARNING: $MaliciousPkg@$pkgSpec referenced in $($df.FullName) - review whether this package/version is expected")
            }
        } elseif (Test-LockfileHasPackageVersion $content $MaliciousPkg "4.2.1") {
            $MaliciousPkgFound++
            Write-Fail "CONFIRMED MALICIOUS REFERENCE in $(Get-ShortPath $df.FullName): $MaliciousPkg@4.2.1"
            [void]$Findings.Add("CRITICAL: Lockfile references confirmed malicious $MaliciousPkg@4.2.1 at $($df.FullName)")
        } elseif (Test-LockfileHasPackageVersion $content $MaliciousPkg "0.0.1-security.0") {
            $SecurityHolderPkgFound++
            Write-Ok "$MaliciousPkg@0.0.1-security.0 referenced in $(Get-ShortPath $df.FullName)"
        } else {
            $OtherMaliciousPkgHits++
            Write-Warn "$MaliciousPkg referenced in $(Get-ShortPath $df.FullName) (version unclear or non-malicious)"
            [void]$Findings.Add("WARNING: $MaliciousPkg referenced in $($df.FullName) with version unclear or not equal to 4.2.1")
        }
    }
}

if ($MaliciousPkgFound -eq 0 -and $OtherMaliciousPkgHits -eq 0 -and $SecurityHolderPkgFound -eq 0) {
    Write-Ok "No trace of $MaliciousPkg anywhere"
}

# =============================================================================
# 4. Package manager caches
# =============================================================================
Write-Banner "4/7  Scanning package manager caches"

# npm cache
# The npm _cacache stores both registry manifests (packuments) and actual
# package tarballs. Packuments list ALL published versions of a package,
# so a string match for "1.14.1" in a manifest is expected and NOT a compromise.
#
# To distinguish real risk from metadata noise we check:
#   1. index-v5 keys - a key like "axios-1.14.1.tgz" means the actual
#      compromised tarball was fetched and cached.
#   2. plain-crypto-js index keys - if the malicious package was ever
#      resolved, it will have its own index entry.

$npmCachePath = Join-Path $env:APPDATA "npm-cache"
if (-not (Test-Path $npmCachePath)) { $npmCachePath = Join-Path $env:LOCALAPPDATA "npm-cache" }
if (-not (Test-Path $npmCachePath)) { $npmCachePath = Join-Path $env:USERPROFILE ".npm" }

if (Test-Path $npmCachePath) {
    $npmCacheRisk = "none"
    $indexPath = Join-Path $npmCachePath "_cacache\index-v5"
    $contentPath = Join-Path $npmCachePath "_cacache\content-v2"

    # Check index for actual tarball cache entries for compromised versions
    if (Test-Path $indexPath) {
        foreach ($cv in $CompromisedVersions) {
            $tarballPattern = "axios-$cv.tgz"
            $indexHits = Get-ChildItem -Path $indexPath -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match [regex]::Escape($tarballPattern) } |
                Select-Object -First 1
            if ($indexHits) {
                $npmCacheRisk = "tarball"
                $CompromisedFound++
                Write-Fail "Compromised axios@$cv TARBALL cached - actual package was downloaded"
                [void]$Findings.Add("CRITICAL: Compromised axios@$cv tarball in npm cache - run 'npm cache clean --force'")
            }
        }

        # Check for plain-crypto-js tarball cache entries versus registry metadata
        $pcjMaliciousTarball = Get-ChildItem -Path $indexPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match [regex]::Escape("$MaliciousPkg-4.2.1.tgz") } |
            Select-Object -First 1
        $pcjSecurityTarball = Get-ChildItem -Path $indexPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match [regex]::Escape("$MaliciousPkg-0.0.1-security.0.tgz") } |
            Select-Object -First 1
        $pcjIndexMetadata = Get-ChildItem -Path $indexPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match [regex]::Escape("request-cache:https://registry.npmjs.org/$MaliciousPkg") } |
            Select-Object -First 1
        if ($pcjMaliciousTarball) {
            $npmCacheRisk = "tarball"
            $MaliciousPkgFound++
            Write-Fail "$MaliciousPkg@4.2.1 tarball cached - confirmed malicious package download"
            [void]$Findings.Add("CRITICAL: $MaliciousPkg@4.2.1 tarball in npm cache - run 'npm cache clean --force'")
        } elseif ($pcjSecurityTarball) {
            $SecurityHolderPkgFound++
            Write-Info "$MaliciousPkg@0.0.1-security.0 security-holder tarball cached"
            Write-Ok "npm cache includes the security-holder replacement for $MaliciousPkg"
        } elseif ($pcjIndexMetadata) {
            Write-Info "$MaliciousPkg appears in npm cache registry metadata only"
            Write-Info "This does not prove that $MaliciousPkg@4.2.1 was downloaded"
        }
    }

    # If no tarball-level hits, do broader content scan and classify as metadata
    if ($npmCacheRisk -eq "none") {
        $manifestHits = 0
        $pcjContent = $null
        if (Test-Path $contentPath) {
            foreach ($cv in $CompromisedVersions) {
                $escapedCv = [regex]::Escape($cv)
                $contentHit = Get-ChildItem -Path $contentPath -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match "axios.*$escapedCv" } |
                    Select-Object -First 1
                if ($contentHit) { $manifestHits++ }
            }

            $pcjContent = Get-ChildItem -Path $contentPath -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match [regex]::Escape($MaliciousPkg) } |
                Select-Object -First 1
        }

        if ($manifestHits -gt 0 -or $pcjContent) {
            Write-Info "Compromised version strings appear in npm cache registry manifests only"
            Write-Info "This is expected - npm caches the full version list for resolved packages"
            Write-Info "No actual compromised tarballs were downloaded (low risk)"
            Write-Ok "npm cache - metadata references only, no compromised packages cached"
        } else {
            Write-Ok "npm cache clean of axios and $MaliciousPkg"
        }
    }
} else {
    Write-Ok "No npm cache directory found"
}

# bun cache
$bunCachePath = Join-Path $env:USERPROFILE ".bun\install\cache"
if (Test-Path $bunCachePath) {
    $bunAxios = Get-ChildItem -Path $bunCachePath -Directory -Filter "axios@*" -ErrorAction SilentlyContinue
    if ($bunAxios) {
        foreach ($entry in $bunAxios) {
            $bunVer = ($entry.Name -replace '^axios@', '') -replace '@.*$', ''
            Write-Info "axios@$bunVer in bun cache"
            if ($CompromisedVersions -contains $bunVer) {
                $CompromisedFound++
                Write-Fail "Compromised axios@$bunVer in bun cache"
                [void]$Findings.Add("CRITICAL: Compromised axios@$bunVer in bun cache")
            }
        }
    } else {
        Write-Ok "bun cache clean of axios"
    }

    $bunMalicious = Get-ChildItem -Path $bunCachePath -Directory -Filter "$MaliciousPkg@*" -ErrorAction SilentlyContinue
    if ($bunMalicious) {
        foreach ($entry in $bunMalicious) {
            $bunVer = ($entry.Name -replace ('^' + [regex]::Escape($MaliciousPkg) + '@'), '') -replace '@.*$', ''
            $bunCategory = Get-PackageVersionCategory $bunVer
            switch ($bunCategory) {
                "malicious" {
                    $MaliciousPkgFound++
                    Write-Fail "$MaliciousPkg@4.2.1 found in bun cache"
                    [void]$Findings.Add("CRITICAL: $MaliciousPkg@4.2.1 in bun cache")
                }
                "security" {
                    $SecurityHolderPkgFound++
                    Write-Ok "$MaliciousPkg@0.0.1-security.0 security-holder package found in bun cache"
                }
                "unknown" {
                    $OtherMaliciousPkgHits++
                    Write-Warn "$MaliciousPkg found in bun cache, but its version could not be parsed"
                    [void]$Findings.Add("WARNING: $MaliciousPkg found in bun cache, but its version could not be parsed")
                }
                default {
                    $OtherMaliciousPkgHits++
                    Write-Warn "$MaliciousPkg@$bunVer found in bun cache - not the confirmed malicious 4.2.1 release"
                    [void]$Findings.Add("WARNING: $MaliciousPkg@$bunVer found in bun cache - review whether this package/version is expected")
                }
            }
        }
    } else {
        Write-Ok "bun cache clean of $MaliciousPkg"
    }
} else {
    Write-Ok "No bun cache directory found"
}

# Global npm
if (Get-Command npm -ErrorAction SilentlyContinue) {
    $npmGlobalPath = & npm prefix -g 2>$null
    if (-not $npmGlobalPath) {
        Write-Warn "Unable to determine npm global prefix - global npm check skipped"
    } elseif (Test-Path (Join-Path $npmGlobalPath "node_modules\axios")) {
        $gVer = Get-AxiosVersion (Join-Path $npmGlobalPath "node_modules\axios\package.json")
        Write-Warn "axios@$gVer installed globally"
        if ($CompromisedVersions -contains $gVer) {
            Write-Fail "COMPROMISED axios@$gVer installed globally"
            [void]$Findings.Add("CRITICAL: Compromised axios@$gVer installed globally - run 'npm uninstall -g axios'")
        }
    } else {
        Write-Ok "No global axios installation"
    }
} else {
    Write-Ok "npm not installed - global npm check skipped"
}

# yarn
if (Get-Command yarn -ErrorAction SilentlyContinue) {
    $yarnCache = & yarn cache dir 2>$null
    if ($yarnCache -and (Test-Path $yarnCache)) {
        $yarnAxios = Get-ChildItem -Path $yarnCache -Filter "axios-*" -ErrorAction SilentlyContinue
        if ($yarnAxios) { Write-Warn "axios found in yarn cache" }
        else { Write-Ok "yarn cache clean of axios" }
    }
} else {
    Write-Ok "yarn not installed - skipped"
}

# pnpm
if (Get-Command pnpm -ErrorAction SilentlyContinue) {
    $pnpmStore = & pnpm store path 2>$null
    if ($pnpmStore -and (Test-Path $pnpmStore)) {
        $pnpmAxios = Get-ChildItem -Path $pnpmStore -Directory -Filter "axios" -Recurse -ErrorAction SilentlyContinue
        if ($pnpmAxios) { Write-Warn "axios found in pnpm store" }
        else { Write-Ok "pnpm store clean of axios" }
    }
} else {
    Write-Ok "pnpm not installed - skipped"
}

# =============================================================================
# 5. IDE extensions
# =============================================================================
Write-Banner "5/7  Scanning IDE extensions"

$ideAxiosCount = 0
$ideDirs = @{
    "cursor"      = Join-Path $env:USERPROFILE ".cursor\extensions"
    "vscode"      = Join-Path $env:USERPROFILE ".vscode\extensions"
    "antigravity" = Join-Path $env:USERPROFILE ".antigravity\extensions"
    "windsurf"    = Join-Path $env:USERPROFILE ".windsurf\extensions"
}

foreach ($entry in $ideDirs.GetEnumerator()) {
    $ideName = $entry.Key
    $ideDir = $entry.Value

    if (Test-Path $ideDir) {
        $extAxios = Get-ChildItem -Path $ideDir -Recurse -Filter "package.json" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "\\node_modules\\axios\\package\.json$" }

        foreach ($ea in $extAxios) {
            $version = Get-AxiosVersion $ea.FullName
            $extName = $ea.FullName -replace [regex]::Escape($ideDir + "\"), "" -replace "\\node_modules\\axios\\package\.json$", ""
            $ideAxiosCount++

            if ($CompromisedVersions -contains $version) {
                $CompromisedFound++
                Write-Fail "COMPROMISED axios@$version in $ideName extension: $extName"
                [void]$Findings.Add("CRITICAL: Compromised axios@$version in $ideName extension $extName")
            } else {
                Write-Ok "axios@$version (safe) in $ideName extension: $extName"
            }
        }

        $extMalicious = Get-ChildItem -Path $ideDir -Recurse -Filter "package.json" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "\\node_modules\\$([regex]::Escape($MaliciousPkg))\\package\.json$" }
        foreach ($em in $extMalicious) {
            $pkgVersion = Get-AxiosVersion $em.FullName
            $pkgCategory = Get-PackageVersionCategory $pkgVersion
            $extName = $em.FullName -replace [regex]::Escape($ideDir + "\"), "" -replace "\\node_modules\\$([regex]::Escape($MaliciousPkg))\\package\.json$", ""

            switch ($pkgCategory) {
                "malicious" {
                    $MaliciousPkgFound++
                    Write-Fail "CONFIRMED MALICIOUS PACKAGE: $MaliciousPkg@$pkgVersion in $ideName extension: $extName"
                    [void]$Findings.Add("CRITICAL: Confirmed malicious $MaliciousPkg@$pkgVersion in $ideName extension $extName")
                }
                "security" {
                    $SecurityHolderPkgFound++
                    Write-Ok "$MaliciousPkg@$pkgVersion security-holder package in $ideName extension: $extName"
                }
                "unknown" {
                    $OtherMaliciousPkgHits++
                    Write-Warn "$MaliciousPkg found in $ideName extension: $extName, but its version could not be parsed"
                    [void]$Findings.Add("WARNING: $MaliciousPkg found in $ideName extension $extName, but its version could not be parsed")
                }
                default {
                    $OtherMaliciousPkgHits++
                    Write-Warn "$MaliciousPkg@$pkgVersion found in $ideName extension: $extName - not the confirmed malicious 4.2.1 release"
                    [void]$Findings.Add("WARNING: $MaliciousPkg@$pkgVersion found in $ideName extension $extName - review whether this package is expected")
                }
            }
        }
    }
}

if ($ideAxiosCount -eq 0) {
    Write-Ok "No axios found in any IDE extensions"
}

# =============================================================================
# 6. RAT artifact scan (Windows-specific)
# =============================================================================
Write-Banner "6/7  Scanning for RAT artifacts"

# Scheduled Tasks
if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
    $suspiciousTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object {
            $execs = @()
            foreach ($action in $_.Actions) {
                if ($action.PSObject.Properties['Execute']) {
                    $execs += $action.Execute
                }
            }
            $actionExecutables = $execs -join ' '
            ($actionExecutables -match "crypto|axios|plain-crypto|node") -or ($_.TaskName -match "crypto|axios")
        }

    if ($suspiciousTasks) {
        $RatArtifactsFound++
        foreach ($task in $suspiciousTasks) {
            Write-Fail "Suspicious Scheduled Task: $($task.TaskName)"
        }
        [void]$Findings.Add("WARNING: Suspicious scheduled tasks found")
    } else {
        Write-Ok "Scheduled Tasks clean"
    }
} else {
    Write-Ok "Scheduled task cmdlets unavailable - scheduled task scan skipped"
}

# Startup folder
$startupPaths = @(
    [Environment]::GetFolderPath("Startup"),
    [Environment]::GetFolderPath("CommonStartup")
)

$startupFindings = $false
foreach ($startupPath in $startupPaths) {
    if (Test-Path $startupPath) {
        $suspiciousStartup = Get-ChildItem $startupPath -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "crypto|axios|$MaliciousPkg" }
        if ($suspiciousStartup) {
            $startupFindings = $true
            foreach ($entry in $suspiciousStartup) {
                $RatArtifactsFound++
                Write-Fail "Suspicious startup entry: $($entry.Name)"
                [void]$Findings.Add("WARNING: Suspicious startup entry $($entry.Name)")
            }
        }
    }
}
if (-not $startupFindings) {
    Write-Ok "Startup folders clean"
}

# Registry Run keys
$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$suspiciousReg = $false
foreach ($regPath in $regPaths) {
    if (Test-Path $regPath) {
        $entries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
        $props = @()
        if ($entries) {
            $props = $entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
        }
        foreach ($prop in $props) {
            if ($prop.Value -match "crypto|axios|$MaliciousPkg|plain\.crypto") {
                $RatArtifactsFound++
                $suspiciousReg = $true
                Write-Fail "Suspicious registry Run entry: $($prop.Name) = $($prop.Value)"
                [void]$Findings.Add("CRITICAL: Suspicious registry Run entry '$($prop.Name)'")
            }
        }
    }
}
if (-not $suspiciousReg) {
    Write-Ok "Registry Run keys clean"
}

# Suspicious processes
$suspiciousProcs = Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.ProcessName -match "crypto|axios|plain\.crypto" -and $_.ProcessName -notmatch "CryptoTokenKit|CryptSvc" }

if ($suspiciousProcs) {
    $RatArtifactsFound++
    foreach ($proc in $suspiciousProcs) {
        Write-Fail "Suspicious process: $($proc.ProcessName) (PID: $($proc.Id))"
    }
    [void]$Findings.Add("CRITICAL: Suspicious crypto-related process running")
} else {
    Write-Ok "No suspicious processes running"
}

# Temp directories
$tempDirs = @($env:TEMP, $env:TMP, "C:\Windows\Temp")
$tempFindings = $false
foreach ($tmpDir in ($tempDirs | Select-Object -Unique)) {
    if (Test-Path $tmpDir) {
        $suspiciousTemp = Get-ChildItem $tmpDir -Recurse -Depth 2 -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "crypto|axios|$MaliciousPkg" -and $_.Name -notmatch "CryptoAPI" }
        if ($suspiciousTemp) {
            $tempFindings = $true
            $RatArtifactsFound++
            foreach ($st in $suspiciousTemp) {
                Write-Fail "Suspicious file in temp: $($st.FullName)"
            }
            [void]$Findings.Add("WARNING: Suspicious files in temp directories")
        }
    }
}
if (-not $tempFindings) {
    Write-Ok "Temp directories clean"
}

# Services
$suspiciousServices = Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match "crypto|axios|$MaliciousPkg" -and $_.DisplayName -notmatch "Cryptographic|CryptoSvc" }

if ($suspiciousServices) {
    $RatArtifactsFound++
    foreach ($svc in $suspiciousServices) {
        Write-Fail "Suspicious service: $($svc.DisplayName) ($($svc.Status))"
    }
    [void]$Findings.Add("WARNING: Suspicious services found")
} else {
    Write-Ok "Windows services clean"
}

# =============================================================================
# 7. Recently modified suspicious files
# =============================================================================
Write-Banner "7/7  Checking for recently modified suspicious files"

$recentSuspicious = Get-ChildItem -Path $SearchRoot -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and
        ($_.Name -match "$MaliciousPkg|plain\.crypto") -and
        !(Test-ShouldSkip $_.FullName)
    } | Select-Object -First 20

if ($recentSuspicious) {
    $RatArtifactsFound++
    foreach ($rs in $recentSuspicious) {
        Write-Fail "Recently modified: $($rs.FullName) ($($rs.LastWriteTime))"
    }
    [void]$Findings.Add("WARNING: Recently modified suspicious files found")
} else {
    Write-Ok "No recently modified suspicious files"
}

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "  ===========================================================" -ForegroundColor Blue
Write-Host "    SCAN COMPLETE" -ForegroundColor White
Write-Host "  ===========================================================" -ForegroundColor Blue
Write-Host ""

$axiosColour = if ($TotalAxiosFound -gt 0) { "Yellow" } else { "Green" }
$compColour = if ($CompromisedFound -gt 0) { "Red" } else { "Green" }
$malColour = if ($MaliciousPkgFound -gt 0) { "Red" } else { "Green" }
$otherMalColour = if ($OtherMaliciousPkgHits -gt 0) { "Yellow" } else { "Green" }
$securityHolderColour = "Green"
$ratColour = if ($RatArtifactsFound -gt 0) { "Red" } else { "Green" }

Write-Host "    Axios installations found:      " -NoNewline; Write-Host $TotalAxiosFound -ForegroundColor $axiosColour
Write-Host "    Compromised versions found:      " -NoNewline; Write-Host $CompromisedFound -ForegroundColor $compColour
Write-Host "    Confirmed $MaliciousPkg@4.2.1 found: " -NoNewline; Write-Host $MaliciousPkgFound -ForegroundColor $malColour
Write-Host "    Other $MaliciousPkg hits:        " -NoNewline; Write-Host $OtherMaliciousPkgHits -ForegroundColor $otherMalColour
Write-Host "    $MaliciousPkg security-holder hits: " -NoNewline; Write-Host $SecurityHolderPkgFound -ForegroundColor $securityHolderColour
Write-Host "    Suspicious RAT artifacts:        " -NoNewline; Write-Host $RatArtifactsFound -ForegroundColor $ratColour
Write-Host ""

if ($Findings.Count -gt 0) {
    Write-Host "  +=========================================================+" -ForegroundColor Red
    Write-Host "  |  ACTION REQUIRED - COMPROMISED PACKAGES DETECTED        |" -ForegroundColor Red
    Write-Host "  +=========================================================+" -ForegroundColor Red
    Write-Host ""
    foreach ($finding in $Findings) {
        Write-Host "    * " -ForegroundColor Red -NoNewline; Write-Host $finding
    }
    Write-Host ""
    Write-Host "    Remediation steps:" -ForegroundColor White
    Write-Host "    1. Delete compromised node_modules directories"
    Write-Host "    2. Pin axios to a safe version (1.14.0 or 0.30.3)"
    Write-Host "    3. Delete lockfiles and reinstall: del package-lock.json; npm install"
    Write-Host "    4. Clear caches: npm cache clean --force"
    Write-Host "    5. Investigate and remove any RAT artifacts"
    Write-Host "    6. Rotate any credentials/tokens on this machine"
    Write-Host ""
    exit 1
} else {
    Write-Host "  +=========================================================+" -ForegroundColor Green
    Write-Host "  |  SCAN CLEAN - NO COMPROMISE INDICATORS FOUND            |" -ForegroundColor Green
    Write-Host "  +=========================================================+" -ForegroundColor Green
    Write-Host ""
    Write-Host "  " -NoNewline; Write-Host "Note: " -ForegroundColor Yellow -NoNewline; Write-Host "The malicious postinstall payload is designed to self-destruct"
    Write-Host "  after execution and overwrite its own package.json with a clean stub."
    Write-Host "  A clean scan does " -NoNewline; Write-Host "not" -ForegroundColor Yellow -NoNewline; Write-Host " guarantee the payload never ran. If axios@1.14.1"
    Write-Host "  or axios@0.30.4 was ever installed on this machine, even briefly, treat"
    Write-Host "  it as potentially compromised and rotate exposed credentials."
    Write-Host ""
    exit 0
}
