### PowerShell Profile (26zl) setup script
### This script configures the PowerShell profile by installing necessary tools, fonts, and themes.
### It also sets up Windows Terminal with recommended settings. Run this script in an elevated PowerShell session to ensure all changes are applied correctly.

param(
    [ValidateRange(0, 100)]
    [int]$Opacity = 75,

    [string]$ColorScheme,

    [ValidateRange(6, 30)]
    [int]$FontSize = 11
)

# Ensure the script can run with elevated privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as an Administrator!" -ForegroundColor Red
    return
}

# Set execution policy so the profile can load on future sessions
$currentUserPolicy = Get-ExecutionPolicy -Scope CurrentUser
if ($currentUserPolicy -in @('Restricted', 'AllSigned', 'Undefined')) {
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
    Write-Host "Execution policy set to RemoteSigned for CurrentUser." -ForegroundColor Green
}
# Offer LocalMachine scope (covers all users and both PS editions) but don't force it
$machinePolicy = Get-ExecutionPolicy -Scope LocalMachine
if ($machinePolicy -in @('Restricted', 'AllSigned', 'Undefined')) {
    $reply = Read-Host "  LocalMachine execution policy is '$machinePolicy'. Set to RemoteSigned for all users? [y/N]"
    if ($reply -match '^[Yy]') {
        Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
        Write-Host "Execution policy set to RemoteSigned for LocalMachine." -ForegroundColor Green
    }
    else {
        Write-Host "  Skipped LocalMachine policy. PS5 may not load the profile if CurrentUser is overridden." -ForegroundColor Yellow
    }
}

# Function to test internet connectivity (HTTPS — works through corporate proxies/firewalls)
function Test-InternetConnection {
    try {
        $response = Invoke-WebRequest -Uri "https://github.com" -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        return $response.StatusCode -eq 200
    }
    catch {
        Write-Host "Internet connection is required but not available (cannot reach github.com)." -ForegroundColor Red
        return $false
    }
}

# Function to install Nerd Fonts
function Install-NerdFonts {
    param (
        [string]$FontName = "CascadiaCode",
        [string]$FontDisplayName = "CaskaydiaCove NF",
        [string]$Version = "3.2.1"
    )

    try {
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
        $fontFamilies = (New-Object System.Drawing.Text.InstalledFontCollection).Families.Name
        if ($fontFamilies -notcontains "${FontDisplayName}") {
            Write-Host "  Installing ${FontDisplayName}..." -ForegroundColor Yellow
            $fontZipUrl = "https://github.com/ryanoasis/nerd-fonts/releases/download/v${Version}/${FontName}.zip"
            $zipFilePath = "$env:TEMP\${FontName}.zip"
            $extractPath = "$env:TEMP\${FontName}"

            $webClient = New-Object System.Net.WebClient
            try {
                $webClient.DownloadFile((New-Object System.Uri($fontZipUrl)), $zipFilePath)
            }
            finally {
                $webClient.Dispose()
            }

            Expand-Archive -Path $zipFilePath -DestinationPath $extractPath -Force
            $destination = (New-Object -ComObject Shell.Application).Namespace(0x14)
            Get-ChildItem -Path $extractPath -Recurse -Filter "*.ttf" | ForEach-Object {
                If (-not(Test-Path "$env:SystemRoot\Fonts\$($_.Name)")) {
                    $destination.CopyHere($_.FullName, 0x10)
                }
            }

            Remove-Item -Path $extractPath -Recurse -Force
            Remove-Item -Path $zipFilePath -Force
            Write-Host "  ${FontDisplayName} installed." -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "  ${FontDisplayName} already installed." -ForegroundColor Green
            return $true
        }
    }
    catch {
        Write-Host "  Failed to install ${FontDisplayName}: $_" -ForegroundColor Red
        return $false
    }
}

# Check for internet connectivity before proceeding
if (-not (Test-InternetConnection)) {
    return
}

# JSONC comment-stripping regex (here-string avoids PS5 parser bug with [^"] in strings)
$jsoncCommentPattern = @'
(?m)(?<=^([^"]*"[^"]*")*[^"]*)\s*//.*$
'@

# Download profile-config.json (single source of truth for theme + WT metadata)
$profileConfig = $null
$configCachePath = Join-Path $env:LOCALAPPDATA "PowerShellProfile"
if (!(Test-Path -Path $configCachePath)) {
    New-Item -Path $configCachePath -ItemType "directory" -Force | Out-Null
}
try {
    $configUrl = "https://raw.githubusercontent.com/26zl/powershell-profile/main/profile-config.json"
    $configTmp = Join-Path $env:TEMP "profile-config.json"
    Invoke-RestMethod $configUrl -OutFile $configTmp -TimeoutSec 10 -ErrorAction Stop
    $profileConfig = Get-Content $configTmp -Raw | ConvertFrom-Json
    Copy-Item $configTmp (Join-Path $configCachePath "profile-config.json") -Force
    Remove-Item $configTmp -ErrorAction SilentlyContinue
}
catch {
    Write-Host "Could not download profile-config.json. Theme and color scheme steps will be skipped." -ForegroundColor Yellow
}

# Check for winget availability
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "winget (App Installer) is required but not found." -ForegroundColor Red
    Write-Host "Install it from the Microsoft Store or https://aka.ms/getwinget" -ForegroundColor Yellow
    return
}

Write-Host ""
Write-Host "PowerShell Profile Setup" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host ""

# Profile creation or update (install for both PS5 and PS7)
Write-Host "[1/6] Profile" -ForegroundColor Cyan
$profileUrl = "https://github.com/26zl/powershell-profile/raw/main/Microsoft.PowerShell_profile.ps1"
# Derive Documents root from $PROFILE (works correctly even when Documents is in OneDrive)
$docsRoot = Split-Path (Split-Path $PROFILE)
$profileDirs = @(
    Join-Path $docsRoot "PowerShell"          # PS7 (Core)
    Join-Path $docsRoot "WindowsPowerShell"    # PS5 (Desktop)
)
$profileInstalled = $true
foreach ($dir in $profileDirs) {
    $targetProfile = Join-Path $dir "Microsoft.PowerShell_profile.ps1"
    try {
        if (!(Test-Path -Path $dir)) {
            New-Item -Path $dir -ItemType "directory" -Force | Out-Null
        }
        # Download to temp first so a partial/corrupt download never overwrites the existing profile
        $tempDownload = Join-Path $env:TEMP "profile_download_$(Split-Path $dir -Leaf).ps1"
        Invoke-RestMethod $profileUrl -OutFile $tempDownload -TimeoutSec 30 -ErrorAction Stop
        if (Test-Path -Path $targetProfile -PathType Leaf) {
            $backupPath = Join-Path $dir "oldprofile.ps1"
            Copy-Item -Path $targetProfile -Destination $backupPath -Force
            Write-Host "  Backup saved to [$backupPath]" -ForegroundColor DarkGray
        }
        Move-Item -Path $tempDownload -Destination $targetProfile -Force
        Write-Host "  Profile installed at [$targetProfile]" -ForegroundColor Green

        # Create starter user override file if it doesn't exist (never overwrite)
        $userProfilePath = Join-Path $dir "profile_user.ps1"
        if (-not (Test-Path $userProfilePath)) {
            @'
### profile_user.ps1 — Personal overrides (survives Update-Profile)
### This file is dot-sourced at the end of the main profile.
### Uncomment or add your own customizations below.

# --- Custom aliases ---
# Set-Alias -Name myalias -Value Get-ChildItem

# --- Custom functions ---
# function hello { Write-Host "Hello, $env:USERNAME!" }

# --- Override PSReadLine colors ---
# Set-PSReadLineOption -Colors @{ Command = '#61AFEF'; String = '#98C379' }

# --- Import additional modules ---
# Import-Module posh-git
'@ | Set-Content $userProfilePath -Encoding UTF8
            Write-Host "  User override file created at [$userProfilePath]" -ForegroundColor Green
        }
        else {
            Write-Host "  User override file already exists at [$userProfilePath] (preserved)" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "  Failed to install profile at [$targetProfile]: $_" -ForegroundColor Red
        Remove-Item $tempDownload -ErrorAction SilentlyContinue
        $profileInstalled = $false
    }
}

# Function to download Oh My Posh theme locally
function Install-OhMyPoshTheme {
    param (
        [Parameter(Mandatory)]
        [string]$ThemeName,
        [Parameter(Mandatory)]
        [string]$ThemeUrl
    )
    $cachePath = Join-Path $env:LOCALAPPDATA "PowerShellProfile"
    if (!(Test-Path -Path $cachePath)) {
        New-Item -Path $cachePath -ItemType "directory" -Force | Out-Null
    }
    $themeFilePath = Join-Path $cachePath "$ThemeName.omp.json"
    try {
        Invoke-RestMethod -Uri $ThemeUrl -OutFile $themeFilePath -TimeoutSec 10
        Write-Host "  Theme '$ThemeName' downloaded." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "  Failed to download theme: $_" -ForegroundColor Red
        return $false
    }
}

# OMP Install
Write-Host "[2/6] Oh My Posh" -ForegroundColor Cyan
$ompInstalled = $false
$null = winget install -e --accept-source-agreements --accept-package-agreements JanDeDobbeleer.OhMyPosh 2>&1 | Out-String
if ($LASTEXITCODE -eq 0) {
    Write-Host "  Oh My Posh installed." -ForegroundColor Green
    $ompInstalled = $true
}
elseif ($LASTEXITCODE -eq -1978335189) {
    Write-Host "  Oh My Posh already up to date." -ForegroundColor Green
    $ompInstalled = $true
}
else {
    Write-Host "  Oh My Posh install may have failed (exit code: $LASTEXITCODE)" -ForegroundColor Red
}
if ($profileConfig -and $profileConfig.theme.name -and $profileConfig.theme.url) {
    $themeInstalled = Install-OhMyPoshTheme -ThemeName $profileConfig.theme.name -ThemeUrl $profileConfig.theme.url
}
else {
    Write-Host "  Skipped theme download (profile-config.json missing or incomplete)." -ForegroundColor Yellow
    $themeInstalled = $true  # skip is not a failure
}
# Invalidate cached init scripts so they regenerate with correct paths on next startup
Remove-Item (Join-Path $configCachePath "omp-init.ps1") -ErrorAction SilentlyContinue
Remove-Item (Join-Path $configCachePath "zoxide-init.ps1") -ErrorAction SilentlyContinue

# Font Install
Write-Host "[3/6] Nerd Fonts" -ForegroundColor Cyan
$fontInstalled = Install-NerdFonts -FontName "CascadiaCode" -FontDisplayName "CaskaydiaCove NF"

# eza Install (modern ls replacement with icons and git status)
Write-Host "[4/6] eza" -ForegroundColor Cyan
$ezaInstalled = $false
$null = winget install -e --id eza-community.eza --accept-source-agreements --accept-package-agreements 2>&1 | Out-String
if ($LASTEXITCODE -eq 0) {
    Write-Host "  eza installed." -ForegroundColor Green
    $ezaInstalled = $true
}
elseif ($LASTEXITCODE -eq -1978335189) {
    Write-Host "  eza already up to date." -ForegroundColor Green
    $ezaInstalled = $true
}
else {
    Write-Host "  eza install may have failed (exit code: $LASTEXITCODE)" -ForegroundColor Red
}
# Clean up leftover Terminal-Icons if present
Remove-Module Terminal-Icons -Force -ErrorAction SilentlyContinue
Uninstall-Module Terminal-Icons -AllVersions -Force -ErrorAction SilentlyContinue

# zoxide Install
Write-Host "[5/6] zoxide" -ForegroundColor Cyan
$zoxideInstalled = $false
$null = winget install -e --id ajeetdsouza.zoxide --accept-source-agreements --accept-package-agreements 2>&1 | Out-String
if ($LASTEXITCODE -eq 0) {
    Write-Host "  zoxide installed." -ForegroundColor Green
    $zoxideInstalled = $true
}
elseif ($LASTEXITCODE -eq -1978335189) {
    Write-Host "  zoxide already up to date." -ForegroundColor Green
    $zoxideInstalled = $true
}
else {
    Write-Host "  zoxide install may have failed (exit code: $LASTEXITCODE)" -ForegroundColor Red
}

# Windows Terminal configuration (merges font, theme, and appearance into existing settings)
Write-Host "[6/6] Windows Terminal" -ForegroundColor Cyan
$wtSettingsPath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
if (Test-Path $wtSettingsPath) {
    try {
        # Backup original (ConvertTo-Json strips JSONC comments and may reorder keys)
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $backupPath = "$wtSettingsPath.$timestamp.bak"
        Copy-Item $wtSettingsPath $backupPath -Force
        Write-Host "  Backup saved to $backupPath" -ForegroundColor DarkGray

        $wtRaw = (Get-Content $wtSettingsPath -Raw) -replace $jsoncCommentPattern, ''
        $wt = $wtRaw | ConvertFrom-Json

        # Set defaults (font, acrylic, cursor, padding)
        if (-not $wt.profiles.defaults) {
            $wt.profiles | Add-Member -NotePropertyName "defaults" -NotePropertyValue ([PSCustomObject]@{}) -Force
        }
        $defaults = $wt.profiles.defaults
        $defaults | Add-Member -NotePropertyName "font" -NotePropertyValue ([PSCustomObject]@{ face = "CaskaydiaCove NF"; size = $FontSize }) -Force
        $defaults | Add-Member -NotePropertyName "opacity" -NotePropertyValue $Opacity -Force
        $defaults | Add-Member -NotePropertyName "useAcrylic" -NotePropertyValue $true -Force
        # Explicit -ColorScheme param wins over config
        $cfgColorScheme = if ($PSBoundParameters.ContainsKey('ColorScheme')) { $ColorScheme }
        elseif ($profileConfig -and $profileConfig.windowsTerminal.colorScheme) { $profileConfig.windowsTerminal.colorScheme }
        else { $null }
        $cfgCursorColor = if ($profileConfig -and $profileConfig.windowsTerminal.cursorColor) { $profileConfig.windowsTerminal.cursorColor } else { $null }
        if ($cfgColorScheme) {
            $defaults | Add-Member -NotePropertyName "colorScheme" -NotePropertyValue $cfgColorScheme -Force
        }
        $defaults | Add-Member -NotePropertyName "cursorShape" -NotePropertyValue "bar" -Force
        if ($cfgCursorColor) {
            $defaults | Add-Member -NotePropertyName "cursorColor" -NotePropertyValue $cfgCursorColor -Force
        }
        $defaults | Add-Member -NotePropertyName "padding" -NotePropertyValue "8, 8, 8, 8" -Force
        $defaults | Add-Member -NotePropertyName "scrollbarState" -NotePropertyValue "hidden" -Force
        $defaults | Add-Member -NotePropertyName "historySize" -NotePropertyValue 10000 -Force
        $defaults | Add-Member -NotePropertyName "antialiasingMode" -NotePropertyValue "cleartype" -Force

        # Upsert color scheme from config
        if ($profileConfig -and $profileConfig.windowsTerminal.scheme) {
            $schemeDef = [PSCustomObject]$profileConfig.windowsTerminal.scheme
            if (-not $wt.schemes) {
                $wt | Add-Member -NotePropertyName "schemes" -NotePropertyValue @() -Force
            }
            $wt.schemes = @(@($wt.schemes | Where-Object { $_ -and $_.name -ne $schemeDef.name }) + $schemeDef)
        }

        # Ensure PowerShell profiles launch with -NoLogo to suppress
        # the copyright banner and "Loading personal and system profiles took …" message
        if ($wt.profiles.list) {
            foreach ($prof in $wt.profiles.list) {
                $cmd = if ($prof.commandline) { $prof.commandline } else { '' }
                $src = if ($prof.source) { $prof.source } else { '' }
                $isPwsh = $cmd -match 'pwsh' -or $src -match 'Windows\.Terminal\.PowerShellCore'
                $isPS5 = $cmd -match 'powershell\.exe' -or $prof.name -match 'Windows PowerShell'
                if (($isPwsh -or $isPS5) -and $cmd -notmatch '-NoLogo') {
                    $newCmd = if ($cmd) { "$cmd -NoLogo" } elseif ($isPwsh) { "pwsh.exe -NoLogo" } else { "powershell.exe -NoLogo" }
                    $prof | Add-Member -NotePropertyName "commandline" -NotePropertyValue $newCmd -Force
                }
            }
        }

        $wt | ConvertTo-Json -Depth 10 | Set-Content $wtSettingsPath -Encoding UTF8
        $schemeLabel = if ($cfgColorScheme) { $cfgColorScheme } else { "(unchanged)" }
        Write-Host "  Windows Terminal configured (font: $FontSize pt, opacity: $Opacity, scheme: $schemeLabel)." -ForegroundColor Green
    }
    catch {
        Write-Host "  Failed to configure Windows Terminal: $_" -ForegroundColor Red
    }
}
else {
    Write-Host "  Windows Terminal settings not found (skipped)." -ForegroundColor Yellow
}

# Final summary
Write-Host ""
$allGood = $profileInstalled -and $themeInstalled -and $fontInstalled -and $ompInstalled -and $ezaInstalled -and $zoxideInstalled
if ($allGood) {
    Write-Host "Setup complete!" -ForegroundColor Green
}
else {
    Write-Host "Setup completed with some issues. Check the messages above." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "Restart your terminal to apply all changes." -ForegroundColor Cyan
Write-Host ""
if ([Environment]::UserInteractive -and -not [bool]$env:CI) {
    Read-Host "Press Enter to exit"
}
exit ([int](-not $allGood))
