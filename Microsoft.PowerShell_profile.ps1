### PowerShell Profile (26zl)
### https://github.com/26zl/powershell-profile

$profileStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Non-interactive mode detection (sandboxed/AI/CI/SSH-pipe sessions skip network calls and UI setup)
$_outputRedirected = try { [Console]::IsOutputRedirected } catch { $false }
$isInteractive = [Environment]::UserInteractive -and
-not [bool]$env:CI -and
-not [bool]$env:AGENT_ID -and
-not [bool]$env:CLAUDE_CODE -and
-not ($host.Name -eq 'Default Host') -and
-not $_outputRedirected -and
-not ([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '(?i)^-NonI' })

$repo_root = "https://raw.githubusercontent.com/26zl"

# Cache directory outside Documents (avoids Controlled Folder Access / ransomware protection blocks)
$cacheDir = Join-Path $env:LOCALAPPDATA "PowerShellProfile"
if (-not (Test-Path $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }

# JSONC comment-stripping regex (built via variable to avoid PS5 parser bug with [^"] in strings)
$_q = [char]34
$jsoncCommentPattern = "(?m)(?<=^([^$_q]*$_q[^$_q]*$_q)*[^$_q]*)\s*//.*`$"

# Opt-out of telemetry if running as admin (only set once)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin -and -not [System.Environment]::GetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'Machine')) {
    [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'true', [System.EnvironmentVariableTarget]::Machine)
}

# Check for Profile Updates (manual only)
function Update-Profile {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string]$ExpectedSha256,
        [switch]$SkipHashCheck
    )

    $tempProfile = Join-Path $env:TEMP "Microsoft.PowerShell_profile.ps1"
    $tempConfig = Join-Path $env:TEMP "profile-config.json"

    try {
        # Phase 1: Download profile and config
        $profileUrl = "$repo_root/powershell-profile/main/Microsoft.PowerShell_profile.ps1"
        Invoke-RestMethod $profileUrl -OutFile $tempProfile -TimeoutSec 10 -ErrorAction Stop

        $configUrl = "$repo_root/powershell-profile/main/profile-config.json"
        $configDownloaded = $false
        try {
            Invoke-RestMethod $configUrl -OutFile $tempConfig -TimeoutSec 10 -ErrorAction Stop
            $configDownloaded = $true
        }
        catch {
            Write-Warning "Could not download profile-config.json (non-fatal): $_"
        }

        # Phase 2: Hash verification (profile .ps1 only)
        $oldHash = if (Test-Path $PROFILE) { (Get-FileHash -Path $PROFILE -Algorithm SHA256).Hash } else { "" }
        $newHash = (Get-FileHash -Path $tempProfile -Algorithm SHA256).Hash
        $profileChanged = $newHash -ne $oldHash

        # Check if config actually changed
        $configChanged = $false
        $cachedConfig = Join-Path $cacheDir "profile-config.json"
        if ($configDownloaded) {
            $newConfigHash = (Get-FileHash -Path $tempConfig -Algorithm SHA256).Hash
            $oldConfigHash = if (Test-Path $cachedConfig) { (Get-FileHash -Path $cachedConfig -Algorithm SHA256).Hash } else { "" }
            $configChanged = $newConfigHash -ne $oldConfigHash
        }

        if (-not $profileChanged -and -not $configChanged) {
            Write-Host "Profile is up to date." -ForegroundColor Green
            return
        }

        if ($profileChanged) {
            if (-not $SkipHashCheck) {
                if (-not $ExpectedSha256) {
                    Write-Host "Downloaded profile hash: $newHash" -ForegroundColor Yellow
                    Write-Host "Verify this hash matches the latest commit on https://github.com/26zl/powershell-profile" -ForegroundColor Yellow
                    throw "Hash verification required. Re-run with -ExpectedSha256 '$newHash' to confirm, or -SkipHashCheck to bypass."
                }
                $expected = $ExpectedSha256.ToUpperInvariant()
                if ($newHash -ne $expected) {
                    throw "Downloaded profile hash mismatch. Expected $expected, got $newHash."
                }
            }
        }

        # Phase 3: Copy profile to PS5/PS7 dirs (only if changed)
        if ($profileChanged) {
            if ($PSCmdlet.ShouldProcess($PROFILE, "Replace profile with downloaded version (hash: $newHash)")) {
                $docsRoot = Split-Path (Split-Path $PROFILE)
                $profileDirs = @(
                    Join-Path $docsRoot "PowerShell"
                    Join-Path $docsRoot "WindowsPowerShell"
                )
                $copySuccess = 0
                $copyFailed = @()
                foreach ($dir in $profileDirs) {
                    $target = Join-Path $dir "Microsoft.PowerShell_profile.ps1"
                    if (Test-Path $dir) {
                        try {
                            Copy-Item -Path $tempProfile -Destination $target -Force -ErrorAction Stop
                            $copySuccess++
                        }
                        catch {
                            $copyFailed += $target
                            Write-Warning "Failed to copy profile to ${target}: $_"
                        }
                    }
                }
                if ($copySuccess -gt 0 -and $copyFailed.Count -eq 0) {
                    Write-Host "Profile updated ($copySuccess locations)." -ForegroundColor Green
                }
                elseif ($copySuccess -gt 0) {
                    Write-Warning "Profile updated partially. Failed to write: $($copyFailed -join ', ')"
                }
                else {
                    Write-Warning "Profile not updated -- no writable profile directories found."
                }
            }
        }
        else {
            Write-Host "Profile .ps1 unchanged, applying config updates..." -ForegroundColor Cyan
        }

        # Save config to cache dir for runtime use
        if ($configChanged) {
            if ($PSCmdlet.ShouldProcess($cachedConfig, "Save profile-config.json to cache")) {
                Copy-Item -Path $tempConfig -Destination $cachedConfig -Force
            }
        }

        # Load config for remaining phases
        $config = $null
        $cachedConfigPath = Join-Path $cacheDir "profile-config.json"
        if ($configDownloaded) {
            try { $config = Get-Content $tempConfig -Raw | ConvertFrom-Json }
            catch { Write-Verbose "Failed to parse downloaded config: $_" }
        }
        elseif (Test-Path $cachedConfigPath) {
            try { $config = Get-Content $cachedConfigPath -Raw | ConvertFrom-Json }
            catch { Write-Verbose "Failed to parse cached config: $_" }
        }

        # Phase 4: OMP theme sync
        if ($config -and $config.theme -and $config.theme.name) {
            $themeName = $config.theme.name
            $themeUrl = $config.theme.url
            $localThemePath = Join-Path $cacheDir "$themeName.omp.json"
            $shouldDownloadTheme = (-not (Test-Path $localThemePath)) -or $profileChanged -or $configChanged
            if ($shouldDownloadTheme -and $themeUrl) {
                if ($PSCmdlet.ShouldProcess($localThemePath, "Download OMP theme '$themeName'")) {
                    try {
                        Invoke-RestMethod -Uri $themeUrl -OutFile $localThemePath -TimeoutSec 10 -ErrorAction Stop
                        Write-Host "OMP theme '$themeName' updated." -ForegroundColor Green
                    }
                    catch {
                        Write-Warning "Failed to download OMP theme: $_"
                    }
                }
            }

            # Phase 6: Orphan cleanup — remove *.omp.json files that don't match current theme
            $ompFiles = Get-ChildItem -Path $cacheDir -Filter "*.omp.json" -ErrorAction SilentlyContinue
            foreach ($file in $ompFiles) {
                if ($file.Name -ne "$themeName.omp.json") {
                    if ($PSCmdlet.ShouldProcess($file.FullName, "Remove orphaned OMP theme")) {
                        Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
                        Write-Host "Removed orphaned theme: $($file.Name)" -ForegroundColor DarkGray
                    }
                }
            }
        }

        # Phase 5: Cache invalidation (if profile or config changed)
        if ($profileChanged -or $configChanged) {
            $ompCache = Join-Path $cacheDir "omp-init.ps1"
            $zoxideCache = Join-Path $cacheDir "zoxide-init.ps1"
            if (Test-Path $ompCache) {
                if ($PSCmdlet.ShouldProcess($ompCache, "Invalidate OMP init cache")) {
                    Remove-Item $ompCache -Force -ErrorAction SilentlyContinue
                    Write-Host "OMP init cache cleared." -ForegroundColor DarkGray
                }
            }
            if (Test-Path $zoxideCache) {
                if ($PSCmdlet.ShouldProcess($zoxideCache, "Invalidate zoxide init cache")) {
                    Remove-Item $zoxideCache -Force -ErrorAction SilentlyContinue
                    Write-Host "Zoxide init cache cleared." -ForegroundColor DarkGray
                }
            }
        }

        # Phase 7: Windows Terminal sync (only when config changed)
        if ($configChanged -and $config -and $config.windowsTerminal) {
            $wtSettingsPath = Join-Path $env:LOCALAPPDATA "Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
            if (Test-Path $wtSettingsPath) {
                if ($PSCmdlet.ShouldProcess($wtSettingsPath, "Update Windows Terminal colorScheme/cursorColor and sync scheme")) {
                    try {
                        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
                        $backupPath = "$wtSettingsPath.$timestamp.bak"
                        Copy-Item $wtSettingsPath $backupPath -Force
                        Write-Host "WT backup: $backupPath" -ForegroundColor DarkGray

                        $wtRaw = (Get-Content $wtSettingsPath -Raw) -replace $jsoncCommentPattern, ''
                        $wt = $wtRaw | ConvertFrom-Json

                        if (-not $wt.profiles.defaults) {
                            $wt.profiles | Add-Member -NotePropertyName "defaults" -NotePropertyValue ([PSCustomObject]@{}) -Force
                        }
                        $defaults = $wt.profiles.defaults

                        $schemeName = $config.windowsTerminal.colorScheme
                        if ($schemeName) {
                            $defaults | Add-Member -NotePropertyName "colorScheme" -NotePropertyValue $schemeName -Force
                        }
                        $cursorColor = $config.windowsTerminal.cursorColor
                        if ($cursorColor) {
                            $defaults | Add-Member -NotePropertyName "cursorColor" -NotePropertyValue $cursorColor -Force
                        }

                        # Upsert scheme definition
                        $schemeDef = $config.windowsTerminal.scheme
                        if ($schemeDef) {
                            if (-not $wt.schemes) {
                                $wt | Add-Member -NotePropertyName "schemes" -NotePropertyValue @() -Force
                            }
                            $schemeDefName = if ($schemeDef.name) { $schemeDef.name } else { $schemeName }
                            $wt.schemes = @(@($wt.schemes | Where-Object { $_ -and $_.name -ne $schemeDefName }) + ([PSCustomObject]$schemeDef))
                        }

                        $wt | ConvertTo-Json -Depth 10 | Set-Content $wtSettingsPath -Encoding UTF8
                        Write-Host "Windows Terminal settings updated." -ForegroundColor Green
                    }
                    catch {
                        Write-Warning "Failed to update Windows Terminal settings: $_"
                    }
                }
            }
        }

        if ($profileChanged) {
            Write-Host "Please restart your shell to reflect changes." -ForegroundColor Magenta
        }
    }
    catch {
        Write-Error "Unable to check for `$profile updates: $_"
    }
    finally {
        Remove-Item $tempProfile -ErrorAction SilentlyContinue
        Remove-Item $tempConfig -ErrorAction SilentlyContinue
    }
}

# Check for new PowerShell (Core) releases and update via winget
function Update-PowerShell {
    if ($PSVersionTable.PSEdition -ne "Core") {
        Write-Host "Windows PowerShell 5.1 is updated via Windows Update, not winget." -ForegroundColor Yellow
        Write-Host "This command checks for PowerShell 7+ (Core) updates only." -ForegroundColor Yellow
        return
    }
    try {
        Write-Host "Checking for PowerShell updates..." -ForegroundColor Cyan
        $currentVersion = $PSVersionTable.PSVersion
        $gitHubApiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
        $latestReleaseInfo = Invoke-RestMethod -Uri $gitHubApiUrl -TimeoutSec 10
        $latestVersionStr = $latestReleaseInfo.tag_name.Trim('v') -replace '-.*$', ''
        $latestVersion = [version]$latestVersionStr
        if ($currentVersion -lt $latestVersion) {
            Write-Host "Updating PowerShell ($currentVersion -> $latestVersion)..." -ForegroundColor Yellow
            Start-Process pwsh.exe -ArgumentList "-NoProfile -Command winget upgrade Microsoft.PowerShell --accept-source-agreements --accept-package-agreements" -NoNewWindow
            Write-Host "PowerShell update started. Please restart your shell when complete." -ForegroundColor Magenta
        }
        else {
            Write-Host "Your PowerShell is up to date." -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to update PowerShell. Error: $_"
    }
}
# Update Oh My Posh, eza, and zoxide via winget
function Update-Tools {
    $tools = @(
        @{ Name = "Oh My Posh"; Id = "JanDeDobbeleer.OhMyPosh" }
        @{ Name = "eza";        Id = "eza-community.eza" }
        @{ Name = "zoxide";     Id = "ajeetdsouza.zoxide" }
    )
    $upgraded = 0
    $failed = 0
    foreach ($tool in $tools) {
        Write-Host "Updating $($tool.Name)..." -ForegroundColor Cyan
        winget upgrade --id $tool.Id --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -eq 0) { $upgraded++ }
        elseif ($LASTEXITCODE -ne -1978335189) { $failed++ }
    }
    if ($upgraded -gt 0) {
        # Invalidate cached init scripts so they regenerate on next load
        Remove-Item (Join-Path $cacheDir "omp-init.ps1") -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $cacheDir "zoxide-init.ps1") -ErrorAction SilentlyContinue
        Write-Host "$upgraded tool(s) updated. Restart your shell to apply changes." -ForegroundColor Magenta
    }
    if ($failed -gt 0) {
        Write-Warning "$failed tool(s) failed to update. Check the output above."
    }
    if ($upgraded -eq 0 -and $failed -eq 0) {
        Write-Host "All tools are up to date." -ForegroundColor Green
    }
}
# Clear user temp/browser caches (-IncludeSystemCaches for system dirs)
function Clear-Cache {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$IncludeSystemCaches
    )

    Write-Host "Clearing cache..." -ForegroundColor Cyan

    $targets = @(
        @{ Name = "User Temp"; Path = "$env:TEMP\*"; Recurse = $true },
        @{ Name = "Internet Explorer Cache"; Path = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*"; Recurse = $true }
    )

    if ($IncludeSystemCaches) {
        $targets += @(
            @{ Name = "Windows Temp"; Path = "$env:SystemRoot\Temp\*"; Recurse = $true },
            @{ Name = "Windows Prefetch"; Path = "$env:SystemRoot\Prefetch\*"; Recurse = $false }
        )
    }

    foreach ($target in $targets) {
        if ($PSCmdlet.ShouldProcess($target.Path, "Clear $($target.Name)")) {
            Write-Host "Clearing $($target.Name)..." -ForegroundColor Yellow
            if ($target.Recurse) {
                Remove-Item -Path $target.Path -Recurse -Force -ErrorAction SilentlyContinue
            }
            else {
                Remove-Item -Path $target.Path -Force -ErrorAction SilentlyContinue
            }
            Write-Host "Cleared $($target.Name)." -ForegroundColor Green
        }
    }
}

# Admin Check and Prompt Customization (fallback when Oh My Posh is not loaded)
$adminSuffix = if ($isAdmin) { " [ADMIN]" } else { "" }
function prompt {
    if ($adminSuffix) { "[" + (Get-Location) + "] # " } else { "[" + (Get-Location) + "] $ " }
}
$Host.UI.RawUI.WindowTitle = "PowerShell {0}$adminSuffix" -f $PSVersionTable.PSVersion.ToString()

# Editor Configuration (lazy — only resolves on first use)
function vim {
    if ($null -eq $script:EDITOR) {
        foreach ($e in 'code', 'sublime_text', 'notepad', 'nvim', 'vim', 'vi') {
            if (Get-Command $e -ErrorAction SilentlyContinue) { $script:EDITOR = $e; break }
        }
        if ($null -eq $script:EDITOR) { $script:EDITOR = 'notepad' }
    }
    & $script:EDITOR @args
}

# Quick Access to Editing the Profile
function Edit-Profile {
    vim $PROFILE
}
Set-Alias -Name ep -Value Edit-Profile

# Create file or update its timestamp
function touch($file) {
    if (Test-Path $file) {
        (Get-Item $file).LastWriteTime = Get-Date
    }
    else {
        New-Item -ItemType File -Path $file | Out-Null
    }
}
# Recursive file search by name
function ff($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.FullName)"
    }
}

# Network Utilities
function pubip {
    try {
        (Invoke-WebRequest https://ifconfig.me/ip -TimeoutSec 10).Content
    }
    catch {
        Write-Error "Failed to retrieve public IP: $_"
    }
}

# Open WinUtil full-release (downloads to temp file, then executes locally)
function winutil {
    $scriptPath = Join-Path $env:TEMP "winutil.ps1"
    try {
        Invoke-RestMethod https://christitus.com/win -OutFile $scriptPath -TimeoutSec 10 -ErrorAction Stop
        & $scriptPath
    }
    catch {
        Write-Error "Failed to run WinUtil: $_"
    }
    finally {
        Remove-Item $scriptPath -ErrorAction SilentlyContinue
    }
}


# Open elevated Windows Terminal (detects PS edition)
function admin {
    $shell = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh.exe" } else { "powershell.exe" }
    if ($args.Count -gt 0) {
        $command = $args -join ' '
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
        Start-Process wt -Verb runAs -ArgumentList "$shell -NoExit -EncodedCommand $encoded"
    }
    else {
        Start-Process wt -Verb runAs
    }
}

Set-Alias -Name su -Value admin
# System Uptime (PS5-compatible)
function uptime {
    try {
        if ($PSVersionTable.PSVersion.Major -eq 5) {
            $lastBoot = (Get-WmiObject win32_operatingsystem).LastBootUpTime
            $bootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($lastBoot)
        }
        else {
            $bootTime = (Get-Uptime -Since)
        }

        $formattedBootTime = $bootTime.ToString("dddd, MMMM dd, yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        Write-Host "System started on: $formattedBootTime" -ForegroundColor DarkGray

        $uptime = (Get-Date) - $bootTime
        Write-Host ("Uptime: {0} days, {1} hours, {2} minutes, {3} seconds" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds) -ForegroundColor Blue
    }
    catch {
        Write-Error "An error occurred while retrieving system uptime."
    }
}
# Unzip Utility (PS5-compatible)
function unzip ($file) {
    $resolved = Resolve-Path -LiteralPath $file -ErrorAction SilentlyContinue
    if (-not $resolved) {
        Write-Error "File not found: $file"
        return
    }
    Write-Output "Extracting $($resolved.Path) to $pwd"
    Expand-Archive -Path $resolved.Path -DestinationPath $pwd
}
# Hastebin-like upload function (PS5-compatible, no dependencies)
function hb {
    if ($args.Length -eq 0) {
        Write-Error "No file path specified."
        return
    }

    $FilePath = $args[0]

    if (Test-Path $FilePath) {
        $Content = Get-Content $FilePath -Raw
    }
    else {
        Write-Error "File path does not exist."
        return
    }

    $uri = "https://bin.christitus.com/documents"
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $Content -ErrorAction Stop -TimeoutSec 10
        $hasteKey = $response.key
        $url = "https://bin.christitus.com/$hasteKey"
        Set-Clipboard $url
        Write-Output "$url copied to clipboard."
    }
    catch {
        Write-Error "Failed to upload the document. Error: $_"
    }
}
# Grep Utility (PS5-compatible, no dependencies)
function grep($regex, $dir) {
    if ( $dir ) {
        Get-ChildItem $dir | select-string $regex
        return
    }
    $input | select-string $regex
}

# Disk volume info
function df {
    get-volume
}

# Find and replace text in a file
function sed($file, $find, $replace) {
    $content = Get-Content $file -Raw
    if ($null -eq $content) {
        Write-Warning "File is empty: $file"
        return
    }
    $content.replace("$find", $replace) | Set-Content $file
}

# Show the full path of a command
function which($name) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}

# Set an environment variable in the current session
function export($name, $value) {
    set-item -force -path "env:$name" -value $value;
}

# Kill process by name
function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}

# List processes by name
function pgrep($name) {
    Get-Process $name
}

# Display first n lines of a file (default 10)
function head {
    param($Path, $n = 10)
    Get-Content $Path -Head $n
}

# Display last n lines of a file (default 10, -f to follow)
function tail {
    param($Path, $n = 10, [switch]$f = $false)
    Get-Content $Path -Tail $n -Wait:$f
}

# Quick File Creation
function nf { param($name) New-Item -ItemType "file" -Path . -Name $name }

# Directory Management
function mkcd { param($dir) mkdir $dir -Force; Set-Location $dir }

# Move item to Recycle Bin via Shell.Application COM
function trash($path) {
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Host "Error: Item '$path' does not exist."
        return
    }

    $item = Get-Item -LiteralPath $path

    if ($item.PSIsContainer) {
        $parentPath = $item.Parent.FullName
    }
    else {
        $parentPath = $item.DirectoryName
    }

    $shell = New-Object -ComObject 'Shell.Application'
    $folder = $shell.NameSpace($parentPath)
    if (-not $folder) {
        Write-Host "Error: Cannot access parent folder '$parentPath'."
        return
    }
    $shellItem = $folder.ParseName($item.Name)
    if (-not $shellItem) {
        Write-Host "Error: Cannot find '$($item.Name)' in '$parentPath'."
        return
    }
    $shellItem.InvokeVerb('delete')
    Write-Host "Item '$($item.FullName)' has been moved to the Recycle Bin."
}

### Quality of Life Aliases

# Navigation Shortcuts
function docs {
    $docs = if (([Environment]::GetFolderPath("MyDocuments"))) { ([Environment]::GetFolderPath("MyDocuments")) } else { $HOME + "\Documents" }
    Set-Location -Path $docs
}

function dtop {
    $dtop = if ([Environment]::GetFolderPath("Desktop")) { [Environment]::GetFolderPath("Desktop") } else { $HOME + "\Desktop" }
    Set-Location -Path $dtop
}

# Enhanced Listing (eza — modern ls replacement with icons and git status)
if (Get-Command eza -ErrorAction SilentlyContinue) {
    # Remove-Alias exists only in PS6+; PS5 needs Remove-Item on the Alias: drive
    if (Get-Command Remove-Alias -ErrorAction SilentlyContinue) {
        Remove-Alias ls -Force -ErrorAction SilentlyContinue
    }
    else {
        Remove-Item Alias:\ls -Force -ErrorAction SilentlyContinue
    }
    function ls { eza --icons @args }
    function la { eza -a --icons @args }
    function ll { eza -la --icons --git @args }
    function lt { eza --tree --icons --level=2 @args }
}
else {
    if ($isInteractive) { Write-Warning "eza not found. Install it with: winget install -e --id eza-community.eza" }
    function la { Get-ChildItem -Force | Format-Table -AutoSize }
    function ll { Get-ChildItem -Force | Format-Table -AutoSize }
    function lt { Get-ChildItem -Recurse -Depth 2 | Format-Table -AutoSize }
}

# Git Shortcuts
function gs { git status }

function ga { git add . }

# Remove built-in gc alias (Get-Content) so our function is reachable
if (Get-Command Remove-Alias -ErrorAction SilentlyContinue) {
    Remove-Alias gc -Force -ErrorAction SilentlyContinue
}
else {
    Remove-Item Alias:\gc -Force -ErrorAction SilentlyContinue
}
function gc { git commit -m "$args" }

function gpush { git push }

function gpull { git pull }

# Jump to github directory via zoxide
function g {
    if (Get-Command __zoxide_z -ErrorAction SilentlyContinue) {
        __zoxide_z github
    }
    else {
        Write-Warning "zoxide is not initialized. Install zoxide and restart your shell."
    }
}

function gcl { git clone @args }

# Add all + commit
function gcom {
    git add .
    git commit -m "$args"
}
# Add all + commit + push
function lazyg {
    git add .
    git commit -m "$args"
    if ($LASTEXITCODE -eq 0) {
        git push
    }
    else {
        Write-Warning "Commit failed. Push skipped."
    }
}

# Quick Access to System Information
function sysinfo { Get-ComputerInfo }

# Networking Utilities
function flushdns {
    Clear-DnsClientCache
    Write-Host "DNS has been flushed"
}

# Clipboard Utilities
function cpy { Set-Clipboard ($args -join ' ') }
function pst { Get-Clipboard }

# Safely insert clipboard text into the prompt buffer (never executes directly)
function Invoke-Clipboard {
    $clipboardText = Get-Clipboard -Raw
    if ([string]::IsNullOrWhiteSpace($clipboardText)) {
        Write-Host "Clipboard is empty." -ForegroundColor Yellow
        return
    }

    # Never execute clipboard contents. Insert into prompt buffer when available.
    try {
        if ($isInteractive -and (Get-Module PSReadLine -ErrorAction SilentlyContinue)) {
            [Microsoft.PowerShell.PSConsoleReadLine]::Insert($clipboardText)
            return
        }
    }
    catch {
        Write-Warning "Could not insert clipboard into prompt buffer: $_"
    }

    Write-Output $clipboardText
}
Set-Alias -Name icb -Value Invoke-Clipboard

# Enhanced PSReadLine Configuration
$PSReadLineOptions = @{
    EditMode                      = 'Windows'
    HistoryNoDuplicates           = $true
    HistorySearchCursorMovesToEnd = $true
    Colors                        = @{
        Command   = '#61AFEF'  # Blue
        Parameter = '#98C379'  # Green
        Operator  = '#56B6C2'  # Cyan
        Variable  = '#E5C07B'  # Yellow
        String    = '#98C379'  # Green
        Number    = '#D19A66'  # Orange
        Type      = '#61AFEF'  # Blue
        Comment   = '#5C6370'  # Gray
        Keyword   = '#C678DD'  # Soft purple
        Error     = '#E06C75'  # Red
    }
    BellStyle                     = 'None'
}
Set-PSReadLineOption @PSReadLineOptions

# PSReadLine features that require an interactive console host
if ($isInteractive -and (Get-Module PSReadLine)) {
    # Core-only prediction settings (PredictionSource/PredictionViewStyle don't exist on Desktop)
    # Guard against hosts without VT support (e.g. AI/Codex terminals, redirected output)
    if ($PSVersionTable.PSEdition -eq "Core") {
        $supportsPrediction = $false
        try {
            $supportsPrediction = [bool]$Host.UI.SupportsVirtualTerminal -and -not [Console]::IsOutputRedirected
        }
        catch {
            $supportsPrediction = $false
        }

        if ($supportsPrediction) {
            try {
                Set-PSReadLineOption -PredictionSource HistoryAndPlugin -ErrorAction Stop
                Set-PSReadLineOption -PredictionViewStyle ListView -ErrorAction Stop
            }
            catch {
                Write-Verbose "PSReadLine prediction unavailable: $_"
            }
        }
    }
    Set-PSReadLineOption -MaximumHistoryCount 10000

    # Custom key handlers
    Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
    Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
    Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
    Set-PSReadLineKeyHandler -Chord 'Ctrl+d' -Function DeleteChar
    Set-PSReadLineKeyHandler -Chord 'Ctrl+w' -Function BackwardDeleteWord
    Set-PSReadLineKeyHandler -Chord 'Alt+d' -Function DeleteWord
    Set-PSReadLineKeyHandler -Chord 'Ctrl+LeftArrow' -Function BackwardWord
    Set-PSReadLineKeyHandler -Chord 'Ctrl+RightArrow' -Function ForwardWord
    Set-PSReadLineKeyHandler -Chord 'Ctrl+z' -Function Undo
    Set-PSReadLineKeyHandler -Chord 'Ctrl+y' -Function Redo
    $smartPasteHandler = {
        try {
            $clipboardText = Get-Clipboard -Raw
            if (-not [string]::IsNullOrWhiteSpace($clipboardText)) {
                [Microsoft.PowerShell.PSConsoleReadLine]::Insert($clipboardText)
            }
        }
        catch {
            [Microsoft.PowerShell.PSConsoleReadLine]::Ding()
        }
    }
    Set-PSReadLineKeyHandler -Chord 'Alt+v' -BriefDescription SmartPaste -Description 'Paste clipboard as one block into prompt' -ScriptBlock $smartPasteHandler

    # Filter sensitive commands from history
    Set-PSReadLineOption -AddToHistoryHandler {
        param($line)
        $sensitive = @('password', 'secret', 'token', 'apikey', 'connectionstring')
        $hasSensitive = $sensitive | Where-Object { $line -match $_ }
        return ($null -eq $hasSensitive)
    }
}

# Custom completion for common commands
$scriptblock = {
    param($wordToComplete, $commandAst, $cursorPosition)
    $customCompletions = @{
        'git'  = @('status', 'add', 'commit', 'push', 'pull', 'clone', 'checkout')
        'npm'  = @('install', 'start', 'run', 'test', 'build')
        'deno' = @('run', 'compile', 'test', 'lint', 'fmt', 'cache', 'info', 'doc', 'upgrade')
    }

    $command = $commandAst.CommandElements[0].Value
    if ($customCompletions.ContainsKey($command)) {
        $customCompletions[$command] | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
}
Register-ArgumentCompleter -Native -CommandName git, npm, deno -ScriptBlock $scriptblock

# dotnet completion (only if dotnet is installed)
if (Get-Command dotnet -ErrorAction SilentlyContinue) {
    $dotnetScriptblock = {
        param($wordToComplete, $commandAst, $cursorPosition)
        dotnet complete --position $cursorPosition $commandAst.ToString() |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
    Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock $dotnetScriptblock
}

# Oh My Posh initialization (interactive only, cached for fast startup)
if ($isInteractive) {
    if (Get-Command oh-my-posh -ErrorAction SilentlyContinue) {
        # Read theme name + URL from cached config
        $profileConfigPath = Join-Path $cacheDir "profile-config.json"
        $themeName = $null
        $themeUrl = $null
        if (Test-Path $profileConfigPath) {
            try {
                $cfg = Get-Content $profileConfigPath -Raw | ConvertFrom-Json
                if ($cfg.theme.name) { $themeName = $cfg.theme.name }
                if ($cfg.theme.url) { $themeUrl = $cfg.theme.url }
            }
            catch { Write-Verbose "Failed to parse profile-config.json: $_" }
        }
        if (-not $themeName) {
            Write-Verbose "No profile-config.json found in cache. Run Update-Profile or setup.ps1 to configure the OMP theme."
        }
        $localThemePath = if ($themeName) { Join-Path $cacheDir "$themeName.omp.json" } else { $null }
        if ($localThemePath -and -not (Test-Path $localThemePath)) {
            # Try migrating from old location (Documents\PowerShell), fall back to download
            $oldThemePath = Join-Path (Split-Path $PROFILE) "$themeName.omp.json"
            if (Test-Path $oldThemePath) {
                try { Move-Item $oldThemePath $localThemePath -Force -ErrorAction Stop }
                catch { Write-Warning "Could not migrate theme from Documents: $_" }
            }
            if (-not (Test-Path $localThemePath) -and $themeUrl) {
                try {
                    Invoke-RestMethod -Uri $themeUrl -OutFile $localThemePath -TimeoutSec 10
                    Write-Host "Downloaded missing Oh My Posh theme to $localThemePath"
                }
                catch {
                    Write-Warning "Failed to download theme file: $_"
                }
            }
        }
        if ($localThemePath -and (Test-Path $localThemePath)) {
            # Cache the OMP init script so we don't shell out every startup
            $ompCachePath = Join-Path $cacheDir "omp-init.ps1"
            $ompVersion = (oh-my-posh version)
            $cacheValid = $false
            if (Test-Path $ompCachePath) {
                $cacheContent = Get-Content $ompCachePath -First 1
                if ($cacheContent -eq "# OMP_CACHE_VERSION: $ompVersion") { $cacheValid = $true }
            }
            if (-not $cacheValid) {
                $initScript = oh-my-posh init pwsh --config $localThemePath
                if ($initScript) {
                    "# OMP_CACHE_VERSION: $ompVersion" | Set-Content $ompCachePath -Encoding UTF8
                    $initScript | Add-Content $ompCachePath -Encoding UTF8
                }
                else {
                    Write-Warning "oh-my-posh init produced no output. Cache not written."
                }
            }
            try {
                . $ompCachePath
            }
            catch {
                Remove-Item $ompCachePath -Force -ErrorAction SilentlyContinue
                try {
                    $initScript = oh-my-posh init pwsh --config $localThemePath
                    if ($initScript) {
                        "# OMP_CACHE_VERSION: $ompVersion" | Set-Content $ompCachePath -Encoding UTF8
                        $initScript | Add-Content $ompCachePath -Encoding UTF8
                        . $ompCachePath
                    }
                    else {
                        Write-Warning "oh-my-posh init produced no output."
                    }
                }
                catch {
                    Write-Warning "Failed to initialize oh-my-posh: $_"
                }
            }
        }
    }
    else {
        Write-Warning "oh-my-posh not found. Install it with: winget install JanDeDobbeleer.OhMyPosh"
    }
}

# zoxide initialization (interactive only, cached for fast startup)
if ($isInteractive) {
    if (Get-Command zoxide -ErrorAction SilentlyContinue) {
        $zoxideCachePath = Join-Path $cacheDir "zoxide-init.ps1"
        $zoxideVersion = (zoxide --version) 2>$null
        $cacheValid = $false
        if (Test-Path $zoxideCachePath) {
            $cacheContent = Get-Content $zoxideCachePath -First 1
            if ($cacheContent -eq "# ZOXIDE_CACHE_VERSION: $zoxideVersion") { $cacheValid = $true }
        }
        if (-not $cacheValid) {
            $initScript = (zoxide init --cmd z powershell | Out-String)
            "# ZOXIDE_CACHE_VERSION: $zoxideVersion" | Set-Content $zoxideCachePath -Encoding UTF8
            $initScript | Add-Content $zoxideCachePath -Encoding UTF8
        }
        try {
            . $zoxideCachePath
        }
        catch {
            Remove-Item $zoxideCachePath -Force -ErrorAction SilentlyContinue
            try {
                $initScript = (zoxide init --cmd z powershell | Out-String)
                "# ZOXIDE_CACHE_VERSION: $zoxideVersion" | Set-Content $zoxideCachePath -Encoding UTF8
                $initScript | Add-Content $zoxideCachePath -Encoding UTF8
                . $zoxideCachePath
            }
            catch {
                Write-Warning "Failed to initialize zoxide: $_"
            }
        }
    }
    else {
        Write-Warning "zoxide not found. Install it with: winget install ajeetdsouza.zoxide"
    }
}

# Help Function (PS5-compatible — $PSStyle only exists in PS7.2+)
function Show-Help {
    if ($null -ne $PSStyle) {
        $c = $PSStyle.Foreground.Cyan; $g = $PSStyle.Foreground.Green
        $y = $PSStyle.Foreground.Yellow; $m = $PSStyle.Foreground.Magenta; $r = $PSStyle.Reset
    }
    else {
        $c = ""; $g = ""; $y = ""; $m = ""; $r = ""
    }
    $helpText = @"
${c}PowerShell Profile Help${r}
${y}=======================${r}
${g}Edit-Profile${r} - Opens the current user's profile for editing using the configured editor.
${g}Update-Profile${r} - Syncs profile, theme, caches, and Windows Terminal settings. Requires -ExpectedSha256 or -SkipHashCheck.
${g}Update-PowerShell${r} - Checks for the latest PowerShell release and updates if a new version is available.
${g}Update-Tools${r} - Updates Oh My Posh, eza, and zoxide via winget.

${c}Git Shortcuts${r}
${y}=======================${r}
${g}g${r} - Changes to the GitHub directory.
${g}ga${r} - Shortcut for 'git add .'.
${g}gc${r} <message> - Shortcut for 'git commit -m'.
${g}gcl${r} <repo> - Shortcut for 'git clone'.
${g}gcom${r} <message> - Adds all changes and commits with the specified message.
${g}gpull${r} - Shortcut for 'git pull'.
${g}gpush${r} - Shortcut for 'git push'.
${g}gs${r} - Shortcut for 'git status'.
${g}lazyg${r} <message> - Adds all changes, commits with the specified message, and pushes to the remote repository.

${c}Shortcuts${r}
${y}=======================${r}
${g}Clear-Cache${r} [-IncludeSystemCaches] - Clears user caches; system caches only when explicitly requested.
${g}cpy${r} <text> - Copies the specified text to the clipboard.
${g}icb${r} - Inserts clipboard text into the current prompt buffer (never executes clipboard code).
${g}df${r} - Displays information about volumes.
${g}docs${r} - Changes the current directory to the user's Documents folder.
${g}dtop${r} - Changes the current directory to the user's Desktop folder.
${g}ep${r} - Opens the profile for editing.
${g}export${r} <name> <value> - Sets an environment variable.
${g}ff${r} <name> - Finds files recursively with the specified name.
${g}flushdns${r} - Clears the DNS cache.
${g}grep${r} <regex> [dir] - Searches for a regex pattern in files within the specified directory or from the pipeline input.
${g}hb${r} <file> - Uploads the specified file's content to a hastebin-like service and returns the URL.
${g}head${r} <path> [n] - Displays the first n lines of a file (default 10).
${g}ls${r} - Lists files with icons (eza).
${g}la${r} - Lists all files including hidden with icons (eza).
${g}ll${r} - Lists all files in long format with icons and git status (eza).
${g}lt${r} - Shows directory tree with icons, 2 levels deep (eza).
${g}mkcd${r} <dir> - Creates and changes to a new directory.
${g}nf${r} <name> - Creates a new file with the specified name.
${g}pgrep${r} <name> - Lists processes by name.
${g}pkill${r} <name> - Kills processes by name.
${g}pst${r} - Retrieves text from the clipboard.
${g}pubip${r} - Retrieves the public IP address of the machine.
${g}sed${r} <file> <find> <replace> - Replaces text in a file.
${g}sysinfo${r} - Displays detailed system information.
${g}tail${r} <path> [n] - Displays the last n lines of a file (default 10).
${g}touch${r} <file> - Creates a new empty file or updates timestamp.
${g}unzip${r} <file> - Extracts a zip file to the current directory.
${g}uptime${r} - Displays the system uptime.
${g}which${r} <name> - Shows the path of the command.
${g}winutil${r} - Runs the latest WinUtil full-release script from Chris Titus Tech.
${y}=======================${r}

Use '${m}Show-Help${r}' to display this help message.
Edit '${m}profile_user.ps1${r}' in your profile directory for customizations that survive updates.
"@
    Write-Host $helpText
}

# User overrides (survives Update-Profile)
$userProfile = Join-Path (Split-Path $PROFILE) "profile_user.ps1"
if (Test-Path $userProfile) { . $userProfile }

# Startup complete — show load time
$profileStopwatch.Stop()
if ($isInteractive) {
    Write-Host "Profile loaded in $($profileStopwatch.ElapsedMilliseconds)ms." -ForegroundColor DarkGray
    Write-Host "Use 'Show-Help' to display help" -ForegroundColor Yellow
}
