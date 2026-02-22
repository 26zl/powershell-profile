# PowerShell Profile

[![PSScriptAnalyzer](https://github.com/26zl/powershell-profile/actions/workflows/lint.yml/badge.svg)](https://github.com/26zl/powershell-profile/actions/workflows/lint.yml)

A PowerShell profile with Oh My Posh theming, Unix-like aliases, git shortcuts, and useful utilities. Originally inspired by [ChrisTitusTech/powershell-profile](https://github.com/ChrisTitusTech/powershell-profile).

## Quick Install

Run this in an **elevated** PowerShell window:

```powershell
irm "https://github.com/26zl/powershell-profile/raw/main/setup.ps1" | iex
```

This installs fonts, Oh My Posh, zoxide, eza, configures Windows Terminal, and copies the profile into place (both PS5 and PS7). Restart your terminal after running.

### Manual Setup

If you prefer to clone the repo first:

```powershell
git clone https://github.com/26zl/powershell-profile.git
cd powershell-profile
.\setup.ps1
.\setprofile.ps1
```

#### Terminal Customization (manual setup only)

When running `setup.ps1` locally you can override Windows Terminal defaults:

```powershell
.\setup.ps1 -Opacity 85 -ColorScheme "One Half Dark" -FontSize 12
```

| Parameter | Default | Description |
| --- | --- | --- |
| `-Opacity` | `75` | Background opacity (0–100) |
| `-ColorScheme` | from `profile-config.json` | Color scheme name |
| `-FontSize` | `11` | Font size in points |

These parameters are not available with the `irm | iex` one-liner.

## What's Included

- **Oh My Posh** theming with Nerd Font support (theme configured via `profile-config.json`)
- **eza** modern ls replacement with icons, colors, and git status (`ls`, `la`, `ll`, `lt`)
- **zoxide** for fast directory navigation (`z`)
- **Unix-like commands**: `touch`, `grep`, `which`, `head`, `tail`, `sed`, `pkill`, `pgrep`, `export`
- **Git shortcuts**: `gs`, `ga`, `gc`, `gpush`, `gpull`, `gcom`, `lazyg`
- **Utilities**: `pubip`, `uptime`, `sysinfo`, `flushdns`, `hb`, `winutil`, `Clear-Cache`, `trash`
- **PSReadLine** enhancements with pastel colors, history search, and tab completion
- **Windows Terminal** auto-configuration (Nerd Font, color scheme from `profile-config.json`, acrylic)
- **Sandbox-safe**: non-interactive sessions (CI, AI agents, SSH/SCP) skip network calls and theme loading

Run `Show-Help` in your terminal to see all available commands.

## Manual Updates

```powershell
Update-Profile      # Sync profile, theme, caches, and Windows Terminal settings
Update-PowerShell   # Check for new PowerShell releases
Update-Tools        # Update Oh My Posh, eza, and zoxide
```

`Update-Profile` requires hash verification by default — it shows the downloaded hash and asks you to confirm with `-ExpectedSha256 '<hash>'`, or use `-SkipHashCheck` to bypass.

## Customization

Add your personal customizations to `profile_user.ps1` in the same directory as your profile (run `Split-Path $PROFILE` to find it). `setup.ps1` creates a starter file with commented-out examples — just uncomment or add your own:

```powershell
# Custom aliases
Set-Alias -Name myalias -Value Get-ChildItem

# Override PSReadLine colors
Set-PSReadLineOption -Colors @{ Command = '#61AFEF' }

# Import additional modules
Import-Module posh-git
```

This file is dot-sourced at the end of the main profile, so your settings always win. `Update-Profile` never touches `profile_user.ps1`.

You can also edit the main profile directly:

```powershell
Edit-Profile   # opens $PROFILE
```

## Windows Ransomware Protection

Cache files (Oh My Posh theme, init scripts) are stored in `%LOCALAPPDATA%\PowerShellProfile\` to avoid conflicts with Controlled Folder Access.

However, the profile file itself (`$PROFILE`) lives in `Documents\PowerShell\` which **is** protected. If `setup.ps1` or `Update-Profile` fails with access denied errors, whitelist PowerShell (run as admin):

```powershell
# PowerShell 7
Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Program Files\PowerShell\7\pwsh.exe"
# Windows PowerShell 5.1 (if you run setup.ps1 from there)
Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
```

## Keyboard Shortcuts

Keybindings configured via PSReadLine:

| Key | Action |
| ----- | -------- |
| `Up` / `Down` | Search history matching current input |
| `Tab` | Menu-style tab completion |
| `Ctrl+D` | Delete character |
| `Ctrl+W` | Delete word backwards |
| `Alt+D` | Delete word forwards |
| `Ctrl+Left` / `Ctrl+Right` | Jump word backwards / forwards |
| `Ctrl+Z` / `Ctrl+Y` | Undo / Redo |
| `Alt+V` | Smart paste — inserts clipboard into prompt without executing |

## Command Reference

### Profile & Updates

| Command | Description |
| --------- | ------------- |
| `Edit-Profile` / `ep` | Open the profile in your editor |
| `Update-Profile` | Sync profile, theme, caches, and WT settings (requires `-ExpectedSha256` or `-SkipHashCheck`) |
| `Update-PowerShell` | Check for new PowerShell releases |
| `Update-Tools` | Update Oh My Posh, eza, and zoxide via winget |
| `Show-Help` | Show all commands in the terminal |

### Git Shortcuts

| Command | Description |
| --------- | ------------- |
| `gs` | `git status` |
| `ga` | `git add .` |
| `gc <msg>` | `git commit -m "<msg>"` |
| `gpush` / `gpull` | `git push` / `git pull` |
| `gcl <repo>` | `git clone` |
| `gcom <msg>` | `git add .` + `git commit -m` |
| `lazyg <msg>` | add + commit + push in one go |
| `g` | `z github` (zoxide jump to github dir) |

### Unix-like Utilities

| Command | Description |
| --------- | ------------- |
| `touch <file>` | Create file or update timestamp |
| `grep <regex> [dir]` | Search for pattern in files |
| `which <cmd>` | Show command path |
| `head <path> [n]` | First *n* lines (default 10) |
| `tail <path> [n] [-f]` | Last *n* lines, optional follow |
| `sed <file> <find> <replace>` | Find and replace in file |
| `pkill` / `pgrep <name>` | Kill / list processes by name |
| `export <name> <value>` | Set environment variable |

### File & Directory

| Command | Description |
| --------- | ------------- |
| `ls` / `la` / `ll` / `lt` | eza listings (icons, hidden, long, tree) |
| `ff <name>` | Find files recursively |
| `nf <name>` | Create new file |
| `mkcd <dir>` | Create directory and cd into it |
| `trash <path>` | Move to Recycle Bin |
| `unzip <file>` | Extract zip to current directory |
| `docs` / `dtop` | Jump to Documents / Desktop |

### System & Network

| Command | Description |
| --------- | ------------- |
| `pubip` | Show public IP |
| `uptime` | System uptime |
| `sysinfo` | Detailed system info |
| `df` | Disk volumes |
| `flushdns` | Clear DNS cache |
| `Clear-Cache` | Clear user temp/cache (`-IncludeSystemCaches` for system dirs) |
| `admin` / `su` | Open elevated terminal |
| `winutil` | Launch Chris Titus WinUtil |
| `hb <file>` | Upload file to hastebin, copy URL |

### Clipboard

| Command | Description |
| --------- | ------------- |
| `cpy <text>` | Copy to clipboard |
| `pst` | Paste from clipboard |
| `icb` | Insert clipboard text into prompt (never executes) |
