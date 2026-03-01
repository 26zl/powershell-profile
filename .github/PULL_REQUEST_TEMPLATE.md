# Pull Request

## Summary

<!-- Brief description of what this PR does -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Configuration change
- [ ] Documentation

## Checklist

- [ ] PSScriptAnalyzer passes with no warnings or errors
- [ ] Tested on PowerShell 5.1 (if script behavior changed)
- [ ] Tested on PowerShell 7+ (if script behavior changed)
- [ ] No hardcoded user paths (`C:\Users\`, `/home/`)
- [ ] No embedded secrets or tokens
- [ ] No em dashes or non-ASCII characters in source files
- [ ] UTF-8 without BOM for all file writes (`[System.IO.File]::WriteAllText()`)
