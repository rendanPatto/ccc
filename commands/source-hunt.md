---
description: Scan a GitHub public repo or local repo path for leaked secrets, risky config files, and GitHub Actions / CI patterns. Usage: /source-hunt target.com --repo-url https://github.com/org/repo [--allow-large-repo]
---

# /source-hunt

Scan source repositories for high-signal leak exposure.

## Usage

```bash
/source-hunt target.com --repo-url https://github.com/org/repo
/source-hunt target.com --repo-path /path/to/local/repo
/source-hunt target.com --repo-url https://github.com/org/repo --allow-large-repo
```

## What This Does

1. Probes GitHub public repos before clone
2. Requires confirmation when the repo exceeds configured size or file-count thresholds
3. Runs builtin secret/config rules
4. Runs GitHub Actions / CI risk checks
5. Writes results to `findings/<target>/exposure/`
