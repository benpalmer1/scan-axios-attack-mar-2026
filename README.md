# Axios supply-chain attack scanner

> **Note:** This scanning script does not pretend to accommodate all execution environments and scenarios. It was initially developed with local development environments in mind, including IDEs such as VS Code.

This repository contains cross-platform triage scripts for the 30-31 March 2026 axios npm supply-chain compromise, in which a hijacked maintainer account was used to publish poisoned axios releases (`1.14.1` and `0.30.4`) containing a postinstall-based remote access trojan (RAT) dropper via the `plain-crypto-js` dependency.

## Validated attack facts

The scanner logic is based on the official axios disclosure issue and the StepSecurity technical analysis:

- Official disclosure: https://github.com/axios/axios/issues/10604
- StepSecurity write-up: https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
- Compromised axios releases: `1.14.1` and `0.30.4` (published 31 March 2026 via compromised npm credentials, no matching GitHub commit or tag)
- Malicious dependency: `plain-crypto-js@4.2.1` (postinstall hook runs `setup.js`, a cross-platform RAT dropper targeting macOS, Windows, and Linux)
- Attacker accounts: `jasonsaayman` (hijacked maintainer, email changed to `ifstap@proton.me`) and `nrwise` (`nrwise@proton.me`, used to publish `plain-crypto-js`)

Additional validation performed while reviewing these scripts:

- `plain-crypto-js` currently resolves on npm to the security-holder package `0.0.1-security.0`
- safe axios versions `1.14.0` and `0.30.3` are currently available
- compromised package-version endpoints for `axios@1.14.1` and `axios@0.30.4` now return 404, which is consistent with post-incident takedown behavior

## What the current scripts check

The maintained scanners are:

- `scan-axios-attack.sh` for macOS/Linux (Bash; compatible with zsh)
- `scan-axios-attack.ps1` for Windows PowerShell 5.1+

In a deeply unfunny bit of symmetry, the checks are cross-platform too.

They currently check for:

1. installed `axios` copies under `node_modules`
2. references in dependency manifests and lockfiles, including:
   - `package.json`
   - `package-lock.json`
   - `npm-shrinkwrap.json`
   - `yarn.lock`
   - `pnpm-lock.yaml`
   - `bun.lock`
   - `bun.lockb`
3. installed or referenced `plain-crypto-js`
4. package-manager cache evidence in npm, yarn, pnpm, and bun
5. globally installed npm copies of `axios`
6. bundled copies inside common IDE extension directories
7. platform-specific persistence and artifact locations that may indicate post-install malware activity

## Important behavior notes

- These scripts are intended as **incident-response triage helpers**, not as definitive forensic proof.
- A hit in a lockfile or cache can indicate prior exposure even if the malicious package no longer exists on disk.
- The npm cache logic intentionally distinguishes between cached registry metadata and cached tarball/index entries to reduce false positives.
- The scripts now include explicit support for Bun lockfiles and Bun cache locations.

## Known limitations

- The default search roots are broad (`/` on Unix-like systems and the system drive on Windows), so large scans can take time.
- Some checks are heuristic by design, especially the artifact and persistence sweeps.
- A clean result should not be treated as a guarantee that no malicious postinstall behavior executed in the past.
- `older version/scan-windows.ps1` is kept as a legacy reference only; prefer `scan-axios-attack.ps1`.

## Recommended usage

Run the scanner from a trusted shell and, if possible, scope it to the project or home directory you want to inspect.

The Unix scanner uses a Bash shebang and is also kept compatible with zsh, so any of the following are valid:

Examples:

```bash
./scan-axios-attack.sh "$HOME"
```

```bash
bash ./scan-axios-attack.sh "$HOME"
```

```bash
zsh ./scan-axios-attack.sh "$HOME"
```

```powershell
.\scan-axios-attack.ps1 -SearchRoot "$env:USERPROFILE"
```

If a compromised version or `plain-crypto-js` is found, remove affected installs, delete lockfiles, reinstall from a safe version, clear caches, and rotate credentials that may have been exposed on the machine.
