# SDS Rapid Check: PyPI Cred Stealer (November 2026)

Checks Python folders for published indicators of the agent-framework credential stealer.

## About SDS

**Security, AI & Systems Engineering**

Secure Data Solutions helps businesses strengthen their security and put AI to work. We engineer the systems and workflows that reduce repetitive work, help teams understand and respond to threats, and turn security findings into verified improvements.

We publish SDS Rapid Checks as free, focused tools to help the community investigate specific risks and understand what needs attention. Each check states what it looks for, how to run it, and what its results can and cannot tell you.

[Discuss your project](https://sdsitgroup.com/contact) · [Explore our services](https://sdsitgroup.com/services/)

Ran this and found something, or not sure what you're looking at? [Contact us](https://sdsitgroup.com/contact). We're happy to talk it through, and when it's urgent, we pick up.

Read the script first. [pth_check.py](pth_check.py)

Requires Python 3.8 or later. Use a trusted Python installation. Keep `-I -B -S` in the command so Python ignores user startup settings, does not write bytecode, and does not run `.pth` hooks before the check.

## How to run

The script always scans the site-packages of the Python that runs it, then walks only the additional folders you name. Pass `.` to walk the current folder; omit directory arguments to check only this Python's site-packages. It stops at each `site-packages` or `dist-packages` folder it finds, and skips only `.git` and `node_modules`. If you run it from `~/.ssh` and pass `.`, it only walks that folder — not your whole home directory.

### 1. Go to your home folder

```sh
cd ~
```

Do this first for two reasons: the script and checksum file are downloaded into the current directory, and the folders you name are what it walks. Running from your home folder, then passing `$HOME`, checks your home directory even if you later change directories.

### 2. Download the script and the checksum file

```sh
base='https://github.com/SecureDataSolutions/sds-rapid-check-pypi-cred-stealer/releases/latest/download'
curl -fsSLo pth_check.py "$base/pth_check.py"
curl -fsSLo SHA256SUMS "$base/SHA256SUMS"
```

If you skip this step, Python will fail with `can't open file '.../pth_check.py'`.

### 3. Verify the SHA-256 before you run anything

We publish a SHA-256 checksum for `pth_check.py` in `SHA256SUMS`. The next command matches the file you downloaded against that published checksum.

On macOS:

```sh
shasum -a 256 -c SHA256SUMS
```

On Linux:

```sh
sha256sum -c SHA256SUMS
```

It must print `pth_check.py: OK`. In the copy-paste command below, `&&` means the script never runs if the checksum does not match. Do not skip this step, and do not run the script if verification fails.

### 4. Run the check

```sh
python3 -I -B -S pth_check.py "$HOME"
```

What the flags do:

- `-I` isolates Python from user site packages and environment settings that could change startup.
- `-B` stops Python from writing `.pyc` bytecode files.
- `-S` skips the `site` module so `.pth` hooks do not run before the check.

You can name more folders if Python environments live outside your home directory, for example a Homebrew prefix, conda environment directories, or `/usr/local`:

```sh
python3 -I -B -S pth_check.py "$HOME" /opt/homebrew /usr/local
```

Do not pass a whole conda or Anaconda root. The `pkgs/` cache will inflate the counts. Pass the `envs` directory, or individual environment folders, instead.

### 5. How long it takes

Runtime depends on the number of folders and files, permissions, and storage speed. Cloud or phone mounts can make it slower. Start with the specific folders you need to check.

### 6. How to read the output

- `hook:` lines are `.pth` files with executable lines. Most are normal (setuptools, virtualenv, editable installs). The script lists them for review; a hook line is not a finding by itself.
- `!!` lines are flagged findings: a published indicator of the bad releases. Those need attention.
- The summary reports how many site-packages folders, `.pth` files, and lock or requirements files were checked, and how many were flagged (`Flagged (!!):`).
- `Scan incomplete: N read or parse error(s)` means the script could not read some paths. That is common with cloud and phone mounts (for example macOS `~/Library/CloudStorage/`, including phone mounts such as MacDroid) and with folders that return "Permission denied." Those errors are not findings. You can ignore errors from mounts you did not intend to scan, or rerun and name only the folders you want so those mounts are left out.

### 7. Copy-paste command (macOS and Linux)

This is a single line. It changes to your home folder, downloads both files, verifies the checksum, and only then runs the check. If verification does not print `pth_check.py: OK`, the script does not run.

macOS:

```sh
cd ~ && base='https://github.com/SecureDataSolutions/sds-rapid-check-pypi-cred-stealer/releases/latest/download' && curl -fsSLo pth_check.py "$base/pth_check.py" && curl -fsSLo SHA256SUMS "$base/SHA256SUMS" && shasum -a 256 -c SHA256SUMS && python3 -I -B -S pth_check.py "$HOME"
```

Linux:

```sh
cd ~ && base='https://github.com/SecureDataSolutions/sds-rapid-check-pypi-cred-stealer/releases/latest/download' && curl -fsSLo pth_check.py "$base/pth_check.py" && curl -fsSLo SHA256SUMS "$base/SHA256SUMS" && sha256sum -c SHA256SUMS && python3 -I -B -S pth_check.py "$HOME"
```

## Windows (PowerShell)

The same rules apply: download both files, verify the published SHA-256, and only then run the script. If the checksum does not match, the commands below throw an error and the script never runs.

```powershell
& {
$ErrorActionPreference = 'Stop'
Set-Location $HOME
$base = 'https://github.com/SecureDataSolutions/sds-rapid-check-pypi-cred-stealer/releases/latest/download'
Invoke-WebRequest "$base/pth_check.py" -OutFile .\pth_check.py
Invoke-WebRequest "$base/SHA256SUMS" -OutFile .\SHA256SUMS
$entries = @(Get-Content .\SHA256SUMS | Where-Object { $_ -match '^([0-9a-fA-F]{64})  pth_check\.py$' })
if ($entries.Count -ne 1) { throw 'Expected one SHA-256 entry for pth_check.py' }
$expected = $entries[0].Substring(0, 64).ToLowerInvariant()
$actual = (Get-FileHash .\pth_check.py -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'pth_check.py SHA-256 verification failed' }
  py -3 -I -B -S .\pth_check.py $HOME
}
```

To check only this Python's site-packages, omit the directory argument. You can also name additional folders after `$HOME`.

## What a result means

The check looks for published file names and fingerprints, affected package versions, wheel fingerprints, and supported lock-file pins. It lists executable `.pth` lines for review. The indicators cover known files and versions, so they cannot establish that a system is clean.

No finding is not proof of no compromise.

## Sources

- [GitHub advisory GHSA-764m-3ppc-5m73](https://github.com/advisories/GHSA-764m-3ppc-5m73)
- [PyPI release history](https://pypi.org/project/agent-framework/#history)
- [Wiz analysis](https://wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi)
- [The Register report](https://www.theregister.com/security/2026/11/18/microsofts-official-python-agent-framework-hijacked-to-distribute-malware/5310858)
- [JFrog analysis](https://research.jfrog.com/post/agent-framework-hijack/)

## Want the full check?

The AI Coding Tool Check covers up to five developer machines and one build pipeline. The fixed price is $1,250 for the first three teams.

[Discuss your project](https://sdsitgroup.com/contact) · [All services and pricing](https://sdsitgroup.com/services/)

Run only on systems you own or are authorized to check. Licensed under the MIT License.
