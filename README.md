# SDS Rapid Check: PyPI Cred Stealer (November 2026)

Checks Python folders for published indicators of the agent-framework credential stealer.

**Who this is for.** Python developers, IT admins and MSP technicians investigating a workstation or build runner. You need terminal access and permission to read its Python environments. If someone manages your laptop for you, send them this check.

## Before you run it

Use a Python 3.8+ interpreter from a source you trust. A suspicious project's virtual environment can stay inactive: the check reads its files using the interpreter you choose. The uppercase flags matter: `-I` isolates startup, `-B` prevents bytecode writes, and `-S` skips the startup step that would normally execute package hooks.

If you suspect the interpreter or host itself has been altered, use a separate trusted machine and inspect a read-only copy or mounted image of the suspect files. A new virtual environment on the suspect host uses its underlying Python. The release checksum verifies the downloaded script against the published digest; it cannot establish trust in the machine running it. [Read the v0.1.0 script](https://github.com/SecureDataSolutions/sds-rapid-check-pypi-cred-stealer/blob/v0.1.0/pth_check.py).

## How to run

**macOS and Linux.** From a shell where `python3` resolves to your trusted interpreter, paste the whole block. It keeps both downloads in a dedicated **PyPI Checks** folder and runs the check after checksum verification. This first pass covers the package directories associated with that interpreter, including its existing user package directory.

```sh
mkdir -p "$HOME/PyPI Checks" && cd "$HOME/PyPI Checks" && base='https://github.com/SecureDataSolutions/sds-rapid-check-pypi-cred-stealer/releases/download/v0.1.0' &&
curl -fsSLo pth_check.py "$base/pth_check.py" &&
curl -fsSLo SHA256SUMS "$base/SHA256SUMS" &&
if command -v sha256sum >/dev/null; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi && python3 -I -B -S pth_check.py
```

**Windows (PowerShell).** Use this block when `py -3` selects a trusted interpreter. If you have a designated interpreter, use its full path with PowerShell's call operator (`&`) in the final command.

```powershell
& {
$ErrorActionPreference = 'Stop'
$checkDir = Join-Path $HOME 'PyPI Checks'
New-Item -ItemType Directory -Force -Path $checkDir | Out-Null
Set-Location -LiteralPath $checkDir
$base = 'https://github.com/SecureDataSolutions/sds-rapid-check-pypi-cred-stealer/releases/download/v0.1.0'
Invoke-WebRequest "$base/pth_check.py" -OutFile .\pth_check.py
Invoke-WebRequest "$base/SHA256SUMS" -OutFile .\SHA256SUMS
$entries = @(Get-Content .\SHA256SUMS | Where-Object { $_ -match '^([0-9a-fA-F]{64})  pth_check\.py$' })
if ($entries.Count -ne 1) { throw 'Expected one SHA-256 entry for pth_check.py' }
$expected = $entries[0].Substring(0, 64).ToLowerInvariant()
$actual = (Get-FileHash .\pth_check.py -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'pth_check.py SHA-256 verification failed' }
py -3 -I -B -S .\pth_check.py
}
```

## Find and check other environments

A machine can have dozens of Python environments. You only need one trusted interpreter to inspect them. The folder containing the downloaded script is independent of the folders you ask it to inspect.

1. **Locate installations and environments.** On macOS/Linux, `type -a python3` lists candidates on your shell path. On Windows, `where.exe python` lists path matches and `py -0p` lists runtimes known to the launcher where supported. Include environments outside the shell path: project-local virtual environments, pyenv versions, Conda environments, and CI workspace or runner directories. Use `conda env list` if your Conda installation is trusted.
2. **Look on disk without starting the discovered interpreters.** For example, from a macOS/Linux project directory, run `find . -type f -name pyvenv.cfg -print`. On Windows, use `Get-ChildItem -Path . -Recurse -Force -Filter pyvenv.cfg -File` from the project directory. These markers identify standard virtual environments within that tree. Check other users, volumes, containers and build runners separately where authorized.
3. **Pass the actual roots.** From **PyPI Checks**, append one or more paths to the verified command. For example, if your projects live in `~/projects`, run `python3 -I -B -S pth_check.py "$HOME/projects"`. On Windows, if your environments live under `D:\envs`, run `py -3 -I -B -S .\pth_check.py 'D:\envs'`. Use the actual environment directories for Conda to avoid counting cached packages. The check looks for package directories, supported lock files and wheels under the paths supplied.
4. **Account for coverage.** Record the roots you supplied and any unreadable or unavailable paths. The summary counts package directories, not distinct interpreters. For a mounted image, distinguish findings on the mounted paths from the analysis machine's own package directories, which the script also includes.

## Read the result

- **`!!`** flags a known indicator. The path and message distinguish an installed file or version from a downloaded wheel or a dependency pin.
- **`hook:`** lists executable startup lines for review. Legitimate packages use these too.
- **`Scan incomplete`** identifies a coverage gap. Review the reported errors even when the flagged count is zero.
- **Zero flagged** means the check found none of its published indicators in the files it could examine.

## About SDS

**Security, AI & Systems Engineering**

Secure Data Solutions helps businesses strengthen their security and put AI to work. We engineer the systems and workflows that reduce repetitive work, help teams understand and respond to threats, and turn security findings into verified improvements.

We publish SDS Rapid Checks as free, focused tools to help the community investigate specific risks and understand what needs attention. Each check states what it looks for, how to run it, and what its results can and cannot tell you.

[Discuss your project](https://sdsitgroup.com/contact) · [Explore our services](https://sdsitgroup.com/services/)

Ran this and found something, or not sure what you're looking at? [Contact us](https://sdsitgroup.com/contact). We're happy to talk it through, and when it's urgent, we pick up.

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
