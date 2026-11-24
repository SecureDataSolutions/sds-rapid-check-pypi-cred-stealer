# SDS Rapid Check: PyPI Cred Stealer (November 2026)

Checks Python folders for published indicators of the agent-framework credential stealer.

Read the script first. [pth_check.py](pth_check.py)

Requires Python 3.8 or later. Use a trusted Python installation. Keep `-I -B -S` in the command so Python ignores user startup settings, does not write bytecode, and does not run `.pth` hooks before the check.

## macOS

```sh
base='https://github.com/SecureDataSolutions/sds-rapid-check-pypi-cred-stealer/releases/latest/download'
curl -fsSLo pth_check.py "$base/pth_check.py" &&
curl -fsSLo SHA256SUMS "$base/SHA256SUMS" &&
shasum -a 256 -c SHA256SUMS &&
python3 -I -B -S pth_check.py .
```

Replace `.` with the directories you want checked. To check only this Python's site-packages, omit the directory argument.

## Linux

```sh
base='https://github.com/SecureDataSolutions/sds-rapid-check-pypi-cred-stealer/releases/latest/download'
curl -fsSLo pth_check.py "$base/pth_check.py" &&
curl -fsSLo SHA256SUMS "$base/SHA256SUMS" &&
sha256sum -c SHA256SUMS &&
python3 -I -B -S pth_check.py .
```

Replace `.` with the directories you want checked. To check only this Python's site-packages, omit the directory argument.

## Windows (PowerShell)

```powershell
& {
$ErrorActionPreference = 'Stop'
$base = 'https://github.com/SecureDataSolutions/sds-rapid-check-pypi-cred-stealer/releases/latest/download'
Invoke-WebRequest "$base/pth_check.py" -OutFile .\pth_check.py
Invoke-WebRequest "$base/SHA256SUMS" -OutFile .\SHA256SUMS
$entries = @(Get-Content .\SHA256SUMS | Where-Object { $_ -match '^([0-9a-fA-F]{64})  pth_check\.py$' })
if ($entries.Count -ne 1) { throw 'Expected one SHA-256 entry for pth_check.py' }
$expected = $entries[0].Substring(0, 64).ToLowerInvariant()
$actual = (Get-FileHash .\pth_check.py -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'pth_check.py SHA-256 verification failed' }
  py -3 -I -B -S .\pth_check.py .
}
```

Replace `.` with the directories you want checked. To check only this Python's site-packages, omit the directory argument.

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

[Contact form](https://sdsitgroup.com/contact) · [Services](https://sdsitgroup.com/#services)

Run only on systems you own or are authorized to check. Licensed under the MIT License.
