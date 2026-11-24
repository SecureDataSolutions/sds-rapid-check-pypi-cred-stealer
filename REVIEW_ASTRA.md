# Pre-public security review

**Verdict — SHIP.** An unreadable fingerprint candidate could produce a successful exit. Local fix `da8ca0e84da7d9c3fe53eb282831457ff20d336c` reports the read error and marks the scan incomplete. The review started at `185575a5ebaf9652ee8aa7f66c4751cb43b08183`.

| Check | Evidence |
| --- | --- |
| Files and history | Inspected the working files, workflow token references, Git blobs and commit metadata. Found no embedded credential, internal hostname or IP, workstation path, or workstation email. Commit identities use GitHub noreply addresses. |
| Offline scan | The scanner walks local directories and reads package metadata, lock files, wheels and startup hooks. An isolated CLI test on local fixtures observed zero Python socket, URL-request or subprocess events. The scanner listed a fixture hook without executing it. |
| Error handling | Before the fix, a read-denied package initializer returned exit 0. After the fix the same fixture returned 2 and reported one read error. Separate runs returned 0 for a readable benign fixture and 1 for a flagged version pin. |
| Checksums | Regenerated `SHA256SUMS` in the fix commit. `shasum -a 256 -c SHA256SUMS` passed for `pth_check.py`. |
| README | The documented `-I -B -S` are interpreter options. The scanner takes optional positional directory roots and has no `--file` option. The download commands precede the local scan. |
| Reporting and license | `SECURITY.md` directs sensitive reports to GitHub private vulnerability reporting and contains no personal email. The MIT license is present. |

This review used local files and Git objects. The release download links and availability of the hosted reporting form were outside the local checks. Signed tags were intentionally omitted.
