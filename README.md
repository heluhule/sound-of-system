# The sound of System

A standard user plays a sound on Windows 11 and ends up as `NT AUTHORITY\SYSTEM` - no memory corruption, no admin, no reboot. Four reasonable assumptions, stacked into one standard-user to SYSTEM elevation-of-privilege chain.

This repository contains the write-up for that chain, as a single self-contained HTML page with an embedded proof-of-concept recording.

## Read it

Open [`play-music-with-system.html`](play-music-with-system.html) in any modern browser. Everything - text, diagrams, and the PoC clip - is inlined in the one file; nothing else to download.

## The chain, in one line

An unsigned MSIX codec package rides past the AppX content check, Windows' audio engine (`audiodg`) loads the attacker DLL with no signature check as `LOCAL SERVICE`, and a Microsoft-shipped service DACL hands that account the last step up to SYSTEM.

## CVEs

Two advisories came out of this chain. Microsoft's update guide carries the authoritative detail and the affected builds.

- [CVE-2026-97799](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-97799)
- [CVE-2026-116714](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-116714)

## Disclosure timeline

| Date | Event |
| --- | --- |
| 30 Sep 2026 | Reported to the Microsoft Security Response Center with a self-contained PoC |
| 05 Oct 2026 | Behavior confirmed by MSRC |
| 13 Oct 2026 | First fix shipped as CVE-2026-97799 |
| 10 Nov 2026 | Second fix shipped as CVE-2026-116714 |

Thanks to the Microsoft Security Response Center for the fast, professional response.

## Note

Coordinated-disclosure research. Both issues are fixed. Published for authorized testing and defensive understanding only.
