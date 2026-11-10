# PoC source

Source for the standard-user to SYSTEM chain described in the write-up. **Source only** - the
compiled binaries and the packaged MSIX are intentionally not published. Both underlying issues
are fixed (CVE-2026-97799, CVE-2026-116714); this is here to make the research reproducible for
defenders and researchers, not to ship a turnkey exploit.

## Files

| File | Role |
| --- | --- |
| `aio_za_v3.cpp` | all-in-one driver: registers the codec package, forges the endpoint selection, forces the audiodg rebuild, then the LOCAL SERVICE to SYSTEM step |
| `proof_poc.cpp` | the spatial-audio codec DLL that audiodg loads (its `DllMain` is the code-exec point) |
| `syslaunch.c` | relocates the SYSTEM token onto the console session for a visible shell |
| `aio_za.rc` | resource script |
| `pkg/AppxManifest.xml` | the `windows.mediaCodec` manifest declaring the codec via `wincap3:Path` |
| `repack_msix.ps1` | builds the MSIX from `pkg/` + the compiled codec DLL |
| `run_busy_test.ps1` | helper to check for a fresh (uncached) audiodg before a run |
| `music.wav` | the sound that triggers the render graph |

## Build (outline)

The compiled payloads and the `.msix` are not provided; build them yourself:

1. Compile `proof_poc.cpp` to `proof.dll` (the codec).
2. Compile `syslaunch.c` to `syslaunch.exe`.
3. Compile `aio_za_v3.cpp` (with `aio_za.rc`) to the driver executable.
4. Run `repack_msix.ps1` to package `pkg/AppxManifest.xml` + `proof.dll` into the codec MSIX.

Exact toolchain/flags are left to the reader; see the write-up for the mechanism.

## Scope

Lab-only, on a machine you own, against the pre-patch builds. For authorized testing and
defensive understanding only.
