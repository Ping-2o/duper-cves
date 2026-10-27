# iOS 27.2 Fix-Diff Map — CVE localization from Apple's own patches (iPhone17,5)

> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This repository was produced 100% by autonomous
> AI agents (no human authoring — expect slop; re-verify before trusting anything). It exists
> solely for authorized security research and coordinated disclosure, on hardware the project
> owner owns. Every claim cites a checkable artifact (function, vmaddr, both-build disassembly
> receipt, refusal string); nothing here is a weapon. PoC artifacts are deliberately **not**
> committed.

## What this is

When Apple ships a security release, the *diff itself* is a map of admitted bugs: every check
Apple ADDED between the vulnerable and fixed build marks a bug that was LIVE in the vulnerable
build. This repository is the result of sweeping the **iOS 27.0 RC → 27.2 RC** window
(builds **24A435 → 24B115**, iPhone17,5) for the "easy-achievement" (app-reachable,
file-parser) CVE lines of Apple's advisory
[149230 — About the security content of iOS 27.2](https://support.apple.com/en-us/149230)
(released 2026-10-26), using that principle.

Four parallel agent sweeps, one per component group. Each group folder contains the full
fix-site localization: **what the check is, where it landed (vmaddr), what the vulnerable build
did instead (both-side disassembly receipts), and how the missing check is tripped (craft
recipe — field, seed format, public API)**.

**Headline score: 32 of 34 Tier-1 advisory CVE lines localized (~29 PROVEN at instruction
level with both-side receipts, 3 shape-matched, 2 honest negatives recorded as negatives).**
All of these bugs are live on any device still running iOS 27.0 / 27.0.1.

## The board

| Group | CVEs covered | Result |
|---|---|---|
| [`01_imageio/`](01_imageio/) | 112633, 112614, 112634, 112629, 112561, 112627, 112632, 112630, 112571, 112488, 112625 (11) | All 11 mapped to 9 fix families. PROVEN: TIFF planar/tile scatter OOB write (no capacity compare vs destination row); libTIFF dir-entry 32-bit truncated alloc (`lsl w0,count,#k`) → heap smash; PDF rasterize width×bpp gate; JPEG markerLength warn→abort; `_APPx::writeToStream` unclamped (offset,length) → leak bytes land in the emitted JPEG; GPS-IFD rewrite bounds; DDS/BC/KTX/ASTC texture gates; APNG fcTL unchecked short read; TIFF zero-fill / ReadUserComment uninit-output trio |
| [`02_image_libarchive/`](02_image_libarchive/) | 112522, 112621, 86971, 86988 (4) | 3 PROVEN: libarchive ISO9660-Joliet pathname OOB write past a 1024B heap buffer (+ CAB-LZX history bug; **the Joliet OOB was additionally fired live on the macOS 27.0 twin under lldb** — receipt in FINDINGS.md); LinkPresentation `encodeNextFrame` frame-dimension gate (Messages link-preview re-encoder); vImage Deepmap2 `w*h*6+h` unchecked alloc + indexed-colorspace table bounds. **86988 honestly NOT localized**: ColorSync's ICC parse path is byte-identical between builds; the fix lives in the ImageIO/CoreGraphics ICC pipeline |
| [`03_audio/`](03_audio/) | 112546, 113912, 113907, 86972, 86969 (5) | 4 localized: `ImmersiveRendererDataMarshaller::Deserialize` wire-controlled count/size with no destination bound (CoreAudio buffer overflow; craftable blobs — no seed file needed); HOA decoder `mNumHOAcoeffs` up to 121 vs a 37-entry array (OOB read; Apple's own 24B115 error string names the bound); MPEG-D DRC downmix-matrix coefficient-count gate; AVHaptic XPC ASBD/frame-count gate. **86969 ("corrupt kernel memory") honestly NOT localized**: audio kexts diffed clean across builds |
| [`04_font_model3d/`](04_font_model3d/) | 112683, 86970, 112642, 112656, 112565, 112449, 112413, 112485, 112461, 112486, 112425, 112423, 112464, 86991 (14) | All 14 mapped. PROVEN: FontParser scan-scratch 32-bit mul + sign-extended pointer (OOB write) + charstring Push/Pop stack guards; CoreText GDEF caret offset-chase clamp; **Model I/O's fix carrier is libusd_ms 24.1.30→24.1.32** (64-bit checked image allocs, Ptex log2/page guards, USDA nesting cap, SdfZipFile size checks) — ModelIO.dylib itself carries no fix; SceneKit fixed-size plist type-inits shared one 4-float stack slot (vec3/vec4 literally the same address) + primitive-range sign checks |

Per-group detail — including every vmaddr, both-side disassembly, trigger APIs, expected
crash-vs-refusal A/B behavior, and the craft recipes — is in each group's `FINDINGS.md`.

## What is deliberately NOT in this repo

This repo ships **analysis only**: this README and the four group `FINDINGS.md` documents.
The underlying research tree additionally contains — and does NOT publish:

- **PoC artifacts (`seeds/` in each group).** The actual crafted crash-trigger files. The
  craft recipes to regenerate each one live in `FINDINGS.md` — nothing committed is a
  ready-to-fire exploit input.
- **Raw disassembly receipt files and `receipts/` folders** — both-build instruction dumps
  derived from Apple's binaries (the decisive excerpts are quoted inline in `FINDINGS.md`).
- **Tooling scripts, symbol dumps, compiled test oracles, and on-device probe-row specs
  (`HARNESS_ROW.md`)** — research-internal.
- **Apple firmware binaries (`extracted/`)** — too large and not ours to redistribute.

## Repo layout

```
README.md              this file
01_imageio/FINDINGS.md    11 CVE lines — ImageIO fix families + craft recipes + census
02_image_libarchive/FINDINGS.md   112522 / 112621 / 86971 PROVEN, 86988 honest negative
03_audio/FINDINGS.md     5 CVE lines — audio stack + the honest 86969 negative
04_font_model3d/FINDINGS.md   14 CVE lines — fonts, CoreText, libusd_ms, SceneKit
```

## Method (so you can verify any claim)

1. Obtain the two iPhone17,5 builds: iOS 27.0 RC (24A435) and iOS 27.2 RC (24B115).
2. The vulnerable-side dylibs/kexts are in each device's dyld shared cache; both are
   extractable with [ipsw](https://github.com/blacktop/ipsw):
   ```
   ipsw dyld info  <dsc> --dylibs | grep -i <component>     # locate + version oracle
   ipsw dyld extract <dsc> <FULL install path> -o out/       # extract per build
   ipsw macho disass <dylib> --vaddr <vm> --count N          # targeted disassembly
   ```
3. For any fix site claimed in a FINDINGS.md: disassemble both builds at the given vmaddr
   (vulnerable = the unchecked op sequence, fixed = the added gate + refusal string), or
   simply string-grep the fixed dylib for the named refusal message (present in 24B115,
   absent in 24A435 — every headline receipt in this repo was spot-checked that way).
4. Tripping the missing check on a vulnerable device produces the crash; the fixed build
   refuses with the new error string. That pair — not a crash alone — is a proven live bug.

## The credit engine — unfixed sibling candidates (new bugs, ours to report)

The same diffs also expose checks Apple did **not** add around the parsed fields it just fixed.
The strongest candidates for new, creditable reports (all recorded in the group FINDINGS.md):

1. **libarchive RockRidge relocation-cycle infinite loop** — upstream fixed it
   (`d14de384fcc6`, Sept 2026); Apple did NOT take the commit → believed live on iOS 27.0
   **and current 27.2**. Same for the RR CE sign-extension fix (`00718a07bf9e`).
2. **HOA `mNumHOAcoeffs4SC[i]` per-subband counts** — Apple bounded the aggregate but not the
   per-SC indices its own log calls invalid.
3. **25 `_APPx::writeToStream` siblings** with the same unclamped (offset,length) emit path.
4. **SceneKit variable-length plist consumers** — the count-pinning fix skipped them.
5. LPAnimatedImageTranscoder unguarded frame fields; vImage Deepmap2 encoder-side asymmetries;
   CoreText GDEF AttachList offset-chase; libusd gcl decode path; ColorSync's new-in-27.2
   ISO-5 parsers; a possible 20-vs-40-byte capacity-math asymmetry in Apple's own fixed
   ImmersiveRenderer V1 gate.

## Ethics

- Research targets: the project owner's devices and Apple's publicly-shipped firmware.
- Purpose: coordinated disclosure. Findings go to Apple Product Security before anything else.
- PoCs are crash-oracles only — inputs that trip a missing bounds check and crash the parser;
  never weaponization.

## Attribution context

The CVEs covered here are credited by Apple to their original researchers (advisory 149230
lists every credit — among them Mateusz Jurczyk of Google Project Zero, Nik Tsytsarkin,
Hcamael, Ivan Fratric, and others). This repo claims no CVE credit; its contribution is the
on-record fix-site localization, the verification methodology, the craft recipes, and the
unfixed-sibling census.
