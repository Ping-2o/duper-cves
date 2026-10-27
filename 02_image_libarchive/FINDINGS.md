# FINDINGS.md — cve_groups/02_image_libarchive: image-adjacent parsers + libarchive (iOS 27.2 advisory 149230)

> AI-generated security research (same notice as AGENTS.md). Authorized research on the owner's
> device + Apple's publicly-shipped firmware, coordinated disclosure. PoCs are crash-oracles ONLY.
> Method: fix-diff (METHODOLOGY §1/§4/§4a/§5). Vulnerable build = iOS 27.0 RC **24A435** (what the
> iPhone 16e runs). Fixed build = iOS 27.2 RC **24B115**. Both extracted from the ADATA dsc caches
> into `extracted/24A435/` and `extracted/24B115/`.
>
> **Local live-oracle bonus**: the Mac (macOS 27.0, build 26A5368g) ships the SAME vulnerable fork
> versions of libarchive (182.0.0) and vImage (650.0.1) — byte-shape-identical function sizes. Its
> system binaries (`bsdtar`, CoreGraphics) were used to fire the vulnerable side of the A/B TODAY;
> extracted to `extracted/mac27_0/`. The fixed side of each A/B is proven statically from 24B115
> (and, for libarchive, corroborated by upstream's own regression tests).

## Scoreboard

| CVE | Component | Verdict | Fix site(s) |
|---|---|---|---|
| CVE-2026-112522 | libarchive | **PROVEN** (2 sites) | ISO9660-Joliet pathname OOB write + CAB-LZX match-before-history reject |
| CVE-2026-112621 | LinkPresentation | **PROVEN** | `-[LPAnimatedImageTranscoder encodeNextFrame]` frame-dimension gate |
| CVE-2026-86971 | Accelerate | **PROVEN** (2 sites) | vImage Deepmap2 buffer-size overflow guards + `ConvertIndexedToDirect` palette bound |
| CVE-2026-86988 | ColorSync | **NOT LOCALIZED in ColorSync.framework** (honest) | ColorSync ICC parse path byte-identical; fix must live elsewhere (leads below) |

---

## 1. CVE-2026-112522 — libarchive ("crafted file → app termination, OOB write / bounds checking")

`/usr/lib/libarchive.2.dylib` 182.0.1 → 182.40.6. **Only 6 functions changed** (responsive-fix
shape; diff via `scripts/funcdiff.py`): `_lzx_decode_blocks` +200, `_lzx_read_blocks` +100,
`_lzx_decode_init` +8, `_build_pathname_utf16be` +40, `_create_filesystem_object_at` +32,
`_restore_entry` −4. Apple's fork is upstream-open; both security sites cross-reference EXACTLY
to upstream commits (libarchive GitHub).

### Site 1 (the OOB write): ISO9660 **Joliet pathname buffer overflow**
Upstream commit `750e8d7b25de` — *"Fix joliet pathname buffer overflow"*, **Tim Kientzle, 2026-04-26**
(2-line fix; missed by Apple's 27.0 fork snapshot, picked up in 27.2):

```c
 build_pathname_utf16be(unsigned char *p, size_t max, size_t *len, struct file_info *file)
   if (file->parent != NULL && file->parent->utf16be_bytes > 0) {
       if (build_pathname_utf16be(p, max, len, file->parent) != 0)
           return (-1);
+      if (*len + 2 > max)                       /* THE ADDED CHECK */
+          return (-1); /* Path is too long! */
       p[*len] = 0; p[*len + 1] = '/';           /* unbounded before the fix */
       *len += 2;
   }
```

**Receipts (both sides, real vmaddrs):**

- VULN `extracted/24A435/libarchive.2.dylib` `_build_pathname_utf16be` @`0x2c076dda4`:
  after the recursive call succeeds (`bl _build_pathname_utf16be; cbz w0, ...`) the code writes the
  separator with **no bound**: `strb wzr, [p+*len]` / `mov w8,#0x2f; strb w8, [p+*len+1]`
  (`scripts/lldb_joliet_receipt3.txt` shows the exact vulnerable instruction stream).
- FIXED `extracted/24B115/libarchive.2.dylib` @`0x2c86fdfa4`: the identical site now begins
  `ldr x8,[len]; add x8,x8,#0x2; ldr x9,[sp,#0x18](max); subs x8,x8,x9; b.ls ok; mov w8,#0xffffffff`
  — the compiled `*len + 2 > max → ARCHIVE_FATAL` (see `scripts/create_fso.diff.txt` region and
  the disass in the analysis trail; the +40-byte size delta is this check).
- macOS 27.0 (vulnerable twin, `extracted/mac27_0/libarchive.2.dylib` @`0x19146ea70`) is
  shape-identical to 24A435 (function size 448 vs 24B115's 488).

**Bug mechanics:** `read_header` calls
`build_pathname_utf16be(malloc(1024) /* UTF16_NAME_MAX */, 1024, &len, file)` for every entry.
Each recursion appends the parent's name (bounds-checked), then writes the 2-byte UTF-16BE `'/'`
separator — **unchecked in the vulnerable build**. A Joliet path-table/directory chain whose
parent-path sums to **exactly 1024** makes the deepest unwind write `p[1024]=0x00, p[1025]=0x2F`
— a 2-byte heap OOB write (0x002F overwrites the following malloc chunk's header; the next
allocation is usually `utf16be_previous_path`, whose free then trips malloc sanity — delayed
crash/abort, or silent corruption).

**LIVE PROOF (executed on the Mac, macOS 27.0 / libarchive 182.0.0):**
seed `seeds/joliet_pathname_oob.iso` (built by `scripts/build_joliet_overflow_iso.py`):
PVD@16, Joliet SVD@17 (escape `25 2F 45`), root extent@19, nested dirs A(206B name)/B(206)/C(206)/
D(206)/E(192) → cumulative path 4×206+192+4×2 = **1024 exactly**, then file "F" inside dirE.

```
$ bsdtar -tvf seeds/joliet_pathname_oob.iso
 . / A*103 / A…/B*103 / …C…/D*103            # dirs listed, dirE path = exactly 1024 bytes
bsdtar: Pathname is too long                  # F's entry: recursion ends at 1024, the vulnerable
                                               # sep write fires at p[1024] BEFORE the FATAL
```

LLDB receipt (`scripts/lldb_joliet_receipt3.txt`): hardware breakpoint on the vulnerable separator
store `build_pathname_utf16be+132: strb wzr,[x8]`, conditioned on `(x8 - p) == 1024`:

```
Breakpoint 2 hit: 0x19802eaf4 strb wzr, [x8]
  x8 = 0x00000001005b3280   (= utf16be_path + 1024, one past the 1024-byte heap buffer)
  bt: build_pathname_utf16be+132 ← archive_read_format_iso9660_read_header+524 ←
      _archive_read_next_header2 ← bsdtar read_archive
```

That is the OOB write firing at exactly `p+1024` on a live system build of the same vulnerable fork
the iPhone runs. Fixed side (24B115 + upstream): the post-recursion check returns
ARCHIVE_FATAL "Pathname is too long" **before** any store.

**A/B oracle:** same ISO: 24A435 = 2-byte heap corruption then FATAL; 24B115 = clean FATAL, no write.
Device-side crash-oracle quality: medium (silent corruption or delayed malloc abort; the .ips
shape would be a malloc `free(): invalid pointer`-class abort in archive cleanup).

### Site 2: CAB **LZX matches before initialized history** (upstream `9a7668153148`)
*"cab: reject LZX matches before initialized history"*, Malachi Moody, 2026-08-08 — adds
`w_filled` to `struct lzx_dec`, bookkeeping in `lzx_read_blocks`/`lzx_decode_blocks` (init/verbatim/
copy paths), and the reject:

```c
if (copy_pos == 0 || copy_pos > w_filled) goto failed;   /* ARCHIVE_FAILED (-25) */
```

**Receipts:** VULN `_lzx_decode_blocks` @`0x2c07238f4` (3292B): computes
`copy_pos = (w_pos - copy_pos) & w_mask` and falls straight into the copy loop (`scripts/lzx_decode_blocks.diff.txt`).
FIXED @`0x2c86b3a2c` (3492B):

```
0x2c86b43c8:  cbz   w8, loc_2c86b43e4          ; copy_pos == 0 → failed
0x2c86b43d0:  ldrsw x8, [sp,#0x80]             ; copy_pos
0x2c86b43d4:  ldr   x9, [sp,#0x68]             ; w_filled (NEW field)
0x2c86b43d8:  subs  x8, x8, x9
0x2c86b43dc:  b.ls  loc_2c86b43e8              ; copy_pos <= w_filled → proceed
0x2c86b43e4:  b     loc_2c86b46e8              ; → ARCHIVE_FAILED (mov w8,#0xffffffe7 = -25)
```

**LIVE PROOF (executed on the Mac):** upstream ships its own regression fixture
`seeds/test_read_format_cab_lzx_invalid_history.cab` (118 bytes; fetched from libarchive master;
`test_read_format_cab_lzx_invalid_history.c` documents the expected FIXED behavior:
`archive_read_data → ARCHIVE_FATAL, "LZX decompression failed (-25)"`).

```
$ bsdtar -xvf test_read_format_cab_lzx_invalid_history.cab
x x                                # VULNERABLE: extraction SUCCEEDS, exit=0
$ xxd x                            # 00 00 — bytes produced from the UNINITIALIZED LZX window
```

The vulnerable build happily produces output from history bytes that were never written —
an uninitialized-heap read that lands in the extracted file (info-leak channel). 24B115 refuses
the same file with the −25 error. **This A/B pair is complete**: live vuln behavior captured,
fixed-side refusal proven by disassembly + upstream's own test.

(The March `79a0787b4715` "Fix Heap OOB Write in CAB LZX decoder" (CFDATA uncompressed_size cap)
is ALREADY in 24A435 — both builds contain "Invalid CFDATA uncompressed size" — so it is NOT live
on our device; do not re-report.)

**Other libarchive deltas:** `_create_filesystem_object_at`/`_restore_entry` (write_disk) +32/−4 =
minor non-parse churn (no bounds-check shape); `_build_pathname_utf16be` is the only other
security-shaped site. Apple also absorbed `c0cdc557fbce`/`a57c3d21db26`-class upstream cab work
(implied by the LZX/bookkeeping code shape).

**Craft recipes (crash-oracle only):**
- Joliet ISO: `scripts/build_joliet_overflow_iso.py` → `seeds/joliet_pathname_oob.iso`
  (chain of 5 nested Joliet dirs with names 206/206/206/206/192 UTF-16BE bytes; parent path
  lands at exactly 1024; the file entry triggers the separator OOB). Variant knobs: make the
  deepest name 190 to stop at 1022 (in-bounds, control), or 192 as shipped (OOB).
- LZX CAB: upstream regression fixture is the seed (`seeds/test_read_format_cab_lzx_invalid_history.cab`).
  For mutation-based hunting of the adjacent condition (`copy_pos == 0` self-referential match),
  bit-flip the first CFDATA block of `seeds/test_read_format_cab_lzx.cab` (fetch from upstream
  test suite) and diff vulnerable-extract vs fixed-reject.

**Trigger surface:** on-device, `/usr/lib/libarchive.2.dylib` is callable from app context via
dlopen + `archive_read_new/support_format_cab|iso9660/read_open_memory/next_header/read_data`
(all exports preserved in the dsc image). Real-world iOS consumers of libarchive include
Archive/Notes/backup pipelines (any `bsdtar`-family tooling in daemons). The ISO/CAB files are
also the on-disk shapes that get scanned (MDM, Mail attachments, archival importers).

---

## 2. CVE-2026-112621 — LinkPresentation ("crafted image → memory corruption, OOB write / bounds checking")

`/System/Library/Frameworks/LinkPresentation.framework/LinkPresentation` 313.0.0 → 317.0.0.
The version bump is mostly the "visual refresh" feature churn (style accessors, Swift thunks),
BUT it carries exactly one security-shaped change — and it is in the **Messages link-preview
media path**:

### `-[LPAnimatedImageTranscoder encodeNextFrame]` — frame-dimension mismatch gate (PROVEN)

New-in-fixed error string:
`"LPAnimatedImageTranscoder<%d>: failed, frame %zu is %gx%g, but the first frame is %gx%g"`
(`__TEXT.__oslogstring` @`0x1adba49fb`; absent from 24A435's string table — the ONLY transcoder
string added).

**Receipts:**

- FIXED `_...encodeNextFrame]` @`0x1adb24a20` (956B, was 776B — +176):
  ```
  0x1adb24a68/74:  ucvtf d8,d9        ; current frame width/height
  0x1adb24a80:     ldp  d0,d1,[x19,#0x40]   ; FIRST frame dims (stored at transcoder init)
  0x1adb24a84:     fcmp d0, d8             ; width equal?
  0x1adb24a88:     fccmp d1, d9, #0, eq    ; AND height equal?
  0x1adb24a8c:     b.eq loc_1adb24b40      ; both match → append frame to the writer
  0x1adb24a90+:    (fail) log "failed, frame %zu is %gx%g, but the first frame is %gx%g" →
                   transcoder aborts the frame (ARCHIVE-of-the-transcode style failure)
  ```
- VULN @`0x1ad6ba25c` (776B): after decoding each frame's dimensions
  (`ucvtf d8,x22 / ucvtf d9,x24` @`0x1ad6ba398`) the values go **directly** into surface
  creation/append calls (`bl 0x1b0132f60/0x1b0132f90`) — **no comparison against the first
  frame's dimensions anywhere in the function** (receipt: `scripts/lp_encode_old.txt`).

**Bug mechanics:** the transcoder turns an animated image (GIF/APNG — exactly what a Messages
**link preview / rich-card media** carries) into a video via AVAssetWriter; its surface/pixel-buffer
geometry is established from the FIRST frame (`initWithAnimatedImage:` stores `_frameCount`,
`_bufferSize`, first-frame dims). A crafted animated image whose frame N is LARGER than frame 0
proceeds into the writer append on the vulnerable build — geometry mismatch → OOB write in the
surface/pixel-buffer path (Apple line: memory corruption / app termination). 24B115 refuses any
frame that doesn't match frame 0's dims, log receipt first.

**Craft recipe (crash-oracle):** animated GIF or APNG where frame 0 is small (e.g. 16×16) and a
later frame declares different dimensions (e.g. 1024×1024, or simply a larger GIF logical screen
on later frames). Seed plan: mutate `seeds/indexed_palette_oob.png`-style script —
`scripts/build_animated_size_mismatch.(gif|apng).py` TODO-flagged for the harness run; the
on-device probe row (HARNESS_ROW.md cell LP-ANIM) instantiates the private class via
`NSClassFromString(@"LPAnimatedImageTranscoder")` + `initWithAnimatedImage:` + the
`transcodeWithCompletionHandler:`/`_transcodeWithCompletionHandler:` selectors, feeds the crafted
file, and reads back the transcode result + the os_log line (fixed side prints the new
"failed, frame …" message; vulnerable side attempts the append).

**Class surface (for the probe):** `LPAnimatedImageTranscoder` ivars `_sourceImage, _completionHandler,
_imageSource, _outputURL, _frameCount, _currentFrame, _nextFrameTime, _bufferSize, _adaptor,
_writer, _input, _stopEncoding, _hasReadyForDataObserver, _loggingID` — an image-source-driven,
AVAssetWriter-backed re-encoder (nm receipts in the trail).

---

## 3. CVE-2026-86971 — Accelerate ("crafted image → app termination, OOB write / bounds checking")

Version deltas: **vImage 650.0.1 → 650.40.4** (libCGInterfaces mirrors the version, **0 function
changes**), libBNNS 2212.2.1 → 2212.42.1 (libc++ hardening-assert/SDK churn only — triaged, not
the CVE), libvDSP/libvMisc unchanged. vImage's delta is a **responsive-fix shape**: 25 changed
functions, ALL inside the Deepmap2 codec family + the indexed-palette converter.

### Site A: Deepmap2 decode buffer-size arithmetic — 64-bit overflow + magnitude guards (PROVEN)

**Receipt (cleanest):** `_Deepmap2DecodeDefaultMaxRawBufferSize`:

- VULN @`0x244111f14` (28B) — the whole function:
  ```
  mul   x8, x1, x0          ; width * height   (NO overflow check)
  mov   w9, #6
  add   x10, x1, x8
  madd  x8, x8, x9, x10     ; *(6)+h
  add   x8, x8, #0xf
  and   x0, x8, #~0xf       ; → returned raw-buffer size
  ```
- FIXED @`0x248471250` (100B):
  ```
  cmp    x0, #0 / ccmp x1, #0, #0x4, ne        ; zero-dim rejection
  umulh  x8, x1, x0 / mul x9, x1, x0           ; 128-bit multiply
  ccmp   xzr, x8, #0, ne / csel x8, xzr, x9, ne ; overflow (umulh != 0) → 0
  cbz    x0/x1/x8 → 0                          ; any degenerate → 0
  mov    x10, #0x402aaa…; cmp x8, x10; csel x9, xzr, x9, hi   ; magnitude ceiling → 0
  add    x8, x1, x8; add x8, x8, x9 …           ; same formula, all inputs guarded
  ```
Same guard shape added to: `_DecodeImageDefaultScratchBufferSize` (80→136),
`_Deepmap2DecodeDefaultRawBufferSize` (68→136), `_Deepmap2DecodeDefaultScratchBufferSize`
(136→196), and the internal stride/row arithmetic of `_DecodeImageDefault` (1100→1180,
`umulh/ccmp/csel` blocks — receipt `scripts/decode_image_default.diff.txt`), plus the encoder
family (`_EncodeImageDefault` +96, `_Deepmap2Encode*` +36..+96) and both stream processes
(`_vImageDeepmap2DecodeStreamProcess`/`_vImageDeepmapDecodeStreamProcess` +32/+52). Deepmap-1
inherits via wrappers (`_vImageDeepmapDecodeScratchBufferSize` → `_DecodeImageDefaultScratchBufferSize`).

**Mechanics:** callers allocate decode/scratch buffers from these size helpers (also exported as
`vImageDeepmap2DecodeScratchBufferSize` etc.); the vulnerable helpers do unchecked
`w*h*6(+h)` arithmetic — attacker-controlled deepmap2 header dims (`w`,`h` feed straight in) can
make the returned size SMALLER than what the decoder writes (overflow wrap/magnitude csel in the
old code collapses size to 0/small) → **OOB write into the under-sized caller buffer → app
termination**. Exactly the advisory line. Deepmap2 is Apple's depth-map codec (AVDepthData /
HEIF depth aux images) — "processing a maliciously crafted image".

**Craft recipe:** the APIs are exported (`_vImageDeepmap2Decode`, `_vImageDeepmap2DecodeStreamCreate/
Process`, `_vImageDeepmap2DecodeScratchBufferSize` — nm receipt): the harness row feeds a
crafted deepmap2 stream (valid magic/container from a real depth aux, dims mutated so
`w*h` overflows the helper's arithmetic) and compares 24A435's returned scratch/raw sizes vs
24B115's zero-rejection. File-level reach: HEIF with depth-aux (deepmap2 payload) —
`AVDepthData`/ImageIO path; container seed from any portrait HEIC's aux image.

### Site B: `_ConvertIndexedToDirect` — indexed colorspace palette bound (PROVEN)

**Receipt:**

- FIXED @`0x2485ca1ac` (1360B, was 1168B — +192), `ConvertAnyToAny.c`:
  ```
  0x2485ca370:  lsl   w27, w8, w9        ; w27 = 1 << bitsPerComponent
  0x2485ca374:  cmp   x0, x27            ; x0 = CGColorSpaceGetColorTableCount()
  0x2485ca378:  csel  x24, x0, x27, cc   ; x24 = min(colorTableCount, 1<<bpc)
  0x2485ca388:  b.hs  …                  ; count >= 2^bpc → old path
  0x2485ca38c:  sub   x28, x27, x24      ; deficit
  …             (new loops copy only the real entries, then ZERO-FILL the deficit —
                 the added `mov w8,#0; strb …` fill blocks in scripts/convert_indexed.diff.txt)
  ```
- VULN @`0x24426ad74` (1168B): after `cgColorSpaceGetColorTableCount`, the palette-expansion loop
  copies/uses the table **without any min(count, 1<<bpc) bound** — an 8bpc indexed colorspace with
  colorTableCount < 256 leaves entries ≥ count derived from out-of-bounds table memory.

**Craft + LIVE seed (tested on the Mac, macOS 27.0 / vImage 650.0.1):**
`scripts/build_indexed_png.py` → `seeds/indexed_palette_oob.png` — a PNG whose PLTE has 2 entries
but whose 8-bit pixel indices run up to 255. ImageIO maps it to
`kCGColorSpaceModelIndexed` with **tableCount=2 vs index range 0…255** (verified on the Mac:
`[*] INDEXED space, tableCount=2 (bpc=8 => 256 range)`). Drawing it into an RGB bitmap context
(the preview/thumbnail path — CG→libCGInterfaces→vImageConverter) executes
`ConvertIndexedToDirect`. Variant `seeds/indexed_255_oob.png` (all pixels index 255): on the
vulnerable build every pixel decodes to `00ff00` (palette entry 1 — a value derived from beyond
the 2-entry table's copied region); the fixed build's zero-fill maps OOB indices to 0x000000.
**Deterministic cross-build output delta = the A/B oracle** (plus a potential crash on iOS where
the heap layout differs). The row can also skip ImageIO entirely:
`vImageConverter_CreateWithCGImageFormat` (exported) + a programmatic 2-entry indexed colorspace.

---

## 4. CVE-2026-86988 — ColorSync ("crafted image → disclosure of process memory", Jurczyk + Tsytsarkin)

`ColorSync` 3929.0.0 → 3929.1.5. **Honest verdict: NOT LOCALIZED.**

- 37 functions changed (funcdiff, `scripts/ColorSync_funcdiff.txt`): all of them are the
  **ISO-5 / HDR headroom metadata feature rework** (new `_ColorSyncProfileGetISO5Headroom`,
  `_create_iso5_meta_tag_data` 3264B, `_get_D50_XYZ_for_cicp_primaries`, …; shrink of
  `_ColorSyncProfileCreateCopyWithISO5Metadata` 3912→1032; gamma estimation refactored into the
  new `_AppleCMMEvaluateProfileGamma`). Strings added: feature names only
  (`"HDR Metadata"`, `"com.apple.cmm.DerivedISO5Metadata"`). **No bounds-check shape anywhere.**
- The **ICC parse path is byte-identical** between the two builds:
  `CMMProfile::GetTag`, `CMMProfileMaker::MakeProfile`, and all 1024 C++ CMM tag classes
  (`CMMCurveTag`, `CMMParaCurveTag`, `CMMPQCurveTag`, `NxMLUT*`, …) are unchanged — a
  crafted-profile OOB READ in the tag parsers cannot be what changed.
- Swept for Apple's own security-tag receipts (`CG-SEC-<radar>` strings): ColorSync has NONE.
  CoreGraphics gained two (`CG-SEC-187882049` PDF type-5 shading range check,
  `CG-SEC-187882136` used-cmap codespace dimension) — both PDF-domain (other group's CVEs).
- ImageIO (2851.0.0→2851.1.8, 267 changed functions) and CoreGraphics (2050.0.0→2050.1.6, 953)
  both reworked; ImageIO's ICC-adjacent changes are the ISO-5/HDR feature + a new
  **CGColorSpaceFromICCDataCache** (Lockdown-Mode-gated caching feature, not a fix).

**Leads (not conclusions):** the credited pair (Jurczyk/Tsytsarkin, also credited on the ImageIO
cluster in the same advisory) most likely hit the ICC-handling code that ColorSync's CVE entry
owns but which physically lives in ImageIO/CoreGraphics's ICC extraction+conversion pipeline —
the other group's ImageIO diff is where to look (I extracted both-build ImageIO/CoreGraphics into
`extracted/` for them). Alternatively the fix rides inside the ISO-5 metadata rework (the
24A435-era ISO5 functions parse profile-controlled dictionaries) — SHAPE-MATCHED only, no check
localized.

---

## 5. Sibling census (the credit engine — checks Apple did NOT add / upstream fixes Apple did NOT take)

1. **CANDIDATE (high) — libarchive/iso9660: Rock Ridge CL/RE relocation CYCLES.**
   Upstream `d14de384fcc6` *"iso9660: detect cycles in Rock Ridge CL/RE relocation chains"*
   (Tobias Stoeckmann, 2026-09-22) adds Floyd cycle detection to `re_get_entry()` — a malformed
   image can chain CL/RE reparenting so parent pointers form a cycle with no `re` flag → the
   vulnerable code **spins forever**. Apple's fork did NOT take it in 27.2: `_re_get_entry` is
   100 bytes, byte-count identical in 24A435 and 24B115, no two-pointer detection pattern
   (disass receipt taken). **Live on iOS 27.0 AND 27.2.** Craft: RR ISO with a CL/RE parent loop.
   Reportable to Apple Product Security under OUR name (upstream already fixed publicly — cite it).
2. **CANDIDATE (medium-high) — libarchive/iso9660: RR CE location sign-extension.**
   Upstream `00718a07bf9e` *"do not sign-extend the Rock Ridge CE location"* (2026-09-14) — not in
   Apple's delta (no iso9660 function besides `_build_pathname_utf16be` changed) → possible OOB
   access via negative CE offsets, live on both builds. Same crafted-ISO pipeline as #1.
3. **CANDIDATE (medium) — LinkPresentation/`LPAnimatedImageTranscoder`: only frame DIMENSIONS
   are gated.** Not checked by the new gate: per-frame **pixel format / bits-per-component /
   bytes-per-row** of later frames, and **frameCount** consistency (property-declared vs actual
   stream). A format-switching animated image (frame 2 with different bytes-per-row) drives the
   same AVAssetWriter/surface geometry mismatch the dims check guards against → same corruption
   class. Also un-audited: `_delayTimeFromImageProperties` (+176 in this window) — frame-timing
   parsing on image-property data.
4. **CANDIDATE (medium) — vImage: Deepmap2 *encoder*-side and stream-stateful paths.**
   The size helpers for DECODE got full umulh guards; the ENCODER helpers grew too
   (`_Deepmap2EncodeDefault*` +36..+96) but the encoder's `_vImageDeepmap2EncodeCreateBuffer`
   (+32) and `vImageDeepmap2EncodeStreamProcess` paths deserve an independent audit — the 27.2
   sweep touched them, implying the same class existed; anything they MISSED is ours
   (e.g. `_Deepmap2DecodePalette` +4 vs `_DecodeImagePalette` +24 asymmetry).
5. **CANDIDATE (high-value fuzz target) — ColorSync ISO-5 metadata parsers.**
   The 27.2 rework ships brand-new profile-data-driven parser code
   (`_create_iso5_meta_tag_data` 3264B, `_headroom_reference_white_pair_from_iso5_metadata`,
   `_reference_white_from_iso5_metadata`, `create_content_light_level_dict`, …) plus the
   24A435-era versions already shipped (`_ColorSyncProfileCopyISO5Metadata` etc.). Dictionary-
   typed metadata parsed from ICC profile bytes = classic disclosure surface; zero public
   fuzzing history. Fresh attack surface shipped in 27.2 itself.
6. **Noted for the other groups:** CoreGraphics `CG-SEC-187882049` (PDF type-5 shading
   range-vs-colorspace) and `CG-SEC-187882136` (used-cmap codespace dimension, "falling back to
   identity") are security-tagged fixes whose CVEs belong to the PDF/ImageIO cluster docs.
7. **Checked and NOT bugs:** Deepmap-1 scratch-size helpers inherit the decode guards through
   wrappers (verified `_vImageDeepmapDecodeScratchBufferSize` → guarded
   `_DecodeImageDefaultScratchBufferSize`); libarchive ASCII `build_pathname` uses auto-growing
   archive_string (no Joliet-class overflow); the March `79a0787b4715` CFDATA-size fix is already
   in 27.0 (both builds carry "Invalid CFDATA uncompressed size").

## 6. Inventory

- `extracted/{24A435,24B115,mac27_0}/` — both-build dylibs for ColorSync, LinkPresentation
  (×3), vImage, libCGInterfaces, libBNNS, libarchive, plus ImageIO & CoreGraphics (extracted for
  the ColorSync search; left for the ImageIO group), and the Mac's vulnerable libarchive.
- `scripts/` — `funcdiff.py`, `disass_diff.py` (both fixed for ObjC/space names + decimal addrs),
  `diff_strings.sh`, `dylibs_{24A435,24B115}.txt` (full dsc image+version lists = version-delta
  oracle), per-component funcdiff/strdiff outputs, both-side disass receipt files
  (`lzx_decode_blocks.diff.txt`, `create_fso.diff.txt`, `convert_indexed.diff.txt`,
  `decode_image_default.diff.txt`, `lp_encode_old.txt`, `lp_cold_fixed.txt`, `lp_enc_full_fixed.txt`,
  `gamma_old/new.txt`, `lldb_joliet_receipt*.txt`), upstream cross-refs (`upstream_cab_master.c`,
  `upstream_iso9660_{master,379}.c`), and the local-oracle programs
  (`indexed_oob_test.c`, `png_indexed_oob_test.c`, `png_dump.c` + compiled binaries).
- `seeds/` — `joliet_pathname_oob.iso` (Joliet OOB-write seed, LIVE-tested),
  `indexed_palette_oob.png` / `indexed_255_oob.png` (vImage indexed-palette seeds, LIVE-tested),
  `test_read_format_cab_lzx_invalid_history.cab` (+ its `.c`/.uu`, upstream regression fixture for
  the LZX site, LIVE-tested on the vulnerable build).
- `HARNESS_ROW.md` — probe-row spec for the on-device run.
