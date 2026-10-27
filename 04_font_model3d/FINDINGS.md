# FINDINGS.md — CVE group 04: FontParser / CoreText / Model I/O+USD / SceneKit

> AI-generated security research (same notice as AGENTS.md). Authorized research on the
> project owner's device + Apple's publicly-shipped firmware, for coordinated disclosure.
> PoCs are crash-oracles ONLY. Every claim below carries a receipt (both-side disassembly
> with vmaddrs) or is explicitly marked SHAPE-MATCHED.

**Builds:** vulnerable = iOS 27.0 RC **24A435** (what the device runs), fixed = iOS 27.2 RC
**24B115**. Method: METHODOLOGY §1/§4a — each check Apple ADDED in 24B115 is an admitted bug,
live on 24A435. Version deltas from the DSC image lists; both-build dylibs extracted to
`extracted/{24A435,24B115}/`; symbol dumps + diffs in `scripts/symjson/`.

## 0. Where the fixes actually landed (headline)

| dylib | 24A435 → 24B115 | verdict |
|---|---|---|
| libFontParser.dylib | 459.0 → 463.1.0.1 | 3 targeted fix clusters (§2) |
| CoreText | 904.0 → 910.0 | 1 targeted fix (+ shaping churn) (§3) |
| ModelIO | 270.1.3 → **270.1.3 (unchanged)** | **binary differs but ALL changes are one benign member-offset shift (`ldr x[n],[x, #0xf38]`→`ldr x[n],[x]`, 11 functions, `scripts/modelio_sbs.txt`) — NO added checks. The Model I/O CVE fixes live in its sub-parser `libusd_ms.dylib` (§4)** |
| /usr/lib/usd/libusd_ms.dylib | 24.1.30 → 24.1.32 | **the real "Model I/O" fix carrier** (§4) |
| SceneKit | 612.0 → 612.101 | 4 targeted fix sites (§5) |
| USDObjCKit | 59.1.5 → 59.2.2 | plain rebuild, no parse-visible fix shape (not analyzed further) |

libc++ "Hardening assertion" strings appear in BOTH builds (only the BuildRoot path
changed) — NOT a hardening flip, per-component noise from it was nil.

---

## 1. Scope vs. advisory lines

Apple advisory 149230 lines assigned to this group:

- FontParser: **CVE-2026-112683** (OOB write → app term / corrupt memory), **CVE-2026-86970** (OOB read → disclosure), **CVE-2026-112642** (OOB read → disclosure)
- CoreText: **CVE-2026-112656** (OOB read → disclosure)
- Model I/O: **CVE-2026-112565**, **CVE-2026-112449** (integer overflow), **CVE-2026-112413** (OOB read), **CVE-2026-112485** (memory handling), **CVE-2026-112461**, **CVE-2026-112486** (OOB write)
- SceneKit: **CVE-2026-112425**, **CVE-2026-112423** (OOB read), **CVE-2026-112464** (heap corruption OOB write), **CVE-2026-86991** (buffer overflow)

---

## 2. FontParser (libFontParser.dylib)

### 2.1 CVE-2026-112683 — scan-conversion scratch OOB write — **PROVEN (fix site + old-code shape)**

**The fix:** 24B115 adds THREE new throw-guarded helpers (new symbols, absent in 24A435 —
`scripts/symjson/diff_libFontParser.txt`):

```
__ZL22CheckedScanScratchSizeit           (int, unsigned short)
__ZL31CheckedScanScratchRowBaseOffsetit  (int, unsigned short)
__ZL34CheckedScanScratchOffsetWithinSizeitj (int, unsigned short, unsigned int)
```

`CheckedScanScratchSize(n, w)` @0x1b84e0ea4 (24B115):
```
0x1b84e0eb4  lsr    w8, w0, #0x1d
0x1b84e0eb8  cbnz   w8, loc_1b84e0ed8   ; n must be non-negative and < 2^29 → else THROW
0x1b84e0ec0  bl     CheckedScanScratchRowBaseOffset
0x1b84e0ec4  adds   w0, w0, w19, lsl #3 ; + n*8, carry → THROW
```
`CheckedScanScratchRowBaseOffset(n, w)` @0x1b84e0ef8: rejects negative n (`tbnz w0,#0x1f`),
computes `n * ((w<<1)+4)` in **64-bit** `umull`, throws if ≥ 2^32.
`CheckedScanScratchOffsetWithinSize(n, w, size)` @0x1b84e0f40: throws if
`Size(n,w) > size`, else returns `RowBaseOffset`. All throw paths build a
`TException(kind=5)` + message (same shape as the pre-existing `CheckedF26Dot6Add`
@0x1b7a4bd3c old / 0x1b84e0d38 new).

**The bug (24A435 `RenderBitmap` @0x1b7a4b4e0 → 24B115 @0x1b84e04a8, +52B):**

OLD unchecked scratch-size product (0x1b7a4b794-0x1b7a4b7b8):
```
0x1b7a4b794  ldrsh  w9,  [x26, #0x5c]    ; ymax  (int16 from sc_BitMapData)
0x1b7a4b798  ldrsh  w10, [x26, #0x58]    ; ymin
0x1b7a4b79c  sub    w9,  w9, w10          ; rows = ymax-ymin   (can be NEGATIVE / huge)
0x1b7a4b7a0  ldrh   w10, [x26, #0x60]    ; width (u16)
0x1b7a4b7a4  lsl    w10, w10, #1          ; *2
0x1b7a4b7a8  add    w10, w10, #0xc        ; +12
0x1b7a4b7ac  mul    w9,  w10, w9          ; scratchSize = rows*(2*width+12)  ← UNCHECKED 32-bit mul (wraps; negative rows → negative size)
0x1b7a4b7b8  str    w9,  [x8, #0x20]      ; stored as the scan context size
```
OLD unchecked end-pointer (0x1b7a4b938-0x1b7a4b940):
```
0x1b7a4b930  ldrh   w10, [x24, #0x62]
0x1b7a4b934  add    w10, w10, #2
0x1b7a4b938  mul    w8,  w10, w8           ; (width+2)*rows  ← UNCHECKED
0x1b7a4b93c  add    x8,  x9, w8, sxtw #1   ; base + SIGN-EXTENDED product ← UB pointer math
0x1b7a4b940  str    x8,  [x24, #0x50]
```
NEW replaces both with `bl CheckedScanScratchSize` (0x1b84e0768/0x1b84e0788, stores at
ctx+0x10/+0x20) and `bl CheckedScanScratchOffsetWithinSize` (0x1b84e08e0 → ctx+0x48,
0x1b84e0a50 → ctx+0x50) with **zero-extended** adds (`add x8, x19, w0, uxtw`).

**Producer also rewritten:** `sc_FindExtrema4(fnt_ElementType*, sc_BitMapData*, int,
fsg_SplineKey*)` — 24A435 @0x1b7aca14c → 24B115 @0x1b855fbe8, −468B, 97% instruction
rewrite (block_invoke_2 → block_invoke_4). This is the function that fills the
`sc_BitMapData` int16 geometry fields consumed above; the rewrite is consistent with
clamping the bitmap extents (exact new clamps not instruction-extracted — shape-level).

**Reach (in-app, public API):** draw path — `CTFontDrawGlyphs*` / CoreGraphics glyph
rendering → scaler → `RenderBitmap` (per `analysis/priv24A435_font_cff_leftover.md` §7 the
create path is `CTFontManagerCreateFontDescriptorFromData` → `FPFontCreateWithData`;
bitmap rendering additionally requires a draw). Prior art graded the CFF/sbix/COLR table
surfaces fail-closed; this fix proves the bug lived in the SCAN-CONVERSION rasterizer, not
the table walkers.

**Craft recipe (crash-oracle):** TrueType font, `head.unitsPerEm=16`, one glyph whose
outline spans ±32767 font units → at a large requested point size (≥512 pt) the scaled
bitmap extent far exceeds int16; rows*(2*width+12) wraps 32 bits → undersized/negative
scratch → OOB write during scan conversion. Seed built: **`seeds/huge_bbox.ttf`**
(`scripts/mkfont.py`, parses + maps 'A'→gid1 under macOS CoreText and fontTools —
`bbox -1048544..2097088` at 512pt confirms the extreme geometry reaches the scaler).
**Expected A/B:** 27.0 = app crash/corruption on draw of 'A' at ≥512pt; 24B115 =
`TException` (font rejected / empty render), no crash.

**Mapping:** OOB write + "corrupt process memory" = **CVE-2026-112683** (shape: the only
OOB-write fix in FontParser).

### 2.2 CVE-2026-86970 / CVE-2026-112642 — charstring operand stacks — **PROVEN (fix sites), CVE split SHAPE-MATCHED**

**The fix (24B115):** new throw-guarded stack ops for the Type1→Type2 charstring
conversion contexts (new symbols):
```
TType1ToType2CharStringConversionContext::Push(int)  @0x1b8544f90  — count < 0x30 else TType1Exception; store into ctx+0x254[count] with brk#1 secondary guard
TType1ToType2CharStringConversionContext::Pop()      @0x1b8545010  — count > 0 else TType1Exception; read ctx+0x254[count-1]
TType1ToType2CharStringConversionContext::PopCounterValue() @0x1b8545a10 — vector end-check, throws on empty
TBufferedCharStringStreamingContext::Push(int)       @0x1b8510bcc — count < 0x19 (25) else throw; array at ctx+0x228
TBufferedCharStringStreamingContext::Pop()           @0x1b85124c8 — count > 0 else throw; brk guard at 0x19
```
All throw paths build `TType1Exception(kind=5)` (full sequence quoted in the receipt
dumps; e.g. `Push` fail: `mov w0,#0x10; bl operator_new; strh #5,[x0]; ldr x1,[GOT];
mov x2,#0; bl throw`). Old `ConvertT1ToT2CharString(unsigned short, bool&)`
@0x1b7a4b4e0→0x1b8542d44 grew **+792B**; `ProcessCharString` +264; `MakeHandler` +88;
`TFlexConversion::AddValue` +80; `BlendVal` +24 — the inline unchecked stack ops were
extracted into the guarded helpers.

OLD inline pattern (still present at 24A435 0x1b7aad7e8 for the opcode push, but the POP
sites had no underflow guard): `str w8, [x27, x9, lsl #2]` with count from the context and
`subs/ldr` pops reading `ctx->stack[--count]` with no `count > 0` test — an underflowing
charstring (operator popping more operands than pushed; Type1 `callother`/blend/counter
operators) reads below the array = **OOB read → disclosure**, or via the 25-slot
`TBufferedCharStringStreamingContext` blend stack (`BlendVal` writes) → OOB write into
the fixed 96-byte member. The old `TInlineBufferAllocator<T,30>` inline buffers were
replaced by 60/120/240/1248/208-slot versions + `__vallocate` — capacity rework of the
same stacks.

**Reach (in-app):** Type1 charstrings (`ConvertT1ToT2CharString` runs during
flatten/hinting of Type1/CFF data) and Type2 streaming (CFF2) — reached from
`CTFontManagerCreateFontDescriptorFromData` / `CGFontCreateWithDataProvider` on crafted
Type1/CFF data (prior art §7 table).

**Craft recipe:** Type1 charstring whose operators pop more values than pushed
(e.g. repeated `blend`/counter operators with empty operand stack), or a CFF2 charstring
abusing the buffered streaming context. Not auto-built (Type1 charstring surgery is
manual); harness phase will iterate from a minimal Type1 seed. Expected A/B: 27.0 = OOB
read (possible disclosure) or heap smash; 24B115 = `TType1Exception`, font rejected.

**Mapping:** two distinct guarded stacks (conversion context; streaming context) ≈ the
two disclosure lines **86970** and **112642** (SHAPE-MATCHED — which is which is not
distinguishable without beta-window data).

### 2.3 FontParser residuals (no CVE claim)
`FPFontCreateFontsFromData` +1228, `FPGetStandardEncodingSID` +792,
`FPFontCreateMemorySafeFontsWithPath` +264 — Swift `CheckedBufferView` plumbing growth;
no added bounds-check shape on table fields. `GetSubtable`/`FillInverseMap`/`AppendWOFFEntities`
±20-24B — compiler churn. Not claimed.

---

## 3. CoreText (CVE-2026-112656) — ligature-caret offset OOB read — **PROVEN**

**`TFont::GetLigatureCaretPositionsForGlyph(unsigned short, double*, long)`**
24A435 @0x19a2db77c → 24B115 @0x19a47c924 (+128B).

OLD (0x19a2db9dc-0x19a2dba00):
```
0x19a2db9dc  ldrh   w8, [x25]
0x19a2db9e0  rev    w8, w8
0x19a2db9e4  lsr    w8, w8, #0x10        ; caret offset (BE u16 from the GDEF LigCaret chain)
0x19a2db9ec  add    x0, sp, #0xa0
0x19a2db9f0  add    x1, x25, x8           ; caretTable + offset  ← NO end-check, NO sign-check
0x19a2db9f4  mov    x2, x24               ; table end (x24) — unused for this address
0x19a2db9fc  bl     #0x19a26a880          ; consume from x1
```
NEW (0x19a47cb84-0x19a47cbc4):
```
0x19a47cb88  ldrh   w8, [x25, #2]
0x19a47cb8c  rev    w8, w8
0x19a47cb90  lsr    w8, w8, #0x10
0x19a47cb94  adds   x9, x23, w8, uxtw #1  ; (table+4) + offset*2 — carry check
0x19a47cb98  b.hs   → fail
0x19a47cb9c  cmp    x9, x24               ; vs table end
0x19a47cba0  b.ls   → ok
; fail path CLAMPS the entry count to (end - base)/2 and rejects on mismatch
; (sub x10,x24,x23; lsr x10,#1; csel …; cmp x9,x8; b.ne → reject path 0x19a47cc78)
```
i.e. the caret offset is now bounds-checked against the GDEF table slice and the caret
count clamped; the old build chased an unchecked table-relative offset = **OOB read →
process-memory disclosure** = **CVE-2026-112656**.

**Reach (public API):** `CTFontGetLigatureCaretPositions` (public), and the typesetter's
caret/draw path (`GetLigatureCaretPositionsForGlyph` is the TFont core). GDEF
LigCaretList/CaretValue offsets are file-controlled.

**Craft recipe / seed:** TTF with a GDEF LigCaretList for gid1 whose CaretValue offset =
0x8000 (table is ~30 bytes) → 27.0 reads 32 KiB past the table slice (crash/leak);
24B115 clamps and rejects. Seed built: **`seeds/gdef_caret_oob.ttf`** (parses under macOS
CoreText; `CTFontGetLigatureCaretPositions` is exercised by the seed-check binary —
on a fixed-era macOS it consumed the LigCaretList without crashing; the A/B oracle is the
device run). Note: the exact GDEF sub-table alignment (which field x25 points at) should
be confirmed on-device — if the first refire doesn't crash, sweep the offset field knob
(`scripts/mkfont.py build_gdef(caret_off=…)`).

---

## 4. "Model I/O" — fixes live in libusd_ms.dylib (ModelIO itself is clean)

ModelIO (270.1.3 → 270.1.3) shows only a benign member-offset shift (§0). ModelIO's
heavy lifting for USD/USDZ is delegated to `/usr/lib/usd/libusd_ms.dylib`
(24.1.30 → 24.1.32) — loaded by `MDLUSDLoader` (prior art
`analysis/priv24A435_usd_entry.md`): all six "Model I/O" CVE fixes were located there.

### 4.1 CVE-2026-112565 / CVE-2026-112449 — image-dimension integer overflow — **PROVEN**

`adobe::usd::Image::allocate(int w, int h, int ch)` 24A435 @0x2c4ad5220 → 24B115
@0x2cca20798 (+424B); same for `Image::read` (+400). NEW string (24B115 only):
```
"Image::allocate: image dimensions (%d x %d x %d) are invalid or too large; refusing to allocate to avoid integer overflow"
"Image::read: decoded image dimensions (%d x %d %d ...) are invalid or too large; refusing to allocate to avoid integer overflow"
"nanoexr error: invalid or too-large image dimensions"
```
OLD body (textbook):
```
0x2c4ad523c  mul    w8, w2, w1          ; h*w      32-bit
0x2c4ad5240  mul    w8, w8, w3          ; *ch      32-bit  ← WRAPS
0x2c4ad5244  sxtw   x1, w8              ; sign-extend (negative count possible)
0x2c4ad524c  bl     #0x2c323e7a8        ; allocate(wrapped)
```
NEW:
```
0x2cca207d4  orr    w8, w2, w1
0x2cca207d8  orr    w8, w8, w3
0x2cca207dc  tbnz   w8, #0x1f, → fail   ; any negative dim rejected
0x2cca207e0  umull  x8, w21, w22        ; w*h in 64-bit
0x2cca207e8  mul    x1, x8, x9          ; *ch 64-bit
0x2cca207ec  mov    x8, #0x100000001
0x2cca207f0  cmp    x1, x8
0x2cca207f4  b.hs   → fail              ; ≥ 2^32+1 elements rejected (error+log path)
```
Overflow → undersized heap buffer written with w*h*ch elements = heap corruption.
Trigger surface: glTF/EXR imagery imported through the USD glTF path in libusd_ms
(the anisotropy/metallic-roughness processors around it grew too:
`processAnisotropyPixels*` +368×2, `translateSpecularGlossiness…` +196).

**Craft recipe:** embedded image (glTF/EXR) declaring e.g. 0x10000×0x10000×4 with a tiny
pixel buffer → wrapped alloc on 27.0, overflow during decode; 24B115 refuses with the new
log. Not auto-built (needs a glTF-with-image wrapper — harness phase).

**Mapping:** the two "integer overflow" lines 112565/112449 = allocate/read pair
(SHAPE-MATCHED split, PROVEN family).

### 4.2 CVE-2026-112461 / CVE-2026-112486 — Ptex OOB writes — **PROVEN (fix sites), CVE split SHAPE-MATCHED**

`HdStPtexMipmapTextureLoader::Block::SetSize(u8, u8, bool)` 24A435 @0x2c518cdf4
(14 instructions, zero checks) → 24B115 @0x2cd0dab84 (+428B):
```
OLD: lsl w9, w8, w1 ; lsl w8, w8, w2   ; width=1<<log2w, height=1<<log2h  (log2 = u8 from the Ptex header, up to 255 → shifts wrap)
NEW: orr w8, w2, w1 ; cmp w8, #0x10 ; b.lo ok ; …else error+log path
```
NEW strings: `"Ptex face %d has an out-of-range resolution log2 (%d, %d); skipping to avoid
an out-of-bounds write."`, `"Ptex face %d tile (%d x %d) does not fit in the texture page
(%d x %d); skipping to avoid an out-of-bounds write."`, `"Ptex face resolution log2 (%d x
%d) exceeds the maximum packable size (%d); rejecting face by treating it as 1x1."`
Also `Block::Generate` +680B with the same guards. ModelIO-adjacent reach: USD
model with a Ptex texture (QuickLook 3D / RealityKit render path); the fix strings name
the OOB-write primitive.

### 4.3 USDA text nesting — stack overflow fix — **PROVEN (site), CVE line SHAPE-MATCHED**

`Sdf_ParseLayerFromBuffer` 24A435 @0x2c43ac6e4 → 24B115 @0x2cc2f6840 (+1404B).
NEW strings: `"Maximum nesting depth for container values (lists, tuples, and
dictionaries) in the USDA text file format. Input nested more deeply than this is
rejected as a parse error to prevent a thread-stack overflow…"` and
`"Value nesting too deep (exceeds maximum depth of %zu). Increase
SDF_TEXT_FILE_FORMAT_MAX_NESTING_DEPTH if this input is trusted."` — referenced from
inside the parser (adrp xrefs at 0x2cc2fcd40… within Sdf_ParseLayerFromBuffer).
Prior art (§Hunt 2) had only per-TYPE tuple-depth checks; lists/dicts recursed unbounded.
Seed built: **`seeds/deep_nest.usda`** (20,000-deep nested lists in an asset path) and
**`seeds/deep_nest_dict.usda`** (20,000-deep nested dictionaries). Expected A/B: 27.0 =
thread stack overflow (app term); 24B115 = parse error, no crash. CVE line: fits
"unexpected app termination" shapes — most plausibly part of **112485 (memory handling)**
or a SceneKit "DoS" line — SHAPE-MATCHED.

### 4.4 USDZ entry loading — SdfZipFile rewrite — **PROVEN-AT-SITE (structural), CVE line SHAPE-MATCHED**

24B115 adds `SdfZipFile::_Impl::GetOrLoadEntryData(uint32_t, uint32_t)` (new mangled-name
string; the new out-of-line loader `sub_2cc53c1a4` right after `GetFile` carries it:
0x480-byte frame, asset `GetSize()` vtable call, `cmp x0, x8` declared-vs-actual compare,
`GetBuffer` vtable call), a 0x108→0x188-byte Impl (per-entry lazy state), and strings:
```
"[SdfZipFile] asset (size=%zu) is not readable via the no-mmap fallback path"
"[SdfZipFile] pread fallback read %zu of %u bytes at file offset %u (fd=%d)"
```
plus `SdfZipBufferDeallocateRawBuffer` +1764 and new `TfRefPtr<SdfBuffer>` machinery
(buffer-lifetime handling — the "memory handling" line **CVE-2026-112485** candidate).
OLD `SdfZipFile::Open(shared_ptr<ArAsset>)` @0x2c45eff04 mapped the archive and handed
out mapped pointers without per-entry validation (prior art §Hunt 3: `GetFile` =
`cbz x8; ldr x0,[x8,#0x40]; ret` — still true in 24B115; the NEW validation is at
entry-DATA load time). Craft recipe / seed built: **`seeds/truncated_entry.usdz`**
(valid member + a second local header declaring 1 MiB uncompressed with only 8 bytes
present). Expected A/B: 27.0 = OOB read past the archive mapping on the second entry;
24B115 = size-validation reject + pread-fallback log.

### 4.5 Not-ModelIO notes
`aaplUsdGclCodec::compressMesh` +3692 is the ENCODER (gcl write side) — the gcl decode
path shows no fix; `HdStBasisCurves::GetBuiltinPrimvarNames` +3696, `HdMeshUtil::
ComputeTriangulatedFaceVaryingPrimvar` +784, `HioImageIO_Image::Write` are renderer-side
(Hydra/Storm) — reachable from RealityKit-class consumers, not from MDLAsset alone.
Recorded, not CVE-mapped.

---

## 5. SceneKit

### 5.1 Buffer-overflow family — plist type-inits — **PROVEN** (→ CVE-2026-112464 and/or CVE-2026-86991, split SHAPE-MATCHED)

The C3D property-list type initializers in 24A435 passed the **caller-supplied register**
as the destination element count into `_C3DInitFloatArrayWithPropertyList`:

```
OLD _C3DVector4InitWithPropertyList @0x24ba41e08 (aliases _C3DVector3InitWithPropertyList — SAME address!):
0x24ba41e1c  mov   x2, x3              ; count := caller register
0x24ba41e20  b     _C3DInitFloatArrayWithPropertyList
OLD _C3DMatrix4x4InitWithPropertyList @0x24ba2d5a0:
0x24ba2d5b0  mov   x2, x3              ; same flaw
OLD _C3DColor4InitWithPropertyList @0x24b9fe430:
0x24b9fe458  mov   x2, x19 (x19=x3)    ; same flaw
```
24B115 pins each count and SPLITS the aliases:
```
NEW _C3DVector4InitWithPropertyList @0x24f7850e4:  mov w2, #0x4
NEW _C3DVector3InitWithPropertyList @0x24f785018: (separate function, w2=3)
NEW _C3DMatrix4x4InitWithPropertyList @0x24f7707b0: mov w2, #0x10
NEW _C3DColor4InitWithPropertyList @0x24f7415c0:   mov w2, #0x4
```
Callers: `__C3DNodeInitWithPropertyList` (+0x338/+0x3c0) and `__C3DSceneInitWithPropertyList`
(+0x120) pass a **plist-derived count** (`mov x3, x21`) and the destination is a
**stack slot** (`add x0, sp, #0x50`) — a node "position"/"orientation" array with >4
entries overflows a 16-byte stack vec4 on 24A435. Additionally
`__C3DInitNumberArrayWithPropertyList` (+48B, new `cold.4`) now requires
plist-count == expected count (`cmp x0, w23, uxtw; b.ne → error`) and per-element
validation with NEW string `"Error: Could not deserialize a number (%@) in a number
array"` — the OLD checked only `count < 1`.

Seed: **`seeds/oversize_position.scnplist`** (node position array with 32 floats —
schema best-effort, confirm the C3D keys in the harness phase). Expected A/B: 27.0 =
stack smash on scene load; 24B115 = clamp/refuse.

### 5.2 OOB read family — **PROVEN sites** (→ CVE-2026-112425 and/or 112423, split SHAPE-MATCHED)

`_C3DIndicesContentEnumeratePrimitivesByEvaluatingPrimitiveRanges` 24A435 @0x24ba14528 →
24B115 @0x24f7576d4 (+48B): OLD range check was a ccmp chain that let **negative**
primitive-range start/length through; NEW adds explicit sign checks:
```
NEW 0x24f757788  tbnz   x23, #0x3f, → reject   ; range start < 0 → reject
    0x24f757790  tbnz   x9,  #0x3f, → reject   ; range length < 0 → reject
    … cmp x11, x10 ; ccmp w23, w11, #2, ls ; b.hs → reject
```
`_C3DCreateTangentsWithGeometryOptimized` (+52B + new cold.8 with string `"Error: Could
not deserialize a number (%@)…"`-family logging) now validates the tangent index bound
with a 64-bit `umaddl a*(n-1)+b` against the buffer length before use
(0x24f75e164-0x24f75e17c).
`_C3DBaseTypeGetCompoundType` restructured compare-ladder → bounded jump table
(`cmp x16, #0x2e; csel…`) with NEW `"Unreachable code: Compound type %s%d is not
supported"` error paths.
`_C3DSceneSourceCreateSceneAtIndex` +148: second `GetFileFormat` result now validated
(`cmn x25, #1` reject) — defensive plumbing.

---

## 6. Sibling census (new-bug candidates for OUR disclosure)

| # | Candidate | Evidence | Unchecked field / consuming path |
|---|---|---|---|
| S1 | **SceneKit variable-length plist consumers**: the count-pinning fix covered ONLY the fixed-size types (vec3/4, color4, matrix). `__C3DMeshSourceInitWithPropertyList`, `__C3DGeometryInitWithPropertyList`, `__C3DImageInitWithPropertyList` take plist arrays with legitimately-variable counts — if any of them copies a plist count into a fixed inline buffer, the same overflow family is LIVE on 24B115 | §5.1 diff scope | Mesh source/geometry/image arrays in the C3D plist scene loader |
| S2 | **FontParser scan BITMAP buffer vs scratch buffer**: the Checked trio validates the scratch size and row base, but `RenderBitmap` also writes the destination `scalerBitmap` whose dims come from the same `sc_BitMapData` — whether the destination bitmap allocation uses the same checked product was not yet verified | §2.1 | `sbit_GetBitMapInfo`/`ComputeDestBitmap` changed too (+52/−76) — audit whether ALL products of the (possibly wrapped) extents are checked on 24B115 |
| S3 | **CoreText GDEF siblings**: the caret fix clamps the LigCaret chain; the OTHER GDEF consumer — `AttachList`/`AttachPoint` (attachment points, same offset-chasing shape) — was not touched in this window; check `TBaseFont` attachment-point readers for the same unchecked table-relative offset | §3 | `GetAttachmentPoints`-class functions, GDEF attachList offsets |
| S4 | **libusd_ms gcl DECODE path**: `compressMesh` (encode) got +3692 of changes, the gcl mesh DECODER did not move in this window — audit it for the same product-wraps the image/Ptex fixes just closed | §4.5 | gcl mesh decode from USDZ |
| S5 | **SceneKit `_C3DSceneSourceCreateSceneAtIndex` index argument**: the +148 growth validates the file-format result; the scene *index* argument itself (`x1`) — verify it is bounds-checked against the scene count on both builds (classic OOB read sibling) | §5.2 | scene-source index |
| S6 | **Image::allocate bound semantics**: NEW accepts up to 2^32+1 ELEMENTS — 4-channel float RGBA can still demand ~68 GB → allocation-failure DoS, and the check is on elements not bytes (channels*4 can exceed). Low severity, note for hardening report | §4.1 | w*h*ch*4 byte count |

---

## 7. Seed & craft inventory

| seed | targets | oracle |
|---|---|---|
| `seeds/gdef_caret_oob.ttf` | CoreText 112656 | 27.0: OOB read/crash in `GetLigatureCaretPositionsForGlyph`; 24B115: clamp+reject |
| `seeds/huge_bbox.ttf` | FontParser 112683 | 27.0: scan-scratch OOB write on draw at ≥512pt; 24B115: TException |
| `seeds/deep_nest.usda`, `seeds/deep_nest_dict.usda` | libusd_ms USDA nesting | 27.0: parser stack overflow; 24B115: "Value nesting too deep" parse error |
| `seeds/truncated_entry.usdz` | libusd_ms SdfZipFile | 27.0: OOB read on oversized entry; 24B115: size-validation reject + pread-fallback log |
| `seeds/oversize_position.scnplist` | SceneKit plist family | 27.0: stack smash in node transform load; 24B115: pinned count |
| (recipe only) Type1 charstring underflow | FontParser 86970/112642 | manual charstring surgery — harness phase |

Scripts: `scripts/mkfont.py` (from-scratch TTF builder, validated vs fontTools + macOS
CoreText), `scripts/mkseeds.py`, `scripts/msym.py`, `scripts/funcdiff.py`,
`scripts/codealign.py`, `scripts/sbs.py`, `scripts/xref.py`, `scripts/adrpxref.py`,
`scripts/{fpdump,skdump,mdiodiffs}.py` (receipt dumpers). Symbol dumps + diffs:
`scripts/symjson/{24A435,24B115}/*.txt` and `diff_*.txt`.

## 8. Provenance grades

- PROVEN fix sites (both-side receipts): FontParser scan-scratch (112683), FontParser
  charstring stacks (86970/112642 family), CoreText lcaret (112656), libusd Image
  allocate/read (112565/112449 family), libusd Ptex (112461/112486 family), libusd USDA
  nesting cap, SceneKit plist count-pins (112464/86991 family), SceneKit primitive-range
  sign checks (112425/112423 family).
- PROVEN-AT-SITE (structural, some semantics inferred): libusd SdfZipFile entry-loader
  rewrite (112413/112485 candidates).
- SHAPE-MATCHED: every CVE↔site split within a family (86970↔112642, 112565↔112449,
  112461↔112486, 112464↔86991, 112425↔112423, USDA-nesting CVE line) — needs
  beta-window bisection or Apple credit to pin individually.
- Honest negatives: ModelIO dylib itself — no security-shaped delta; USDObjCKit — plain
  rebuild; `SelectOpticalStyleFromOS2` +2348 / `TFont::Hash` +236 / shaping churn in
  CoreText — feature-grade, not claimed.
