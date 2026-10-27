# FINDINGS.md — ImageIO CVE cluster (iOS 27.2 advisory 149230): the 24A435→24B115 fix map, triggers, and sibling census

> AI-generated security research (same notice as AGENTS.md). Authorized research on the
> project owner's device (iPhone 16e, iOS 27.0 RC 24A435) + Apple's publicly-shipped
> firmware, for coordinated disclosure. PoCs are **crash-oracles only**.
> Method: METHODOLOGY §1/§4/§4a/§5 (fix-diff; every check Apple ADDED is an admitted bug,
> live on 24A435). Written 10-27 by the ImageIO subagent. **Re-verify before trusting.**

## 0. Scope, assets, base math

- Component: **ImageIO 2851.0.0.0.0 (24A435, vulnerable, ON OUR DEVICE) → 2851.1.8.0.0
  (24B115, iOS 27.2 RC, the fix build)** — version delta confirmed via
  `ipsw dyld info <dsc> --dylibs` on both caches.
- Extracted: `extracted/24A435/ImageIO`, `extracted/24B115/ImageIO`
  (base: 24A435 `__TEXT` vmaddr 0x1878b2000, 24B115 0x187822000; fileoff = VA − base).
- Receipts: `receipts/*.disass` (both-side raw dumps, this session).
- Advisory target set: **11 ImageIO memory CVEs** (149230):
  - OOB write / bounds checking → app termination: **CVE-2026-112633, CVE-2026-112614**
  - OOB read → app termination or **disclosure of process memory**: **CVE-2026-112634, CVE-2026-112629, CVE-2026-112561, CVE-2026-112627**
  - uninitialized memory → **disclosure of process memory**: **CVE-2026-112632, CVE-2026-112630, CVE-2026-112571**
  - buffer overflow → **corrupt process memory**: **CVE-2026-112488**
  - **integer underflow** → memory corruption: **CVE-2026-112625**
- **Prior art (DONE, do not redo)**: the JPEG-EXIF/HEIF thumbnail `offset+length` family —
  `_CGImagePluginInitThumbJPEGAtOffsetWithOptions` callee gate + `IIO_Reader_LibJPEG::initThumbnail`
  + `IIO_Reader_AppleJPEG::initThumbnail` + `IIO_Reader_HEIF::extractImageInfo` — localized
  instruction-level in `analysis/entry_callers_imageio.md` §5 (all four sites re-confirmed present
  in this diff; initThumbnail +44/+36, extractImageInfo +76, callee +108). Reach:
  `CGImageSourceCreateThumbnailAtIndex(Ex)` on a crafted-EXIF-IFD1 JPEG; PoCs already staged (`poc/`).

## 1. The fix-site inventory (PROVEN unless labeled)

Diff cost ladder: cstring diff (125 added strings; `scripts/ds_iio_cstring_diff.py`) →
function-size diff over 14,266 common text syms (456 changed; `scripts/ds_iio_fndiff.py`) →
string→function xref (`scripts/ds_iio_strxref.py`) → both-side disassembly (`receipts/`).

| # | Fix family (24B115 additions) | 24A435 (vulnerable) | 24B115 (fixed) | Receipt |
|---|---|---|---|---|
| **A** | **TIFF planar scatter capacity gate** — `TIFFReadPlugin::decodeStripPlanar` (948→1064B) + `decodeTilePlanar` (1088→1120B) | scatter write-pointer offset computed **32-bit** (`mul w21, w8, w22` @0x187d99228) and written with **no capacity compare** | 64-bit `umull` need-vs-capacity compare @0x187d0eed0–e8 → `"*** ERROR: decodeStripPlanar destination row is %u bytes, the scatter needs %llu"` (tile: @0x187d0f688–94 + "cannot handle %d bytes/component") | PROVEN |
| **B** | **libTIFF dir-entry array alloc overflow** — all 8 `TIFFReadDirEntry{Short,Sshort,Long,Slong,Long8ArrayWithLimit,Slong8,Float,Ifd8}Array` (+16 each) | output alloc size = **32-bit truncated** `lsl w0, count, #log2(elemsize)` (e.g. ShortArray @0x18795a940–54; Long8 @0x18795c138 `lsl w0,w25,#0x3`) then per-element conversion loop writes `count` entries → heap OOB write on wrap | new `_TIFFCheckMalloc_type(tif, count, elemsize, type, __func__)` (e.g. @0x1878cb17c; `__func__` literals 0x187dcb9b3…0x187dcc0fd) — 64-bit checked size | PROVEN |
| **C** | **ImageIO PDF rasterize buffer gate** — `PDFReadPlugin::decodeImageData` (724→784B) | rasterizes the PDF page into the caller's decode buffer with **no size validation** (0x187aaafec falls straight to page setup) | `umull x27, w24, w23; cmp x27, x21; b.hi` @0x187a1c590–98 → `"*** decode buffer too small: need %zu bytes (%zu x %zu), have %zu"` → return −0x32 | PROVEN |
| **D** | **JPEG marker-length gate** — `_JPEGFile::processData` | oversized marker length = `"*** WARNING: check markerLength: %d"` @0x187969914 and **parse continues** (OOB read) | `"*** ERROR: markerLength too big: %u max: %zd"` (+ "too small (%d)") @0x1878da2f8/8da2dc → abort | PROVEN |
| **E** | **APPx marker write clamp** — `_APPx::writeToStream` (72→168B) | writes `length` bytes from `base+offset` to the output CFWriteStream with **zero bounds math** (0x187b294b0–c8) — OOB heap bytes are **written into the emitted JPEG file** = disclosure in the output artifact | computes `end−offset`, `csel` clamps the write, `"*** ERROR: marker 0x%04X is out of bounds (offset %llu, length %u, size %zd) - skipping"` @0x187a9c018–6c | PROVEN |
| **F** | **GPS-IFD bounds rewrite** — `GPSCopy::processData` (988→1880B) + 4 new helpers + new `OutOfBounds` C++ exception class | GPS-IFD walk via raw dereferences + a single unchecked `read32` (old 0x187b20948, removed) | every access via new `checkCapacity` / `checkInitializedLength` / `pointerToOffset` / `read32Unchecked` (throwing OutOfBounds on violation) | PROVEN |
| **G** | **Compressed-texture cluster** — `ASTCReadPlugin::initialize` (+656), `BCReadPlugin::initialize` (+1152), `KTXReadPlugin::initialize` (+392), `KTX2ReadPlugin::initialize` (+56), KTX/KTX2 `decodeImageImp` (+836/+1008), new `_sniffDDS`/`DDSDXGIFormatIsASTC`/`dds_dx9_packed_format_for_masks` | truncation = `"*** WARNING: file truncated. Only the first %lu miplevels..."` @0x187ab16e0 + decode continues (block decoder reads past data); block-byte math unchecked; KTX check used the wrong quantity ("channels") | zero-complete-miplevel = hard error (`"*** ERROR: BC (KTX) no complete miplevel in file"` @0x187a23174); 64-bit `umull/umulh` mip size math @0x187a2275c–78; `"*** bad DDS/ASTC width/height %u"` + `"*** DDS/ASTC: image dimensions overflow"` (`lsr x9,x8,#0x3c; cbnz` @0x1878fde10) + `"*** bad DDS/ASTC data: expected %llu bytes"` @0x1878fde3c + `"*** bad packed KTX: [%ldx%ld] fileSize: %d"` (srcBpp semantics, 64-bit getSize) + channel-coverage (`"*** RGBX coverage? bitMask"`, `"*** overlapping G-A/B-A channels"`) | PROVEN (old KTX/BC bounds existed but were conditional on the LZFSE path / wrong quantity — the negative space is the plain-DDS/BC7/KTX path) |
| **H** | **APNG fcTL truncation validation** — `IIO_Reader_PNG::getImageCount` (1392→1536B) | reads **34 bytes** at the fcTL offset (`mov w3,#0x22` @0x1878edf48) with **NO return check** — a file truncated mid-fcTL leaves a 34-byte **stack buffer uninitialized**, parsed as frame geometry (w/h/x_off/y_off/delay); dims checks existed, the short-read path did not | reads **26 bytes**, `cmp x0,#0x1a; b.ne` @0x1878dfe8 → `"*** truncated 'fcTL' chunk at offset %ld"`; chunk-header read gated (`"*** truncated chunk header"`) + `"*** bad 'fcTL' chunk size at offset %ld: %u"` seq/frame-count receipts | PROVEN |
| **I** | **TIFF chunky zero-fill** — `TIFFReadPlugin::decodeStripChunky` (1228→1308B) | **ignores the `TIFFReadEncodedStrip` return** @0x187953338 — on read failure scatters the **uninitialized malloc'd strip buffer** into the output image (uninit-heap → disclosure in decoded pixels) | `cmn x0,#1; b.ne` @0x1878c3b38 → `"*** TIFFReadEncodedStrip(%d) failed - strip %d is zero-filled"` | PROVEN |
| **J** | **EXIF UserComment short-read** — `ReadUserComment` (668→724B) | `getBytesAtOffset(buf, off, count)` return **unchecked** → short read leaves the malloc'd buffer tail uninitialized, served as the UserComment metadata value | `cmp x0, x3` @0x187a45dac → `"*** ERROR: short read for tag %d, count: %d"` | PROVEN |
| **K** | PVR bpp-vs-channel-bits — `PVRReadPlugin::initialize` (+76) | channel-bits *match* checks existed (`_greenBits/_blueBits vs _redBits`) but **no total-bpp lower bound** | `"*** _bitsPerPixel %d is too small for 4 channels of %d bits [%d-%d-%d-%d]"` @0x187a5954c | PROVEN (check added; exact OOB direction runtime-dependent) |
| L | TIFF dir plumbing (error receipts: `"*** ERROR: TIFFSetDirectory failed"`, `"updateTiffStruct failed..."`, `decodeTileChunky` +48 read-path refinement, `loadTIFFStructure` +40) | error handling upgrades | — | SHAPE-WEAK (error-handling grade; not counted as a CVE site) |
| M | XMP extended-block reassembly (`CGImageCreateCombinedXMPData` +68: `"no XMP could be reassembled"`) | empty-reassembly handled | — | SHAPE-WEAK |
| N | **Feature churn, no security shape**: PSD 8BIMiOpa opacity/hidden-layer feature (`parseLayers` +160, `mergeLayers` +488 — the new rect checks already existed in 24A435 @0x187b6a63c–48; "cannot apply opacity" guards live inside the NEW feature); ICO/KTX/PSD/BMP writers; ISO5/AVLL/HDR color metadata (`IIO_CreateMergedISO5Metadata` etc.); XMP SDK rebuild (build-UUID churn); `HEIFReadPlugin::initialize` +1268 (XMP/ISO5 feature + 1 error receipt); APNG `PNGReadPlugin::DecodeComposedImage` +304 (SDR-conversion buffer receipt) | — | — | NO SECURITY DELTA CLAIMED |

Sites A–K = 11 proven/strong fix families ≈ the advisory's 11 CVEs (1:1 accounting is
SHAPE-MATCHED, see §2). Note the delta spans the whole 27.0→27.2 window (feature-scale
b1 mixing included); window-attribution per beta was NOT re-derived here (see
METHODOLOGY §2 for how; the JPEG-EXIF family is known b4→RC only).

## 2. CVE mapping (SHAPE-MATCHED — Apple publishes no CVE→site map)

| CVE line | Candidate site(s) | Confidence |
|---|---|---|
| OOB write ×2 (112633/112614) | **A** (TIFF planar/tile scatter heap OOB write), **C** (PDF rasterize decode-buffer OOB write) | strong shape (write+bounds) |
| OOB read ×4 (112634/112629/112561/112627) | **D** (marker length), **E** (APPx stream write = OOB READ whose bytes land in the output file — the advisory's "disclosure" wording fits E best), **F** (GPS), **G** (texture cluster) | strong shape; per-ID assignment unresolvable |
| uninit ×3 (112632/112630/112571) | **I** (uninit strip → decoded pixels), **J** (uninit EXIF UserComment → metadata value), **H** (uninit stack as APNG frame geometry) | strong shape (three distinct uninit→disclosure sites ↔ three uninit CVEs) |
| buffer overflow → corrupt (112488) | **B** (count×elemsize 32-bit alloc overflow → heap smash in the conversion loop) | strong shape |
| integer underflow (112625) | **B** wrap class or **A**'s old 32-bit offset math (`sub`-underflow shape), or **K** (bpp < channel-bit sum) | ambiguous — SHAPE-MATCHED only |

Also live and CVE-relevant: the prior-art EXIF/HEIF thumbnail `offset+length` family
(`analysis/entry_callers_imageio.md`) fits the OOB read/write lines; exact ID unresolvable
(credits: Jurczyk/Tsytsarkin/Choi/Raj/Duszynski/sh3rlock — no Calif name).

## 3. Trigger + craft recipe per family (crash-oracle ONLY)

All families reach from **app context** via `CGImageSourceCreateWithData` /
`CGImageSourceCreateThumbnailAtIndex` / `CGImageDestination*` / `CGImageCopyFileWithGPSInformation`
on a file the app was handed (attachment, download, AirDrop). Seeds in `seeds/`
(generator: `scripts/ds_iio_seeds.py`; run `python3 scripts/ds_iio_seeds.py`).

| Seed | Family | Craft (container → field) | Expected 24A435 | Expected 24B115 |
|---|---|---|---|---|
| `ds_iio_tiff_planar_scatter.tif` (2.2KB) | A | TIFF: `PlanarConfiguration=2`, `SamplesPerPixel=4`, `Photometric=RGB(2)`, BPS=[8,8,8,8] → 4th plane scatters past the RGB-sized destination row | heap OOB write in `decodeStripPlanar` → crash (SIGSEGV in the scatter loop) or corrupt output | `"*** ERROR: decodeStripPlanar destination row is %u bytes, the scatter needs %llu"` + clean failure. Permutations if no crash: SPP∈{2..6} × Photometric∈{0,1,2,6} × BPS∈{8,16,32} |
| `ds_iio_tiff_trunc_strip.tif` (434B) | I | TIFF: 2 strips, 2nd physically truncated (16B present, `StripByteCounts` claims 512) | decode "succeeds"; output pixels of strip 2 = **uninitialized heap** (disclosure oracle: non-reproducible pixel values across runs; or crash) | `"*** TIFFReadEncodedStrip(%d) failed - strip %d is zero-filled"` — output deterministic zeros |
| `ds_iio_apng_trunc_fctl.png` / `..._fctl2.png` (94/102B) | H | PNG + `acTL(2 frames)` + `fcTL` truncated at 4 bytes / proper chunk header claiming 26B with 4B present | 34-byte stack buffer at [sp+0x50,0x72) parsed as frame geometry → garbage APNG frame (uninit stack) → decode crash/garbage | `"*** truncated 'fcTL' chunk at offset %ld"` + `"*** bad 'fcTL' chunk size ..."` |
| `ds_iio_jpeg_markerlen.jpg` (366B) | D | JPEG: APP1 marker declaring length 0xFFEE with ~30 bytes of payload present | `"WARNING: check markerLength"` in the log then **OOB parse continues** (crash or garbage EXIF) | `"*** ERROR: markerLength too big: %u max: %zd"` + abort, no crash |
| `ds_iio_exif_usercomment.jpg` (370B) | J | JPEG: EXIF IFD0 `UserComment` (0x9286) type 7 count 0x400, value offset just past the marker | `CGImageSourceCopyPropertiesAtIndex`/metadata read returns **stale heap bytes** as the comment (disclosure; compare across runs/heap states) | `"*** ERROR: short read for tag %d, count: %d"` |
| `ds_iio_exif_gps_oob.jpg` (404B) | F | JPEG: EXIF GPS IFD whose entry value-offsets point +0x10000/+0x20000 past the tiny GPS blob | `CGImageCopyFileWithGPSInformation` → raw deref past the GPS buffer → crash (SIGSEGV in `GPSCopy::processData`) | OutOfBounds exception caught → error, no crash |
| `ds_iio_dds_trunc_mip.dds` (192B) | G | DDS: BC7 fourCC, 512×512, mipmapcount 1, 64 bytes of data (needs 65536) | truncated-miplevel WARNING + block decode reads past data → crash | `"*** ERROR: BC (KTX) no complete miplevel in file"` + dimension/data-size gates |
| (big-file oracle, not pre-generated) | B | TIFF with an IFD entry type 6 (SBYTE), **count = 0x20000000** backed by a **sparse 512MB file**; `TIFFReadDirEntryLong8ArrayWithLimit` conversion path: alloc = `(count<<3) mod 2^32` = 0 → conversion loop writes 4GB → immediate crash. Generate on-device (sparse) via a variant of `ds_iio_seeds.py`; 24B115's `_TIFFCheckMalloc_type` rejects | crash in the conversion loop; or 0-byte alloc + SIGSEGV | `_TIFFCheckMalloc_type` overflow check → tag read error |

Non-crash disclosure oracles (E, I, J) are the *fingerprinting* receipts; crash oracles (A, B,
D, F, G, H) are the .ips receipts. **Local macOS qlmanage is not a valid oracle** (hangs on
controls too — prior art, poc/README.md); the A/B must run on the 27.0 RC device vs a 27.2
device/simulator build.

## 4. Sibling census — the checks Apple did NOT add (new-bug candidates, OUR credit)

Each candidate = a parsed field in the same class as a fix Apple shipped, left unchecked in
24B115 (i.e., live on BOTH builds — reportable under our name):

1. **`writeToStream` family (E's siblings)** — 25 `*::writeToStream` implementations exist
   (`_APP0`, `_APP1`, `_APP3`, `_APP13`, `_APP1XMP`, `_APP2ICC`, `_APPData`, `_APP1Exif`,
   `_APP1ExtendedXMP`, `_MPEntry`, `GlobalMPOInfo`, `IIOColorMap`, `GIFBufferInfo`,
   `HEIFItem`/`HEIFMainImage`/…). Apple clamped **only `_APPx`**. Any sibling still writing
   `(buffer+offset, length)` unvalidated on the CGImageDestination re-encode path = the same
   OOB-read-into-output-file disclosure. **CANDIDATE — audit needed** (I did not prove another;
   the class is proven by the `_APPx` fix shape).
2. **APNG `fdAT` frame-data truncation (H's sibling)** — fcTL got truncation checks; the
   per-frame `fdAT` compressed-data reads on the decode path (`PNGReadPlugin::DecodeComposedImage`,
   which also changed, SDR-related) were not visibly gated the same way. A truncated `fdAT`
   (IDAT-style stream) → uninit/garbage frame rows? **CANDIDATE** — consume path:
   `CGImageSourceCreateImageAtIndex` on a multi-frame APNG.
3. **TIFF tile-path short reads (I's sibling)** — `decodeStripChunky` now zero-fills failed
   strips; `decodeTileChunky`'s `TIFFReadTileWithSize` error path only checks `== -1` (both
   builds) — a **short (non-error) tile read** may still leave partial-uninit tile buffers in
   the scatter. **CANDIDATE** — truncated-tile TIFF, decode, inspect determinism.
4. **PVR channel-count variants (K's sibling)** — the new bpp-vs-bits check names **"4
   channels"** only; the 1/2/3-channel PVR variants keep whatever arithmetic existed.
   **CANDIDATE** — PVR with bpp < sum of channel bits in a 1- or 3-channel variant.
5. **BC coverage guards only on the RGBX path** — `BCReadPlugin` grew `decode1010102toRGBA16`,
   `decodePacked16toRGBA16`, `decodeUncompressedToRGBA` (new refactor targets) while the
   bitMask-coverage validation receipt (`"*** RGBX coverage? bitMask: %08X"`) looks
   log-shaped on the RGBX path only. **CANDIDATE** — bitMask that covers no RGB channel on the
   RGBA16 paths.
6. **ICO read-side header consistency** — the ICO *writer* got
   `"bytes is too small for a BITMAPINFOHEADER"` / `"header %u + pixels %zu + mask %zu exceeds %zu"`
   checks; the *reader* (`ICOReadPlugin::decodeImageData`) checks read counts but BITMAPINFOHEADER
   field consistency (biBitCount vs palette, biClrUsed) is unverified both builds. **CANDIDATE**
   (weak) — needs a focused read-side audit.
7. **`GPSCopy::adjustIFDOffsets` / `CreateGPSBufferFromPropertiesTIFFNew`** — unchanged
   functions now called behind the new checks; any OTHER caller of these (if any) inherits the
   old trust. **CANDIDATE-lite** — enumerate callers.

Not siblings (checked, negative): `TIFFReadDirEntryDoubleArray` (already 64-bit `ubfiz x0,x21,#3,#32`
— safe), `ByteArray` (no second alloc), `IIO_Reader_MPO::initThumbnail` (already `getSize` +
`adds`-overflow math in 24A435), `decodeTileChunky` error check (pre-existing `cmn x0,#1`).

## 5. What this session produced

```
cve_groups/01_imageio/
  FINDINGS.md            <- this file
  HARNESS_ROW.md         <- probe-row spec for the device run
  extracted/24A435/ImageIO, extracted/24B115/ImageIO
  receipts/              <- 28 both-side disassembly dumps (the raw evidence)
  scripts/ds_iio_cstring_diff.py   (string diff, __cstring only)
  scripts/ds_iio_fndiff.py         (function-level size diff via symtab)
  scripts/ds_iio_strxref.py        (adrp+add xref: cstring VA -> referencing function)
  scripts/ds_iio_seeds.py          (crash-oracle seed generator)
  seeds/                  <- 8 crafted files (crash-oracle only)
```

Reproduction (static side):
```bash
ipsw dyld info "<dsc24A435>" --dylibs | grep ImageIO    # version oracle
python3 scripts/ds_iio_fndiff.py extracted/24A435/ImageIO extracted/24B115/ImageIO
python3 scripts/ds_iio_seeds.py                          # regenerates seeds/
ipsw macho disass extracted/24B115/ImageIO --vaddr 0x187a9bfe0   # e.g. _APPx fix
```

## 6. Honest labels

- Every "PROVEN" above means: both-side instruction-level receipts captured in `receipts/`
  (vulnerable form in 24A435, fixed form in 24B115), static analysis only.
- CVE→site mapping is **SHAPE-MATCHED** (Apple publishes no CVE→fix-site map); per-ID
  assignment within a class (e.g. which uninit CVE is J vs I) is unresolvable without
  researcher disclosure or device A/B fingerprints.
- No runtime validation yet — the seeds are staged for the on-device run (HARNESS_ROW.md);
  per METHODOLOGY §5 the pair (27.0 crash + 24B115 refusal log) is the discriminator.
- Feature churn is labeled as such (§1N) — PSD/HEIF/ISO5/XMP-SDK deltas are NOT claimed
  as security fixes.
