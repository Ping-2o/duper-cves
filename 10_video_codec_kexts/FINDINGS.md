# FINDINGS.md — Group 10: the video codec kernel stack (AppleAVD + AVEVideoEncoder), iOS 27.2 advisory 149230

> **NOTICE — AI-GENERATED SECURITY RESEARCH** (same terms as AGENTS.md). Written 100% by autonomous
> AI agents. Authorized security research on the owner's devices + Apple's publicly-shipped
> firmware; coordinated-disclosure aim; PoCs are crash-oracles only. Every claim cites a receipt
> (file + address + disassembly line) or an explicit SHAPE grade; re-verify before trusting.

**Scope**: 9 CVEs from advisory 149230 (iOS 27.2, released 10-26-2026), device pair iPhone17,5
24A435 (27.0 RC, pre-fix, = our device, security-equivalent to 27.0.1/24A446) → 24B115 (27.2 RC,
fixed). The bug FAMILY was already mapped by prior art; this group's job is **per-CVE site
assignment** + sites the family map missed + the sibling census.

**Assets** (quoted volume name "ADATA ELITE SE880"):
- Kexts pre-carved: `.../24A435__iPhone17,5/kexts/com.apple.driver.AppleAVD` (993.1) /
  `com.apple.driver.AppleAVE2` (913.43.1); `.../24B115__iPhone17,5/kexts/` (AppleAVD **995.0**,
  AppleAVE2 **913.64.1**) — versions verified via `LC_SOURCE_VERSION` (receipt below).
- Userspace plugins pre-carved: `.../plugins_24A435/{AVD.videodecoder,ave.videoencoder}` (993.1 /
  913.43.1) and `.../plugins_24B115/` (**AVD.videodecoder 995.0**, ave.videoencoder 913.64.1).

**Version receipts (otool -l, LC_SOURCE_VERSION)**: AppleAVD kext 993.1→995.0; AppleAVE2 kext
913.43.1→913.64.1; AVD.videodecoder 993.1→995.0; ave.videoencoder 913.43.1→913.64.1.
NOTE: the ipsw-diffs "996" naming for the RC plugin in prior docs resolved to **995.0** at RC —
the MV-HEVC layer-validation + slice-cap window (b4→RC) IS this 993.1→995.0 pair.

**Method**: strings-diff first (METHODOLOGY §4) → symbol-based function-level diff (plugin pairs
have full LC_SYMTAB, 6628/1539 syms) → capstone instruction-level diff of every changed function
→ kext side: shift-robust 32-byte chunk-hash census + assert-string xref (kexts have no symtab).
Tools written for this group: `scripts/ds_fn_diff.py`, `ds_idiff.py`, `ds_disas.py`,
`ds_strxref.py`, `ds_scan_store.py`, `ds_kext_chunkdiff.py`. All raw receipts in `extracted/`.

---

## 1. The advisory lines, verbatim (support.apple.com/en-us/149230, fetched 10-28)

| CVE | Apple impact | Apple fix line | Credit |
|---|---|---|---|
| CVE-2026-112416 (AppleAVD) | "Processing a maliciously crafted video file may lead to unexpected app termination" | OOB write, **improved bounds checking** | anonymous, Dohyeon An @PILAB, **Hcamael & 章鱼哥@aipy**, Narendra Singh, Nik Tsytsarkin |
| CVE-2026-112415 (AppleAVD) | "An app may be able to cause unexpected system termination or corrupt process memory" | OOB write, **improved input validation** | **Hcamael & 章鱼哥@aipy**, Rahul Raj |
| CVE-2026-112454 (AppleAVD) | "Processing a maliciously crafted video file may lead to unexpected app termination or corrupt process memory" | **improved memory handling** | @Licht_jb, **Hcamael & 章鱼哥@aipy** |
| CVE-2026-112705 (AVEVideoEncoder) | "An app may be able to cause unexpected system termination" | OOB write, **improved bounds checking** | **Marco Schmitt, Andrey Chernykh, Josh Maine of Calif.io** |
| CVE-2026-112689 (AVEVideoEncoder) | "unexpected system termination or corrupt kernel memory" | OOB write, **improved input validation** | Franco Belman (Blackwing Intelligence) |
| CVE-2026-112470/112469/112468 (AVEVideoEncoder) | "unexpected system termination or corrupt kernel memory" | OOB write ×3, **improved bounds checking** | **Hcamael & 章鱼哥@aipy** |
| CVE-2026-112466 (AVEVideoEncoder) | "unexpected system termination or **read kernel memory**" | OOB read, **improved input validation** | **Hcamael & 章鱼哥@aipy** |

Reading of the impact lines that drives everything below:
- **All three AppleAVD impacts are PROCESS-memory / app-termination** (not kernel) → the fix sites
  must live in the **in-process userspace plugin `AVD.videodecoder`** (VideoToolbox loads it into
  the decoding process). The kext diff corroborates (§2.1: no new validation anywhere in it).
- The AVEVideoEncoder impacts are **kernel memory** → fix sites in the AppleAVE2 kext (+ the
  plugin's own FIG setters, which front the same fields).

---

## 2. THE FIX INVENTORY — every changed validation site, both pairs

### 2.1 AppleAVD kext 993.1 → 995.0 — NO security-fix content (negative, receipted)

- `__text` 0x68a14 → 0x68a1c (**+8 bytes total**). Strings delta: **9 added / 19 removed, ALL
  compiler junk** (`extracted/strings_{added,removed}_AppleAVD_kext.txt`) — zero new
  log/assert strings, i.e. no new validation anywhere (a bounds-fix in this codebase always
  ships with a rejection log — cf. the plugin and AVE2 fixes).
- Shift-robust chunk census (`scripts/ds_kext_chunkdiff.py`,
  `extracted/chunkdiff_AppleAVD_kext.txt`): 2473 changed regions ≈0x2eb98 of 0x68a14 —
  **pervasive small-offset churn** (the daemon↔kext video-context/frame-param structs gained
  fields; every struct-offset access changed), not function-scale rewrites.
- Prior art (REPORT_CALIF_CHAIN.md §4a, BN function-by-function): the only two structural
  changes — `AppleAVDUserClient::processFrameDone` +80 (inlining refactor) and
  `AppleAVDCommandPatcher::addFrameRefToMemory` +4 (log shuffling) — were REFUTED as security
  fixes. My independent strings+census data corroborates: **the AVD kext carries none of the
  three AVD CVE fixes.**

### 2.2 AVD.videodecoder plugin 993.1 → 995.0 — THE AVD FIX CARRIER (5 fix sites)

Function-level diff (`extracted/fndiff_AVD_videodecoder.txt`): 19 size-changed symbols of which
10 are symbol-order noise (thunks/typeinfo); real changed functions and their fixes:

**(F1) AVC slice cap — the parse bound is now the platform's real slice capacity.**
- Strings: `AVC_MAX_SLICES` (compile-time) REMOVED; `m_avc_max_slices` + `"too many slices!"`
  ADDED.
- `AVC_RBSP::parseNALUs` (old 318 → new 325 ins): old bound `cmp w27, #0x384` (900) replaced by
  ```asm
  ldrh w8, [x20, #0x16]     ; m_avc_max_slices (per-frame parser input)
  cmp  w8, #0x384
  csel w8, w8, w9(0x384), lo ; cap = min(m, 900)
  str  w8, [sp, #8]  ... ldr w8,[sp,#8]; cmp w27, w8   ; slice count vs THE CONFIGURABLE CAP
  ```
- `CAVDAvcDecoder::processParserOut`: same replacement at the slice-count check
  (`cmp w21, #0x384` → `ldrh w23,[x0,#0x1d34]; cmp w21, w23`) + the `.cold.2` "too many slices!".
- `CAVDAvcDecoder::VAStartDecode`/`VADecodeFrame`: NEW `ldrh w9,[x0,#0x1d34]; strh w9,[x8,#0x16]`
  — propagate the member into the parser input each session-start/frame.
- **The bug shape (why it was OOB)**: the per-generation HW decoder work area has been sized by
  `m_avc_max_slices` in BOTH builds — `CAHDecTansyAvc::C2`: `w8 = *(u16*)(dec+0x1d34)*0x3bc +
  0x2c8a0 → [this+0x1b0]` (allocation size; identical in 993/995, receipt
  0x22a372b10 / 0x22c500bf8) — while the parse path accepted up to 900 slices. **Any generation
  whose real capacity `m < 900` accepted slice counts in `(m, 900]` and walked per-slice work
  structs past their allocation** → OOB write in the decoding process. The fix aligns the parse
  cap with the allocation size. `m_avc_max_slices` (+0x1d34) has no immediate writer in either
  build (bulk kext createDecoder-output copy — platform/session-derived), read by every
  generation's `initPicture`/`populateAvdWork`.

**(F2) MV-HEVC requested-layer validation — NEW input-validation chain in
`AppleAVDWrapperHEVCDecoderSetProperty`** (920 → 987 ins; cold.7/8/10/11/12 new):
```asm
0x22c4d32f8: ldr w21, [x19, #0x1458] ; wrapper state
             cmp w21, #2 ; b.lo ok    ; decoding started → "cannot be changed after decoding has started"
0x22c4d3394: CFArrayGetCount < 1 → error
0x22c4d3418: cmp w25, #0x40 ; b.hs cold.10  ; layer id >= 64 → "videoLayerID %d out of range [0,%d)"
0x22c4d3424-0x22c4d344c: loop over wrapper+0x2035 byte array (count at +0x2030, csel-clamped 63):
             layer id must appear in the VPS-declared list, else cold.8 "videoLayerID %d not declared in VPS"
cold.11 = "invalid layer id at index %d"  (CFNumber sanity)
```
(receipt: `extracted/avd995_setproperty_mvc_handler.txt`; strings delta; the property key
`kVTDecompressionPropertyKey_RequestedMVHEVCVideoLayerIDs` xref'd to this handler.)

**(F3) MV-HEVC layer-count bound in `calcLayersToDecodeFromDisplayLayersList`** (87 → 101 ins,
new `.cold.1`):
```asm
0x22c5eb6b0: and w8, w20, #0xff   ; numLayersToDecode
             cmp w8, #3
             b.hs cold.1          ; > 2 → "calcLayersToDecodeFromDisplayLayersList ERROR: numLayersToDecode %d exceeds supported 2" → return -1
```
(the count is derived from the FILE's VPS-declared layers ∩ requested layers — pre-fix unbounded
into the ≤2-layer per-layer consumer arrays.)

**(F4) Histogram IOSurface attachment — raw pointer → random cookie ("memory handling").**
- NEW import `_arc4random_buf` (undefined-sym diff receipt) used in `AppleAVDOpenConnection`:
  `add x0, x20, #0xf20; mov w1, #8; bl <arc4random_buf>` — 8 random bytes into the video context.
- `attachHistogramToIOSurface` (+4): OLD `str x19, [x8, #8]` — **the raw context pointer was
  embedded into the 0x220-byte blob attached to the decode-output IOSurface** (an app-readable
  surface); NEW `ldr x9, [x19, #0xf20]; str x9, [x8, #8]` — the random cookie instead.
  (receipts: `extracted/avd99{3,5}_attachHistogram.txt`, both builds disassembled.)

**(F5) "Could not enable multiview decoding"** — new error path in the wrapper's MV-HEVC enable
(strings delta; hardening companion of F2/F3).

Unresolved minors (likely churn, recorded for honesty): `decodeHEVCDecoderConfigurationRecord`
−8, `decodeFrameFig` −4, `setRefDartVAddr` (identical 6 ins — noise), `DumpHevcStream` /
`is_lgh_super_frame_offset` / `getNumberLayersToDecode` / `CreateInstance` / `CAVDDecoderD0`:
instruction-count identical or adrp-rebase-only (verified by idiff; the "size deltas" were
symbol-order artifacts).

### 2.3 AppleAVE2 kext 913.43.1 → 913.64.1 — THE GATE WAVE (receipted independently)

`__text` 0x1d0028 → 0x1d3ef8 (+0x3ED0). Full assert/receipt-string inventory
(`extracted/strings_added_AppleAVE2_kext.txt`), all NEW in 913.64.1 (absent from 913.43 — the
strings-side absence receipt for every check below):

**The gate, verified verbatim in the fixed binary (my disas, this session):**
`AVE_Client_CheckMCTFInfo` @0xfffffff00876108c (`extracted/checkmctfinfo_91364_disas.txt`):
```asm
ldr w8,[x21,#0x68];  sub w8,w8,#1; cmp w8,#2;      b.hs reject   ; iLayerNum ∈ [1,2]
ldr w8,[x21,#0x510]; cmp w8,#8;                    b.hs reject   ; sGOP.iNumOfTemporalLayer 0..7
ldr w8,[x21,#0x768]; cmp w8,#8;                    b.hs reject   ; uPropCfg.sHEVC.iNumberOfTemporalLayers 0..7
ldr w8,[x21,#0x1888]; cmp w8,#6;                   b.hi reject   ; vps_max_sub_layers_minus1 < 7
ldr w8,[x21,#0x27f8]; cmp w8,#0xf;                 b.hi reject   ; vps_num_layer_sets_minus1 < 16
ldr w8,[x21,#0x2c10]; cmp w8,#0x10;                b.hi reject   ; vps_num_hrd_parameters <= 16
ldrb w8,[x21+0x42c7]; cmp w8,#1;                   b.hi reject   ; vps_num_rep_formats_minus1 < 2
ldr w8,[x21,#0x27f4]; cmp w8,#0x3f;                b.hs reject   ; vps_max_layer_id < 63
ldrb w8,[x21+0x32c0]; cmp w8,#0x41;                b.hs reject   ; num_add_layer_sets <= 64
then: bl 0xfffffff00875e6c8  (AVE_HEVC_CheckVPSExtBounds, arg pInfo+0x1880)
```
`AVE_HEVC_CheckVPSExtBounds` @0xfffffff00875e6c8
(`extracted/checkvpsextbounds_91364_disas.txt`): `vps_num_layer_sets_minus1(+1)+num_add_layer_sets
<= 64` (`cmp #0x41; b.hs`); `+num_add_olss <= 64` (`cmp #0x40; b.hi`); per-byte
`layer_id_in_nuh[i] < 64` loop (array +0x17fb); `highest_layer_idx_plus1` row sums (stride 0x40,
base +0x1a41).
`AVE_Client_CheckLRMEInfo` @0xfffffff008761c10 mirrors the same checked-offset set
(`extracted/checklrmeinfo_91364_disas.txt`).
**Call sites**: the Verify-family gate `sub_87624fc` calls CheckMCTFInfo @0x87629d0
(`bl 0x876108c; cbz w0 → reject`) and CheckLRMEInfo @~0x8762ac4 — BEFORE the blob is accepted
(prior art REPORT §4b verified the memcpy ordering). Also called from the VPS/PS ingestion paths
sub_875d8d4 / sub_875fa10 / sub_87604d8 (fixmap) — my receipt: gate 0x87624fc `bl 0x87604d8`
@0x87625a4 (a PS path now carrying checks).

**The full check inventory of the wave** (assert strings + receipt strings, each = one
pre-fix live axis on 913.43 = our device):
| # | Check family | Fields / bound | Receipt string (verbatim, 913.64.1) |
|---|---|---|---|
| A | VPS 5-count mega-assert | sub_layers<7, layer_sets<16, hrd≤16, rep_formats<2, max_layer_id<63 | `pInfo->sHEVC_VPS.vps_max_sub_layers_minus1 < 7 && ...` |
| B | VPS-ext bounds (CheckVPSExtBounds) | max_layers<64, layer-set/OLS totals ≤64, layer_id_in_nuh<64, highest_layer_idx sums<65 | `HEVC VPS extension layer/OLS counts are out of range`, `...layer_id_in_nuh is out of range`, `...highest_layer_idx_plus1 sum...` |
| C | Layer/temporal | iLayerNum 1..2, GOP iNumOfTemporalLayer ≤7, prop iNumberOfTemporalLayers ≤7 | `number of sub layer is out of range`, `number of temporal layers (prop) is out of range` |
| D | MCTF | strength counts 0..2 (sAV1/sHEVC/sMCTF), MCTF info correctness | `AV1/HEVC MCTF strength count out of range`, `MCTF info is not correct` |
| E | LRME / refnum | LRME info, `0 <= iRefNum && iRefNum <= iMaxRefNum` | `LRME info is not correct`, `iRefNum is out of range` |
| F | PS-set counts | AVC PPS count; HEVC SPS/PPS/VPS/RPS counts; "too many parameter sets" ×2; RPS `num_short_term_ref_pic_sets < 65 && (lts+ltp) <= 16` | `AVC/HEVC {S,P,V,R}PS count is out of range` |
| G | AVC syntax | iLog2MaxFrameNum 4..16, iLog2MaxPOCLsb 4..17, bit-depth 8/8, iNumSliceGroups==1, ref-idx defaults 1..16 | `AVC log2_max is out of range`, `AVC bit depth is not supported` |
| H | HEVC syntax | log2_max_pic_order_cnt_lsb_minus4 ≤12, SPS sub_layers<7 + ltrp≤16, PPS tiles ≤256/qp-offset-list ≤5/extra_slice_bits==0 | `HEVC log2_max_pic_order_cnt_lsb_minus4 is out of range` (xrefs 0x875df..0x87623, 20 sites) |
| I | PS-context alias | `psPSCtxSrc != psPSCtxDst` | `source and destination alias` (xrefs 0x881f028..0x881f24c) |
| J | MB/CTU stats + slice-map | `saMBStats[m].iAddr != 0`, "invalid MB/CTU stats firmware buffer", `0 <= iNum && iNum < 20` | (xrefs 0x881e45c-0x881ecd8, 0x873ddd4-0x873e2c4) |
| K | DPB | userDPBnumFrames 2..16/17, num_ref_frame ≤16 (macro re-derived), LA frame count ≤48/layer | `2 <= pInfo->VideoParamsDriver.userDPBnumFrames && ...` |
| L | Dispatch receipts | DispatchCmd/GOPMgr failure propagation | `DispatchCmd failed`, `GOPMgr Process failed` |

### 2.4 ave.videoencoder plugin 913.43.1 → 913.64.1 — the app-side front of the same wave

Function-level diff (`extracted/fndiff_ave_videoencoder.txt`, 36 size-changed + 11 added
symbols). Security-relevant changes (feature churn — MachThreadPriority props, AV1 TokenPush/
WrapAV1BlockBuffer, `H264VideoEncoderFrameReceiver::SendFrame` +2652 CMBlockBuffer rework —
separated out):

| Fix site | Receipt (instruction-level, this session) |
|---|---|
| **`AVE_Prop_HEVC_SetNumberOfTemporalLayers`** — the CAL-K1 fire key | OLD: `cmp w8,#0; b.le reject` (≥1 only, raw store to session+0x12438). NEW @0x2c567a688: `cmp w9,#7; b.hs reject` + assert `0 < iNumberOfTemporalLayers && iNumberOfTemporalLayers <= 7` — **the FIG bound 1..7 is NEW** (the 913.43 assert was only `iNumberOfTemporalLayers >= 1`). |
| **`AVE_Prop_HEVC_SetDPBRequirements`** (+272, AVC twin +272) | OLD: raw count stored (`str w8,[x25,#0x744]`, no bound) — the OVERTURNED candidate-A composer (register-indexed CFArray walk through session+0xb68/+0xbac, 17 slots). NEW @0x2c567c920: `cmp w8,#0x11; b.ge <error>` before the store — **count < 17 bound NEW** + full error block. |
| **`AVE_HEVC_ST_RPS_Retrieve`** (+244, RetrieveArray +16) | NEW @0x2c5662f9c: `ldr w9,[x19,#0x30]; cmp w9,#0x10; b.hi err; cmp w8,#0x11; b.hs err` — **num_negative/num_positive pics ≤ 16, total ≤ 17 NEW** (assert `pInfo->num_negative_pics <= 16 && pInfo->num_positive_pics <= 16`). |
| **`AVE_Prop_HEVC_SetUserRPSForFaceTime`** | OLD `cmp w24,#0; b.le` → NEW @0x2c567dd04: `cmp w8,#0x40; b.hs` — **iUserRPSForFaceTime 1..64 NEW**. |
| Marshal-side (`AVE_Session_HEVC_Prepare` +20, `AVE_USL_Drv_Start/Complete`) | NEW asserts `num_frames <= 16/17`, `pSnapshot->num_ref_frame <= 16` — DPB/RPS count family front. |
| **UNCHANGED (sibling census, §6)** | `SetLRMERSPassNum`, `SetMCTFEdgeCount`, `SetMCTFEdgeThresh`, `SetMCTFMaxNextRefNum`, `SetMCTFRampUpFrameNum`: **276 ins identical in both builds — still sign-only (≥0), NO upper bound.** |

---

## 3. PER-CVE SITE ASSIGNMENT TABLE

Grades: **CONFIRMED** = credit line + impact + fix-class + our receipts all align;
**SHAPE** = fix-shape and impact match, exact-ID assignment not provable from the advisory;
**SHAPE-STRONG** = shape + a unique consumer receipt. Apple publishes no CVE→fix-site map —
every AVE assignment below is SHAPE-grade unless noted; the SITES themselves are
instruction-receipted either way.

### AppleAVD (all three: fix carrier = AVD.videodecoder plugin, per §1 impact-line reading + §2.1 negative)

| CVE | Assigned site | Grade | Reasoning + receipts |
|---|---|---|---|
| **CVE-2026-112416** | **F1 — the AVC slice-cap alignment** (`parseNALUs`/`processParserOut` bound: `#0x384` → `m_avc_max_slices`; work area always sized by the member) | **SHAPE-STRONG** | "maliciously crafted **video file**" + "improved **bounds checking**" + OOB write = exactly F1's shape (a crafted bitstream with slice count in (m, 900] overflows the per-slice work structs allocated for m). Multi-credit line (5 parties) fits a long-standing, easily-found-by-fuzzing bug. Secondary candidate under the same CVE line: **F3** (numLayersToDecode ≤2 — also file-driven bounds checking). The two share the "crafted video file" phrasing; flag the ambiguity honestly. |
| **CVE-2026-112415** | **F2 — the RequestedMVHEVCVideoLayerIDs validation chain** (+F3/F5 companions) | **SHAPE** | "**An app** may be able to cause..." (app-driven property, not a file parse) + "improved **input validation**" = F2's shape verbatim: pre-fix, an app-set CFArray of layer ids flowed unvalidated (no 64-cap, no VPS-membership, no state check) into the ≤2-layer MV-HEVC decode arrays → OOB write, corrupt process memory. Credit overlap (Hcamael) consistent — same researcher family mapping the same MV-HEVC surface as 112416's secondary. |
| **CVE-2026-112454** | **F4 — the histogram IOSurface pointer→cookie rework** (`arc4random_buf` + attachHistogramToIOSurface) | **SHAPE** (weakest) | "improved **memory handling**" (the only non-OOB fix-class line) + "crafted **video file**" (histogram attach is driven by decode output of a file) matches the only non-bounds fix in the component diff: the raw context POINTER embedded in an app-readable IOSurface attachment replaced by a random 8-byte cookie. Primitive direction (leak vs forged-ID deref) unmapped — reader side not reconstructed (OPEN). Honest alternative: none found in the diff (F1/F2/F3 are the only other candidates and they match the other two CVE lines better). |

### AVEVideoEncoder (all six: fix carrier = AppleAVE2 kext gate wave + plugin FIG bounds)

| CVE | Assigned site(s) | Grade | Reasoning + receipts |
|---|---|---|---|
| **CVE-2026-112705** (Calif.io) | **The `vps_max_sub_layers_minus1` family: `AVE_PSGen::Init`'s w24 linear fill loops** (pClient+0x4678 / +0x6424 / +0x8098, count = VPS+8 from the client blob), killed by gate A's `<7` check (`ldr w8,[x21,#0x1888]; cmp #6`) + the NEW plugin FIG bound 1..7 on the injection key | **CONFIRMED** | Credit names Calif.io; impact = "unexpected system termination" = exactly our **8 on-device panic receipts** (v190/v191: FAR 0x100000059 at AVE2+0xDA78, deterministic across boots; analysis/ave2_sve_delivery_channel.md §7, ave2_weaponize.md §10). The full app→videocodecd→AVE2 channel (FIG `NumberOfTemporalLayers` raw store → VPS+8 → blob → pClient+0x3760 → fill) is proven end-to-end; the fixed kext gate + the fixed FIG setter (both receipted in §2.3/§2.4) close exactly this axis. |
| **CVE-2026-112689** (Blackwing) | **The MCTF/LRME input-validation family (families D+E)**: kext prop-apply consumers of the MCTF/LRME config (sub_86f1cf0 region, sign-only fields) + gate checks "MCTF/LRME info is not correct", iRefNum 0..max | **SHAPE** | "improved **input validation**" is the fix-class of the CheckMCTFInfo/CheckLRMEInfo gates (they validate input CONFIG, unlike A/B/C's numeric bounds); the pre-fix kext consumed the five FIG MCTF/LRME ints with **sign-only checks** (plugin census + the 10-27 mctf-mode panic whose register fingerprint matched the fill band — ave2_extcal_v192.md §4). MAY SHARE the 112705 fix wave (same gate insertion); flagged. |
| **CVE-2026-112470** | **The VPS-ext layer-set WRITE family (family B)** — pre-fix consumer: `HEVC_VPS::vps_encode_independent_layer_parameters` (sub_87fc86c) layer-set fill loop @0x87fcc38: bound `vps_num_layer_sets_minus1` (raw u32) → rows 64+ write ~0x2FFF past the 0x1018 kalloc_type wrapper + `counts[i]` onto the caller stack (PROVEN value-controlled OOB write, analysis/ave2_second_gen_consumers.md §2) | **SHAPE-STRONG** | One of the three Hcamael write CVEs; this is the single richest pre-fix write primitive the B-family checks guard (`<16` gate at +0x27f8 + CheckVPSExtBounds totals ≤64). "Bounds checking" matches B's shape. |
| **CVE-2026-112469** | **The temporal-layer index WRITE (family C)** — pre-fix consumer: `sub_87fbd74` VPS-init: `*(VPS+0xf3c + sxtw(4x−4)) = {0,2}` / `*(VPS+0xf20 + ...) = 4`, x = iNumOfTemporalLayer unvalidated → **±8GB-range 4-byte-stride writes at fixed values** (second_gen_consumers §3) | **SHAPE** | Same class, distinct field/consumer (the ≤7 gates at +0x510/+0x768 exist ONLY for this consumer family). The three Hcamael CVEs = three distinct count fields; this is the second-strongest pre-fix write. |
| **CVE-2026-112468** | **The PS-set count family (F) / AVC mirror (G)** — pre-fix consumers: `saHEVC_SPS[i]/saHEVC_PPS[i]/saAVC_PPS[i]` arrays + GOPMgr/DPB arithmetic fed by AVC log2_max ("too many parameter sets" ×2 forms; "AVC PPS count is out of range"; the log2_max assert) | **SHAPE** | The third write family (parameter-set COUNTS indexing fixed PS arrays; AVC log2_max into DPB math). Honest caveat: 112468 could equally be the H-family (PPS tiles/chroma-qp) or the A-family HRD/rep-format write consumers — three CVEs, ≥5 candidate count fields; the 1:1 mapping is unresolvable without Hcamael's writeup. Presented as the best-shape triple: 470=B, 469=C, 468=F(+G). |
| **CVE-2026-112466** | **The VPS-serialization READ family** — pre-fix consumers: `HEVC_VPS::video_parameter_set_rbsp` (sub_87fc2ac) HRD loop (vps_num_hrd_parameters, reads VPS+0x1394+4i), `sub_87fd29c` per-layer PTL loop (`*(VPS+0x2a44)`, masked 0x1ac-stride span), rep_formats loop (VPS+0x2a47), layer_id_included rows — **all serialized into the returned VPS bitstream = a ~0x800-byte/session kernel-heap disclosure to the app** (the extcal/readback channel, ave2_extcal_v192.md §2) | **SHAPE-STRONG** | The ONLY pre-fix OOB-READ family on the surface, matching the advisory's only AVE read CVE ("**read kernel memory**", "improved input validation" = gates A/B bound exactly these fields). The extcal oracle (non-crashing, app-visible VPS bitstream growth) is the A/B channel. |

**Shared-fix flags (per task item 3):**
- 112689 plausibly shares the CheckMCTFInfo/CheckLRMEInfo gate insertion with the 112705 family
  (one code drop, one gate family, two CVE credits) — cannot be excluded.
- 112470/112469/112468 are three count families gated by ONE wave; if Hcamael's report enumerated
  three distinct field/consumer pairs (the most likely reading given three CVE IDs), the
  470=B / 469=C / 468=F+G split above is the best-shape assignment; alternates recorded in the table.

---

## 4. CRAFT / ORACLE RECIPES per assigned CVE (app reach via VideoToolbox; crash-oracle only)

### AppleAVD (decode side — seeds BUILT, in `seeds/`)
- **112416 (F1, slice cap)**: `seeds/avd_avc_slices_{32..900}.h264` (built by
  `scripts/ds_gen_avd_slice_seed.sh`, ffmpeg/libx264, tall-frame trick; NAL-histogram-verified:
  the 900 seed = exactly 900 IDR-slice NALs + SPS/PPS/SEI). Recipe: `VTDecompressionSession`
  (H264, `kVTVideoDecoderSpecification_RequireHardwareAcceleratedVideoDecoder` to pin AVD) over
  each seed, 24A435 device → crash/corruption band expected at counts > the platform's
  `m_avc_max_slices` (unknown; the ladder spans 32..900 to bracket it — the BOUNDARY cell pins m);
  24B115 device → `"too many slices!"` log + clean rejection (the fixed-side receipt).
  Note the 900 seed sits exactly AT the old cap (0x384 = 900): accepted pre-fix, rejected post-fix
  (for m<900) — the cleanest single-cell A/B.
- **112415 (F2, MV-HEVC property)**: app recipe — create an MV-HEVC (spatial-video shaped)
  VTDecompressionSession against a 2-layer MV-HEVC sample (the format-description VPS declares 2
  layers), then `VTSessionSetProperty(kVTDecompressionPropertyKey_RequestedMVHEVCVideoLayerIDs,
  CFArray)` with (a) count > 2, (b) ids ≥ 64, (c) ids absent from the VPS, (d) set AFTER the first
  decode. Pre-fix: all four accepted (old handler stored the array raw); post-fix: the four
  receipt strings of §2.2 F2. A crafted FILE variant (no property): a VPS declaring >2 layers /
  out-of-list ids exercises F3 via the same arrays. Crash-oracle: decoder-arrays overflow →
  app-termination receipt in the decoding process.
- **112454 (F4, histogram)**: app recipe — decode a file that produces a decode histogram
  (any H264/HEVC hardware-decode with histogram metadata enabled; the attach path fires on the
  IOSurface output), then read the IOSurface attachment from the app: pre-fix the 0x220 blob's
  +8 field is the live decoder-context POINTER (disclosure receipt); post-fix it is a random
  cookie (blob bytes differ every decode — the A/B receipt). The write-side primitive (if any)
  remains OPEN (reader side unmapped) — this recipe establishes the disclosure/behavior A/B only.

### AVEVideoEncoder (encode side — property/session-level; the exact knobs are prior-art-proven)
- **112705**: the v190 SVE recipe unchanged (EncoderUsage=1, RCMode=20,
  `NumberOfTemporalLayers` = N, then first `PrepareToEncodeFrames`): 24A435 = kernel panic at
  N ≥ 12742 (pool-forge band; 8 receipts in hand); 24B115 = FIG setter returns −2004 ("out of
  range", the NEW 1..7 bound, receipt §2.4) and/or kext `HEVC VPS count is out of range` + no panic.
  Single-shot: `-calk1key NumberOfTemporalLayers -calk1val N` (CAL-K1 harness).
- **112689 (MCTF/LRME)**: the v192 `-calk1mode mctf` ladder — the five unbounded keys
  (`LRMERSPassNum`, `MCTFEdgeCount`, `MCTFEdgeThresh`, `MCTFMaxNextRefNum`, `MCTFRampUpFrameNum`)
  × {4, 64, 4096}; 24A435 = the 10-27 mctf-panic family receipt; 24B115 = expect either the new
  "MCTF/LRME info is not correct" gate receipt — **or no gate at all** (see sibling S1: the five
  keys' fields are NOT in the checked-offset set of CheckMCTFInfo/CheckLRMEInfo as far as the
  mapped head of those functions shows) — that cell is itself the discriminator.
- **112470 (VPS-ext layer-set write)**: R5 channel — compose a session blob with
  `vps_num_layer_sets_minus1 ≥ 64` + vps_extension bit + crafted layer_id_included rows (the
  app-side composer was OVERTURNED-open via `AVE_Prop_HEVC_SetDPBRequirements`'s unbounded CFArray
  walk — now closed plugin-side in 913.64.1, receipt §2.4 — so on 24A435 the DPBRequirements
  property IS the arm channel: >17 pairs walk the session VPS; on 24B115 the count<17 FIG bound
  rejects). Crash-oracle: the ≥255 infinite-loop hang / ≥64 stack-guard panic shapes
  (second_gen_consumers §2b/2c).
- **112469 (temporal index)**: same blob family via any path carrying
  sGOP.iNumOfTemporalLayer / prop iNumberOfTemporalLayers > 7 (the kext-side second-gen consumer
  sub_87fbd74); plugin FIG `NumOfTemporalLayer` is min(·,4)-clamped (dead) — the daemon-composed
  blob is the open channel (same smuggle question as the 26.6-era OPT-SMUGGLE work).
- **112468 (PS counts)**: encoder-session parameter-set count axis — drive
  NumberOfTemporalLayers-family counts + user parameter-set ids (AVC session mirror) past the
  saHEVC_SPS/PPS array bounds; the "too many parameter sets"/"AVC PPS count" receipts on 24B115
  are the fixed-side oracle.
- **112466 (READ side)**: the v192 `-calk1mode extcal` ladder — counts 23..1768: pre-fix =
  non-crashing app-visible VPS-bitstream growth (the returned bytes READ kernel heap: compare
  encoded-header bytes 24A435 vs 24B115 per count; identical input geometry, different leaked
  bytes = the disclosure receipt); post-fix = gate rejections (`HRD count is out of range` family).

---

## 5. UNMAPPED FIXES (fix sites with no plausible CVE line — the "extra" list)

1. **`psPSCtxSrc != psPSCtxDst` (family I)** — the PS-context source/dest alias check (memcpy
   overlap class). No advisory line (OOB write ×5 are all count-shaped; no overlap/type-confusion
   AVE line). Either part of one of the six silently, or a separately-fixed bug with no CVE.
   xrefs 0x881f028-0x881f24c (fixed kext).
2. **The MB/CTU-stats cluster (family J)** — `saMBStats[m].iAddr != 0` (existed 913.48+),
   "invalid MB/CTU stats firmware buffer" (NEW), `iNum < 20` slice-map tighten (NEW, 32 → 20;
   xrefs 0x881e45c-0x881ecd8). No CVE line maps to MB-stats; candidate unlisted fix.
3. **The AVC syntax family (G) + HEVC syntax (H)** — if Hcamael's three CVEs are 470=B/469=C/
   468=F as assigned, then G/H are either components of those (same wave) or unlisted. The PPS
   tile/chroma-qp assert (`num_tile_columns_minus1 <= 256 ...`) in particular guards a consumer
   family no advisory line names.
4. **DispatchCmd/GOPMgr failure receipts (L)** — error propagation, hardening; not CVE-shaped.
5. **AppleAVD kext +0x8 / the pervasive struct-offset churn** — the video-context struct gained
   fields (the 8-byte cookie + layer plumbing); no validation added (§2.1) — but the churn means
   the daemon↔kext frame-param/video-context LAYOUT changed in 27.2: any external map of those
   structs (including ours) is stale on 24B115.
6. **Plugin-side `num_frames <= 16/17` + `pSnapshot->num_ref_frame <= 16` marshal asserts** —
   could be 112705-family (RPS/DPB counts riding the same blob) or unlisted; ambiguous.

## 6. SIBLING CENSUS — checks the gate wave did NOT add (OUR disclosure candidates)

Ranked by (receipt strength × reachability), all live on 24A435 AND — where noted — plausibly
still live on 24B115/27.2:

- **S1 (TOP): the five unbounded MCTF/LRME FIG keys remain unbounded in BOTH builds.**
  Plugin 913.43.1 AND 913.64.1: `SetLRMERSPassNum` / `SetMCTFEdgeCount` / `SetMCTFEdgeThresh` /
  `SetMCTFMaxNextRefNum` / `SetMCTFRampUpFrameNum` are instruction-identical (276 ins, sign-only
  `tbnz w8,#0x1f` reject; receipt §2.4). The fixed kext's CheckMCTFInfo/CheckLRMEInfo
  checked-offset set (COMPLETE function bodies disassembled, 0x876108c..0x8761c10; receipt
  `extracted/checkmctfinfo_91364_disas.txt`) = {0x68, 0x510, 0x768, 0x1888, 0x27f4, 0x27f8,
  0x2c10, bytes 0x42c7/0x32c0} + CheckVPSExtBounds(+0x1880) — i.e. the cfg block is checked ONLY
  at the layer/temporal counts. Decisive: the five keys' kext-side consumer LOG strings are
  **count-identical between builds (8/8/8/10/10)** and **NO assert-style bound string for any of
  the five exists in EITHER kext** (Apple added asserts for iMCTFStrengthLevelNum 0..2 but not
  for EdgeCount/EdgeThresh/PassNum/MaxNextRefNum/RampUpFrameNum). The 10-27 mctf-mode panic is
  the on-device receipt that this family crashes pre-fix. **The channel plausibly remains OPEN
  on CURRENT 27.2 — our report candidate; the blob-side landing offsets of the five fields are
  the one open RE item (then a 27.2-device mctf-ladder refire decides it).**
- **S2: CheckDMVInfo's non-shared fields.** The fix added families A/B/C to CheckDMVInfo (REPORT
  §4b) — but the DMV attach channel (client type 5) carries its own blob (dims/DLB verified only
  pre-fix, plus the new families). Any DMV-only field outside the shared families remains
  unvalidated in both builds. Open: enumerate the type-5 blob fields the new checks skip.
- **S3: the PPS tile off-by-one shape.** The new assert allows `num_tile_columns_minus1 <= 256`
  (i.e. 257 columns) while consumer arrays in this codebase are conventionally sized 256 — the
  classic fencepost the rest of the wave was written to close. One RE pass at the tile consumers
  (column-width loops) decides.
- **S4: the old slice-map 20..32 band.** Pre-fix CheckInfo allowed slice-map num ≤ 32; the fix
  tightens to < 20 (`(1+2)*(1+9)`). Consumers indexed 20..31 pre-fix may still be reachable via
  paths not covered by the assert (the assert is log-shape, enforcement point unmapped).
- **S5: AVC mirror consumers.** The AVC gate family (log2_max/bit-depth/slice-groups) guards
  GOPMgr/DPB arithmetic, but the 26.6-era SInt32 window findings (REPORT §4d) show the AVC
  DPB/GOP consumers had count-derived arithmetic issues; the new bounds may not cover every
  derived quantity (e.g., ref-idx products, DPB size × level).
- **S6 (AVD): `m_avc_max_slices` provenance.** The member is bulk-copied from the kext's
  createDecoder output (no plugin-side writer, receipt §2.2 F1); its consistency with the
  generation's REAL array capacities is only as good as the kext's table. Low priority
  (kernel-derived), recorded for completeness.

## 7. HONEST NEGATIVES

- AppleAVD kext 993.1→995.0: **no security-fix content found** (strings + chunk census + prior
  BN diff agree); the three AVD CVEs are plugin-side.
- The AVD plugin functions with size deltas that are symbol-order artifacts
  (`getNumberLayersToDecode`, `DumpHevcStream`, `is_lgh_super_frame_offset`, `CreateInstance`,
  `CAVDDecoderD0`, `setRefDartVAddr`): instruction-diffed, NO semantic change (adrp-rebase noise
  only) — recorded so nobody re-chases them.
- The 112466 read-side and 112470 write-side VPS-ext primitives are NOT reachable through the
  plain VT FIG HEVC property surface per the plugin censuses (vps_extension flag has no plugin
  writer; layer-set count capped at 3 by the MV-HEVC composer) — pre-fix reachability runs
  through the blob-composition channels (DPBRequirements walk — now gated, SetDPBRequirements
  <17; per-frame FrameSettings weak typing; other-client composition), which is why the kext
  gate is "defense at the boundary" rather than at the FIG setter (except the temporal-layers
  key, which Apple DID front-door — receipt §2.4).
- CVE 112454's write-side primitive (if any) is unproven: F4's receipt shows the pointer→cookie
  change; the reader/consumer of the attachment was not reconstructed this session.

## 8. Artifact index

- `extracted/strings_{added,removed}_{AppleAVD_kext,AppleAVE2_kext,AVD_videodecoder,ave_videoencoder}.txt`
- `extracted/fndiff_{AVD_videodecoder,ave_videoencoder}.txt` (function-level diffs)
- `extracted/idiff_{avc_parseNALUs,calcLayers,SetDPBRequirements_HEVC}.txt` (instruction diffs)
- `extracted/avd99{3,5}_attachHistogram.txt`, `avd995_setproperty_mvc_handler.txt`
- `extracted/check{mctfinfo,lrmeinfo,vpsextbounds}_91364_disas.txt` (fixed-kext gate bodies)
- `extracted/chunkdiff_AppleAVD_kext.txt`
- `seeds/avd_avc_slices_{32..900}.h264` + `seeds/README.md`
- `scripts/ds_{fn_diff,idiff,disas,strxref,scan_store,kext_chunkdiff}.py`,
  `scripts/ds_gen_avd_slice_seed.sh`
- `HARNESS_ROW.md` (the VD-K1 row spec)
