# FINDINGS — CVE-2026-112688 (CoreMedia): DOVI RPU ext-metadata-block array overruns

> AI-generated security research (same notice as AGENTS.md). Authorized research on the
> project owner's devices + Apple's publicly-shipped firmware, coordinated disclosure.
> PoCs are crash-oracles ONLY. Every claim below carries a receipt or an explicit
> SHAPE-MATCHED caveat.

**Verdict: LOCALIZED + PROVEN at instruction level, both sides.** The fix is in
`hevcbridgeParseVdrDmDataPayloadExMetadatatBlocks` — the Dolby Vision (RP 2086) RPU
"ext metadata block" parser inside CoreMedia. It was renamed (typo fix) and given **three
new pre-write count guards** in 24B115; the 24A435 build writes metadata-block array
elements with unchecked counts → **OOB write of attacker-influenced 14/28/36-byte
records past three fixed-capacity arrays** in a 0x73b4-byte metadata struct that callers
place **on the stack** (public API `CMGetDMVersionLevelFromRPU`) — the array-A overrun
reaches past the struct end into the caller's saved registers. This is the strongest
shape-match in the "CoreMedia" cluster for the only advisory line claiming outright
**arbitrary code execution** (CVE-2026-112688, credited 정우 하 @0xfa11babe +
Chris Bailey).

## 1. The fix (receipts)

### 1.1 Function identity delta (version + symbol receipts)

| Build | CoreMedia | Function | Size | Cold blocks |
|---|---|---|---|---|
| 24A435 (27.0 RC, device) | 3350.77.1.6.0 | `_hevcbridgeParseVdrDmDataPayloadExMetadatatBlocks` @ `0x18eed3198` | 5052 B | 3 |
| 24B115 (27.2 RC, fixed) | 3385.14.1.2.0 | `_hevcbridgeParseVdrDmDataPayloadExMetadataBlocks` @ `0x18ef5b238` | 5080 B | 6 |

Symbol receipts (`nm`, both extracted dylibs in `extracted/`):
```
000000018eed3198 t _hevcbridgeParseVdrDmDataPayloadExMetadatatBlocks        (24A435)
000000018efeb548 t _hevcbridgeParseVdrDmDataPayloadExMetadatatBlocks.cold.1  (24A435)
000000018efeb57c t ...cold.2   000000018efeb5b0 t ...cold.3                  (24A435)
000000018ef5b238 t _hevcbridgeParseVdrDmDataPayloadExMetadataBlocks          (24B115)
000000018f073c24 t ...cold.1 … 0x18f073c58 .cold.2 … 0x18f073c8c .cold.3
000000018f073cc0 t ...cold.4 … 0x18f073cf4 .cold.5 … 0x18f073d28 .cold.6      (24B115)
```
Every fixed cold block calls `FigSignalErrorAtGM` with a distinct source line:
vuln lines {7771,7772,7774} → fixed lines {7327 (cold.3), 7527 (cold.2), 7623 (cold.1),
7818 (cold.6), 7819 (cold.5), 7821 (cold.4)} (`mov w4,#imm` in `receipts/vdrdm_*_cold`
disass; 0x1c9f=7327, 0x1d27=7527, 0x1dc7=7623, 0x1e8a=7818, 0x1e8b=7819, 0x1e8d=7821).
**Six error paths where three existed = three substantive new bounds refusals.**

### 1.2 The three admitted bugs (both-side disassembly receipts)

The parser dispatches on the DOVI ext-metadata `block_id` (u(8), jump table
`0x18ee2a874`+`adr 0x18eed3310`, cases 1..11; receipts in `receipts/vdrdm_vuln.disass`).
Three cases write per-block records into fixed-capacity arrays inside the metadata
struct (`x21`+offset; `x23 = x21+0x7000`):

| Array | base (x21+) | stride | capacity | count field (x23+) | block-id case (vuln) |
|---|---|---|---|---|---|
| **A** | 0x7338 | 28 B (0x1c) | 4 | `+0x334` | 1 (L8-multi-target region) |
| **B** | 0x71dc | 14 B (0xe) | 8 | `+0x1d8` | 2 (and class-2 companions) |
| **C** | 0x726c | 36 B (0x24) | 5 | `+0x268` | 6 et al. (via shared tail) |

**BUG A — vulnerable (24A435) @ 0x18eed3620:**
```
0x18eed3620:  ldr  w8, [x23, #0x334]      ; count
0x18eed3624:  cmp  w8, #0x3
0x18eed3628:  b.hi loc_18eed3634          ; count > 3: skips ONLY the count increment
0x18eed362c:  add  w9, w8, #0x1           ; (count++ only when count <= 3)
0x18eed3630:  str  w9, [x23, #0x334]
0x18eed3634:  ldur w9, [fp, #-0x34]       ; ← write proceeds EITHER WAY
0x18eed3644:  umull x8, w8, w11           ; index = count * 28   (w11=0x1c) — UNCHECKED
...          ; 28-byte element write at x21+0x7338 + count*28
```
With a 5th block of this id: count already 4 → write at struct+0x73a8..0x73c4
(array ends at 0x7338+4*28 = 0x73a8) → **28-byte OOB write**. Every later block
re-writes the same index-4 slot (count never increments past 4).

**BUG A — fixed (24B115) @ 0x18ef5b6c0:**
```
0x18ef5b6c0:  ldr  w8, [x23, #0x334]
0x18ef5b6c4:  cmp  w8, #0x4
0x18ef5b6c8:  b.hs loc_18ef5c5fc          ; count >= 4 → HARD ERROR
0x18ef5c5fc:  bl   ...ExMetadataBlocks.cold.1  ; FigSignalErrorAtGM(err, line 7623)
0x18ef5b6cc:  add  w9, w8, #0x1           ; count++ only after the guard
0x18ef5b6d4:  ldr  w9, [sp, #0x38]        ; write at index count (0..3, in-bounds)
```

**BUG B — vulnerable @ 0x18eed3720 (increment) / 0x18eed3c18 (write):**
```
0x18eed3720:  ldr  w8, [x23, #0x1d8]      ; count (unconditional per block)
0x18eed3724:  add  w8, w8, #0x1           ; count++  — NO upper guard at all
0x18eed3728:  str  w8, [x23, #0x1d8]
...
0x18eed3c18:  ldr  w9, [x23, #0x1d8]      ; re-read incremented count
0x18eed3c1c:  sub  w10, w9, #0x1
0x18eed3c38:  smull x10, w10, w13          ; index = (count-1)*14 — 32-BIT signed mul
0x18eed3c40:  strh w11, [x13]              ; 7×u16 write (14 B) at x21+0x71dc+idx*14
0x18eed3c68:  cmp  w9, #0x8
0x18eed3c70:  csel w9, w9, w10(=8), cc     ; clamp stored count to 8 — AFTER the write
0x18eed3c74:  str  w9, [x23, #0x1d8]
```
9th+ block: count 9 → index 8 → write at struct+0x71dc+112 = **0x724c..0x725a, 14 B
OOB past the 8-element array**; the clamp then pins stored count at 8, so every further
block re-writes the same index-8 slot with attacker-influenced u16s.

**BUG B — fixed @ 0x18ef5bcb0:**
```
0x18ef5bcb0:  ldr  w9, [x23, #0x1d8]
0x18ef5bcb4:  cmp  w9, #0x8
0x18ef5bcb8:  b.hs loc_18ef5c348 → cold.3 (line 7327)   ; HARD ERROR before any write
0x18ef5bcbc:  add  w10, w9, #0x1                        ; count++
0x18ef5bcd0:  lsl  x12, x9, #0x4                        ; index = count*14 via
0x18ef5bcd4:  sub  x9, x12, x9, lsl #0x1                 ;   64-BIT shifts (smull retired)
0x18ef5bcdc:  strh w10, [x12]                            ; in-bounds write (idx 0..7)
```

**BUG C — vulnerable @ 0x18eed3c8c / fixed @ 0x18ef5bd18** (same shape as A;
`cmp w9,#0x4; b.hi` skips only the increment in vuln; fixed `cmp w9,#0x5; b.hs` →
cold.2, line 7527; index = count*36 → 6th block writes 36 B at struct+0x7320..0x7344,
which also overlaps array A's element 0 (0x7338) — cross-array clobber):
```
VULN:  0x18eed3c94: b.hi loc_18eed3ca0   ; skips only count++
       0x18eed3ca8: add x9, x9, x9, lsl #0x3 ; x21 = base + count*36 — UNCHECKED
FIXED: 0x18ef5bd20: b.hs loc_18ef5c3ac → cold.2 (line 7527) ; HARD ERROR
```

Additionally the fixed build converts the pre-existing soft entry checks
(ext-block `len` ue ≤ 0x100, `block_id` u(8) sanity, `bits_remaining >= len`) into
logged hard errors (cold.6/.5/.4, lines 7818/7819/7821) — defensive, no new bound.

### 1.3 Caller chain — why "parsing a file" (receipts: BL xref scan, `scripts/blxref.py`)

```
CMGetDMVersionLevelFromRPU (PUBLIC CoreMedia API, exported)
  └─ FigHEVCBridge_GetRPUMetadata (exported; prepends RPU NAL hdr 0x7C 0x01)
       └─ hevcbridgeParseDolbyRPUDataRBSP        (header: magic 0x19, rpu_type==2, rpu_format u(11)…)
            └─ hevcbridgeParseVdrDmDataPayload   (DM-data head + ext-block loops: class-1 loop
                  (count = ue ≤ 0xFE) and class-2 loop (num_ext_blocks ue ≤ 0xFF, ID 0x271))
                 └─ hevcbridgeParseVdrDmDataPayloadExMetadatatBlocks   ← THE FIX
FigHEVCBridge_GetRPUMetadataFromRPU (exported) → hevcbridgeParseDolbyRPUDataRBSP → …same
```
Call-site xrefs (24A435): `0x18efdf990→ParseVdrDmDataPayload`, `0x18efe8618/0x18efe86bc
→ExMetadatatBlocks`, `0x18eec8f0c→ParseDolbyRPUDataRBSP (hevcbridgeParseNALUnit)`.
`FigHEVCBridge_GetRPUMetadataFromRPU` takes the RAW RPU payload (verified live on the
macOS 27.0 twin: payload byte0 = 0x19 straight into the parser — no NAL header).

**Reachability from a FILE:** DOVI RPUs ride HEVC/AV1 tracks in MP4/MOV/HLS-fMP4 —
per-sample RPU NALs (or the dvcC config); the demux hands the RPU payload to this
CoreMedia parse chain (VideoToolbox imports `FigHEVCBridge_CreateDolbyRPUNAL` +
`kCVImageBufferDolbyVisionRPUDataKey` — decode-side attach; MediaToolbox imports the
FigHEVCBridge HLS-fMP4 parsing family). Any AVAsset/AVPlayer/QuickLook open of a
DOVI movie reaches the parser in-process. → advisory line "Parsing a file may lead
to … arbitrary code execution" matches.

### 1.4 The exploit-shape receipt — why this is the ACE-class line

`CMGetDMVersionLevelFromRPU` (24A435 @ `0x18efbf940`) places the metadata struct
**on its own stack frame**:
```
0x18efbf954:  mov  w9, #0x73c0
0x18efbf968:  sub  sp, sp, #0x7, lsl #0xc     ; +0x7000
0x18efbf96c:  sub  sp, sp, #0x3c0             ; = 0x73c0-byte stack slot
0x18efbf978:  add  x21, sp, #0xc              ; struct base = sp+0xc
0x18efbf97c:  mov  w1, #0x73b4
0x18efbf980:  bl   _memset                    ; struct size = 0x73b4
0x18efbf9a4:  bl   _FigHEVCBridge_GetRPUMetadata
```
Struct ends at sp+0x73c0 = the register-save area of the same frame:
`[sp+0x73c0]=x22, +0x73c8=x21, +0x73d0=x20, +0x73d8=x19, +0x73e0=fp, +0x73e8=lr`
(push order at `0x18efbf944/948/94c`). **Array A's OOB write (struct+0x73a8..0x73c4,
28 B) crosses the struct end (0x73b4) and overwrites saved x22/x21 (+16 B of saved
x20)** with parsed metadata halfwords — block-id-1's element tail (`SPullAlways`
u(16) fields, trace IDs 0x25d/0x25e/0x25f) is **16-bit-controlled** → the caller's
restored x22/x21 can be steered to invalid pointers (e.g. 0x0fff_0fff_0fff_0fff) →
SIGSEGV in the caller, or a controlled non-canonical/old-pointer state. The fix's
guard eliminates the 5th+ block entirely. Arrays B and C stay intra-struct
(corrupt neighboring parsed L8/L9/L10 fields + array-A element 0 = cross-array
type-confusion of display-metadata values — silent corruption path).

## 2. Trigger + craft recipe

**Container field:** the DOVI RPU's `vdr_dm_data_payload` ext-metadata-block
sequence — repeat the **same block-id** enough times to exceed its array cap:
- block-id 1 × ≥5 (cap 4) → array-A OOB (the struct-escaping, register-clobbering one)
- block-id 2-class × ≥9 (cap 8) → array-B OOB
- block-id 6-class × ≥6 (cap 5) → array-C OOB (cross-array)

**Block grammar (vuln function, from disassembly):** per block — `ue(v)` len-ish V1
(≤0x100; parser asserts ≥V1 bits remain), `u(8)` block_id, then per-id fields;
block-id 1: `u(12)×3` (IDs 0x224/0x225/0x226), `u(8)×6` (0x26b..0x270),
`u(8)×2+` (0x250/0x259/0x25a…), a u(8) that unlocks the u(16) tail when ≥0x13,
then `u(16)×3` (0x25d/0x25e/0x25f — the fields that land on saved x22/x21).

**Wrap:** DM-data head requires reaching `hevcbridgeParseVdrDmDataPayload` (after the
RP 2086 RPU header: magic `0x19`, rpu_type u(6)=2, rpu_format u(11), then the VDR
profile/RL/NSW structures), then class-2 `num_ext_blocks` ue ≥ 5 + the blocks.
`scripts/gen_rpu.py` emits candidates; **state: WIP** — the header grammar
(`hevcbridgeParseDolbyRPUDataRBSP`, ~800 instrs, RP 2086 VDR structures) is
reconstructed only through the entry checks (magic/rpu_type/rpu_format verified LIVE
on the macOS 27.0 twin via `scripts/rpuprobe.c` + lldb pull-tracing; receipts in §4).
The remaining iteration is mechanical: extend the writer per `receipts/rpu_grammar_macos.txt`
(`scripts/grammar_walk.py` output) until the parse reaches
`hevcbridgeParseVdrDmDataPayload` (breakpoint oracle), then fire the ≥5 blocks.

**Expected A/B (METHODOLOGY §5):**
- 27.0 RC device (24A435): 5th block-id-1 ext block writes the 28-byte OOB record →
  corrupted x22/x21 → app crash on return-path use (or silent L8/L9 field corruption
  for B/C); `.ips` under CMGetDMVersionLevelFromRPU/AVAsset frames.
- 24B115 (27.2): parser REFUSES with its own error receipt —
  `FigSignalErrorAtGM` at FigHEVCBridge.c lines 7327/7527/7623 ("…" + err
  `kCMFormatDescriptionBridgeError_…`), no write, no crash.

## 3. Attribution honesty

- **PROVEN:** the fix family (3 count guards + 64-bit index + entry-error hardening)
  is real, instruction-level, in the "CoreMedia"-attributed dylib, in a file-parse
  path — a memory-corruption fix of exactly the advisory's shape ("memory corruption
  addressed with improved memory handling").
- **PROVEN:** the vulnerable primitives (A/B/C overruns) are LIVE on the 27.0 RC
  device build (same binary family; macOS 27.0 twin byte-shape identical — array-A
  check at `0x18d7026d4` `cmp w22,#3; b.hi 0x18d7030d4` skipping only the increment,
  `receipts/vdrdm_macos.disass`).
- **SHAPE-MATCHED (strong):** mapping to CVE-2026-112688 specifically (vs the sibling
  CoreMedia line CVE-2026-86992 "video file → app term"): the OOB-write/struct-escape
  + saved-register clobber is the natural carrier of the "…or arbitrary code
  execution" wording — 86992's "app termination" is also satisfiable by the same
  parser. Secondary candidates in the same window: `hevcbridgeParseVDRRPUDataPayload`
  (+104 B, whole-function rewrite — likely further count-check changes, unreconstructed),
  `FigHEVCBridge_CreateDolbyRPUNAL` (+8 B), MediaToolbox/VideoToolbox string deltas
  (1970/11302 lines, not triaged this session). Corroboration ladder position:
  fix-window + fix-shape + component + impact-line (strong), awaiting GM-advisory
  credit detail (Apple did not disclose function-level fixes).
- Live crash receipt NOT yet captured (header grammar iteration outstanding, §2);
  the macOS-twin firing loop is prepared (rpuprobe + lldb worked end-to-end through
  the magic checks).

## 4. Sibling census (OUR disclosure candidates)

| # | Candidate | Evidence | Status |
|---|---|---|---|
| S1 | `hevcbridgeParseVDRRPUDataPayload` rewrite (+104 B, 2860→2964) — additional unlocalized checks in the DM-data/NSW head | `nm` sizes both sides; fundiff shows whole-function restructure | FOLLOW-UP (BN pass) |
| S2 | Writer-side loops: `FigHEVCBridge_CreateDolbyRPUNAL` (+8 B) + `hevcbridgeIPush` gained cold.2/.cold.3 (fixed) — re-serializes the same counts/arrays; on VULNERABLE builds parses-corrupted counts (e.g. A=4-cap with element at idx 4 written) feed the writer → second-order corruption on RPU re-emission (remux/transcode paths) | cold-block deltas | CANDIDATE — check writer loop bounds |
| S3 | AV1-DOVI path: `FigAV1Bridge_CopyITU_T_T35MetadataDolbyVisionRPURawByteSequence` (484 B, UNCHANGED) feeds RPU bytes into the same parser family — any AV1-T.35-specific len/count handling unchecked upstream is a separate file-bug surface | symbol present, size-identical | CANDIDATE |
| S4 | `cmp w9,#0x100` on a u(8) in the block header is a dead check (u(8) ≤ 0xFF always) — suggests the author expected a wider field elsewhere; audit sibling u(9)/u(10) fields in the same header for width mismatches | `0x18ef5b368` both sides | NOTE |
| S5 | Intra-struct corruption reach of arrays B/C even WITHOUT the count overrun: B's element slots overlap the stored fields at [x23,#0x24c..0x25a] region (0x724c..0x725a) — i.e. the parser's own storage aliases across block types; mis-typed L8/L9/L10 consumers downstream (display pipeline) deserve a data-flow audit | struct-offset algebra above | CANDIDATE (audit) |

## 5. Files

- `extracted/{24A435,24B115}/CoreMedia|MediaToolbox|VideoToolbox` — both-build dylibs;
  `extracted/macos27_3350/CoreMedia` — macOS 27.0 twin (live-fire side).
- `receipts/` — vdrdm_vuln/fixed(.cold) disass, fundiff, rpu header disass both builds,
  grammar walks, string diffs, macOS receipts.
- `scripts/` — `verdiff.py` (version oracle), `diff_strings.py` (raw-byte strings),
  `fundiff.py`, `blxref.py` (BL scanner), `grammar_walk.py`, `gen_rpu.py` (seed
  builder, WIP header), `rpuprobe.c` (macOS twin harness — dlsym's the exported
  entry, prints the parse's own error receipts).
- `seeds/rpu_probe_v0.bin` — grammar probe (WIP; passes magic/rpu_type/rpu_format,
  dies mid-VDR-header) — keep as the iteration baseline, NOT a crash oracle yet.
