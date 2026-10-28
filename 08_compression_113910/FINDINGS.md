# FINDINGS.md — CVE-2026-113910 (Compression / AppleFSCompression, kernel-memory disclosure)

> AI-generated security research (same notice as AGENTS.md). Authorized research on the
> owner's device + Apple's publicly-shipped firmware, coordinated disclosure. PoCs are
> leak/crash-oracle seeds ONLY. Every claim cites a checkable artifact (binary + vmaddr +
> both-side disassembly, or a script + its output). Produced by a subagent session in one
> pass; re-verify before trusting.

**CVE line (iOS 27.2 GM advisory 149230, Compression section)**: "Impact: An app may be
able to disclose kernel memory. Description: A memory initialization issue was addressed
with improved memory handling." Credited: **Tucker Willenborg**. The advisory ALSO carries
an **AppleFSCompression acknowledgment** ("We would like to acknowledge Dawar Abbasi,
Tucker Willenborg for their assistance") — the researcher's name appears in both places.

## 0. Verdict in one line

**PROVEN (instruction-level, both sides)**: the 27.2 fix is a **produced-vs-expected gate
in the kernel decmpfs chunk-decompression driver** — `AppleFSCompressionTypeZlib.kext`,
source `AppleFSCompression/Common/ChunkCompression.cpp`, NEW log line at **:789**:

```
%s:%d: chunk %u produced %lld of %lld expected bytes
```

Pre-fix (27.0 RC, our device): a chunk that decompresses to FEWER bytes than the page-fill
descriptors demand is **copied short and the read still SUCCEEDS** — the unfilled tail of
the kernel buffer-cache page(s) retains its previous contents (stale kernel heap) and is
handed to the reading app → **kernel-memory disclosure**. Post-fix (27.2): short produce →
log + EINVAL, no disclosure. This is the advisory's "memory initialization issue addressed
with improved memory handling" verbatim: pages that were never initialized with file
content are no longer validated into the page cache.

Component placement is PROVEN (only memory-safety change in the whole compression family
in this window, exact impact shape, version-bump corroboration); the CVE↔site mapping is a
strong shape-match short of Apple's internal ticket (ranked PROVEN-site / shape-matched-CVE).

## 1. What changed (version-diff oracles, METHODOLOGY §4)

Kernel kexts (`ipsw kernel kexts`, both kernelcaches; the bundle versions are PINNED — the
real oracle is bytes + `LC_SOURCE_VERSION`):

| binary | 24A435 | 24B115 | delta |
|---|---|---|---|
| `com.apple.AppleFSCompression.AppleFSCompressionTypeZlib` | 98,656 B, SOURCE_VERSION 182.0.0 | 115,032 B, SOURCE_VERSION **182.40.4** | **+16,376 B (+16.6%)** — the fix carrier |
| `com.apple.kec.Compression` | 65,664 B | 65,664 B | bytes differ, **zero string receipts → rebuild churn** (honest negative, §6) |

Userspace dsc images (`ipsw dyld info --dylibs`):

| image | 24A435 | 24B115 |
|---|---|---|
| `AppleFSCompression.framework` | 182.0.0 | **182.40.4** (same `40.4` fix-train suffix as AppleDiskImages2 598.40.4) |
| `libcompression.dylib` | 212.0.1 | 212.40.2 (grew 16 KB, **zero string receipts** — rebuild churn; public Compression.framework is a re-export stub of this dylib) |
| `libParallelCompression.dylib` | 469.0.0 | 469.40.4 (same tree) |
| `GeometryCompression`/`SignalCompression`/`URLCompression`/liblzma/libswiftCompression | unchanged | unchanged |

Strings-diff of the kext pair (`strings -a | sort -u | comm`) — the ENTIRE meaningful delta:

- **NEW in 24B115 (exactly one)**: `%s:%d: chunk %u produced %lld of %lld expected bytes`
  @ vmaddr `0xfffffff007432d57` (file off 0x3ff7), plus the `182.40.4` version string and
  the new xbs build-UUID paths (source re-layout, same file paths).
- GONE: only the old build-UUID paths.
- The same delta holds in the **userspace AppleFSCompression.framework** (new:
  the identical produced/expected string + `PROJECT:AppleFSCompression-182.40.4`, gone:
  `PROJECT:AppleFSCompression-182`) — one source tree (`ChunkCompression.cpp`) compiled
  into both the framework (process-memory facet) and the kext (kernel-memory facet, the CVE).
- `grep -cF 'produced %lld'` over the WHOLE kernelcaches: 24A435 = **0**, 24B115 = **1**
  (the kext blob only; the kernel proper never had it — its fix is kext-side only).

## 2. The fix site, both sides (receipts)

Stripped kexts (LC_SYMTAB empty) → located via strings + raw ADRP/ADD xref scanners
(`scripts/ds_strscan.py`, `ds_xref_raw.py`, `ds_page_refs.py`). Function boundaries from
`pacibsp` (0xD503237F) function starts (`scripts/ds_fnstrings.py` →
`extracted/receipts/pacibsp_fntable_sizes.txt`). Full disassemblies preserved in
`extracted/receipts/`.

### 2a. Function-level map (functions in identical order, sizes)

The chunk driver **FN#30** grew **1,228 → 3,024 bytes (+146%)**; the old per-chunk worker
**FN#37** (1,784 B, `0xfffffff008b9e00c`) shrank to a 532-B stub — its logic was INLINED
into FN#30 (+1,796 ≈ old worker 1,784 + the new gate). All other size deltas are codec/
codegen churn (inflate/huffman engines FN#3/8/9/17/21/22 — verified mnemonic-level,
no fix shape; see §6).

### 2b. The vulnerable path (24A435 — LIVE on our 27.0 RC device)

Driver `0xfffffff008b9d460` builds per-page {dest,len} descriptors (16 B each) for the
requested range and calls the worker `0xfffffff008b9e008` per batch. The worker decodes a
chunk via the kec.Compression-backed decode `0xfffffff008b9cb18`, which returns
**produced-bytes in the low 32 bits** (error flag in the high bits):

Single-descriptor path — **success WITHOUT any produced-vs-expected compare**:

```
0xfffffff008b9e440:  bl    0xfffffff008b9cb18      ; decode chunk
0xfffffff008b9e444:  cbz   x0, loc_...e614         ; 0 → "decode failed" error
0xfffffff008b9e448:  mov   x8, x0                  ; x8 = PRODUCED (may be < expected!)
0xfffffff008b9e44c:  mov   w0, #0                  ; <<< SUCCESS unconditionally
0xfffffff008b9e450:  str   x8, [x19]               ; outSize = produced
0xfffffff008b9e454:  b     exit                    ; <<< NO compare of produced vs (w25-w26)
```

Multi-descriptor path — the copy loop copies only `min(len, produced)` per descriptor and
then returns **success**:

```
0xfffffff008b9e5d0:  bl    0xfffffff008b9cb18      ; decode into workbuffer
0xfffffff008b9e5d4:  cbz   x0, <decode failed>
0xfffffff008b9e5d8:  mov   x22, x0                 ; x22 = PRODUCED
0xfffffff008b9e5dc:  lsr   x8, x0, #0x20 ; cbz → e69c  ; size/err split check only
...
0xfffffff008b9e6b4:  cmp   x10, w22, uxtw          ; descriptor len vs PRODUCED
0xfffffff008b9e6b8:  csel  x26, x10, x8, lt        ; copy = min(len, produced)
0xfffffff008b9e6c8:  (memcpy into the page descriptor)
...
0xfffffff008b9e384:  mov   w0, #0                  ; <<< SUCCESS; shortfall pages UNWRITTEN
```

The driver's only tail check is dead code: `subs x8, x28, [sp,#0x28]; b.hs → success`
compares total-produced against the SKIPPED-PARTIAL offset (trivially true) — it can never
catch a shortfall. `extracted/receipts/worker_fn37_24A435.disasm.txt` + `driver_fn30_24A435.disasm.txt`.

### 2c. The fixed path (24B115)

Driver `0xfffffff008bcf010` (worker inlined). New decode helper `0xfffffff008bce6b8`;
after each chunk's decode+copy the NEW gate:

```
0xfffffff008bcf7c8:  cmp   x28, x22                ; total_copied vs EXPECTED (batch)
0xfffffff008bcf7cc:  b.lt  loc_...f8ac             ; short →
0xfffffff008bcf8b8:  mov   w8, #0x315              ; ChunkCompression.cpp line 789
0xfffffff008bcf8cc:  adrp  x0, ...
0xfffffff008bcf8d0:  add   x0, x0, #0xd57          ; "%s:%d: chunk %u produced %lld of %lld expected bytes"
0xfffffff008bcf8d4:  bl    __stub_...              ; kernel log
0xfffffff008bcf8d8:  mov   w27, #0x16              ; EINVAL → error return, no page commit
```

Both the single-chunk (decode direct-into-page) and multi-chunk (decode-into-workbuffer +
memcpy-out) paths route through this gate. `extracted/receipts/driver_fn30_24B115.disasm.txt`.

### 2d. Pre-existing checks (NOT the fix — do not re-credit)

These strings appear in BOTH builds (moved/inlined by the restructure, same line numbers
in the source): chunk-index-vs-count (`attempting to read chunk %u from file with %u
chunks` :527), xattr-vs-disk-header (:537), `resource fork offsets are out of order`
(:575), `invalid zlib header` (:614), `decode failed`/`decmpSize too big`/:640/:647,
`vecTotal is too big` (:631). The ONLY genuinely new validation in the whole kext is the
produced-vs-expected gate at :789 — a single-check fix, responsive-fix shape
(METHODOLOGY §2: one window, one subsystem, one check = the classic responsive-fix signature).

## 3. The reach path (how an app gets the stale kernel bytes)

Receipted kernel-side architecture (strings in the 24A435 kernel proper, unchanged in 24B115):

```
decmpfs_pagein_compressed: couldn't ubc_upl_map a single page   (decmpfs.c)
register_decmpfs_decompressor %d: CMP_Type%d failed: %d
com.apple.decmpfs / com.apple.ResourceFork / "VM object is read-only (decmpfs?)"
```

1. App calls `read()`/`mmap()` (or anything that faults a page) on a file with a decmpfs
   xattr (transparent-compressed file; chunked scheme = resource-fork payload + chunk table,
   64 KiB chunks).
2. Kernel `decmpfs_pagein_compressed` builds a **UPL over the file's buffer-cache pages**
   and hands it to the registered compressor plugin (this kext).
3. The kext's chunk driver fills the UPL page descriptors with decompressed content.
4. **27.0**: an under-producing chunk (corrupted compressed data, or a chunk table whose
   claimed sizes exceed what the streams produce) leaves the tail of the page(s)
   UNWRITTEN — the pages are pre-existing kernel buffer-cache pages containing stale
   kernel heap contents — and the read returns SUCCESS.
5. VFS validates the page; the app receives the stale kernel bytes → **kernel-memory
   disclosure**. ("Memory initialization issue": the page was never initialized with the
   file's content.)
6. **27.2**: step 4 refuses (`cmp x28, x22; b.lt` → log + EINVAL); the read fails cleanly.

**The precondition** — getting an under-producing compressed file read by the victim — is
the one OPEN reachability item (SHAPE-MATCHED honestly): it requires a malformed/corrupt
compressed file (valid files always produce exactly the chunk-table sizes). Candidate
craft routes (the probe row's cells exist to decide them, §5 + HARNESS_ROW.md):
(a) direct `setxattr(com.apple.decmpfs…)` — the xattr namespace may be
kernel-restricted (test: EPERM vs success is itself a receipt);
(b) macOS-twin route: `ditto --hfsCompression` creates a valid compressed file;
    corrupt the resource-fork chunk payload (`scripts/ds_corrupt_chunk.py`) and read it
    back (`scripts/ds_scan_leak.py`) — the 27.0 macOS twin gives the A/B directly,
    as group 02 did for libarchive;
(c) system-created compressed files whose payload got corrupted post-compression
    (no attacker craft needed — matches "memory initialization issue" as a real-world
    defect class; the researcher's disclosure will tell).

Userspace facet: the same `ChunkCompression.cpp` in `AppleFSCompression.framework`
(`_decompressFile`/`_catFile`/`_decompressWithCallback`, symbols present in the dsc
extraction) got the same gate — pre-fix that path disclosed PROCESS memory to the
library's caller (the system daemons that cat compressed files). The AppleFSCompression
acknowledgment covering both names is consistent with one report touching both facets.

## 4. Oracle recipe (readback/scan, not crash — METHODOLOGY §5 adapted for leaks)

Memory-init leaks don't crash, so the discriminator is a **content scan**:

- **Seed**: a transparent-compressed file whose plaintext is KNOWN and uniform (e.g.
  200 KB of 0x00), then one chunk's compressed payload corrupted so the decode succeeds
  but produces short (see `scripts/ds_corrupt_chunk.py`).
- **Vulnerable-side receipt (27.0)**: `read()`/`cat` SUCCEEDS; the returned byte range
  contains NON-plaintext garbage in the short-fill region (run `ds_scan_leak.py`:
  foreign-byte runs past the corruption offset, byte histogram = kernel-artifact
  fingerprint). Optional corroboration: `.ips` absence (no crash — that's the point).
- **Fixed-side receipt (27.2)**: read returns EINVAL (or clean short read) AND the kernel
  log carries `chunk %u produced %lld of %lld expected bytes` (unified log / `log show
  --predicate 'eventMessage CONTAINS "expected bytes"'`) — the fix's OWN error receipt.
  The pair (vulnerable garbage vs fixed refusal+log) = the proven-live A/B.
- **Noise control**: repeat the read after scrubbing the page cache (drop caches on the
  mac twin; different files on iOS) so the stale-page contents differ between runs —
  variability across runs where the plaintext is constant = independent proof the
  returned bytes are not file-derived.

## 5. Harness row (summary — full spec in HARNESS_ROW.md)

Row **CMP-K1** (one row, 4 cells, no daemon/epoch machinery): C0 xattr-write reachability
probes (setxattr com.apple.decmpfs / resource fork — EPERM-vs-success receipt),
C1 valid-compressed-file readback baseline, C2 corrupted-chunk readback + scan (the leak
oracle), C3 chunk-table-size mismatch variant (corrupt the 16-byte {off,len} entry's len
UPWARD instead of the payload — same gate, different precondition). Per-cell receipts:
errno, bytes read, foreign-run count/offsets, and the `.ips captureTime <-> [stamp]`
correlation line. The macOS-twin pre-run (cell C2 fired on macOS 27.0 first) is the cheap
live receipt before any device time.

## 6. Sibling census — unfixed/adjacent candidates for OUR disclosure

1. **Chunk-table sizes vs xattr logical size, on the FIXED build too** (strongest): the
   fix gates per-batch `copied >= expected`, but `expected` is computed by CLAMPING to the
   chunk-table entry's own size (`csel` against `[x12+8]`). I found NO check that
   `sum(chunk-table sizes) >= xattr logical size`. A file whose chunk table legitimately
   covers fewer bytes than the logical size (table crafted short, or truncated table)
   passes every per-chunk gate and STILL short-fills the page range on 27.2 — the
   disclosure may survive the fix through this route. Needs: sum-vs-logical-size check
   census in the driver + kernel side (`decmpfs_pagein_compressed` error handling).
2. **Compress-side accounting**: whether `CompressFile` (userspace) / the kext compressor
   can WRITE a chunk table whose claimed sizes exceed what it actually stored (interrupted
   compression, error-path accounting) — if yes, under-producing files arise WITHOUT
   corruption, both pre- and post-fix; that is the real-world shape of the "memory
   initialization issue". Audit the compressor's produced-vs-claimed symmetry.
3. **Dead tail check**: the driver's final `subs x8, x28, x10; b.hs` (produced vs
   skipped-partial) remains semantically dead in BOTH builds — a requested-range-vs-
   produced check never existed at the driver tail; the batch loop only exits on
   remaining==0 or chunk-count. Edge: requested range extending past the last chunk.
4. **`kec.Compression` decode contract**: the low32-produced/high32-error return packing
   is consumed by the kext with checks; OTHER kexts/paths consuming kec.Compression
   (if any) may still trust produced implicitly — census of kec.Compression callers
   in the 24B115 kernelcache is the follow-up.
5. **libcompression.dylib** (userspace, 212.40.2): zero string receipts; its +16 KB is
   unexplained rebuild churn — a function-level audit of its decoders for the same
   produced-vs-expected trust could surface the userspace twin of sibling #1 (process
   disclosure, not kernel).

## 7. Honest negatives + coverage limits

- `com.apple.kec.Compression`: bytes differ but **no fix-shaped change** — 3 functions
  differ at mnemonic level; spot-checked FN#11's changed region (stack-guard/PAC idiom
  reshuffle) — churn, no new bounds/zeroing receipt. Not the fix.
- `libcompression.dylib`: no string delta at all — rebuild churn candidate, NOT triaged
  function-level (out of scope for the kernel-CVE; listed as sibling #5).
- The CVE↔site mapping is shape-based (one fix of exactly the advisory's shape in the
  credited component); Apple's internal ticket or Willenborg's disclosure would close it.
- The on-device craft route (iOS xattr restrictions) is unresolved — C0's job.
- I did not decode the chunked-format header fully (magic constants 0x1cc/0x2ff/0x306/
  0x4fe/0x4ff/0x5ff/0x6ff observed as scheme IDs); `ds_corrupt_chunk.py inspect` is the
  format-mapping tool for whoever builds the final seed.

## 8. Deliverables in this folder

- `extracted/kernel_24A435|24B115/` — both-build kexts (TypeZlib + kec.Compression)
- `extracted/dsc_24A435|24B115/` — AppleFSCompression framework, libcompression,
  libParallelCompression (both builds)
- `extracted/receipts/` — driver/worker disassemblies both sides + function-size table
- `scripts/` — `ds_strscan.py` (string locate), `ds_xref_raw.py`/`ds_page_refs.py`/
  `ds_adrp_pages.py` (raw ADRP xrefs), `ds_fnstrings.py` (per-function string map),
  `ds_mnemdiff.py` (mnemonic diff), `ds_fndiff.py` (function pairing), plus the two
  oracle scripts `ds_corrupt_chunk.py` / `ds_scan_leak.py`
- `seeds/` — see README (seed recipe = valid compressed file + corruption script)
- `HARNESS_ROW.md` — the CMP-K1 probe-row spec

## 9. Reproduce the headline receipts

```bash
# strings delta (the ONE new string)
strings -a extracted/kernel_24*/com.apple.AppleFSCompression.AppleFSCompressionTypeZlib | grep -cF 'produced %lld'
# 24A435: 0 ; 24B115: 1   (also 1 in the whole 24B115 kernelcache, 0 in 24A435's)

# string vmaddr + xref
python3 scripts/ds_strscan.py extracted/kernel_24B115/com.apple.AppleFSCompression.AppleFSCompressionTypeZlib "produced %lld" --xrefs
python3 scripts/ds_page_refs.py  extracted/kernel_24B115/com.apple.AppleFSCompression.AppleFSCompressionTypeZlib 0xfffffff007432000 | grep d57
# → add@0xfffffff008bcf8d0 (adrp@0xfffffff008bcf8cc) -> 0xfffffff007432d57

# the gate (fixed) vs the silent success (vulnerable)
/opt/homebrew/bin/ipsw macho disass extracted/kernel_24B115/...TypeZlib --vaddr 0xfffffff008bcf7c8 --count 8
/opt/homebrew/bin/ipsw macho disass extracted/kernel_24A435/...TypeZlib --vaddr 0xfffffff008b9e440 --count 8
/opt/homebrew/bin/ipsw macho disass extracted/kernel_24A435/...TypeZlib --vaddr 0xfffffff008b9e6b4 --count 8
```
