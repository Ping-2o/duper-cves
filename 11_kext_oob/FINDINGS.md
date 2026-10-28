# FINDINGS.md — CVE group 11 "kext OOB primitives" (iOS 27.2 advisory 149230, iPhone17,5 24A435→24B115)

> AI-generated security research (same notice as AGENTS.md). Authorized research on the owner's
> device + Apple's publicly-shipped firmware, coordinated disclosure, crash-oracle PoCs only.
> Every claim cites a checkable artifact (function + VA + both-side disasm, or a script + its
> output file in `extracted/`). Re-verify before trusting.

## 0. Inputs, method, and what is new in this pass

Binaries (all quoted paths on `/Volumes/ADATA ELITE SE880`):

| lane | 24A435 (27.0 RC, vulnerable) | 24B115 (27.2 RC, fixed) |
|---|---|---|
| IOStorageFamily | `kdiff_272/kexts24A435/com.apple.iokit.IOStorageFamily` (copied to `extracted/24A435/`) | `kdiff_272/kexts24B115/...` (id.) |
| IOSurface | id. (`com.apple.iokit.IOSurface`) | id. |
| AppleH16ANEInterface | **newly carved** `ipsw kernel extract` → `extracted/24A435/` (1,910,000 B) | id. 24B115 (1,975,760 B) |
| AppleT8140ANEHAL | newly carved (`extracted/24A435/`) | id. |
| livefiles_hfs.dylib | **newly carved** `ipsw dyld extract` UserFS.plugin → `extracted/24A435/` (version 751.0.0) | id. 24B115 (753.42.1) |
| IOKit framework (USERSPACE) | newly carved `IOKit.framework/Versions/A/IOKit` (100288.0.9) | id. 24B115 (100288.40.8) |
| IOMFB-adjacent kexts | newly carved IOMobileGraphicsFamily(+DCP), AppleMobileDispH17P-DCP, AppleDCP | id. |
| kernel proper | `kdiff_272/kernel24A435/com.apple.kernel` | `kdiff_272/kernel24B115/com.apple.kernel` |

Version-receipt (full census in `extracted/kexts_24A435.txt` / `kexts_24B115.txt`, 318 each):
AppleH16ANEInterface **10.19.6→10.102.4**, AppleT8140ANEHAL 10.19.3→10.102.3, IOSurface
402.8→403.1, livefiles_hfs 751.0.0→753.42.1, IOKit.framework 100288.0.9→100288.40.8.
IOStorageFamily/IOHIDFamily/IOMobileGraphicsFamily*/AppleMobileDispH17P-DCP/AppleDCP are
version-pinned with byte drift.

**Method (the map §0 pipeline, rebuilt + hardened).** The prior session's scripts survive in
the old temp dir and were copied to `scripts/` (paths fixed). New this session:

1. `scripts/fn_shape.py` — **layout-churn-robust pairing**: functions pair across builds by
   (instruction-count, mnemonic-sequence hash), then difflib-fuzzy pair the remainder; dumps
   mnemonic-level diffs. This defeats the code-movement churn that made the old
   normalized-hash pipeline produce false "surgical pairs" (map-1 §4's IOSurface "struct
   re-layout churn" was PAIRING NOISE — the kext has exactly 3 changed functions, see §4).
2. Strings-first everywhere (`strings -a | sort -u | comm`).
3. `scripts/ds_strxref.py` (adrp+add string xrefs), `scripts/ds_dis.py` (capstone disasm),
   `scripts/ds_blxref.py` (BL census) for the receipts.
4. Cross-reference of the decoded `__DATA_CONST,__assert` census
   (kernel_272_diff_map_2.md §2, `k2/asserts_diff.json`) for IOKit markers: **0 records in
   any iokit/IOUserClient/IOService/IOCommand/IOMemory file** — the kernel-proper assert route
   is an honest dead end for CVE-2026-65385 (see §5).

Shape-pair results (the whole-change census per binary):

| binary | shape-identical | changed | only-old/only-new |
|---|---|---|---|
| IOStorageFamily | 545/563 | 18 pairs | 0/0 |
| IOSurface | **1327/1330** | **3 pairs** | 0/0 |
| AppleH16ANEInterface | 4721/4959 | 157 pairs | 81/222 |
| AppleT8140ANEHAL | (no string deltas; not shape-run — HAL carries no new validation strings) | — | — |
| livefiles_hfs.dylib | 670/677 | 3 pairs | 4/4 |
| IOKit.framework (userspace) | 3566/3575 | 5 pairs | 4/15 |
| IOMobileGraphicsFamily | 1154/1156 | 2 pairs | 0/0 |

---

## 1. CVE-2026-112554 — IOStorageFamily OOB read — **PROVEN** (the map §4 triage, finished)

Apple line: *"An app may be able to cause unexpected system termination or read kernel memory.
An out-of-bounds read was addressed with improved bounds checking."*
Credits: Bhetwal, Kiyok, Song, Seriot, DeVoss/Braze, Willenborg, Premkasem, Gokulakannan,
Malone, Zana (9 researchers — the "everybody found it" class).

### 1a. The fix site: the GPT partition-name scan in the partition-descriptor builder

The one content-changed function pair (269 ins, ratio 0.97) is the partition property-dictionary
builder (its strings: `Untitled %d`, `Base`, `Partition ID`, `UUID`, `GPT Attributes` — the
IOMedia/IOGUIDPartitionScheme property family). `x19` (arg1) is a **raw `gpt_ent`**:
`ldp x25,x26,[x19,#0x20]` = start/end LBA (gpt_ent+0x20/0x28), `[x19+0x30]` = attributes, and
**`[x19+0x38]` = the 72-byte UTF-16LE `partition_name`** (gpt_ent layout verbatim).

OLD (24A435, fn 0xfffffff00a33c6cc) — the name scan:

```
0xfffffff00a33c788: mov  x8, #0
0xfffffff00a33c78c: add  x0, x19, #0x38          ; &ent->partition_name (72 bytes)
0xfffffff00a33c790: ldrh w9, [x0, x8, lsl #1]    ; scan UTF-16 chars for NUL
0xfffffff00a33c794: cbz  w9, done
0xfffffff00a33c798: add  x8, x8, #1
0xfffffff00a33c79c: cmp  x8, #0x48              ; <<< BOUND = 72 CHARS = 144 BYTES
0xfffffff00a33c7a0: b.ne 0xfffffff00a33c790     ;     72 bytes PAST the 72-byte field
...
0xfffffff00a33c7c0: lsl  x1, x8, #1             ; len = 2 * scanned_count (up to 144)
0xfffffff00a33c7dc: bl   0xfffffff00a34a8e4     ; name -> UTF-8 (dst cap w4=0x6d)
```

NEW (24B115, fn 0xfffffff00a37e58c) — three receipts:

1. **bound halved to the true field size**:
```
0xfffffff00a37e660: cmp  x8, #0x24              ; <<< 36 chars = 72 bytes = the field
0xfffffff00a37e664: b.ne 0xfffffff00a37e654
```
2. **conversion-result validation** (new error arm):
```
0xfffffff00a37e6a4: cbnz w0, +0xc               ; helper failed ->
0xfffffff00a37e6a8: ldr  x8, [sp, #0x10]         ; outLen
0xfffffff00a37e6ac: cbnz x8, +0x10              ; produced bytes -> proceed
0xfffffff00a37e6b0: ldrh w8, [x24]              ; else first char of source name
0xfffffff00a37e6b4: cbnz w8, 0xfffffff00a37e97c ; non-empty source, empty result -> ABORT to cleanup
```
3. wider stack zero-init (`stp q0,q0,[x29,#-0x80]` → `[x29,#-0x90]`).

The other 17 changed pairs are a **codegen refactor** (hoisted `ldp` prologues, a `+0x1b`
bit-clear at `[obj+8]`, dispatcher validation moved into 42-ins per-case handlers — same
checks both sides, e.g. `cmp w11,#0x54; b.lo` / `cmp w10,#0x13c; b.lo` at
0x38bb00/0x38bb08), NOT fixes. No added bounds anywhere else in the kext (mnemonic census:
the 171 old-pipeline "edited pairs" contain ONLY bl/b retargets, 543/543 symmetric).

### 1b. Live-bug statement, reach, oracle

- **Primitive**: pre-fix, a GPT entry whose 72-byte name field contains no NUL makes the scan
  read 144 bytes from a 72-byte field — up to **72 bytes past the end of the `gpt_ent`**. For
  the last entry in the kernel heap buffer holding the parsed GPT, that is past the
  allocation. The over-scanned bytes are converted into the partition's name property
  (`Base`/`Partition ID`/`UUID`/`GPT Attributes` dictionary) — a kernel-heap
  **disclosure** that matches the advisory's "read kernel memory". The termination arm: a
  scan across a page end panics.
- **Reach (iPhone17,5)**: attach a GPT block device over USB-C (the 16e supports USB-C flash
  drives; IOGUIDPartitionScheme parses the GPT in-kernel). The 27.0 attacker needs a crafted
  GPT on media the user mounts, not an app syscall — the advisory's "app" phrasing fits the
  macOS twin better (any app reads the registry), but the vulnerable code ships in our
  kernelcache and runs on mount.
- **Oracle (A/B)**: same crafted GPT — 27.0: registry/media name property contains bytes from
  past the entry (marker-pattern seed) or panic; 27.2: name truncated to ≤36 UTF-16 chars and
  the abort path for overlong names. Seed: `seeds/gen_gpt_oob_seed.py` → `gpt_oob_seed.img`
  (128 entries, all names NUL-free, verified).
- **Grade**: PROVEN fix site (both-side disasm); CVE mapping exact (the only OOB-read-shaped
  change in the kext; IOHIDFamily/112515 was the other OOB-read line and is group 06's).

### 1c. Sibling census (IOStorageFamily)

- The `ldrh [xN,xM,lsl#1]` 16-bit-scan census over the whole kext: **exactly one site** — the
  fixed one (24A435 0xa33c790; 24B115 0xa37e654). No unfixed sibling scan.
- The 42-ins handler family retains all its argument-size gates on both builds (checked in
  the shape dump: `cmp #0x54`, `#0x13c`, `#0x5c`, `#0x3c` present both sides).
- Residual: the gpt LBA fields (`start`/`end` × block size at 0xa33c864) are consumed with no
  LBA-vs-disk-size check in this function — that bound, if any, lives in the caller
  (unpinned; the caller is reached via chained fixups, no BL/adrp xref).

---

## 2. CVE-2026-112456 — HFS "heap corruption" — **PROVEN, USERSPACE** (reachability answered)

Apple line: *"Processing a maliciously crafted file may lead to heap corruption. An
out-of-bounds write issue was addressed with improved input validation."* (Jihwan Yoon,
Yash Pandya, Parth Raval). NOTE: the advisory says **heap corruption, not kernel heap** — that
wording is the first clue, and it is borne out by the diff.

### 2a. Where HFS lives on iOS 27 (the reachability answer, honest)

- The iPhone17,5 kernelcache has **no HFS kext**: `ipsw kernel kexts` (318 entries both
  builds) lists none; a strings sweep of the kernelcache finds only GPT/media glue
  (`findAppropriateIOMediaObject: >> Apple_HFS <<`, sandbox paths `hfs.util`/`fsck_hfs`) —
  the HFS filesystem *implementation* is absent from kernel memory on this device.
- The HFS carrier is **`/System/Library/PrivateFrameworks/UserFS.framework/PlugIns/livefiles_hfs.dylib`**
  — Apple's userspace filesystem plugin (livefiles) — version **751.0.0 → 753.42.1** in this
  window (dsc listing receipt). HFS on iOS 27 is a **UserFS userspace** filesystem: the
  crafted-file heap corruption happens in the mounting/inspection PROCESS, not the kernel.
- Reachability on a stock iPhone: the parser is reachable where a crafted HFS *image/file*
  gets processed — the UserFS/disk-images attach path (DiskImageKit/DiskImages2 also moved
  598.0.1→598.40.4 in this window, and AppleDiskImages2 kext likewise). No stock app can
  mount an arbitrary image on iOS; the realistic vectors are (a) the macOS twin (full-reach,
  same livefiles family), (b) on-device MDM/enterprise or Xcode-adjacent image attach, and
  (c) any first-party surface that inspects HFS volumes (e.g. backup/import) — **unmapped**.
  The honest verdict: fix PROVEN and localized; on-device app-reach is NOT open, macOS-reach
  is immediate.

### 2b. The fix sites (3 functions, symbols kept by the dylib)

| function | 24A435 | 24B115 | change |
|---|---|---|---|
| `_hfs_swap_HFSPlusBTInternalNode` | 0x2b30b9548 (1222 ins) | 0x2baf21668 (1228) | **the OOB fix** |
| `_VerifyHeader` | 0x2b30b12f8 (53) | 0x2baf192f8 (56) | new `ldrh w8,[x1,#0x10]; cmp; b.hi` header bound |
| `_RotateLeft` | 0x2b30d841c (240) | 0x2baf407b4 (248) | new `ldrh; cmp; b.lo` + restructured loads |

`_hfs_swap_HFSPlusBTInternalNode` is the classic HFS+ B-tree node byte-swapper — the exact
function family of the historic hfs catalog bugs (CVE-2010-0105 class), now living in the
userspace port. Verbatim:

OLD (24A435) — trusts the on-disk keyLength for the in-place UTF-16 swap loop:
```
0x2b30b9acc:  (loop) ldrh w11, [x9, x8, lsl #1] ; swap keyLength UTF-16 units
0x2b30b9ad0:  rev   w11, w11 ; lsr #0x10 ; strh  ; in place, in the node buffer
0x2b30b9adc:  add   x8, x8, #1
0x2b30b9ae0:  cmp   x8, x10                       ; x10 = keyLength itself — the only "bound"
0x2b30b9ae4:  b.lo  loop                          ; keyLength = 0xFFFF walks ~128KB out
...
0x2b30b9aec:  rev16 w8, w10 ; strh w8, [x27, #0xa] ; raw length storeback, unclamped
```

NEW (24B115) — three added gates before the same loop:
```
0x2baf21bd4: and   w12, w10, #0xffff             ; clamp
0x2baf21bd8: and   x10, x10, #0xffff
0x2baf21bdc: add   x11, x9, x10, lsl #1          ; end = name + len*2
0x2baf21be0: cmp   w12, #0xff                    ; <<< len > 255 (kHFSMaxNameChars)?
0x2baf21be4: b.hi  0x2baf22474                   ;     -> error path
0x2baf21be8: cmp   x11, x8                       ; <<< end > node-buffer end?
0x2baf21bec: b.hi  0x2baf22474                   ;     -> error path  (OOB WRITE fixed)
0x2baf21bf0: cbz   w10, +0xc4                    ; zero-length restructure
```

- **Grade**: PROVEN fix (both-side disasm, named functions). CVE-2026-112456 mapping:
  shape-exact ("OOB write, input validation" = the keyLength clamp); impact class matches the
  advisory's heap (process) corruption.
- **Oracle**: A/B — crafted B-tree node with keyLength/nameLen = 0xFFFF (seed
  `seeds/gen_hfs_btree_keylen_seed.py` → `hfs_btree_keylen_oob_node.bin`, verified): 751.0.0
  plugin heap corruption/crash on parse; 753.42.1 refuses (bounds error) — the macOS twin can
  fire this through any livefiles HFS path.
- **Siblings**: the swapper's OTHER unbounded trusts (record-offset array walk, record count
  in `_RotateLeft`/`_VerifyHeader` neighbors) — the 27.2 pass added three gates here but did
  NOT visibly re-validate the record-offset walk; flagged as a live sibling candidate in the
  userspace plugin on both builds (our-disclosure material, needs the daemon harness).

---

## 3. CVE-2026-112696 + CVE-2026-84494 — Apple Neural Engine OOB writes — **PROVEN fix wave**

Apple lines: *"app ... unexpected system termination or corrupt kernel memory. An
out-of-bounds write ... improved bounds checking"* (112696, Jaeyeong Lee); *"app ... unexpected
system termination or **write kernel memory**. An out-of-bounds write ... improved bounds
checking"* (84494, Tsytsarkin).

Carriers: `com.apple.driver.AppleH16ANEInterface` 10.19.6→10.102.4 (interface kext, the
app-facing one) + `com.apple.driver.AppleT8140ANEHAL` 10.19.3→10.102.3 (HAL — **strings-clean,
no validation receipts; the fix wave is entirely in the interface kext**).

### 3a. Strings diff (the fix-marker census)

603 new strings; the validation-shaped subset (all `[ERROR] %s: %s:` family, new-in-24B115):

- `Procedure %u input/output symbol index %u out of range, totInputBuffers/totOutputBuffers: %u`
- `Procedure %u IO counts out of range - numInputs: %u numOutputs: %u max: %u`
- `Number of procedures(%u) in the program exceeds max number(%u) supported`
- `Too many coalesced input/output surfaces for procedure %u buffer %u, max: %u`
- `Firmware reported %u chaining input buffers, clamping to %u`
- `Endpoint[%ld] message too small for command header / handshake info`
- `Invalid offset and size for endpoint[%ld] bufferSize. Out of bounds message`
- `Shared memory alloc/free/remap message too small`
- `BACK_CHANNEL_RPC: message too small for %u declared rpc items`
- `Channel descriptor %u interrupt source (%u) exceeds max supported (%u)`
- `Process %s split count exceeds kANEMaxBars`, `Split text sections count exceeds kANEMaxBars`
- `Not enough bar info in firmware struct, numofRelocations...`

### 3b. The pinned site (both-side disasm): `processInputBufferMappingInfo`

NEW (24B115 fn 0xfffffff008ccb41c, NEW-only function — the loader was rewritten around the
checks):
```
0xfffffff008ccb4a0: lsl   x9, x20, #2
0xfffffff008ccb4a4: umaddl x9, w11, w12, x9       ; inputIdx*0xb40 + bufferIdx*4
0xfffffff008ccb4a8: add   x9, x9, #0x204          ; &mappingRecord->symbolIndex
...
0xfffffff008ccb4c0: ldr   w19, [x10]              ; symbolIndex
0xfffffff008ccb4c4: ldr   w8, [x22, #0x48]        ; totInputBuffers
0xfffffff008ccb4c8: cmp   w19, w8                  ; <<< THE NEW CHECK
0xfffffff008ccb4cc: b.hs  0xfffffff008ccb894      ; -> error + the new log string
```
(the output twin `processOutputBufferMappingInfo` 0x8ccbae4 has the same check at 0x8ccbfc4.)

OLD (24A435 fn 0xfffffff008c2660c, same `__func__` name — located by the dylib/kext's
`__func__` strings):
```
0xfffffff008c26690: umaddl x9, w11, w12, x9
0xfffffff008c26694: add   x9, x9, #0x204
0xfffffff008c266d4: ldr   w22, [x10]              ; w22 = symbolIndex   <<< NO CHECK
...
0xfffffff008c26780: lsl   x10, x22, #9            ; symbolIndex * 0x200
0xfffffff008c26788: add   x11, x9, w10, sxtw      ; [x21+0x40] + idx*0x200   (unchecked)
0xfffffff008c2679c: lsl   x10, x22, #4            ; symbolIndex * 16
0xfffffff008c267b4: ldr   w9, [x12]               ; READ via unchecked index
0xfffffff008c26728: mov   x2, x22                 ; index handed to callee 0x8c5f974
0xfffffff008c26800: mov   x2, x22                 ; ...and callee 0x8d3e86c
0xfffffff008c26a54: str   w22, [x12]              ; WRITE via unchecked index (storeback)
```
(The `cmp x?,w?,sxtw`+`csel 0x2bad` pairs are the compiler's bounds-safety-PAC idiom —
they only trap on address-computation overflow, NOT index-vs-array-size.)

- **Primitive**: the ANE program (mach-O) the app submits for on-device execution carries
  per-procedure input/output buffer-mapping metadata; `symbolIndex` from that file indexes
  kernel tables at ×16 (read) and ×0x200 strides, unvalidated, in 27.0 → **OOB read+write in
  kernel memory** = the advisory's "write kernel memory". NEW validates against
  `totInputBuffers`/`totOutputBuffers`.
- **Reach**: AppleH16ANEInterface userclient ← CoreML model load (`programLoadFromMachoFile`
  24A435 0x8c3a864 parses the model's ANE mach-O; the mapping-info functions run on load /
  per-request buffer binding). A malicious app ships a crafted model (the ANE program is a
  compiled artifact in the app bundle) → kernel-side parse. App-reachable, no entitlement
  question (same class as the AVE2 kext bugs: the file rides in the app).
- **Oracle**: A/B needs a valid ANE program seed mutated at
  `mappingRecord[inputIdx].symbolIndex` (+0x204 of a 0xb40-stride record) to ≥ totInputBuffers
  → 27.0: kernel OOB (panic-first / silent corruption); 27.2: the new error log
  ("input symbol index out of range") + kIOReturn error. No static seed can be built without a
  real compiled-model artifact (honest limitation; the harness row ANE-K1 specifies the
  mutation recipe instead of a file seed).
- **CVE split within the wave** (both PROVEN as fixes; the per-CVE assignment is
  shape-matched, not credit-proven):
  - **84494 ("write kernel memory")** = the symbol-index family (the ×16/×0x200 kernel-table
    indexing with a storeback — the write primitive).
  - **112696 ("corrupt kernel memory")** = the count family: `makeKernelCopyOfProgramInfo`
    (NEW "IO counts out of range" / `procedure count exceeds max`) + `programLoadFromMachoFile`
    procedure-count gates + the coalesced-surfaces caps (0x8d49af0 / 0x8d4ee68 / 0x8d34f2c /
    0x8d4bc84) — heap corruption by oversized counts.
  - The `HandleRTBuddyMessage` endpoint offset/size + shared-memory message-size gates
    (0x8c80610 / 0x8c7a990) are firmware-side IPC hardening in the same wave — not app-triggered.
- **Sibling census**: `processOutputBufferMappingInfo` got the twin gate (both sides fixed);
  the deeper callee that receives `x2 = symbolIndex` (24A435 0x8d3e86c) was NOT verified to
  re-validate — residual; the split-text/bar-count gates name `kANEMaxBars` as the bound the
  old build did not enforce.

---

## 4. CVE-2026-112477 — IOSurface race — **PROVEN** (the map §4 "site NULL", resolved)

Apple line: *"An app may be able to cause unexpected system termination or corrupt kernel
memory. A race condition was addressed with improved **locking**."* (anonymous)

The prior session's null is overturned by the shape scan: **IOSurface 402.8→403.1 has
exactly 3 changed functions of 1,330** (1327 shape-identical). The "struct re-layout churn
/ 105 surgical pairs" in map-1 §4 was pairing noise. The three functions form ONE state
machine — the **user-client pending-work list teardown race**:

The object is an IOSurface **user client** (receipt: the arming fn 0x24A435 0xa373c08 sets
the IOUserClient lock-policy quartet `IOUserClientEntitlements`,
`IOUserClientDefaultLocking`, `IOUserClientDefaultLockingSetProperties`,
`IOUserClientDefaultLockingSingleThreadExternalMethod` via setProperty — the standard
user-client initializer boilerplate). Its state: registered flag `[uc+0xf0]`, callback
`[uc+0xf8]`, list lock `[uc+0x150]`, pending-item list head `[uc+0x188]` / tail `[uc+0x190]`.

The four list operations (all take the +0x150 lock):
1. insert-pending (24A435 0xa36eb70 / 24B115 0xa3b0a40) — **gained the closing-flag check**
2. cancel-one (0xa36ec74, unchanged)
3. flush/dispatch loop (0xa36ed70, unchanged)
4. teardown gate (24A435 0xa373d5c / 24B115 0xa3b5c44) — **gained the reorder + flag set**
5. unlink-all pass (24A435 0xa36ede4 / 24B115 0xa3b0cc4) — **gained the flag set**

OLD teardown (24A435 0xa373d5c):
```
ldrb w8, [x20, #0xf0]        ; registered?
tbz  w8, #0, tail
ldr  x16, [x20, #0xf8]!      ; callback
sturb wzr, [x21, #-8]        ; clear [uc+0xf0]
call A(provider, uc, cb)     ; 0xa371390
call B(provider, cb)         ; 0xa36db30
call C(provider, uc)         ; 0xa36ede4  <- lock + unlink-all-owned LAST
```

NEW teardown (24B115 0xa3b5c44):
```
ldrb w8, [x20, #0xf0]
tbz  w8, #0, tail
strb wzr, [x20, #0xf0]       ; <<< clear flag FIRST
call C'(provider, uc)        ; <<< lock + unlink-all FIRST
call A(provider, uc, cb)
call B(provider, cb)
```
NEW unlink pass (0xa3b0cc4) gained, under the same lock, BEFORE the walk:
```
0xa3b0cec: bl    lock([uc+0x150])
0xa3b0cf0: mov   w8, #1
0xa3b0cf4: strb  w8, [x20, #0xf1]   ; <<< NEW "client closing" flag
... (walk [uc+0x188], unlink entries with [e+0x58]==uc, assert-brk 0xbffd links)
```
NEW insert (0xa3b0a40) gained, under the same lock, at the top:
```
0xa3b0a7c: bl    lock([uc+0x150])
0xa3b0a80: ldrb  w8, [x21, #0xf1]    ; <<< NEW: owner closing?
0xa3b0a84: tbz   w8, #0, proceed
0xa3b0a88: add   w20, w20, #0x1b     ; -> error 0xe00002d8
0xa3b0a8c: b     done                ; refuse to insert
```

- **The bug (27.0)**: an external-method call on thread X can insert a pending item onto the
  uc's list at any point while thread Y runs the teardown — including AFTER the unlink pass
  has run and before the uc is freed (the flag [+0xf0] is already clear, the list lock is free,
  nothing refuses). The entry (and its owner back-pointer into the uc) then dangles off a
  freed kernel object → **use-after-free-class kernel corruption** ("corrupt kernel memory"),
  or a double-unlink panic ("unexpected system termination").
- **The fix**: a `[+0xf1]` closing flag set under the list lock BEFORE the teardown callbacks
  run, checked by the insert path under the same lock — the enqueue-vs-teardown window closes
  atomically. This is the "improved locking" the advisory names.
- **Reach**: IOSurfaceRootUserClient is app-openable on iOS (prior art
  `analysis/priv24A435_iosurface_overflow_sib.md`; the sandbox profile ships the
  IOSurfaceRootUserClient exception). Trigger: thread A in an external method that enqueues
  pending work (the async-map/schedule paths), thread B calling IOServiceClose/teardown —
  classic app-driven race, no entitlement needed.
- **Oracle**: race-shaped — no deterministic seed; the harness row (SURF-K1) hammers
  enqueue+close concurrently and greps the .ips for the uc's list objects. A/B discriminator:
  27.0 panic/corruption vs 27.2 clean 0xe00002d8 refusals (the new error return is itself a
  fixed-side receipt).
- **Grade**: PROVEN fix (both-side disasm, full state machine). Sibling census: the other two
  list operations (cancel-one, flush) run under the same lock and were left unchanged — no
  unfixed sibling in this family; residual: the uc CLASS name is unpinned (no class strings
  in the three functions; the state machine is pinned though).

---

## 5. CVE-2026-65385 — IOKit buffer overflow — **PROVEN, USERSPACE carrier** (kernel NULL documented)

Apple line: *"A buffer overflow may result in memory corruption and **unexpected app
termination**. An out-of-bounds write issue was addressed with improved bounds checking."*
(Tsytsarkin).

### 5a. The kernel side is a dead end (honest receipts)

- `com.apple.kpi.iokit` is not a fileset entry (`ipsw kernel extract`: "fileset does NOT
  contain com.apple.kpi.iokit") — its code is in the kernel proper, already covered by the
  map-1/map-2 full kernel diff, which found NO added bounds gates and NO new bounds strings.
- The decoded `__assert` census (`k2/asserts_diff.json`): **zero** records in any IOKit
  family file — nothing IOKit-shaped moved at assert level in the kernel proper.

### 5b. The userspace IOKit.framework is the carrier (version receipt 100288.0.9 → 100288.40.8)

The advisory's "**app** termination" wording points at userspace, and the framework moved in
exactly this window. Shape census: 3566/3575 functions identical; the changed set carries an
**IOHIDEvent size-validation wave**:

**Site 1 — `IOHIDEventAppendEvent`** (24A435 0x18f0726ac / 24B115 0x18f0fb82c):

OLD — the type-0xb arm does a fixed-offset read-modify-write with NO size gate:
```
0x18f072710: cmp  w9, #0xb         ; parent type == 0xb
0x18f072714: b.ne  skip
0x18f072720: cmp  w10, #0xb        ; child type == 0xb
0x18f072724: b.ne  skip
0x18f072728: ldr  w8, [x8, #0x34]  ; fixed-offset read @+0x34
0x18f07272c: ldr  w10, [x9, #0x38] ; fixed-offset read @+0x38
0x18f072730: orr  w8, w10, w8
0x18f072734: str  w8, [x9, #0x38]  ; <<< OOB WRITE if the child event's heap < 0x3c bytes
```
NEW — two totalSize gates before the same block:
```
0x18f0fb8a8: ldr  w10, [x9]
0x18f0fb8ac: cmp  w10, #0xa0       ; child->totalSize >= 0xa0 (160)?
0x18f0fb8b0: b.lo skip
0x18f0fb8b4: ldr  w10, [x8]
0x18f0fb8b8: cmp  w10, #0xa0       ; parent->totalSize >= 0xa0?
0x18f0fb8bc: b.lo skip
... (the same orr/str, now provably in-bounds)
```

**Site 2 — `__IOHIDEventCreateWithBytesHelper`** (0x18f0721f4 → 0x18f0fb1f4): new string
`"Failed to create event at index=%d , eventDataSize: %u < minimum size: %u for type: %u"`
(0→1 occurrences) — per-type minimum event-size validation added at creation-from-bytes.

- **Primitive**: an IOHIDEvent is heap-allocated by totalSize; a **short** type-0xb event
  (buffer smaller than the fixed offsets imply) gets its [+0x38] dword OR'd — an in-process
  heap overwrite → "memory corruption and unexpected app termination", the advisory verbatim.
- **Reach**: userspace IOKit.framework HID event APIs (event trees arriving from HID
  system/GameController/accessory paths; a malicious accessory or crafted event bytes
  delivered via the HID stack produce the short event in the consuming process). Exact
  attacker entry (which API feeds crafted child events) UNPINNED — graded honestly.
- **Oracle**: A/B on the macOS twin — build a type-0xb IOHIDEvent with totalSize < 0xa0,
  append → 100288.0.9 heap corruption/crash; 100288.40.8 skips the union write. No seed file
  (API-level trigger; harness row IOKU-F1).
- **Kernel-sibling check**: the IOHIDFamily KEXT does not carry this shape at all (only two
  `orr w8,w10,w8` sites in 2.0.0-byte-drifted kext, neither with the cmp-0xb pair) — no
  kernel twin of the bug found; honest null for the kernelcache side.
- The rest of the framework delta is the IOHIDEventSystem TCC-matching feature (new Security
  framework linkage) — feature work, not the fix.

---

## 6. CVE-2026-112459 — IOMobileFrameBuffer race — **scope-NULL, restated formally**

Apple line: *"An app may be able to cause unexpected system termination or corrupt kernel
memory. A race condition was addressed with improved state handling."* (Cohl, anonymous)

Formal restatement of the scope result (map-1 §4) plus this session's adjacent census:

1. The iPhone17,5 kernelcache has no kext named IOMobileFrameBuffer; the framebuffer path on
   this SoC is DCP-side. The kernelcache-resident IOMFB-adjacent pieces were extracted BOTH
   builds and compared:
   - `com.apple.iokit.IOMobileGraphicsFamily` **343.0.0 both builds** (version-pinned),
     122,729 byte diffs = toolchain churn; **1154/1156 functions shape-identical**. The two
     changed functions: the `stop` slot-cleanup loop (deleted `ldrb [x24,#0x7c]; tbz`
     conditional → cleanup now unconditional per slot; the 0xa1a4758→0xa1e75f8 pair) and a
     NEON stp→str codegen reorder (0xa1b0254→0xa1f30ec). **No locking change, no race-fix
     shape.**
   - `IOMobileGraphicsFamily-DCP` (343.0.0, 182,587 byte diffs), `AppleMobileDispH17P-DCP`
     (140.0, 175,368), `AppleDCP` (1, 35,960) — all version-pinned, strings deltas are
     binary junk only.
2. The user-client surface itself (IOMobileFramebufferUserClient, 69 handlers per
   `analysis/priv24A435_iomfb_uc.md`) is byte-shape-IDENTICAL apart from the two functions
   above — the UC dispatch did not change in this window.
3. Conclusion unchanged and now receipt-backed: **the CVE-2026-112459 fix does not live in
   any kernelcache artifact of this device** — it is in the DCP firmware image (not in the
   kernelcache; not among our artifacts) or userspace graphics stack. Not locally diffable;
   do not spend further time here (per mission).

---

## 7. Verdict table

| CVE | component | verdict | fix site | receipts | app reach | oracle | grade |
|---|---|---|---|---|---|---|---|
| **112554** | IOStorageFamily (kernel kext) | **PROVEN** | GPT partition-name scan bound 0x48→0x24 + conversion-result validation (fns 0xa33c6cc → 0xa37e58c) | both-side disasm §1 | USB-C GPT media on iOS; registry/app read on macOS twin | seed `gpt_oob_seed.img`; leaked-marker readback / panic A/B | fix PROVEN, CVE exact |
| **112456** | HFS = **livefiles_hfs.dylib (USERSPACE)**, not kernel | **PROVEN** | `_hfs_swap_HFSPlusBTInternalNode` keyLength gates (+255 / end-vs-buffer) + `_VerifyHeader` + `_RotateLeft` | both-side disasm §2, version 751.0.0→753.42.1 | **not app-open on iOS** (UserFS image attach paths only); macOS twin full-reach | seed `hfs_btree_keylen_oob_node.bin` | fix PROVEN; on-device reach CLOSED-honest, macOS open |
| **112696** | AppleH16ANEInterface | **PROVEN fix** (CVE split shape-matched) | count family: makeKernelCopyOfProgramInfo / programLoadFromMachoFile / coalesced-surface caps | strings 0→N + new fn set §3a | crafted ANE model (CoreML program load) | A/B needs valid-model mutation (no static seed) | fix PROVEN |
| **84494** | AppleH16ANEInterface | **PROVEN fix** (CVE split shape-matched) | `processInput/OutputBufferMappingInfo` symbolIndex vs totInputBuffers gate; OLD indexes ×16/×0x200 tables unchecked incl. storeback | both-side disasm §3b | crafted ANE model | same | fix PROVEN; write primitive receipted |
| **112477** | IOSurface | **PROVEN** (map §4 null OVERTURNED) | uc pending-list teardown race: `[uc+0xf1]` closing flag set under the +0x150 lock before callbacks; insert path refuses | both-side disasm §4 | app (IOSurfaceRootUserClient openable; enqueue vs IOServiceClose) | race hammer row SURF-K1; fixed-side refusal receipt | fix PROVEN; race primitive proven by construction |
| **65385** | "IOKit" = **IOKit.framework (USERSPACE)** | **PROVEN** | `IOHIDEventAppendEvent` totalSize≥0xa0 gates around the fixed-offset union write + per-type min-size check in `__IOHIDEventCreateWithBytesHelper` | both-side disasm + string 0→1 §5 | HID event paths (accessory/crafted bytes; exact entry unpinned) | macOS-twin API A/B (IOKU-F1) | fix PROVEN; kernel side NULL (documented) |
| **112459** | IOMobileFrameBuffer | **scope-NULL (restated, now receipt-backed)** | not in kernelcache; DCP-side | 4 adjacent kexts extracted, version-pinned, shape-diffed (1154/1156 identical) §6 | DCP-side | none local | not locally resolvable |

## 8. Sibling census / credit-engine candidates (live on 27.0 AND 27.2 unless noted)

1. **livefiles_hfs `_hfs_swap_HFSPlusBTInternalNode` record-offset walk** — the 27.2 pass
   gated the NAME-key path; the node's record-offset array walk (per-record loop) did not
   gain visible validation. Same classic family as the fixed keyLength path → prime
   our-disclosure candidate on the userspace plugin (both builds).
2. **ANE `symbolIndex` deeper callee** — 24A435 0x8d3e86c receives the raw index as x2;
   whether it re-validates was not verified. If it trusts it, the NEW top-level gate is the
   only defense and any second entry into that callee is a bypass route.
3. **IOStorageFamily gpt LBA fields** — start/end LBA consumed as `LBA * blocksize` with no
   LBA-vs-disk bound visible in the descriptor builder (caller-unpinned).
4. **IOSurface flush/dispatch loop under one lock** (0xa36ed70 → 0xa3b0c50) calls a handler
   per entry with the +0x150 lock HELD — if the handler ever enqueues, self-deadlock or
   lock-order issues; unfixed in both builds; low grade.

## 9. Reproducibility

- Extractions: `extracted/{24A435,24B115}/` (ANE pair, livefiles_hfs, IOKit framework,
  IOMobileGraphicsFamily(+DCP), AppleMobileDispH17P-DCP, AppleDCP new; IOStorageFamily /
  IOSurface copied from `kdiff_272/kexts*`).
- Version censuses: `extracted/kexts_24A435.txt`, `kexts_24B115.txt` (`ipsw kernel kexts`
  both kernelcaches, name-keyed join).
- Diffs: `extracted/shape_*.json` + `shape_dump_*.txt` (fn_shape output),
  `extracted/ksim_IOStorageFamily.json`, `kedits_IOStorageFamily.txt`,
  `konly_IOStorageFamily.txt` (old pipeline), `strings_*.txt` pairs (comm inputs).
- Disasm receipts: `scripts/ds_dis.py` invocations quoted in §1–§5 (all addresses absolute
  vmaddrs, stable).
- Seeds: `seeds/gen_gpt_oob_seed.py`, `seeds/gen_hfs_btree_keylen_seed.py` (+ built artifacts,
  structure-verified).
- Prior-art artifacts reused: `k2/asserts_diff.json` (assert census), `k2/fnmap.json`
  (kernel function map), the map §0 scripts (copied to `scripts/`, temp-path fixed).
