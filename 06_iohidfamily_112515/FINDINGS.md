# FINDINGS.md — CVE-2026-112515 (IOHIDFamily OOB read) — 24A435 vs 24B115 fix-diff

> AI-generated security research (same notice as AGENTS.md). Authorized research on the
> owner's device + Apple's publicly-shipped firmware, coordinated disclosure, crash-oracle
> PoCs only. Every claim cites a checkable artifact (vmaddr + both-side disasm in
> `receipts/`). Re-verify before trusting. Produced by a subagent in one session.

**Target:** `com.apple.iokit.IOHIDFamily` (kext, version **PINNED 2.0.0** in both builds —
bytes differ). CVE-2026-112515 (iOS 27.2 advisory 149230): "An attacker may be able to cause
unexpected system termination or read kernel memory. An out-of-bounds read was addressed
with improved bounds checking." (Charles Stevenson, Seung Je Seong, Mathis Mansière).

## 0. Verdict summary

| Item | Verdict |
|---|---|
| Fix site found | **PROVEN** (both-side disasm, 2 live + 2 dead-twin functions, one fix family) |
| Bug shape | Attacker-controlled **signed 32-bit table index** into a 0x14-stride caps table inside the `"hid "` preparsed-data container → **OOB read at `table + idx*0x14 + 8`**; OLD had only a 32-bit multiply-overflow trap, NEW adds `idx >= count → skip/error` |
| Reach | **SHAPE-MATCHED** to the 27.0 → 27.2 OOB-read line; the parse virtual is inherited by the `IOHIDDeviceElementContainer`/`IOHIDElementContainer` family **and** `AppleHIDKeyboard`/`AppleEmbeddedKeyboard`; input = serialized (OSSerialize/XML) out-of-band HID preparsed data (`IOHIDOOBReportDescriptor`/`HIDPreparsedData` strings) |
| Sibling bugs (OURS) | **4 unguarded copies of the same lookup remain in BOTH builds** (live on 27.0 AND 27.2) — see §5 |

## 1. Method and binaries

- OLD: `"/Volumes/ADATA ELITE SE880/ios-critical-bounty/24A435__iPhone17,5/kernelcache.release.iPhone17,5"` (27.0 RC, our device)
- NEW: `"/Volumes/ADATA ELITE SE880/ios-critical-bounty/24B115__iPhone17,5/kernelcache.release.v59.decompressed"` (27.2 RC, fix build)
- Kexts carved per build into `extracted/{24A435,24B115}/` (`ipsw kernel extract`). Fileoffs in the
  carve are valid per-section (`scripts/segtable.py`; `__TEXT` vm−fo 0xfffffff0079a5c80,
  `__TEXT_EXEC` 0xfffffff00a0c2b60, `__DATA_CONST` 0xfffffff008225d88 — old build).
- `ipsw kernel kexts` both sides → `scripts/kexts_24A435.txt` / `kexts_24B115.txt`;
  `scripts/version_delta.py` → IOHIDFamily 2.0.0→2.0.0 (pinned), 51 other kexts bumped.
- Function diff (`scripts/fn_diff.py`): 2815 LC_FUNCTION_STARTS entries per build,
  **2654/2813 pairs hash-identical** under adrp/imm-normalized hashing, 159 changed,
  0 removed / 1 added (4-ins stub `0xfffffff00a14f96c`, a relocated helper).
  The low-ratio cluster (0.75–0.79) is q/d-register constant-pool churn — NOT semantic.
- Guard census (`scripts/guardscan.py`, register-canonicalized) + structural pair diffs
  (`scripts/pairdiff.py`) isolate the real edits, listed below.

## 2. THE FIX — PROVEN (the "hid " preparsed-data table-index bounds check)

### 2a. The container and the lookup

The kext deserializes an out-of-band HID descriptor into a container with magic
`0x68696420` (`"hid "`, big-endian; written by the deserializer at
`0xfffffff00a0f45f0-0xfffffff00a0f45fc`, receipts in `receipts/chain_24A435_*`). Strings
place the family: `IOHIDOOBReportDescriptor`, `site.HIDPreparsedData`,
`site.IOHIDOOBReportDescriptor`, `[ElementContainer] Descriptor:`,
`OSUnserializeXML:NULL`, `Unable to create large report descriptor` — i.e. HIDP-style
**preparsed report-descriptor data**. Container layout (from the parsers):
`+0x00` magic `"hid "`, `+0x08` records array (0x28-stride records), `+0x10` record count,
`+0x38` **caps-table pointer P**, `+0x40` **caps-table count** (only read by the FIXED code),
`+0x68/+0x78` data/len.

Each record carries an int32 index (record `+8` in the record-parser, `+0x30` in the header
parser) that selects a **0x14-byte entry in the caps table**; the parser reads
`*(u32*)(P + idx*0x14 + 8)` and stores it into the parsed output that becomes
HID elements/events.

### 2b. The four fixed functions (one fix family)

| # | 24A435 (vuln) | 24B115 (fixed) | role | fix |
|---|---|---|---|---|
| A | `0xfffffff00a0ea314` (62 ins) | `0xfffffff00a12cecc` (68) | **records-parser (LIVE** — called from `0xfffffff00a137ac0`) | + `cmp idx,count; b.ge skip` + NULL guard on P |
| B | `0xfffffff00a0e5150` (153) | `0xfffffff00a127cd8` (159) | **header-parser (LIVE** — called from `0xfffffff00a137388`) | + `cmp idx,count; b.ge → return -0x3678` |
| C | `0xfffffff00a0ea228` (59) | `0xfffffff00a12cdc8` (65) | dead twin of A (no callers) | same fix (skip) |
| D | `0xfffffff00a0e4eec` (153) | `0xfffffff00a127a5c` (159) | dead twin of B (no callers) | same fix (error) |

**The receipt, pair A (verbatim, both sides; full functions in
`receipts/fixA_recordsparse_*`):**

```
24A435 (vulnerable) 0xfffffff00a0ea3ac..0xfffffff00a0ea3d4 (fn 0xfffffff00a0ea314):
  0xfffffff00a0ea3ac: ldp  w17, w13, [x15, #4]     ; w17 = rec->+4, w13 = rec->+8  == INDEX (attacker data)
  0xfffffff00a0ea3b0: sxtw x13, w13
  0xfffffff00a0ea3b4: smull x13, w13, w12          ; x13 = idx * 0x14   (w12 = 0x14)
  0xfffffff00a0ea3b8: add   x13, x13, #8          ; x13 = idx*0x14 + 8
  0xfffffff00a0ea3bc: cmp   x13, w13, sxtw         ; 32-bit multiply-overflow trap ONLY
  0xfffffff00a0ea3c0: add   x1, x11, w13, sxtw     ; x1  = P + idx          (x11 = blob->0x38)
  0xfffffff00a0ea3c4: add   x16, x11, x13          ; x16 = P + idx*0x14 + 8
  0xfffffff00a0ea3c8: movk  x16, #0x2bad, lsl #48  ; poison tag on overflow path
  0xfffffff00a0ea3cc: csel  x1, x1, x16, eq
  0xfffffff00a0ea3d0: ldr   w13, [x1]              ; <<< OOB READ — NO idx-vs-count check
  0xfffffff00a0ea3d4: stp   w13, w17, [x14]        ; leaked u32 stored into parsed output (dst + i*0x1c)

24B115 (fixed) 0xfffffff00a12ce5c..0xfffffff00a12ce8c:
  0xfffffff00a12ce1c: mov  x9, #0
  0xfffffff00a12ce20: ldr  x10, [x2, #8]          ; records
  0xfffffff00a12ce24: ldr  w11, [x2, #0x40]       ; <<< NEW: read the TABLE COUNT (blob->0x40)
  0xfffffff00a12ce28: mov  w12, #0x14
  ...
  0xfffffff00a12ce5c: ldrsw x15, [x14, #8]        ; idx (sign-extended)
  0xfffffff00a12ce60: cmp   w15, w11              ; <<< NEW BOUNDS CHECK: idx >= count?
  0xfffffff00a12ce64: b.ge  #0xfffffff00a12ce94   ; <<< skip the lookup entirely
  0xfffffff00a12ce68: ldr   x16, [x2, #0x38]      ; table P
  0xfffffff00a12ce6c: cbz   x16, #0xfffffff00a12ce94 ; <<< NEW NULL guard
  0xfffffff00a12ce70: smull x15, w15, w12          ; idx*0x14
  ... (overflow trap as before) ...
  0xfffffff00a12ce8c: ldr   w15, [x17]            ; the read, now guarded
```

**Pair B receipt** (`receipts/fixB_headerparse_*`, 24B115): the identical guard is inserted
at `0xfffffff00a127d2c-0xfffffff00a127d34`:

```
  0xfffffff00a127d28: str  w9, [x19, #4]
  0xfffffff00a127d2c: ldr  w9, [x20, #0x40]       ; table count
  0xfffffff00a127d30: cmp  w8, w9                 ; idx vs count
  0xfffffff00a127d34: b.ge #0xfffffff00a127d6c   ; -> mov w0, #-0x3678 (bad-header error)
```

Pairs C and D show byte-for-byte the same two inserted guards
(`receipts/fixA_deadtwin_*`, `fixB_deadtwin_*`).

### 2c. Why the old check did not help

The OLD `cmp x13, w13, sxtw; csel…0x2bad` idiom is a **32-bit multiply-overflow trap**
(it compares the 64-bit product `idx*0x14+8` against the sign-extension of its own low 32
bits — if the product does not fit in signed 32, the load goes through a poisoned,
deliberately non-canonical pointer and faults). It says NOTHING about
**idx < table count**:

- `idx = -1`  → address `P - 0xC`  → reads **below** the table (product fits: no trap).
- `idx = 0x10000` → address `P + 0x140000` (1.25 MB past the table) → reads adjacent
  kernel heap, no trap, value enters the parsed output.
- Only `|idx*0x14+8| ≥ 2^31` faults via the poison path.

NEW: `idx >= count` (signed compare) rejects ALL of those before the multiply. This is
literally "an out-of-bounds read addressed with improved bounds checking."

## 3. Reach path (receipt level + shape-matched attribution)

```
[serialized OOB descriptor stream, OSSerialize/XML  — "OSUnserializeXML:NULL" strings]
        │  0xfffffff00a0f4510 (deserialize: allocates container, writes "hid " magic)
        ▼
0xfffffff00a1371cc  (VIRTUAL METHOD — parse the container into `this`)
        │   installed in TWO vtables at slots:
        │     0xfffffff0082bd688 (element-container family vtable, base 0xfffffff0082bd600+0x10)
        │     0xfffffff0082c5310 (AppleEmbeddedKeyboard vtable region, base 0xfffffff0082c51f0+0x10)
        │   vtable owners identified via constructors (adrp → class-name cstrings):
        │     0xfffffff00a0f9240 -> "IOHIDElementContainer" (size 0x18)
        │     0xfffffff00a124874 -> "AppleEmbeddedKeyboard"  (size 0x110)
        │   (strings also show IOHIDDeviceElementContainer + AppleHIDKeyboard family)
        ▼
0xfffffff00a137388 (parse driver: header parse + size computation + worker dispatch)
        ├─ 0xfffffff00a0e5150  ← FIX B (header fields incl. the +0x30 index lookup)
        ├─ 0xfffffff00a137cb8 / 0xfffffff00a137e14 (stage-2 workers, each called 3×)
        │      └─ reach the 4 UNFIXED sibling lookups (§5)
        └─ 0xfffffff00a137ac0 (allocates count*0x1c, iterates records)
               └─ 0xfffffff00a0ea314  ← FIX A (per-record caps-table lookup)
                      └─ parsed records -> object creation (0xfffffff00a0faa2c, type 0x201)
                        -> element/event fields (0xfffffff00a1385a0 match walk)
```

- The **disclosure channel**: the OOB-read u32 becomes the FIRST field of each parsed
  record (`stp w13, w17, [x15]`), which feeds element/event construction. Elements and
  event fields are the data userspace HID consumers read (queue/element APIs;
  `IOHIDLibUserClient` is the app-openable UC per `analysis/priv24A435_iohid_uc.md`).
  Tracing the leaked u32 all the way to a specific copyout was NOT completed this session
  → disclosure channel is **SHAPE-MATCHED**, not instruction-proven.
- The **termination channel** is trivial: a large/very negative idx (|idx*0x14| ≥ 2^31
  trips the OLD poison path only at ≥2^31 — a moderately OOB idx reads unmapped kernel
  VA → unhandled kernel fault → panic. Advisory impact "unexpected system termination OR
  read kernel memory" — both arms explained by one missing check.
- **Who supplies the stream**: the container is unserialized from a byte stream passed to
  the virtual method (args: this, data, len at 0xa1371cc). The strings
  (`IOHIDOOBReportDescriptor`, "Unable to create large report descriptor. Dropping large
  report.", "OOB" = out-of-band) indicate descriptor data that did NOT come from parsing
  the device's inline report descriptor — i.e. driver/registry-supplied preparsed data.
  Producer paths NOT traced this session (would need the AppleHIDTransport* kexts,
  version-bumped 1000.41→1010.1, and/or the IOHIDResourceDevice virtual-device path,
  which is entitlement-gated per prior art). The CVE credits (Stevenson/Mansière — USB/HID
  peripherals) fit a **malicious HID peripheral** (USB/BT) supplying crafted descriptor
  data through the OOB path.
- The **app-reachability** of this specific bug from a sandboxed app is UNRESOLVED: the
  container parse is a device-driver virtual, not a userclient selector. Rank: PROVEN
  fix site; SHAPE-MATCHED CVE attribution; reachability = open (peripheral-side more
  likely than app-side).

## 4. Secondary fix in the same kext (shape-matched, separate bug)

`0xfffffff00a1385a0` (100 ins) → `0xfffffff00a17b1d4` (110 ins), receipts
`receipts/fixC_elementwalk_*`. An element-collection walk (the digitizer-transducer match
loop; caller `0xfffffff00a0fc3e4`, same code region as the
"createDigitizerTransducerEventForReport" os_log):

- OLD: collection count fetched ONCE at entry (`cbz w0` checks only != 0,
  `0xfffffff00a1385e4-0xfffffff00a1385e8`), then `getIndexedChild(i)` at loop head guarded
  only by the PREVIOUS iteration's tail re-fetch.
- NEW: count re-fetched at loop head and checked **per iteration**
  (`0xfffffff00a17b248: cmp w21, w0; 0xfffffff00a17b24c: b.hs exit`) + new
  retain/release (`vtable+0x20/+0x28`, `0xfffffff00a17b2a8`/`0xfffffff00a17b354`) around
  the fetched dictionary object.

That is a **shrink-race/refcount hardening** (indexed access on a possibly-shrunk
collection + a use of a possibly-freed lookup result). Not the CVE-112515 OOB-read shape
(no attacker-sized field); listed for completeness — it pairs with the A/B fix family as
one 27.2 hardening wave on this parse path.

Other examined changed pairs (all churn, no security shape): 0xa102158→0xa144d28
(property-publish loop 9→10 entries; 24B115 adds `TCCService` and
`IsSpatialBluetoothHID` keys — feature work),
0xa144e98→0xa187ae0 (digitizer event builder, +1 element-search loop — feature),
0xa1274b0→0xa16a0d8 (400→387, guard renumbering), the whole 0.75–0.79 ratio cluster
(q/d constant-pool moves). `IOUSBHostHIDDevice` (sibling, version pinned 1.2, bytes
differ): exactly ONE changed function 0xa7f5fd8→0xa8377e8 (575→547 ins) — a **removed
retry/poll loop**, no bounds-check shape; carve kept in
`extracted/siblings/`, `scripts/fn_diff_usbhid.json`.

## 5. SIBLING CENSUS — checks Apple did NOT add (our disclosure candidates)

`scripts/smull14_census.py` finds every `#0x14 * idx` caps-table lookup in the kext.
Six sites; **two were fixed (§2b), FOUR remain unguarded in BOTH builds**:

| 24A435 fn (site) | 24B115 fn (site) | guard | live callers |
|---|---|---|---|
| `0xfffffff00a0e4778` (`0xa0e491c`) | `0xfffffff00a1272e8` (`0xa12748c`) | **NONE** | via `0xfffffff00a0e4ae4` — no callers found (dead twin) |
| `0xfffffff00a0e4b04` (`0xa0e4cb4`) | `0xfffffff00a127674` (`0xa127824`) | **NONE** | `0xfffffff00a0e4ecc` ← `0xfffffff00a137cb8` ← `0xa137388` (**LIVE**) |
| `0xfffffff00a0f20a0` (`0xa0f2264`) | `0xfffffff00a134c70` (`0xa134e34`) | **NONE** | via `0xfffffff00a0f2478` — no callers found (dead twin) |
| `0xfffffff00a0f2498` (`0xa0f2668`) | `0xfffffff00a135068` (`0xa135238`) | **NONE** | `0xfffffff00a0f2894` ← `0xfffffff00a137e14` ← `0xa137388` (**LIVE**) |

The live two sit in the stage-2 parse workers (each invoked 3× by the SAME parse driver
`0xfffffff00a137388` that feeds the FIXED functions) and perform the identical
double-lookup: first `idx1 = *(u32*)(rec + 0x44)` scaled ×40 into the records array, then
the fetched record's field scaled ×0x14 into the caps table — with **no idx-vs-count
compare in either build** (receipts `receipts/sibling_*`). The multiply-overflow trap is
the only guard, exactly as in the pre-fix CVE-112515 sites.

**Conclusion:** Apple fixed the record-parser/header-parser pair but left the same
primitive in the caps-array stage-2 workers → live on 27.0 RC **and still live on 27.2
(24B115)**. These are our coordinated-disclosure candidates (same bug class, same
container, same parse driver, same trigger). Recommended report to Apple Product
Security: the four sites with both-build receipts.

## 6. Oracle / probe recipe (crash-oracle only)

Kernel OOB reads are fault-or-silent. Design (device = iPhone 16e, 27.0 RC 24A435):

1. **Trigger** (needs the producer path, NOT app-only): supply a crafted OOB HID
   descriptor stream (serialized preparsed data) whose record index exceeds the
   caps-table count: `idx = count + k` for small k (adjacent-heap read), `idx = 0x40000000`
   and `idx = -0x40000000` (poison/fault). Candidate delivery lanes, cheapest first:
   - Mac-as-USB-HID-gadget / Facedencer-style crafted USB HID device → USB HID stack →
     descriptor/element container parse (matches the CVE credits' USB/HID profile);
   - AppleHIDTransport family (bumped 1000.41→1010.1 — needs its own diff to find the
     producer-side serialization entry);
   - virtual-HID resource device (entitlement-gated — probe needs the entitled lane).
2. **Receipts**: 27.0 RC = kernel panic `.ips` with fault PC at
   `0xfffffff00a0ea3d0` (`ldr w13,[x1]` in fn 0xfffffff00a0ea314, the record parser) or corrupted
   element/event data; 24B115 = clean skip (`b.ge` path) + element-parse failure log.
   The A/B pair = proven live bug (METHODOLOGY §5).
3. **Readback oracle** (if no panic): the parsed record's first u32 field is the leaked
   value — compare the element/event fields visible on the 27.0 device against the
   27.2 refusal for identical input. Marker: leaked value != any legit table entry.

No userspace reproducible crash-oracle is possible without the producer path — the input
is kernel-side serialized data, not a file the app hands to a parser. seeds/ intentionally
empty; see HARNESS_ROW.md for the on-device probe-row spec that fires what CAN be fired
from app context (the UC surface) plus the peripheral-lane design.

## 7. Attribution confidence

- Fix-site: **PROVEN** (both-side instruction receipts, §2b).
- CVE-2026-112515 mapping: **strong shape-match** — OOB read + "improved bounds checking"
  + both advisory impacts (termination AND kernel-memory read) explained by the one
  check; it is the only added-bounds-check family in the whole 2815-function kext diff.
- Beta-window: single-window fix inside a version-pinned kext (responsive-fix shape,
  METHODOLOGY §2). No second-release-train repetition checked (would need older trains).
- Reachability: OPEN (peripheral-producer vs app-side) — honestly unresolved.

## 8. Artifacts

- `extracted/24A435/`, `extracted/24B115/` — carved IOHIDFamily; `extracted/siblings/` —
  IOUSBHostHIDDevice pairs.
- `receipts/` — 24 files: both-side full disasm of the 4 fixed functions + the element-walk
  fix + the call chain (0xa1371cc / 0xa137388 / 0xa137ac0) + the 8 sibling receipts.
- `scripts/` — the pipeline (all real .py, no heredocs): `version_delta.py`,
  `fn_diff.py` (pairing), `guardscan.py`, `pairdiff.py`, `kdis.py` (carved-kext disasm via
  pacibsp anchor), `segtable.py`, `str_at.py`, `datawords.py`, `find_ptrs.py` (KC
  chained-fixup decoder: low32 = target − 0xfffffff007004000), `vtable_of.py`,
  `class_ref.py`, `kcstr_refs.py`, `blcallers.py`, `vcallers.py`, `xrefs_to.py`,
  `smull14_census.py`, plus raw outputs (`fn_diff.json`, `fn_diff_usbhid.json`,
  `kexts_*.txt`, `diffouts/`).
- KC fixup-decode receipt: known-good dispatch-table entry
  0xfffffff0082b8d00 raw `0x8050bcad030d149c` → low32 `0x030d149c` + base =
  `0xfffffff00a0d549c` = the known `IOHIDLibUserClient` selector entry
  (cross-checked against `analysis/priv24A435_iohid_uc.md` §2).
