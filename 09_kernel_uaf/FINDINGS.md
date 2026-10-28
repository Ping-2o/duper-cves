# FINDINGS.md — cve_groups/09_kernel_uaf: the XNU UAF/race/OOB cluster of iOS 27.2 advisory 149230

> AI-generated security research (same notice as AGENTS.md). Authorized research on the owner's
> device + Apple's publicly-shipped firmware, coordinated disclosure, crash-oracle PoCs only.
> Every claim cites a checkable artifact (function VA + verbatim disasm or script + output).
> Re-verify before trusting. Binaries: `/Volumes/ADATA ELITE SE880/ios-critical-bounty/kdiff_272/
> kernel24A435/com.apple.kernel` (27.0 RC, xnu-13432.2.10~2 — quote the path, it has a space) and
> `.../kernel24B115/com.apple.kernel` (27.2 RC, xnu-13432.42.3~28).

## 0. What this session did (method + relation to prior art)

Prior sessions (analysis/kernel_272_diff_map.md, kernel_272_diff_map_2.md) built the function
pairing pipeline (fnmap: 21,073 old→new function pairs), decoded the `__DATA_CONST,__assert`
descriptor tables, and churn-scanned all 14,429 changed pairs, concluding the kernel-cluster
fixes hide inside wholesale-reworked (unpairable) functions — mostly the vm cluster. This
session (subagent) re-ran and extended the assert census at full fidelity, then deep-dived the
deltas the prior summary de-emphasized. **Head result: a NEW, PROVEN fix-family that map-1/map-2
missed — the ipc_port REQUEST-TABLE validation wave** (27.2 added bounds + NULL traps to every
index-consumer of the per-space port-request table; 27.0 has silent OOB read/write paths).

All scripts are in `scripts/` (copied forward from the k2 session + new; they write to `work/`).
Key reproducibility note (cost this session ~30 min): `mach_header_64` must unpack
`<IIIIIIII` (map_2 §0's gotcha is real; `ds_kdiff2.py` carries the broken `<IIQQQQQQ` form).
Run order: `assert_census2.py` → `subsys_census.py` → `xref_str2.py` / `blxref.py` / `kdis.py`
for the site work. Capstone must run with `skipdata=True` (kscan.disasm does).

## 1. THE HEADLINE: ipc_port request-table index validation wave (NEW, PROVEN both sides)

### 1a. The census receipt

`scripts/assert_census2.py` (full decode of both `__assert` tables + live adrp+add code refs +
fnmap pairing; output `work/assert_census_report.txt`, `work/assert_census.json`):
A435 = 205 records / 585 live refs; B115 = 226 records / 610 live refs. After classifying the
65 live-added/42 live-removed records into (i) pure line-churn of pre-existing asserts
(vm_compressor/vm_object/vm_pageout/vm_resident/vm_upl/pmap/task/ipc_kmsg-line 211-218 etc. —
the map_2 §2 delta) and (ii) **genuinely new assertions** (expr absent from the other build at
any line), the new content in the 27.2 kernel proper is:

1. `vm_sk_deferred.c` 7 traps (KNOWN — map_2 §2b) + `exclaves_sensor.c:76` (KNOWN)
2. **`ipc_entry.c` `entry != ((void*)0)` :14/:17, `prev_entry != ((void*)0)` :28 — in 4 only-new
   functions; `ipc_misc.c:11 'entry != NULL'` — 1 only-new function**
3. **`ipc_port.c` `ipr != ((void*)0)` :21/:24/:34/:38/:41, `table != ((void*)0)` :34/:38/:40 —
   in 5 only-new functions**
4. `kern_exit.c:93 'PROC_P_USER_FAULTS_COUNTERS_LIMIT > faults_idx'` — data-only in BOTH builds
   (DEBUG record, no code ref; prior session's kill re-confirmed).

The ipc wave (2+3) is the fix-marker set map_1 §5/map_2 §5 were hunting for. All five
ipc_port.c guard functions are the rewritten consumers of the **per-space port-request table**
(the dead-name/send-possible notification record table hung off the space at +0x68, PAC-armed
with diversity constant `0xb9dc`), identified by three independent fingerprints: the `movk
x17, #0xb9dc, lsl #48` + `autda x16, x17` + `ldr x16, [x17, #0x68]!` load pattern, the 16-byte
entry stride (`ubfiz xN, x2, #4, #0x20`), and the new asserts' `ipr`/`table` identifiers
(ipr = ipc_port_request_t, the notification request record).

### 1b. The three pre-fix defect shapes (verbatim disasm, both sides)

**Site 1 — OOB READ, unchecked index (type-query path).**
A435 fn `0xfffffff00ab86c64..0xfffffff00ab86cd0` (27 ins) ↔ B115
`0xfffffff00abcace0..0xfffffff00abcada0` (48 ins):

```
24A435 (27.0):                                    24B115 (27.2):
... table decode (autda 0xb9dc @+0x68) ...        ... same decode, + cbz guards → trap ...
0xfffffff00ab86ca0: ubfiz x9, x2, #4, #0x20       0xfffffff00abcadfc: cmp  x9, x10
0xfffffff00ab86ca4: ldr  x8, [x8, x9]   ; ★     0xfffffff00abcae00: b.hi → brk  (ipc_port.c:38)
   NO bounds check anywhere. Result bits         0xfffffff00abcad54: ldr  x8, [x8]   ; checked
   (0/1/2/4 masks at ab86ca8-cc8) classify
   the NOTIFICATION TYPE returned to caller.
```

**Site 2 — OOB WRITE through a bounds result that is computed and DISCARDED (free path).**
A435 fn `0xfffffff00ab86cd0..0xfffffff00ab86d9c` (55 ins) ↔ B115
`0xfffffff00abcada0..0xfffffff00abcae8c` (59 ins). Called from 12+ sites (ipc_right_delta at
`0xfffffff00ab8e634`, the 340-ins ipc copyout fn at `0xfffffff00ab8d4c0`, a 599-ins fn at
`0xfffffff00ab8f5e8`, the 462-ins `0xfffffff00ab94670`, the 363-ins `0xfffffff00ab97734`, …):

```
24A435 (27.0):
0xfffffff00ab86d3c: ubfiz x11, x2, #4, #0x20   ; idx*16
0xfffffff00ab86d40: add   x11, x11, #0x10
0xfffffff00ab86d44: add   x12, x8, x10, lsl #4 ; x12 = table + idx*16   (candidate)
0xfffffff00ab86d58: cmp   x11, x9              ; bounds computed
0xfffffff00ab86d5c: csel  x10, xzr, x12, hi    ; ... result → x10 (used ONLY for a later
                                                ;     pointer-EQUALITY compare, never as base)
0xfffffff00ab86d60: ldr   x9, [x12]            ; ★ OOB READ via UNCHECKED x12
0xfffffff00ab86d68: str   w11, [x12, #8]       ; ★ OOB WRITE (table-global w11)
0xfffffff00ab86d6c: str   xzr, [x12]          ; ★ OOB WRITE (16B slot zeroing)

24B115 (27.2):
0xfffffff00abcadfc: cmp   x9, x10
0xfffffff00abcae00: b.hi  → 0xfffffff00abcae5c → guaranteed brk  (ipc_port.c:40/41
                    'table/ipr != ((void*)0)' trap; the mov x9,#0; cbnz x9,→ never-taken
                    pattern is a deliberate compiler-encoded trap)
0xfffffff00abcae20: ldr   x10, [x9]            ; all accesses via CHECKED x9
0xfffffff00abcae28: str   w11, [x9, #8]
0xfffffff00abcae2c: str   xzr, [x9]
```

**Site 3 — OOB READ + conditional OOB WRITE, no bounds at all (mark path, message-send
caller).** A435 fn `0xfffffff00ab86b2c..0xfffffff00ab86b80` (78 ins) ↔ B115
`0xfffffff00abcab54..0xfffffff00abcab54+99` (99 ins). Exactly ONE caller: the 937-ins
ipc_kmsg.c send-path function `0xfffffff00ab7d408` (holds ipc_kmsg.c:124 'kr == 0' assert;
rewritten to the 950-ins `0xfffffff00abc13d4` in B115, which TAIL-CALLS the fixed fn at
`0xfffffff00abc1f30`):

```
24A435:  (BL site 0xfffffff00ab7df1c, called with x2 = idx from [x24,#0x10] —
         ldp x27, x26, [x24, #8] at 0xfffffff00ab7dfd0 = the SAVED table index
         of the space's request table)
0xfffffff00ab86b84: add x8, x8, w2, uxtw #4    ; table + idx*16, NO bounds computation at all
0xfffffff00ab86b88: ldr x9, [x8]               ; ★ OOB READ
0xfffffff00ab86b90: orr x9, x9, #1
0xfffffff00ab86b94: str x9, [x8]               ; ★ conditional OOB WRITE (bit-set of OOB memory)

24B115:  cmp idx*16+0x10 vs decoded size; b.hi → brk (ipc_port.c:34) + NULL traps.
```

**Sites 4-5** — grow/alloc-from-freelist paths A435 `0xfffffff00ab863dc` / `0xfffffff00ab864ac`
↔ B115 `0xfffffff00abca3dc` / `0xfffffff00abca4c4`: A435 computes the csel bounds and (ab863dc)
DEREFERENCES THE NULLED RESULT (`ldr w11,[x10,#8]` with x10=0 → NULL-deref crash at VA 8);
B115 adds `ipr != NULL` traps (ipc_port.c:21/24). Crash-grade pre-fix, not silent.

**Reachability** (HYPOTHESIS-grade, static): every path is Mach-IPC-reachable from an app
(mach_msg / mach_port notification registration — no entitlement). The index that goes OOB is
the space's SAVED request-table index (site 3 loads it from `[x24,#0x10]`), so the plausible
trigger is a **stale-index race**: request-table grow/realloc vs. concurrent message sends /
notification teardown using the saved index. This is exactly the UAF/OOB hybrid the advisory
cluster describes ("use-after-free… improved memory management" / "out-of-bounds write… improved
bounds checking"). What is NOT pinned: the concrete interleaving that produces idx ≥
table_entries on 27.0 — that is the device-oracle's job (HARNESS_ROW.md, row K-IPC1).

### 1c. ipc_entry/ipc_misc guards (crash-grade hardening, same window)

The ipc_entry.c:14/17/28 `entry/prev_entry != NULL` traps live in 4 rewritten port-table
freelist helpers (B115 `0xfffffff00abb96e8/abb97e0/abb9930/abba274`, all only-new). Receipt for
the family: A435 `0xfffffff00ab757a0..0xfffffff00ab758dc` (79 ins) — the entry-free helper:

```
0xfffffff00ab7583c: cmp  x11, x9
0xfffffff00ab75840: csel x23, xzr, x24, hi     ; out-of-range entry → x23 = 0
0xfffffff00ab75844: ldr  w9, [x23, #0xc]       ; ★ 27.0 DEREFERENCES THE NULL → raw panic
```
vs B115 `0xfffffff00abb97e0` (84 ins): same csel logic but the out-of-range value flows to
`cbz x23 → adrp+add record (ipc_entry.c:17) → brk #0xbffc` — a clean trap with receipt, plus
all subsequent accesses unified through the checked pointer (A435's object store uses the
UNCHECKED x24 at `0xfffffff00ab758b0`). Pre-fix impact of these: NULL-deref DoS (not silent
corruption) — weaker CVE shape than the port-request family; they mark the audit surface.

## 2. vm_sk_deferred / framebank (prior session's leading UAF candidate) — new receipts + honest reachability DOWNGRADE

New facts this session:
1. **The hook site is vm_upl.c**: the B115 deferred-page queue (`0xfffffff00ad4c000`) and the
   drain worker (`0xfffffff00ad4bbb4`) are called from the 1402-ins vm_upl.c commit/abort
   function at `0xfffffff00ad52aa0` (strings: `wire_count == 0, m = %p, obj = %p`,
   `vm_upl.c`) — whose A435 counterpart is the 1374-ins `0xfffffff00ad0b96c` (same strings,
   only-old). The other hooks: `0xfffffff00ad1670c` (131 ins → accounting fn ad4c650),
   `0xfffffff00ad2d5bc` (331 ins, NEW: sptm_get_frame_type dispatch +
   `"sptm_get_paddr_type returned failure for paddr 0x%llx"` → accounting fn ad4c328),
   `0xfffffff00b1640e0` (118 ins). All unpairable (wholesale vm rework).
2. Both builds screen page-modified state (`pmap_is_modified`: A435 `0xfffffff00ad45538` ×4
   calls ↔ B115 `0xfffffff00ad8c5e0` ×4, fnmap-paired) — the 27.2 delta is the DEFERRAL
   (page-list carried on a global list with overflow-trapped counters) + the post-withdraw
   modified-page panic, i.e. 27.0 processes SK-page teardown synchronously and hands pages back
   with no post-withdraw validation.
3. **Reachability**: the SK-shared pages are exclaves-domain memory. The deposit/withdraw RPC
   type descriptors (`framebankxnuteller_xnuteller_{deposit,withdraw}…`,
   `com.apple.service.FrameBankXnuContent` — A435 `0xfffffff007048a10`, ONE code ref in the
   40-ins exclaves endpoint bootstrap `0xfffffff00abb08cc`, called by the 169-ins
   `0xfffffff00abae0e0`) and the page classifiers
   (`exclaves_memory_pa_page_is_sk_shared_ro/rw` — assert expressions at
   `0xfffffff0070492c4/…306/…876`; `pmap_pa_is_sk_shared_realtime` in A435 pmap fns
   `0xfffffff00ad395cc`/`0xfffffff00ad47d78`) are all Apple-internal surfaces. **An unentitled
   app cannot create sk_shared mappings; the framebank lifecycle is driven by Apple's exclaves
   services.** This DOWNGRADES map_2 §2c's leading-candidate status for the externally-credited
   UAF CVEs (Scola/Newlin/Wang Yu/STAR Labs et al. cannot test exclaves internals): as an
   external-researcher candidate it is now ranked BELOW the ipc wave; it remains the strongest
   candidate for an Apple-internal/exclaves-adjacent report.

## 3. Subsystem census (workflow §4) — where the change weight sits

`scripts/subsys_census.py` (assert-record attribution of the fnmap pairs; caveat: only
functions holding live asserts attribute — ~600 of 21,614; the 14,183-pair churn sea is
unattributed):

| file | changed pairs | only-old | only-new | note |
|---|---|---|---|---|
| ipc_object.c | 150 | 3 | 4 | inlined io-state/list assert attribution — ipc cluster dominates the attributable set |
| ipc_policy.h | 13 | 0 | 0 | movability policy churn |
| lock_rw.c | 16 | 0 | 0 | rwlock churn |
| ipc_port.c | 7 | 0 | 5 | the §1 wave |
| ipc_kmsg.c | 7 | 1 | 1 | send-path rewrite (§1b site 3 caller) |
| ipc_entry.c | 0 | 0 | 4 | §1c guards |
| ipc_misc.c/ipc_right.c/ipc_importance.c/ipc_pset.c/ipc_notify.c/ipc_kobject.c/mach_port.c | 0-3 | 0 | 1 | ipc periphery |
| vm_resident.c | 7 | 3 | 3 | incl. "Unrecognized relocation reason" rewrite |
| vm_sk_deferred.c | 0 | 0 | 6 | NEW file (all only-new) |
| vm_map.c/vm_fault.c/vm_upl.c | 2/0/0 | 1 each | 1 each | the wholesale rewrites hold the rest (vm_fault.c 2440→3871-ins rewrite, vm_map_remap 395, vm_map_relocate 836, vm_pageout ×5, vm_upl 1374→1402 — see map_1 §3/map_2) |

The vm cluster's rewrites remain the pool for the unattributable CVEs (per map-2 §3's
negative result: NO one-line gate fixes exist in the 14,429-pair sea); the attributable ipc
wave is the fix content this session proved.

## 4. Per-CVE verdict table (the 13 CVEs of this group)

Grades: PROVEN = both-side disasm decisive · SHAPE-RANKED = fix-site proven, CVE attribution by
shape/impact/credit fit · POOL = nothing better than "lives in the rework pool" · NULL = no
candidate.

| CVE (advisory wording) | best candidate site (A435 → B115 VA) | receipts | grade | reachability hypothesis | falsifier |
|---|---|---|---|---|---|
| **112507** OOB write → "write kernel memory" (Tim Michaud) | ipc_port request-table FREE path `0xfffffff00ab86cd0→0xfffffff00abcada0` (OOB `str w11,[x12,#8]`+`str xzr,[x12]` through discarded-bounds x12; mark path `0xfffffff00ab86b2c` adds `orr/str` bit-set write) | §1b verbatim disasm; ipc_port.c:40/41 traps new-in-27.2 (assert census) | fix family **PROVEN**, CVE **SHAPE-RANKED (strongest in this report)** | mach_msg/notification paths; stale saved index vs table realloc (race) | K-IPC1 device run: no 27.0 crash → callers never supply idx ≥ entries → downgrade to hardening |
| **112476** OOB read (Cartagena, Suiche) | type-query path `0xfffffff00ab86c64→0xfffffff00abcace0` (unchecked `ldr x8,[x8,x9]`; bits classify notification type, potentially observable) | §1b site 1 verbatim | fix **PROVEN**, CVE SHAPE-RANKED | same as above; read leaks table-adjacent heap bits into notification-type behavior | same oracle; if 27.2 fix releases were synced to a different window (check 27.1 beta chains via ipsw-diffs), re-rank |
| **65350+112679** UAF "corrupt kernel memory" (Nebula, Michaud, Xinru Chi/Pangu, STAR Labs) | (a) ipc stale-request-index race (same family: a FREED request slot reused = UAF before it is OOB) — (b) vm_sk_deferred framebank lifecycle (map_2 §2b + §2 above) | (a) §1 (b) map_2 §2b + §2's vm_upl.c hook receipt | both SHAPE-RANKED; (b) DOWNGRADED on reachability (exclaves-gated) | (a) app, race (b) Apple exclaves services only | (a) K-IPC1 (b) if Apple's 27.2 GM advisory credits an internal name for framebank, re-map |
| **112517** UAF (Scola, van der Ploeg, Lussier, Karagun) | ipc_entry/ipc_misc freelist NULL-guard wave (`ipc_entry.c:14/17/28`, `ipc_misc.c:11`; A435 silent-NULL-deref shapes at `0xfffffff00ab757a0` family) | §1c verbatim (one of four sites) | SHAPE-RANKED (weaker: pre-fix sites crash-grade) | port-table freelist manipulation from mach_msg teardown paths | if all four A435 counterparts are crash-grade (verify remaining 3), demote to DoS-hygiene, keep 27.0-null-deref as crash-oracle |
| **112516** UAF (see advisory) | same pools: ipc entry/request tables or the vm_map.c rework sea (`0xfffffff00acbe0f0`, `0xfffffff00aca997c`, range-ID validator `0xfffffff00acac08c→0xfffffff00acf19e8` rewritten) | vm_map.c:171 'false && "invalid range ID"' assert MOVED containers (only-old→only-new) — a rewritten validator exists both sides (line churn, not new) | POOL | vm syscalls (mach_vm_*) | needs the vm wholesale-rewrite deep-dive (map_2 §7.4 next-actions) |
| **112514** UAF (Newlin, STAR Labs, greenbynox) | same pools | — | POOL | ipc first (Newlin's mach-port history), else vm | — |
| **84495+112474** UAF "write kernel memory" (Wang Yu, STAR Labs) | vm_map_entry shared-lock count-overflow site (map-1 §2: A435 `0xfffffff00b42d56c` unchecked `ldadd` vs B115 saturation traps at `0xfffffff00ad564fc/ad56594`) OR the ipc free-path OOB write (§1b site 2 — Apple splits read/write across the family) | map-1 §2 (PROVEN fix) + §1b | SHAPE-RANKED (shared with 112507's candidate — ambiguous) | the shared-lock site needs the unpinned count-leak (map_2 §4 census-balanced) | leak audit of the 76-changed vm_map.c fns (open) |
| **112606** type confusion (Wang Yu) | no direct receipt. Nearest type-confusion-shaped surface: ipc_port io_state/movability state machine (ipc_port.c:46/49/200 asserts — PRE-EXISTING in 27.0 at lines 45/48/199, line churn only; NOT new gates) | assert census | POOL (honest: nothing better) | — | vm/IOKit kext rework pools |
| **112698** "improved memory handling" (STAR Labs, OpenAI) | vague wording; POOL = vm rewrites + the vm_upl.c SK-page path (§2) | — | POOL | — | — |
| **112665** kernel-memory-layout info disclosure (Will Estes) | **NULL in kernel proper, re-confirmed**: fresh full strings diff (1,860/1,632, counts match map-1) has ZERO kaslr/slide/layout/randomiz/physmap/leak receipts either direction | `work/str_new.txt`, `work/str_gone.txt` | NULL | likely kext-side (IOKit registry) or state-rework without string footprint | re-run the shape-scan on the 51 changed kexts (map-1 §4 lanes) |
| **112624** bypass Privacy preferences, kernel (Jerry L. Knot) | **NULL in kernel proper**: zero privacy/TCC/preference receipts in the strings diff | same | NULL | the privacy-preferences bypass surface is userspace (dsc) — cross-lead to the userspace groups | `ipsw dyld info` grep for Privacy/Preference daemons on both caches |
| (reference) 112576 COW, 112501 race | DONE by prior sessions — not redone; see map_1/map_2 | — | — | — | — |

**The honest bottom line for the cluster**: the ONLY genuinely-new validation content in the
27.2 kernel proper is (1) the vm_sk_deferred framebank machinery (exclaves-gated), (2) the ipc
port-request/entry table guard wave (app-reachable), and (3) exclaves_sensor. Everything else
in the assert delta is line churn of pre-existing checks. Combined with map_2 §3's
churn-scan negative (no one-line gates in 14,429 pairs), the UAF cluster's center of mass is
**the ipc port-request family** for the externally-credited CVEs and the vm rewrites for the
rest.

## 5. Sibling census (workflow §6 — where OUR credit lives)

1. **ipc port-request family: NO unfixed sibling.** Census via the table's PAC fingerprint
   (`movk x17,#0xb9dc,lsl#48` + `ldr x16,[x17,#0x68]!`): 8 real consumers in A435 → 8 in B115.
   The 5 index-consumers all gained bounds+NULL traps in 27.2; the remaining 3
   (`0xfffffff00ab8ab80/ab94ebc/ab990d8` → `abced1c/abd9064/abdd280`) are whole-table walkers
   (size-decode iterations, table teardown, table cancel-all) with no index parameter — nothing
   left unguarded in 27.2. NEGATIVE (receipt: the census itself, work/sibling census in this
   file's §1 + scan script).
2. **The csel-discard idiom at kernel scale**: 247 sites (A435) vs 244 (B115) — balanced, no
   net cleanup; the raw pattern is mostly a benign clamp idiom
   (`work/sibling_scan.txt`). NEGATIVE.
3. **ipc_entry family**: 4 guards added; the A435 counterparts' remaining silent-NULL-deref
   shapes (e.g. `0xfffffff00ab757a0` writes via unchecked x24 at `0xfffffff00ab758b0`) are
   fixed side-by-side. Sibling candidate: the A435-only `str x17,[x24]` unchecked-pointer
   store shape — verify the other 3 pair-diffs for a *surviving* variant in B115 (NEXT ACTION).
4. **kern_exit user-faults counters**: `PROC_P_USER_FAULTS_COUNTERS_LIMIT > faults_idx` is
   data-only in BOTH builds (compiled out in release) — the runtime bounds on faults_idx are
   absent everywhere; any caller-side trust of that index is an UNFIXED-sibling pattern
   (cross-cite: prior session's kill of the "fix" claim; the sibling angle is ours). Caller
   audit = next action.
5. **Cross-cite (other groups' credit engines, do not redo)**: IOHIDFamily caps-table 4-of-6
   unguarded lookups (group 06); AppleFSCompression chunk-table trusts (group 08); the
   vm_map_entry shared-lock WRITE/try paths' saturation coverage (map_2 §4 left the
   try-acquire `0xfffffff00ad0f590` counterpart's check status implicit — verify B115
   `0xfffffff00ad5662c/ad5aa3c` cover try-acquire, else that is an open sibling).
6. **The `rxpoll`/`netif_filter_na_txsync` weak checks** (map_2 §3.2-3.3): still the best
   skywalk-side sibling candidates; not re-verified this session (cite map_2).

## 6. What would falsify / advance each claim (next actions)

1. **K-IPC1 device run** (HARNESS_ROW.md): the A/B differential oracle for the ipc family. If
   27.0 survives the racer with no anomaly, the stale-index hypothesis dies and the family
   re-grades to prophylactic hardening; if 27.0 crashes with a data-abort PC inside
   `0xfffffff00ab86b2c-0xfffffff00ab86e07` (or a silent heap corruption later), the 112507/112476
   mapping goes PROVEN-live.
2. Disasm-verify the remaining 3 ipc_entry pair-diffs (§5.3) and the B115 try-acquire
   saturation (§5.5) — both afternoons.
3. The 27.1 train (if any) via ipsw-diffs would date the ipc wave within the 27.2 window
   (responsive-fix shape = single-window landing).
4. Watch the 27.2 GM advisory credits + researcher disclosures for the port-request family —
   the credited names for 112507 (Michaud) fit the mach-IPC profile, but credit-fit is not
   proof.
5. The vm wholesale rewrites (map_2 §7) remain the open lane for 112516/112514/112606.
