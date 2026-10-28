# FINDINGS — CVE-2026-112479 (iOS 27.2 advisory 149230, "USB")

> **NOTICE — AI-GENERATED SECURITY RESEARCH.** Written 100% by autonomous AI agents.
> Authorized security research on the project owner's own device + Apple's publicly
> shipped firmware, for coordinated disclosure. PoCs are crash-oracles ONLY
> (crafted descriptor/response bytes, never weaponization). Every claim cites a
> checkable artifact (function VA + both-build disasm, or a script + its output);
> re-verify before trusting. SHAPE-MATCHED items are marked as such.

**CVE line (verbatim):** "A malicious USB device may be able to cause unexpected system
termination or read kernel memory. Description: An out-of-bounds read was addressed with
improved bounds checking." — credited: Rotce, Sandeep Wawdane, Marc Newlin of SkySafe,
Ankur Saini of Volexity, Kwak Kiyong, Song nuri.

**Device:** iPhone 16e (iPhone17,5), iOS 27.0 RC (24A435) — vulnerable side.
**Fix build:** iOS 27.2 RC (24B115).

---

## 0. TL;DR

The 27.0→27.2 USB-family diff converges on **one** "improved bounds checking"-shaped fix:
the **CDC-NCM (USB ethernet tethering class) NTB-parameter validation wave** in
`com.apple.driver.usb.cdc.ncm` + `com.apple.driver.usb.networking`:

1. **PROVEN fix site A — cache-time alignment validation.** 24B115's NCM 1.1
   `cacheNTBParameters`-twin function (`AppleUSBNCM11Data`, 0xfffffff009b4f028) NEWLY
   validates the device-supplied `wNdpOutAlignment` (obj+0x840) and `wNdpInAlignment`
   (obj+0x834) — valid = **power-of-2 AND ≥ 4** — else forces them to 4 and logs
   `"Patching invalid NCM 1.1 NTB parameter wNdpOutAlignment %d"` / `...wNdpInAlignment %d"`.
   The 24A435 counterpart (0xfffffff009b0f768) has **no alignment validation at all** — the
   device's raw response bytes are cached straight through. The sibling NCM 1.0/"HU" path
   (24A435 0xfffffff009b130b0) already had the identical patching in 27.0 — 27.2 closed
   the gap for the NCM 1.1 path. Strings receipt: "Patching invalid" count 2 (24A435,
   HU variants) → 4 (24B115, +NCM 1.1 variants).
2. **PROVEN fix site B — OUT-NTB builder divide guards.** `usb.networking`'s OUT-NTB
   builder uses wNdpOutAlignment in `round_up(12, align)` / `round_up(16, align)` math
   (`udiv` at 24A435 0xfffffff009b1f58c and 0xfffffff009b1f738, UNGUARDED) — 24B115 adds
   `cbz w8` zero-guards plus exact-round-up `csel` at 0xfffffff009b5ef28 / 0xfffffff009b5f0f8.
3. **Trigger:** a malicious USB device presenting a **CDC-NCM 1.1 function** (USB-C
   "ethernet adapter" / facedancer NCM gadget) answers the host's
   `GET_NTB_PARAMETERS` class request (`0xA1/0x80/wValue=0/wIndex=<ctrl if>/wLength=0x1C`)
   with poisoned alignment fields (response offset 22 = wNdpOutAlignment, offset 12 =
   wNdpInAlignment).
4. **Impact mapping:** on 24A435, `wNdpOutAlignment=0` makes the builder's header-size
   math collapse (`udiv` by 0 returns 0 on AArch64 — no trap — but `round_up` degenerates
   to 0), placing the NDP **over the NCMH header** of the NTB the host transmits;
   non-power-of-2 values place the NDP at attacker-chosen misaligned offsets. The
   advisory's "unexpected system termination or read kernel memory" is the class Apple's
   patch prevents; the exact OOB-read instruction is NOT pinned (SHAPE-MATCHED — see §5
   for the honest gap).
5. **USB-family closure (negative census):** across all 41 USB kexts, the ONLY kexts
   with instruction-count deltas are: cdc.ncm (this fix), usb.networking (this fix +
   compiler outlining), AppleUSBXHCI (+10-ins retry-counter **feature**),
   IOUSBHostHIDDevice (−28-ins register-allocation churn), AppleUSBDeviceNCM (code
   REMOVAL: 226→222 fns, "submitPacketGated"/"ncm-no-trm"/"disable-transport-rm" strings
   gone — transport-rm refactor), IOUSBHostFamily (±1-6-ins shifts + new
   `kPortStatUSB3LinkFailureCount*` feature strings), and small churn in
   IOUSBDeviceFamily/AppleUSBEthernetHost/AppleUSBXDCIARM/Type2UpAdapter/DeviceMux.
   **The version-bumped audio kexts (AppleUSBAudio, AppleUSBDeviceAudioController
   901.48→910.2) contain ZERO code changes** — instruction-count multiset identical
   across all 1606/79 functions. Full census: `scripts/ds_count_multiset.py` output below.

---

## 1. Inputs and method

| | 27.0 RC (vulnerable) | 27.2 RC (fixed) |
|---|---|---|
| kernelcache | `/Volumes/ADATA ELITE SE880/ios-critical-bounty/24A435__iPhone17,5/kernelcache.release.iPhone17,5` | `/Volumes/ADATA ELITE SE880/ios-critical-bounty/24B115__iPhone17,5/kernelcache.release.v59.decompressed` |
| kexts | `extracted/24A435/` (all 41 USB-family kexts carved with `ipsw kernel extract`) | `extracted/24B115/` |

Method (METHODOLOGY §1/§4): version-diff the kext table → strings diff (all 41 pairs,
full-file) → section triage → function-table diff (LC_FUNCTION_STARTS + normalized
mnemonic pairing, `scripts/ds_fstarts_diff.py`) → instruction-level disasm of changed
functions (`ipsw macho disass` + `scripts/ds_udiv_census.py` + `scripts/ds_scan_hword.py`).

Version-diff receipt: of the 41 USB-family kexts, only `AppleUSBAudio` and
`AppleUSBDeviceAudioController` changed CFBundleVersion (901.48→910.2) — and both proved
to contain no code change (§6). Everything else is version-pinned but rebuilt (byte-diff
pervasive; semantic diff via function pairing).

**Strings-diff receipt (the decisive triage):** across all 41 USB kext pairs, the ONLY new
validation-shaped strings in 24B115 are, in `com.apple.driver.usb.cdc.ncm`:

```
NEW  Patching invalid NCM 1.1 NTB parameter wNdpOutAlignment %d
NEW  Patching invalid NCM 1.1 NTB parameter wNdpInAlignment %d
```

(everything else: build-path/xbs churn, timestamps, version strings, the 1/2 bitmap noise,
and `IOUSBHostFamily`'s feature strings `kPortStatUSB3LinkFailureCount(ForDevice)`).

---

## 2. Fix site A — cdc.ncm cache-time alignment patching (PROVEN, both sides)

### 2a. The provenance chain (device response → cached fields)

`cacheNTBParameters` (control class, 24A435 fn 0xfffffff009b18088; byte-similar in 24B115
at 0xfffffff009b57a38 — ratio 0.971, only string-address churn) issues the class request:

```
0xfffffff009b180bc: mov w8, #0x80a1      ; bmRequestType=0xA1, bRequest=0x80
0xfffffff009b180c0: stur w8, [fp, #-0x48]
0xfffffff009b180d0: mov w8, #0x1c       ; wLength = 28
0xfffffff009b180d4: sturh w8, [fp, #-0x42]
```

`GET_NTB_PARAMETERS = 0x80` matches the USB-IF CDC-NCM spec (Linux receipt:
`include/uapi/linux/usb/cdc.h`: `#define USB_CDC_GET_NTB_PARAMETERS 0x80`). The 28-byte
response is parsed into the control object at +0x140 (naturally aligned struct; the
`[IN]/[OUT] max size: %u divisor: %u payload remainder: %u alignment: %u` log reads
+0x144/+0x148/+0x14a/+0x14c (IN) and +0x150/+0x154/+0x156/+0x158/+0x15a (OUT) —
receipt at 0xfffffff009b1825c-0xfffffff009b182f4).

The data-interface object copies the whole raw block with a NEON copy
(24A435 receipt; identical in 24B115 at 0xfffffff009b4ffac-0xfffffff009b4ffc0):

```
0xfffffff009b1068c: add x9, x19, #0x828     ; dest = data obj + 0x828
0xfffffff009b10690: add x10, x8, #0x140     ; src  = control obj + 0x140
0xfffffff009b10694: ldur q0, [x10, #0xc]    ; 16 B: IN-align .. OUT-maxdg
0xfffffff009b10698: ldr  q1, [x8, #0x140]   ; 16 B: wLength .. IN-align
0xfffffff009b1069c: str  q1, [x9]           ; -> +0x828..+0x837
0xfffffff009b106a0: stur q0, [x9, #0xc]     ; -> +0x834..+0x843
0xfffffff009b106a4: ldrh w8, [x19, #0x828]  ; wLength  — zero-checked (cbz -> fail)
0xfffffff009b106ac: ldrh w8, [x19, #0x83c]  ; wNdpOutDivisor — zero-checked (cbz -> fail)
```

Resulting object layout (why the fields have no literal-offset writers — the NEON copy is
the writer): **+0x834 = wNdpInAlignment, +0x840 = wNdpOutAlignment, +0x842 =
wNtbOutMaxDatagrams, +0x82c = dwNtbInMaxSize, +0x838 = dwNtbOutMaxSize**. Only
`wLength` and `wNdpOutDivisor` are zero-checked at the copy. **The alignments, the max
sizes, and wNdpInDivisor are trusted raw.**

### 2b. The 24A435 vulnerable cache fn (no validation)

`sub_fffffff009b0f768` (NCM 1.1 data class, 41 ins; adjacent TU carries the
`AppleUSBNCM11Data` metaclass string and instance size 0x848):

```
0xfffffff009b0f784-790: version fields {2,3} -> +0x814
0xfffffff009b0f794-7a8: min(obj[0x7f0]+0x15c, 1514) -> +0x824   (max frame)
0xfffffff009b0f7ac-7b0: ldrh w8, [+0x842]; strh w8, [+0x826]     (max datagrams RAW copy)
0xfffffff009b0f7b8-7e8: "ncm-data-maxntb" DT prop (default 0x7ffc);
                        min(+0x82c, cap) -> +0x820              (dwNtbInMaxSize cap)
0xfffffff009b0f7ec-7f8: min(+0x838, cap) -> +0x81c              (dwNtbOutMaxSize cap)
; *** wNdpInAlignment (+0x834) and wNdpOutAlignment (+0x840): NEVER TOUCHED ***
```

### 2c. The 24B115 fixed cache fn (new gates, +24 instructions)

`sub_fffffff009b4f028` (65 ins) — identical body plus a NEW prologue checking both
alignments (verbatim):

```
0xfffffff009b4f054: ldrh w8, [x0, #0x840]      ; wNdpOutAlignment (device-supplied)
0xfffffff009b4f058: sub  w9, w8, #0x1
0xfffffff009b4f05c: and  w9, w8, w9            ; (align & (align-1)) == 0  → power-of-2
0xfffffff009b4f060: cmp  w8, #0x4              ; >= 4
0xfffffff009b4f064: ccmp w9, #0, #0, cs
0xfffffff009b4f068: b.eq <ok>
0xfffffff009b4f070: LOG "Patching invalid NCM 1.1 NTB parameter wNdpOutAlignment %d"
0xfffffff009b4f07c: mov  w8, #0x4
0xfffffff009b4f080: strh w8, [x19, #0x840]     ; force to 4
0xfffffff009b4f084: ldrh w8, [x19, #0x834]     ; wNdpInAlignment — same gate
0xfffffff009b4f088-098: sub/and/cmp/ccmp
0xfffffff009b4f0a4: LOG "Patching invalid NCM 1.1 NTB parameter wNdpInAlignment %d"
0xfffffff009b4f0ac: mov w8, #0x4; strh w8, [x19, #0x834]
```

### 2d. The sibling path already had it in 27.0

The NCM 1.0/"HU" path's cache fn (24A435 `sub_fffffff009b130b0`, 0xfffffff009b130b0-0x...327c)
carries the same two gates with the older log strings
`"Patching invalid HU NTB parameter wNdpOutAlignment %d"` (0x...9b1319c) /
`"...wNdpInAlignment %d"` (0x...9b131c0). Receipt chain: 24A435 strings 2×"HU" only;
24B115 strings 2×"HU" + 2×"NCM 1.1". **The bug was the missing copy of a known-good check
into the newer NCM 1.1 driver path** — textbook METHODOLOGY §1 negative space.

---

## 3. Fix site B — usb.networking OUT-NTB builder guards (PROVEN, both sides)

The cached params flow to `com.apple.driver.usb.networking` (the shared USB networking
engine, which owns the actual NTB build/parse) via two packer functions in cdc.ncm
(24A435 0xfffffff009b0fb68 IN-side, 0xfffffff009b121f8 OUT-side; both semantically
unchanged between builds — cross-kext stub targets resolved via chained fixups to
usb.networking 0xfffffff009b1d798 / 0xfffffff009b1d650).

The OUT-NTB builder (24A435 fn 0xfffffff009b1f4c4, 326 ins → 24B115 0xfffffff009b5ee5c,
345 ins; 'NCMH'/'NCM0' signatures at 0x...f5cc/f5e4) computes the NDP placement:

```
24A435 (VULNERABLE — unguarded divide by device-controlled alignment):
0xfffffff009b1f584: ldrh w8, [x22, #0xe]     ; wNdpOutAlignment from packed params
0xfffffff009b1f588: mov  w9, #0xc            ; NTH16 header length (12)
0xfffffff009b1f58c: udiv w10, w9, w8         ; <<< NO ZERO GUARD
0xfffffff009b1f590: msub w10, w10, w8, w9    ; 12 % align
0xfffffff009b1f594: sub  x8, x8, x10
0xfffffff009b1f598: add  x8, x8, #0xc       ; headerSize = align + 12 - (12 % align)
   (second variant, 16-byte NTH: same pattern at 0xfffffff009b1f738, #0x10)

24B115 (FIXED):
0xfffffff009b5ef1c: mov  w20, #0xc
0xfffffff009b5ef20: str  x24, [sp, #0x20]
0xfffffff009b5ef24: cbz  w8, <skip>          ; <<< NEW: never divide by 0
0xfffffff009b5ef28: udiv w9, w20, w8
0xfffffff009b5ef2c-34: msub/sub/add
0xfffffff009b5ef38: cmp  w9, #0              ; <<< NEW: exact-multiple refinement
0xfffffff009b5ef3c: csel x20, x20, x8, eq
   (second variant guarded identically at 0xfffffff009b5f0f8)
```

`udiv` census receipts (`scripts/ds_udiv_census.py`):

```
24A435 usb.networking: 0x...9b1f58c udiv by [x22,#0xe]  guarded=False
                       0x...9b1f738 udiv by [x22,#0xe]  guarded=False
24B115 usb.networking: 0x...9b5ef28 guarded=True (cbz w8) ; 0x...9b5f0f8 guarded=True
```

The IN-NTB parser and its dispatcher (24A435 0xfffffff009b1d864-0x...9b1db64 ↔
24B115 0xfffffff009b5d21c-0x...9b5d5xx) are **byte-identical** between builds — the 27.2
change is confined to the OUT builder and the cache fn.

---

## 4. Trigger recipe (what the malicious device sends)

**Attacker model:** physical USB device (facedancer-style gadget, or modified NCM
dongle/Raspberry Pi Zero USB gadget presenting `usb_f_ncm`).

1. Present a CDC-NCM **1.1** function: class 0x02, subclass 0x0D (NCM), protocol 1
   (NTB-16), Communications Interface with header/union/ether functional descriptors +
   NCM functional descriptor (`bcdNcmVersion >= 0x0110`, bmNetworkCapabilities per
   choice), and a Data interface with two bulk endpoints. The probe log receipt
   (`"NCM 1.1 driver: device supports extended capabilities, probe score increased"`,
   `"Attempting to switch to NCM 1.1 mode"`) shows the NCM 1.1 driver claims such
   devices — that is the path with the missing check.
2. During bring-up the host sends **GET_NTB_PARAMETERS**: `bmRequestType=0xA1`,
   `bRequest=0x80`, `wValue=0`, `wIndex=<control interface>`, `wLength=0x1C` (28).
3. Answer with a 28-byte response whose fields poison the cached layout (wire offsets):
   `+0 wLength, +2 bmNtbFormatsSupported, +4 dwNtbInMaxSize, +8 wNdpInDivisor,
   +0xa wNdpInPayloadRemainder, +0xc wNdpInAlignment, +0xe dwNtbOutMaxSize,
   +0x12 wNdpOutDivisor, +0x14 wNdpOutPayloadRemainder, +0x16 wNdpOutAlignment,
   +0x18 wNtbOutMaxDatagrams, +0x1a pad`.
4. Generate OUT traffic (answer DHCP, respond to pings — any IP traffic toward the
   device) to run the OUT-NTB builder on the host.

Seeds (28-byte crafted responses; `seeds/`, built by `scripts/ds_build_ntb_seeds.py`):

| seed | field value | expected 24A435 | expected 24B115 |
|---|---|---|---|
| `A_out_align0.bin` | wNdpOutAlignment=0 | headerSize degenerates to 0 → NDP written over the NCMH header (self-corrupt NTB; see §5) | patched to 4 + kernel log "Patching invalid NCM 1.1 NTB parameter wNdpOutAlignment 0" |
| `B_in_align0.bin` | wNdpInAlignment=0 | cached raw (IN-side consumer is the capacity negotiation) | patched to 4 + log |
| `C_out_align3.bin` | wNdpOutAlignment=3 | NDP placed at ntbuf+15 (unaligned, non-pow2 layout) | patched to 4 + log |
| `D_out_align_huge.bin` | wNdpOutAlignment=0x4000 | headerSize=0x4000 → NDP-end bounds check rejects (error path) | patched to 4 + log |
| `S_in_maxsize0.bin` | dwNtbInMaxSize=0 | SIBLING (see §7): pool-depth `udiv` by capped in-max | same — **unguarded in 24B115 too** |
| `OK_valid.bin` | all valid (align 4) | clean reference | clean reference |

---

## 5. Impact reconstruction — what is PROVEN vs SHAPE-MATCHED

**PROVEN (instruction-level, both sides):**
- 27.0 caches device-supplied `wNdpIn/OutAlignment` with **no validation**; 27.2 adds
  power-of-2/≥4 gating with patch-to-4 and log receipts.
- 27.0's OUT-NTB builder divides/rounds-up by that raw value **unguarded**; 27.2 adds the
  zero guard. With `align=0` on 27.0 the header-size math degenerates:
  `udiv(12,0)=0` (AArch64 UDIV-by-zero returns 0 — **it does not trap**; the naive
  "divide-by-zero panic" theory is explicitly REFUTED), `msub` yields 12, so
  `headerSize = 0 - 12 + 12 = 0` — the NDP is written at `ntbuf+0`, **overwriting the
  NCMH signature and NTH16 header** of the transmit NTB; datagram index entries land at
  `ntbuf+8..` inside the header. The transmitted NTB is attacker-shaped garbage that
  the device parses per its own choosing.
- With non-power-of-2 `align ∈ {3,5,6,7,...}`: `headerSize = align + 12 - (12 % align)`
  (3→15, 5→15, 6→18, 7→14, >12→align), i.e. the NDP placement inside the transmit NTB
  becomes attacker-chosen and can be unaligned.

**SHAPE-MATCHED (honest gap):** the advisory's exact primitives — "unexpected system
termination" and "read kernel memory" — are NOT pinned to single instructions this
session. All builder writes we traced stay inside the NTB-buffer bounds the builder
itself checks (`cmp x24, x26 / cmp x24, [sp+0x20]; b.hi → error`), and the IN parser is
byte-identical. The plausible residual mechanisms, ranked:
1. The degenerate NTB layouts (align 0 / non-pow2) make the host emit NTBs whose internal
   structure (wNdpIndex, wHeaderLength, NDP entries) is attacker-shaped — downstream
   consumers (the device-side read, or the host's own re-parse of IN echoes) may then
   drive reads the builder did not anticipate. Apple's own patch semantics — "force the
   alignment to a legal power-of-2" — says the danger space is exactly these values.
2. The IN-side capacity negotiation (cdc.ncm packer 0x...9b0fb68 → usb.networking
   trampoline 0x...9b1d798 → vtable+0xb0 method) receives wNdpInAlignment; if that
   method rounds a receive-buffer size by it, an invalid value shifts the buffer-size vs
   parse-bound relationship (unmapped this session — the vtable target is out-of-easy-reach).
3. A second, independent consumer not in these two kexts (see §6 residual lane
   IOUSBHostFamily).

Given 6 credited researchers, the bug was likely found by device-fuzzing the NCM
enumeration; the A/B receipts above are the fix, whatever the finders' exact PoC was.

---

## 6. USB-family negative census (what was checked and is clean)

`scripts/ds_count_multiset.py` over all 41 USB kext pairs — a function
instruction-count multiset is a strong no-fix oracle (an added check changes counts):

```
identical multiset (NO function changed size at all): AppleEmbeddedUSB, AppleEmbeddedUSBHost,
  ThunderboltUSBDownAdapter, ThunderboltUSBUpAdapter, TypeCPhyAUSBC, AppleUSBAudio (1606 fns!),
  AppleUSBCardReader, AppleUSBDeviceAudioController (79 fns), AppleUSBEthernetDevice,
  AppleUSBHostMergeProperties, AppleUSBLightningAdapter, AppleUSBMassStorageInterfaceNub,
  AppleUSBMike, AppleUSBTopCaseDriver, AppleUSBXDCI, AppleSynopsysUSB40XHCI, AppleSynopsysUSBXHCI,
  AppleUSBCommon, AppleUSBHostBillboardDevice, AppleUSBHostCompositeDevice,
  AppleUSBHostDeviceSupport, AppleUSBHostPacketFilter, AppleUSBHostiOSDevice, AppleUSBHub,
  usb.cdc, usb.cdc.ecm, usb.ethernet.asix, IOAccessoryPortUSB, IOUSBMassStorageDriver
deltas:
  cdc.ncm            41↔65 (THE fix fn, §2) + 101↔137 (pair-shuffle noise)
  usb.networking     152→150 fns; builder 326→345 (§3) + outlining churn
  AppleUSBXHCI       1884→1894 (+10 = retry-counter FEATURE: NEON counter @+0x318,
                     threshold 20, vtable+0x730 call — verified semantic diff)
  IOUSBHostHIDDevice 575→547 (register-reallocation/inlining churn; frame 0x80→0x60;
                     all checks preserved — verified semantic diff)
  AppleUSBDeviceNCM  226→222 fns, REMOVED strings submitPacketGated/ncm-no-trm/
                     disable-transport-rm (code-removal refactor, device-side NCM)
  IOUSBHostFamily    ±1-6-ins shifts across ~40 fns + kPortStatUSB3LinkFailureCount*
                     feature strings (stat-counter feature; NOT function-diffed to
                     completion — residual lane, see NEXT ACTIONS)
  IOUSBDeviceFamily / AppleUSBEthernetHost / AppleUSBXDCIARM / Type2UpAdapter / DeviceMux:
                     small ±1-16 shifts, no new validation strings — feature/churn grade
```

**The version-bumped audio pair (AppleUSBAudio 901.48→910.2, AppleUSBDeviceAudioController
901.48→910.2) contains NO code fix** — instruction-count multisets identical over all
1606/79 functions. The 27.2 audio CVEs are userspace (confirmed by cve_groups/03_audio).

Prior art (analysis/usb_descriptors.md, usb_commandring.md — AppleSynopsysUSB40XHCI
descriptor/ring audits) is fully consistent: those kexts are semantically untouched in
27.2 (identical multisets), refuting them as CVE-2026-112479 carriers.

---

## 7. Sibling census — checks Apple did NOT add (OUR disclosure candidates)

All fields below arrive in the same 28-byte GET_NTB_PARAMETERS response and are trusted
by the same code paths; the 27.2 fix touched ONLY the two alignment fields.

1. **`dwNtbInMaxSize = 0` (response offset 4) → unguarded pool-depth divide — LIVE ON
   27.0 AND 27.2.** The copy site zero-checks only wLength (+0x828) and
   wNdpOutDivisor (+0x83c). The pool-depth computation divides by the capped
   dwNtbInMaxSize with NO guard in EITHER build:
   ```
   24A435  0xfffffff009b107cc: udiv w9, w8, w9   ; w9 = [+0x820] (capped dwNtbInMaxSize)
   24A435  0xfffffff009b107d8: udiv w8, w8, w9   ; w9 = [+0x81c] ... chain
   24B115  0xfffffff009b500ec / 0xfffffff009b500f8: SAME, STILL UNGUARDED
   (context: pool size w8 (DT "ncm-data-maxpool", default 0x20000, itself zero-guarded
    by csel) divided by the device-controlled NTB-in-max; AArch64 UDIV-by-0 returns 0,
    so the queue depth [+0x728] becomes 0 → downstream ring/queue arithmetic on a
    zero-depth ring — degenerate-state class, needs consumer tracing to score impact.)
   ```
   This is the top candidate for OUR report to Apple Product Security: same response,
   same function family, unfixed even in 27.2.
2. **`wNdpInDivisor` (+0x830)** — not zero-checked at the copy (unlike its OUT twin);
   travels in the IN param struct (offset 8) into usb.networking's capacity/round-up
   helpers (`0x...9b5d8f4` / `0x...9b5d958` round-up by register divisors). A zero/huge
   divisor poisons IN-side offset math. UNPINNED — shape-level candidate.
3. **`wNtbOutMaxDatagrams` (+0x842→+0x826)** — cached raw (no clamp; only used with a
   builder-side `cbz` before the loop). A 0xFFFF value inflates the NDP-end bound check
   early-exit path; no memory-safety impact found — informational.
4. **The NCM 1.0/"HU" parity gap pattern** — the 27.2 fix copied 27.0's HU check into
   the 1.1 path but did NOT unify them; a future NCM 1.2 path would repeat the same
   omission class. Process observation for the disclosure.

---

## 8. Oracle design (A/B, METHODOLOGY §5)

- **Vulnerable side (27.0 RC device):** plug in the crafted NCM gadget (seed A/C/D);
  the OUT builder runs on first IP traffic. Receipts to capture: kernel log lines
  `"NCM 1.1 driver..."` / `"[IN]/[OUT] max size: ... alignment: %u"` (cacheNTBParameters
  logs the poisoned values verbatim — this is the READ-BACK of the attack), plus any
  panic/`.ips` from the degenerate-NTB path. The cached alignment is directly visible
  in the log line — a poison value of 3/0/0x4000 printed there IS the proof the
  unvalidated field reached the cache.
- **Fixed side (24B115):** same gadget → kernel log
  `"Patching invalid NCM 1.1 NTB parameter wNdpOutAlignment 3"` and NO crash — the
  fix's own refusal is the discriminator (METHODOLOGY §5 A/B pair).
- **No app/harness row can fire this from userspace** — the attacker is the physical
  device. The on-device probe is therefore a *witness* (see HARNESS_ROW.md): it reads the
  kernel log/registry state while the USER drives the malicious gadget.

---

## 9. Deliverables in this folder

- `extracted/24A435/`, `extracted/24B115/` — all 41 USB-family kexts, both builds.
- `scripts/ds_kdiff_triage.py` — per-kext section/word diff triage.
- `scripts/ds_strings_diff.py` — full-file strings diff (the decisive triage).
- `scripts/ds_fstarts_diff.py` — LC_FUNCTION_STARTS function-pair semantic diff.
- `scripts/ds_count_multiset.py` — instruction-count multiset no-fix oracle (§6 census).
- `scripts/ds_scan_hword.py` — field-offset access census (found the consumers).
- `scripts/ds_udiv_census.py` — UDIV divide-guard census (found the builder fix + sibling).
- `scripts/ds_bl_scan.py`, `scripts/ds_find_owner.py`, `scripts/ds_container_lookup.py`,
  `scripts/ds_ctrlreq_scan.py`, `scripts/ds_body_diff.py` — locator/utilities.
- `scripts/ds_build_ntb_seeds.py` + `seeds/*.bin` — the six crafted 28-byte responses.
- `HARNESS_ROW.md` — the on-device witness/oracle spec.

## 10. NEXT ACTIONS

1. Pin the OOB-read primitive: trace the IN-capacity trampoline's vtable+0xb0 method
   (cdc.ncm `AppleUSBNCMDataPoller`-class) and its use of wNdpInAlignment in receive
   buffer sizing; compare against the IN parser's bound (capped dwNtbInMaxSize).
2. Function-level diff of IOUSBHostFamily (the residual ±1-shift lane; feature-shaped
   prior, but 1977 functions were only multiset-screened, not pair-diffed).
3. Live A/B with a gadgetfs/facedancer NCM 1.1 function (seeds above) on the 27.0 RC
   device + a 24B115 device: log-line witness for the poison values, panic hunt for the
   termination primitive.
4. Draft the sibling report (§7.1 dwNtbInMaxSize=0) for Apple Product Security — it is
   live on CURRENT 27.2 and would carry OUR credit.
