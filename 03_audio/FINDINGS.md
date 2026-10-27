# FINDINGS.md — CVE group 03: Audio / CoreAudio (iOS 27.2 advisory 149230)

> AI-generated security research (same notice as AGENTS.md). Authorized research on the
> owner's device + Apple's publicly-shipped firmware, coordinated disclosure. PoCs are
> crash-oracles ONLY. Every claim below carries a receipt (both-side disassembly with
> vmaddrs) or an explicit SHAPE-MATCHED / NOT-LOCALIZED caveat.

**Builds compared**: 24A435 (iOS 27.0 RC — **what the device runs = vulnerable**) vs
24B115 (iOS 27.2 RC — the fix build), both iPhone17,5 dyld caches (ADATA drive) + both
kernelcaches. Method: METHODOLOGY §1/§4/§4a (strings-first diff → added check = admitted
bug → both-side disassembly receipts).

**Component version deltas (the cheap change oracle)**:

| image | 24A435 | 24B115 |
|---|---|---|
| AudioToolboxCore | 1638.104.3 | 1638.215.0 |
| AudioToolbox | 1638.104.3 | 1638.215.0 |
| AudioCodecs | 818.0.0.0 | 818.205.0.0 |
| CoreAudio | 482.102.0.0 | 482.208.0.0 |
| AVFAudio | 794.106 | 794.210 |

Extracted binaries: `extracted/24A435/` and `extracted/24B115/` (AudioToolboxCore,
AudioToolbox, AudioCodecs, CoreAudio). Symbol tables per image via
`ipsw dyld symaddr <dsc> --image <path>` (dumps all private symbols; `/tmp/syms_*`).

---

## 0. TL;DR — the fix map

| # | Fix site (24B115) | Added check | 24A435 state | CVE mapping (honest) | Status |
|---|---|---|---|---|---|
| F1 | `ImmersiveRendererDataMarshaller::Deserialize` → new `ReadImmersiveRendererDataV1/V2` (AudioToolbox; same marshaller code exists in AudioToolboxCore) | wire `count` / `dataByteSize` validated against wire-remaining AND **destination capacity** + version sanity 1..3 | count/dataByteSize checked only against wire availability; **dest capacity never checked** → linear OOB write in the AQ/server process | **CVE-2026-113907** (buffer overflow; "app may cause unexpected system termination or corrupt process memory"; Tsytsarkin) | **PROVEN** (both-side receipts §1) |
| F2 | `-[AVHapticServerInstance createCustomAudioEvent:format:frames:options:reply:]` (AudioToolbox; XPC server side of CoreHaptics/AVHapticEngine) | reject invalid-format ASBD; reject `frames × bytesPerFrame` declared against the actual waveform byte count | no such validation (neither string exists in 24A435) | **CVE-2026-113907**-adjacent or second CoreAudio line — same "app → system termination/corrupt process memory" shape | **SHAPE-MATCHED** (receipts §2) |
| F3 | `APACHOADecoder::Initialize` (inlined `HOASpatialDecoder::Initialize`, AudioCodecs) | `mNumHOAcoeffs (field+0x30) cmp #0x25` (37 = `kMaxNumSCs_DynSelSCs4EachSB` array dimension) | only loose `cmp #0x7a` (122) — values 37..121 index the 37-entry array OOB; value is file-controlled via `hoa::CodecConfig::Deserialize` | **CVE-2026-112546** (Audio: crafted file → app termination, OOB read, bounds checking) | **SHAPE-MATCHED, fix PROVEN** (receipts §3) |
| F4 | `mpddrc::UniDrcSelection::selectDownmixMatrix` (AudioCodecs) | nChannels ≤ 8; dims ordered; coefficient count == rows×cols | only zero/equality checks; matrix dims unconsumed-unvalidated from DRC metadata | **CVE-2026-113912** (CoreAudio OOB access; **Anna Groza of Calif.io credited**) or **CVE-2026-86972** (audio file → memory corruption, size validation) | **SHAPE-MATCHED, fix PROVEN** (receipts §4) |
| F5 | `mpddrc::UniDrcSelection::getSignalPeakLevel` | "downmix coefficient count mismatch" reject | absent | same uniDRC family as F4 | SHAPE-MATCHED (receipts §4) |
| F6 | `mpddrc::UniDrcSelection::Process` | "desired effect type count (%d) exceeds request list size (%d)" | absent | same uniDRC family | SHAPE-MATCHED (receipts §4) |
| — | Kernel audio kexts (`AppleEmbeddedAudio`/`AppleCSEmbeddedAudio`/`IOPEmbeddedAudio`/`IOPAudioSpeaker` 1000.45→1010.2; `AppleARMIISAudio`/`IISAudioIsolatedStreamECProxy` 600.28→610.2; `AppleUSBAudio` 901.48→910.2) | **NO added bounds/validation strings in any audio kext** (strings diff = build-path churn only); app-reachable userclient `IOPAudioClientManagerDevice` (400.36) **unchanged** | n/a | **CVE-2026-86969** ("corrupt KERNEL memory", Tsytsarkin) — **NOT LOCALIZED in the audio kexts**; see §5 for candidates | NOT-LOCALIZED |
| — | CoreAudio 482.102→482.208 | deltas are the new **driver-app registration** feature (`AudioServerPlugInRegisterDriver`, `-[Core_Audio_Driver_Registrar register_driver:...]`, entitlement checks) + AudioCapture | feature churn | no CoreAudio-framework file-parser fix | feature churn, recorded honestly |

**The check-count sanity check**: 5 CVE lines for the audio stack; we localized
1 proven server-side wire-buffer-overflow fix (F1), 1 proven client-reachable XPC server
validation fix (F2), 1 proven file-metadata bound fix (F3), 1 proven DRC-metadata
validation family (F4-F6, 3 checks — matching the "size validation" plural shapes of
113912 + 86972), and the kernel line (86969) remains unlocalized in kexts (§5).

---

## 1. F1 — ImmersiveRendererDataMarshaller wire deserialization (PROVEN)

**This is the strongest finding of the group: an app-reachable, fully-reconstructable
linear heap overflow in the audio server, fixed by explicit capacity checks.**

### Functions (a2f-verified)

| build | function | range |
|---|---|---|
| 24A435 (vuln) | `ImmersiveRendererDataMarshaller::Deserialize(CADeserializer&, void*&, uint32_t&)` | 0x1b1ea1464..0x1b1ea16a8 |
| 24A435 (vuln) | `ImmersiveRendererDataMarshaller::Serialize(CASerializer*, const void*, uint)` | 0x1b1ea12dc..0x1b1ea1464 |
| 24B115 (fix) | `ImmersiveRendererDataMarshaller::Deserialize(...)` | 0x1b23f15f4..0x1b23f1714 |
| 24B115 (fix) | `ReadImmersiveRendererDataV2(CADeserializer&, ImmersiveRendererData_V2&, size_t)` (NEW) | 0x1b23f1714..0x1b23f185c |
| 24B115 (fix) | `ReadImmersiveRendererDataV1(CADeserializer&, ImmersiveRendererData_V1&, size_t)` (NEW) | 0x1b23f185c..0x1b23f1a3c |

### Fixed-side receipts (24B115, AudioToolbox)

New rejection log strings (absent in 24A435):
```
ImmersiveRendererDataMarshaller: rejected V1 count %u (wire max %zu, dest max %zu)   @ 0x1b25ba3ed
ImmersiveRendererDataMarshaller: rejected V2 dataByteSize %u (wire avail %zu, dest max %zu) @ 0x1b25ba391
```

Fixed `Deserialize` sanity gates (0x1b23f15f4+):
```
0x1b23f165c:  ldr  w26, [x0]           ; version from wire
0x1b23f1660:  sub  w8, w26, #0x3
0x1b23f1664:  cmn  w8, #0x2
0x1b23f1668:  b.lo fail                ; NEW: version must be 1..3
0x1b23f166c:  cmp  w26, #0x2
0x1b23f1678:  csel x9, x9(12), x8(8)   ; header size by version
0x1b23f167c:  cmp  x21, x9
0x1b23f1680:  b.lo fail                ; NEW: wireLen >= header
0x1b23f1690:  csel x25, x21, x8, eq    ; dest capacity (client-provided or wireLen)
0x1b23f1694:  cmp  x25, x9
0x1b23f1698:  b.hs ok                  ; NEW: dest capacity >= header
   ok: bl ReadImmersiveRendererDataV1/V2 (dest capacity passed as m)
```

Fixed `ReadImmersiveRendererDataV2` (0x1b23f1714+):
```
0x1b23f1730:  subs x21, x2, #0xc       ; destMax = capacity - 12
0x1b23f1734:  b.lo fail
   ...read w22 (dataByteSize wire[0]) , w23 (dataByteSize wire[1])...
0x1b23f1784:  cmp  x21, w23, uxtw      ; dataByteSize vs destMax
0x1b23f1788:  b.lo reject              ; NEW: reject if dataByteSize > destMax
0x1b23f1790:  cmp  x24, x2            ; wire avail vs dataByteSize
0x1b23f1794:  b.lo reject              ; NEW
0x1b23f1798:  ...
0x1b23f1fc:  stp  w22, w23, [x20, #0x4]
   ... memcpy dest+0xc, wire, dataByteSize ...
0x1b23f1840:  adrp x3, "ImmersiveRendererDataMarshaller: rejected V2 dataByteSize %u (wire avail %zu, dest max %zu)"
```

Fixed `ReadImmersiveRendererDataV1` (0x1b23f185c+) — element-count capacity math:
```
0x1b23f18a8:  mov  x9, #0xcccccccccccccccc ; ÷40 magic
0x1b23f18b4:  lsr  x23, x8, #0x4      ; wireMax = wireAvail/40   (elements)
0x1b23f18b8:  sub  x8, x21, #0x8
0x1b23f18c0:  lsr  x24, x8, #0x4      ; destMax = (destCapacity-8)/40
0x1b23f18c8:  cmp  x23, w22, uxtw     ; wireMax >= count?
0x1b23f18cc:  ccmp x24, x21, #0, cs   ; AND destMax >= count?
0x1b23f18d0:  b.hs ok / else reject → "rejected V1 count %u (wire max %zu, dest max %zu)"
```

### Vulnerable-side receipts (24A435, AudioToolbox) — full function in `receipts/marsh_vuln.disass`

V2 path — **the destination is never capacity-checked**:
```
0x1b1ea1628:  str  w8, [x21, #0x8]    ; store wire dataByteSize to dest+8
0x1b1ea1650:  e0 03 08 2a  mov  w2, w8
0x1b1ea1654:  ldp  x1, x9, [x20, #0x10]
0x1b1ea165c:  cmp  x9, w8, uxtw       ; ONLY check: wire avail vs dataByteSize
0x1b1ea1660:  b.ge loc_1b1ea1674
0x1b1ea1664:  mov  x1, #0 ...         ; truncated flag
0x1b1ea1674:  add  x8, x1, x2
0x1b1ea1678:  str  x8, [x20, #0x10]   ; advance read ptr by dataByteSize
0x1b1ea167c:  add  x0, x21, #0xc
0x1b1ea1680:  bl   0x1b8120bb0        ; COPY dataByteSize bytes into dest+0xc
```
If the destination object is smaller than the declared `dataByteSize`, the copy writes
past it — server-side heap overflow with fully attacker-chosen size and content.

V1 path — **the element count from the wire drives an unbounded write loop**:
```
0x1b1ea1530:  bl   GetAndAdvanceReadPtr(4,4)
0x1b1ea1538:  ldr  w8, [x0]           ; count FROM THE WIRE
0x1b1ea153c:  str  w8, [x21, #0x4]   ; stored to dest
0x1b1ea1544:  mov  x23, #0           ; i = 0
0x1b1ea1548:  add  x24, x21, #0x8    ; dest+8 = entries array
0x1b1ea154c:  <loop>                 ; each iteration:
0x1b1ea154c:  add  x8, x23, x23, lsl #0x2
0x1b1ea1550:  add  x25, x24, x8, lsl #0x2   ; entry ptr = dest+8 + 20*i
0x1b1ea1574:  str  w8, [x25]         ;  5 x u32 writes per element (20 bytes)
0x1b1ea1598:  str  w8, [x25, #0x4]
0x1b1ea15bc:  str  w8, [x25, #0x8]
0x1b1ea15e0:  str  w8, [x25, #0xc]
0x1b1ea1604:  str  w8, [x25, #0x10]
0x1b1ea160c:  ldr  w8, [x21, #0x4]
0x1b1ea1610:  cmp  x23, x8           ; loop bound = wire count ONLY
0x1b1ea1614:  b.lo loc_1b1ea154c     ; NO dest bound anywhere
```

Client-side `Serialize` (0x1b1ea12dc+, `receipts/marsh_serialize_vuln.disass`) packages
the app's property blob **verbatim** (version u32, then V1: count + 5-word entries; V2:
size + bytes) — so the wire content is exactly what the caller hands it, making the whole
chain reconstructable from the blob layout (see `scripts/craft_immersive_wire.py` and
`seeds/immersive_*.bin`).

### Trigger & craft (crash-oracle)

- **Wire/blob layout**: `{u32 version; if !=2: u32 count; count×{5×u32} | if ==2: u32 dataByteSize; dataByteSize bytes}`.
- **Seeds (built, no seed dependency)**: `seeds/immersive_v1_count_overflow.bin`
  (count=0x20000 → 20·count ≈ 2.6 MB linear overwrite on 27.0),
  `immersive_v1_count_mild.bin`, `immersive_v2_size_overflow.bin` (declared 0x10000 vs 16
  actual), `immersive_v2_size_mild.bin`.
- **Fire path**: an app sets the immersive-renderer-data property on an AudioQueue /
  spatialization unit (the property that `mSpatializationUnit` consumes — client-side AQ
  code logs `error %d setting mSpatializationUnit immersive renderer data`), or plays
  spatial audio whose file-carried renderer metadata (APAC HOA family, see F3) reaches the
  same marshaller. Exact property ID + serialization table entry: one a2f lookup away at
  harness-build time (see HARNESS_ROW.md cell 1).
- **Expected A/B (oracle)**: 27.0 RC device = crash/corruption in the audio server
  process; 24B115 = clean refusal + log `ImmersiveRendererDataMarshaller: rejected V1
  count ...` (the fix's own receipt).

### CVE mapping

Matches **CVE-2026-113907** ("An app may be able to cause unexpected system termination or
corrupt process memory", buffer overflow, Tsytsarkin) — app-triggered, buffer overflow,
server-process corruption. SHAPE-MATCHED on the credit name (not confirmed); the fix
itself is PROVEN instruction-level on both builds.

---

## 2. F2 — AVHapticServerInstance custom audio event (SHAPE-MATCHED, fix PROVEN)

### Functions

| build | function | range |
|---|---|---|
| 24A435 | `-[AVHapticServerInstance createCustomAudioEvent:format:frames:options:reply:]` | 0x1b1e2e5d8..0x1b1e2ee7c |
| 24B115 | same | 0x1b237e970..0x1b237f4b8 |

### Fixed-side receipts (24B115, AudioToolbox)

New strings (absent in 24A435):
```
%25s:%-5d %s: ERROR: Rejecting custom audio event with invalid format ASBD: %s   @ 0x1b25b12d9
%25s:%-5d %s: ERROR: Rejecting custom audio event declaring %llu frames of %u bytes against a %llu byte waveform @ 0x1b25b1328
```
Referenced at 0x1b237ee8c (+1308) and 0x1b237ef88 (+1560) inside the XPC method
(the reject blocks set up `CA::StreamDescription::AsString` output, the frame count
(%llu), byte size (%u) and the waveform size (%llu) — i.e. the fix computes
`frames × bytesPerFrame` against the actual waveform byte count and refuses mismatches;
receipts in `receipts/haptic_fixed.disass`).

### Vulnerable side

`receipts/haptic_vuln.disass` (full function) contains **neither string nor any
equivalent validation**; the format/frames parameters flow straight into
`HapticAudioUnit::addEnvelope` / `addCustomAudioEnvelopeConnections` (both sides).

### Trigger & craft

App-side CoreHaptics/`AVHapticEngine` custom audio event (AHAP custom-audio path) with
(a) an invalid ASBD, (b) `frames × bytesPerFrame` exceeding the attached waveform buffer.
Expected: 27.0 = crash in the haptics server daemon ("unexpected system termination"
shape); 24B115 = the two new "Rejecting custom audio event ..." logs.

### CVE mapping

Fits the second "app may be able to cause unexpected system termination or corrupt
process memory" line — assigned to **CVE-2026-113907** or a sibling CoreAudio line;
SHAPE-MATCHED (not uniquely attributable; two XPC-server fixes + F1 may span
113907/86969-adjacent lines). The fix itself is proven present/absent on the two builds.

---

## 3. F3 — APAC HOA spatial decoder, mNumHOAcoeffs array bound (fix PROVEN; CVE SHAPE-MATCHED)

### Functions

| build | function | range |
|---|---|---|
| 24A435 | `APACHOADecoder::Initialize(ACParamList const&, apac::observer_ptr<apac::IASCConfig>)` (with inlined `HOASpatialDecoder::Initialize`) | 0x1bc9dcd68..0x1bc9dea80 |
| 24B115 | same | 0x1bd178de8..0x1bd17ab68 |

### Fixed-side receipt (24B115, AudioCodecs)

The ONLY HOA-string delta between the builds (all other mNumHOAcoeffs messages exist in
both — see string diff, §receipts):
```
"%25s:%-5d  Failed to initialize: mNumHOAcoeffs exceeds kMaxNumSCs_DynSelSCs4EachSB array dimension in HOASpatialDecoder::Initialize()"  @ 0x1bda4f935
```
The added check (0x1bd17a70c+, `receipts/apac_hoa_fixed.disass`):
```
0x1bd17a70c:  ldrb w8, [x21, #0x1c]
0x1bd17a710:  tbz  w8, #0, loc_...   ; feature-gated path
0x1bd17a714:  ldr  w8, [x21, #0x30]  ; mNumHOAcoeffs
0x1bd17a718:  cmp  w8, #0x25         ; NEW BOUND: 37 (array dimension)
0x1bd17a71c:  b.lo ok
   fail → the new log string (receipt) → Initialize fails
```

### Vulnerable-side receipt (24A435, AudioCodecs) — `receipts/apac_hoa_vuln.disass`

```
0x1bc9ddf04:  ldr  w8, [x21, #0x30]  ; mNumHOAcoeffs
0x1bc9ddf08:  cmp  w8, #0x7a         ; ONLY bound: <= 121
0x1bc9ddf14:  b.lo ok  else → "Failed to initialize mNumHOAcoeffs in HOASpatialDecoder::Initialize()" @ 0x1bd2b373d
0x1bc9ddf70:  ldr  w9, [x21, #0x34]  ; mNumSalientComponents must be <= mNumHOAcoeffs
0x1bc9ddf74:  cmp  w9, w8
0x1bc9ddfd4:  ldr  w9, [x21, #0x38]  ; mNumAmbientComponents <= mNumHOAcoeffs
```
→ On 24A435 any mNumHOAcoeffs in **[37..121]** passes and the 37-entry
`kMaxNumSCs_DynSelSCs4EachSB`-dimensioned array is indexed out of bounds. The value is
file-controlled: the parse is proven by the pre-existing strings
`Failed to deserialize mNumHOAcoeffs in hoa::CodecConfig::Deserialize()` /
`Failed to deserialize mNumHOAcoeffs4SC[i] ...` (present in BOTH builds) — i.e. the
field comes off the APAC bitstream config.

### Trigger & craft

Crafted APAC/spatial-audio file with HOA codec config setting mNumHOAcoeffs ∈ [0x26..0x79]
(mutator skeleton: `scripts/craft_apac_hoa.py`; needs an APAC seed — Apple Music spatial
lossless capture or on-device encode). Expected: 27.0 = app termination during decode
init; 24B115 = the new "exceeds kMaxNumSCs_DynSelSCs4EachSB" refusal.

### CVE mapping

**CVE-2026-112546** ("Audio — Processing a maliciously crafted file may lead to unexpected
app termination", OOB read, bounds checking): SHAPE-MATCHED (audio-file parse, added
bounds check, app-termination impact). The k-prefixed array name suggests a constant
per-subband table read — consistent with the OOB-read class. Alternates: none fit better
among the Audio lines; the write-shaped lines are accounted by F1/F4.

---

## 4. F4-F6 — MPEG-D DRC (mpddrc::UniDrcSelection) validation family (fixes PROVEN; CVEs SHAPE-MATCHED)

All three checks are in AudioCodecs, file `MPDDRCSelection.cpp` (per the log metadata),
consuming **uniDRC metadata** (ISO/IEC 23003-4) carried by xHE-AAC/USAC streams
(and `MP4LoudnessInfo` vectors — see `mpddrc::UniDrc::Initialize` signature taking
`std::vector<MP4LoudnessInfo>`), i.e. attacker-controlled via a crafted media file.

### F4 selectDownmixMatrix — fixed (24B115, 0x1bd16a3dc..0x1bd16a74c, `receipts/dmx_fixed.disass`)

```
0x1bd16a510:  fmov w27, s0              ; downstream channel count
0x1bd16a514:  ldr  w19, [x20, #0x114]  ; DRC nChannels
0x1bd16a518:  cmp  w19, #0x8           ; NEW: <= 8
0x1bd16a51c:  b.hi fail
0x1bd16a520:  cmp  w27, w19            ; NEW: dims ordered
0x1bd16a524:  b.hu fail
0x1bd16a528:  ldp  x9, x8, [sp, #0x80]
0x1bd16a530:  sub  x8, x8, x9
0x1bd16a534:  asr  x28, x8, #0x2       ; coefficient count (words)
0x1bd16a538:  mul  w8, w19, w27        ; rows × cols
0x1bd16a53c:  cmp  x28, w8            ; NEW: coefficient count must match dims
0x1bd16a540:  b.hs ok
   fail → "ERROR: invalid downmix matrix dimensions %d x %d" @ 0x1bda48c37 (line 0xdf6)
```

### F4 — vulnerable (24A435, 0x1bc9ce3f4..0x1bc9ce694, `receipts/dmx_vuln.disass`)

```
0x1bc9ce4f4:  ldr  w25, [x20, #0x110]  ; match count
0x1bc9ce4fc:  cmp  w25, w26 ; b.ne fail
0x1bc9ce504:  str  w21, [x20, #0xb4]
0x1bc9ce524:  ldr  w8, [x20, #0x114]  ; same field the fix bounds!
0x1bc9ce528:  cbz  w8, loc_1bc9ce60c  ; ONLY a zero check — NO upper bound,
                                       ; no dims product check, no ordering check
```

### F5 getSignalPeakLevel (fixed 0x1bd17daa8, check branch → 0x1bd17e4a8)
New reject: `ERROR: downmix coefficient count mismatch` @ 0x1bda48382 (line 0x208)
(absent in 24A435). `receipts/peak_fixed.disass`.

### F6 UniDrcSelection::Process (fixed 0x1bd1657bc)
New reject: `ERROR: desired effect type count (%d) exceeds request list size (%d)` @
0x1bda485d4 (line 0x8b1) — compares the requested effect count against the request-list
capacity (`x26>>2`). `receipts/effproc_fixed_full.disass`.

### Trigger & craft

Crafted xHE-AAC/USAC file carrying uniDRC metadata with (a) downmix matrix channels > 8,
(b) matrix dims whose product ≠ coefficient count, (c) effect-type count over the request
list. Skeleton: `scripts/craft_xhe_drc.py` (m4a box walker + field map; seed via
`afconvert -f m4af -d xhe`). Expected A/B: 27.0 = decoder-side memory corruption during
DRC selection; 24B115 = the three new ERROR logs + clean refusal.

### CVE mapping

**CVE-2026-113912** ("Processing a maliciously crafted media file may lead to unexpected
app termination or corrupt process memory", OOB access; **Anna Groza of Calif.io**) and
**CVE-2026-86972** ("Processing a maliciously crafted audio file may lead to memory
corruption", buffer overflow, size validation) — both fit this media-file DRC-metadata
validation family; the individual check→CVE assignment within the family is
SHAPE-MATCHED, not proven.

---

## 5. CVE-2026-86969 ("corrupt KERNEL memory") — NOT LOCALIZED; candidate map

The advisory says the fix makes it impossible for "an app ... to cause unexpected system
termination or corrupt KERNEL memory" (OOB write, input validation; Tsytsarkin).
Per the group brief, we checked the kernel side:

- `ipsw kernel kexts` on both kernelcaches — audio-family version deltas:
  `AppleEmbeddedAudio`/`AppleCSEmbeddedAudio`/`AppleCS42L77v2Audio`/`IOPAudioSpeaker`/
  `IOPEmbeddedAudio`/`AppleEmbeddedAudioResourceManager` 1000.45→1010.2;
  `AppleARMIISAudio`/`IISAudioIsolatedStreamECProxy` 600.28→610.2;
  `AppleUSBAudio`/`AppleUSBDeviceAudioController` 901.48→910.2;
  `ExclavesAudioKext`/`AudioSharedDARTMapperProxy` 400.61→410.2.
  **Unchanged**: `IOAudio2Family` (1.0), `IOAudioCodecs` (1.0.0), the app-reachable
  userclient family `IOPAudioClientManagerDevice`/`IOPAudioIOBufferDevice`/... (400.36),
  `IOPAudioDriverFamily` (400.12), `TrustedClockingKEXT`.
- Both-build strings diffs of `AppleEmbeddedAudio`, `AppleCSEmbeddedAudio`,
  `IOPEmbeddedAudio`, `IOPAudioDriverFamily`, `AppleUSBAudio` (`scripts/kext_strdiff.py`):
  **only build-path churn — zero added validation/assert/error strings**.

Candidates & honest reading:
1. The kernel touchpoint may be **userspace-mediated**: the F1 overflow sits in the audio
   server whose corrupted state feeds the HAL → kernel audio stack (AudioServerDriver/
   IOPAudio path) — Apple's "corrupt kernel memory" classification can name the endpoint
   while the fix lands in userspace. F1 (app-triggerable OOB write) is the best candidate
   we have; 86969 may be its CVE. NOT PROVEN.
2. A silent kext-level bounds check (no log) in the 1010.2/610.2/910.2 bumps — possible,
   unproven; disassembly-level kext diff is the follow-up (only `AppleARMIISAudio` failed
   to carve: its image id is `com.apple.iokit.AppleARMIISAudio` — same 600.28→610.2 delta).

**Verdict: NOT-LOCALIZED (kernel)**. No false claim is made.

---

## 6. Negative results (recorded honestly)

- **CoreAudio.framework (482.102→482.208)**: function-size census
  (`scripts/fndiff.py`, 30,883 common symbols) + strings → deltas are the new
  **driver-app hosting** feature (`AudioServerPlugInRegisterDriver`,
  `Core_Audio_Driver_Registrar`, entitlement checks `com.apple.private.audio.driver-host`)
  and AudioCapture plumbing. No file-parser bounds-check shape. The advisory's
  "CoreAudio" fixes are accounted for by the AudioToolbox/AudioCodecs sites above
  (Apple attributes audio-stack CVEs across these components broadly).
- **AudioToolboxCore (1638.104.3→1638.215.0)**: strings add the AudioCapture feature,
  MP4 `ctlc` content-type box handling (`MP4AudioFile::Close` +256B, feature-shaped),
  the shared ImmersiveRendererDataMarshaller refactor (−292B — same fix as F1, the client
  side), and new `PRECONDITION FAILURE` hardening in the new capture code.
  `CAFAudioFile::GetProperty` (+252B) shows **no new referenced strings** and is recorded
  as churn, not a localized CVE fix. If CVE-2026-112546 is not F3, a silent ATC fix is the
  remaining candidate (function-level diff of the 317 changed ATC functions = follow-up).

## 7. Sibling census — NEW-bug candidates for OUR disclosure (the credit engine)

Fields around each fix Apple did NOT gate (each = a candidate; all in 24A435 binaries):

1. **HOASpatialDecoder neighbors of F3** (AudioCodecs, both builds share them):
   `mNumSalientComponents` (+0x34) and `mNumAmbientComponents` (+0x38) are only checked
   `<= mNumHOAcoeffs` (0x1bc9ddf70/0x1bc9ddfd4) — no independent array-dimension bound;
   `mNumHOAcoeffs4SC[i]` / `mNumSubbands4SC[i]` (per-subband counts, consumed by the
   SplitSubbands loop 0x1bc9de60c+ and `HOASpatialDecoder::Process` — its own log admits
   "mNumHOAcoeffs4SC[scIdx] is invalid") — candidate: OOB on per-subband arrays with a
   valid-looking per-SC count. Consuming path: `APACHOADecoder::Initialize` →
   `apac::hoa::SplitSubbands`.
2. **ImmersiveRendererData V2 vs V1 asymmetry** (F1): the fixed V1 path bounds `count`
   by wire/40 and dest/40 — the wire element in the FIXED build reads 5 words per entry
   (20 bytes) while the capacity math divides by 40 — an off-by-2x capacity convention
   worth auditing on the fixed build itself (possible residual overcommit).
   Also: `ImmersiveRendererDataMarshaller::Serialize` (client side) still packages any
   count/size the app hands it — the server check is now the only gate.
3. **uniDRC remaining fields** (F4-F6): `DrcInstructionsUniDrc.gain{Set,Mod}SequenceIndex`,
   `drcSetEffectCount` per instruction, and the `uniDrcConfig.drcLayout` channel-mapping
   indices — the 27.2 fix gated only matrix dims, coefficient count, and one effect-type
   count (in `Process`); the per-instruction effect count and gain-sequence indices
   remain unchecked candidates on BOTH builds. Consuming path:
   `mpddrc::UniDrcProcessor::PrepareDrcGains` / `ApplyDrcGains`.
4. **AVHapticServer neighbors of F2**: `AVHapticServerInstance` methods that accept
   layers/zones/envelopes (`addEnvelope`, `addCustomAudioEnvelopeConnections`) — same
   daemon, same XPC trust boundary; the fix gated only the custom-audio-event entry.

## 8. Files

- `extracted/24A435/`, `extracted/24B115/` — 8 dylibs (the four components × two builds).
- `receipts/` — both-side disassembly (apac_hoa_*, dmx_*, peak_*, effproc_*, marsh_*,
  haptic_*, caf_getprop_*; fixed + vulnerable; caf = negative result).
- `scripts/` — diff_strings.py, str2vm.py, adrp_scan.py, adrp_add_scan.py, sym_lookup.py,
  fn_size.py, fndiff.py, kext_strdiff.py, craft_immersive_wire.py, craft_xhe_drc.py,
  craft_apac_hoa.py.
- `seeds/` — immersive_v1_count_overflow.bin, immersive_v1_count_mild.bin,
  immersive_v2_size_overflow.bin, immersive_v2_size_mild.bin (crash-oracle only).
- `HARNESS_ROW.md` — the on-device probe-row spec.
