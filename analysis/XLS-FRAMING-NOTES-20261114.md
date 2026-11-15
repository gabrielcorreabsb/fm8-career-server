# XLS framing notes — Logon + DownloadPlayerProfile (for mock LSP)
Date: 2026-11-14. Static-only (reader 6.9, run 1ad4e4ac). Target SHA 89bc22...

## Descriptor model (confirmed)
Two record families, both `kind/namePtr/id/...`:
1. **Inline static field/message records** (file-initialized), 4 qwords min:
   `{kind, namePtr, id, max=0x7fffffff}`; message fields (kind 0xc) extend to
   14 qwords: `+0x20 size, +0x28 nestedDescriptorPtr, +0x38 selfPtr, +0x40 count`.
   Envelope: Logon request field `loginData` @0x14490d820 (kind 0xc, id 0x10,
   size 0x110 → inner descriptor 0x144910a78); response field `responseData`
   @0x14490d8f0 (kind 0xc, id 8, size 0x378 → inner 0x144910420).
2. **Runtime-init field tables in .data** (stride 0x60), built by init functions
   in 0x1400dxxxx-0x1400exxxx (thread-guarded, `Init_thread_header` pattern):
   record = `{kind, namePtr, id, max, max, 0, max, max, size, 0, 0, 0}` (0x60).
   Kind values seen: 1=u8?, 2=u8?, 3=string(short), 4=u32, 5=Int64, 6=blob/u64,
   8=array?, 0xc=nested message, 0x10=nested-with-inline-descriptor,
   0x11=byte/bool, 0x12=blob16, 0x15=str15, 0x16=array-of-message?
   The descriptor object header: `{fieldTablePtr, kindCode, 0, namePtr, 0, max, max, 0, max, max, size, selfPtr}`.

## Logon message (Xls::User::Logon)
- Registry entry @0x145b27728 {class 0x1448e6a30, method 0x14490de48 'Logon'}.
- Facade = FUN_141c44d40, virtual slot [1] of **Xls::LspMessageProviders**
  (vftable 0x14491fc68, COL '.?AVLspMessageProviders@Xls@@' @0x145e769b8 via
  COL 0x144f4bb88). Facade builds Xls::User::Logon::Message (vftable 0x14491fca0)
  + BufferTypeAdapter<User::Logon::Response> (vftable 0x14490def0, obj 0x390,
  inside _Ref_count_obj2 0x3a0). Ctor ICF-folded with dtor at 0x141c426c0;
  no recorded callers (reader call-graph gap).
- Facade internals: headers auth @&DAT_14491f78c; class/method strings
  @0x14491f450 / 0x14491f765; POST; X-ContractVersion '73'. Queue via
  FUN_141c07720 + FUN_141c1f090 + (**+0x38)(pipeline). param_3 (parameters) is
  processed by FUN_141bf42b0 (FALSE function — bad boundaries, reader mode).
- Transport/serialize = virtual (**param_2+0x18)(param_2, classPtr, methodPtr,
  requestBuilder) on the service context — NOT YET LOCATED (the walker).
- Pipeline: Xls::LspMessagePipelineBuilder ctor FUN_141c054e0 (8 node slots,
  Xls::Ref<Xls::ILspServiceSession> interface, session name string 0x20,
  LspMessageRetryPolicy defaults ratio 2.0 initial 2000 max 120000; message
  timeouts 2000/120000 ms).

## Logon REQUEST = loginData → **UserLogonData** (inner desc 0x144910a78,
field table 0x145b28310, STATIC in file), fields (id = wire id):
- xuid: 8 (kind 6, size 8)
- gamerTag: 0x10 (kind 0x15, size 0xf)
- userTier: 0x30 (kind 4)
- region: 0x34 (kind 3, string)
- locale: 0x38 (kind 3)
- LCID: 0x3c (kind 3)
- ipAddress: 0x40 (kind 4)
- machineId: 0x48 (kind 6, size 8)
- macAddress: 0x50 (kind 0x16)
(table ends 0x145b28610, then zeros; strings at 0x144910bd0..0x144910c88;
name string 'UserLogonData' @0x144910c88; cmsSlotOverride/cmsSnapOverride/
cmsEnvironmentOverride/shouldResetProfile strings exist nearby — likely SaveProfile
message fields, not in this table)

## Logon RESPONSE = responseData → **UserLogonResponse** (inner desc 0x144910420,
field table 0x145b28af0; 2 static records + runtime-filled records via
init **FUN_1400e91b0** (body 0x1400e91b0-0x1400ea075, xref 0x1400e930f → table
0x145b28bb0)), fields (id, kind, size):
- isProfileValid: 8 (0x11, 1)
- permissions: 0x10 (0x10, nested → MethodPermission, size 0x200)
- featureAreasBanMask: 0x28 (4)
- userFlags: 0x2c (4)
- upsellOfferId: 0x30 (4)
- upsellText: 0x38 (8)
- vipOfferIds: 0x58 (0x15, 300)
- **userData: 0x70 (0xc, size 0xa8, nested desc PTR_vftable_145b28300)** ← profile block
- SecurityId: 0xa8 (0x12, 0x10)
- notificationNonce: 0x118 (1, 2)
- notificationPollIntervalSeconds: 0x128 (2)
- defaultFriendsPollIntervalSeconds: 0x134 (4)
- maxFriendsPollIntervalSeconds: ~0x138 (4)
- notificationCategories: ~0x138 (0x16 → XlsNotificationCategory, 88)
- defaultTimeoutMs: 0x150 (3), defaultContentTimeoutMs: 0x154,
  defaultInGameTimeoutMs: 0x158
- makeDiscounts: 0x160 (→ MakeDiscountData 56), carDiscounts: 0x178
  (→ CarDiscountData 56), allCarDiscount: 0x1c8, makePartsDiscounts: 0x1e0
  (MakePartDiscountData), carPartsDiscounts: ~0x230 (CarPartDiscountData),
  allPartsDiscount: ~0x1f8?, featuredUserEntries, pushNotificationTags
  (PushNotificationTag 40)
- cmsInformation: ~0x2f0 (0xc), availabilityInformation (0x14?),
  FlightRingId, systemTimeUTC: 0x340, lastZendeskTicketCreateTime: 0x350
- **banData: 0x360 (0xc → UserBanData, size 152)**
Note: ids appear to be struct offsets in the flat message (gaps = in-string gaps);
some id/name pairings above are approximate — iterate against client parser.
Nested inline-record names resolved (records at): MethodPermission @0x1448ec490
(name@0x1448ec660), XlsNotificationCategory @0x1448db450, MakeDiscountData
@0x1448fdc40, CarDiscountData @0x1448f6370, MakePartDiscountData @0x1448fdc40-fam
(0x1448fdef0), CarPartDiscountData @0x1448f6bd0, UserBanData @0x144910870
(name@0x144910b88), PushNotificationTag @0x1448f5d20.
Related strings @0x144910ae0+: UserLogonResponse, UserBadgeGrantedNotificationParameters,
expireTime, featureArea, banId, banMessageTitle, banMessageBody, isWarning,
UserBanData, UserBucketedCompareStats, UserCompareStats, gamerTag, userTier, LCID,
ipAddress, machineId, macAddress, ageGroup, cmsSlotOverride, cmsSnapOverride,
cmsEnvironmentOverride, shouldResetProfile.

## DownloadPlayerProfile (for later steps)
- Request desc @0x145b11658 (init FUN_1400db1d0): region (id 0xa0, kind 0x1e),
  recentlySeen (id 0xa2?, kind 0x11) — approximate.
- Response desc/table 0x145b136e8 (init FUN_1400dbd30): per-car carId(0xd0),
  purchasePrice(0xd8), acquisitionType(0xe0), carPointsTotal(0xe4),
  earnedCarPoints(0xe8), purchasedCarPoints(0xec), currentLevel(0xf0),
  experiencePoints(0xf4), tiersAchieved(0xf8), unredeemed(0x110).
- Builder FUN_141b7ea80; creator FUN_141b7fe80 (ICF caveat); Operation vftable
  0x1448d3d88; completion _Do_call FUN_141b80c50.

## WALKER DECODE (CORRIGIDO E COMPLETO 2026-11-14 — FUN_141c30860 decompilado INTEIRO)
FUN_141c2e060 (param_7 da facade = request/message builder): two-pass —
1ª chamada FUN_141c37e90(param_1, message, CCountStream{vftable,0}, param_4, 0)
para medir (count), aloca buffer via FUN_141c25250(streams result), cria
CMemStream (FUN_141c5a810: {vftable CMemStream, ptr, ptr, size, size}), chama
FUN_141c37e90 de novo → buffer serializado. FUN_141c37e90 (ENCODE mirror) tem
boundary falso mas chama FUN_141c30860.

**FUN_141c30860 = DECODE WALKER GENÉRICO** (assinatura: ctx, messageStruct,
param_3=descriptor ptr, param_4=stream, param_5=sink). Retorna 0/negativo
(-0x7faffffc param nulo; -0x7fafffff ptr nulo; -0x7fafffc0 stream read; -0x7fafffa4
parse/limite; -0x7faffff4 campo maior que max; -0x7faffffc nulos).
- ctx+0x42b0 = stream interface: read = (**stream+8)(stream,dst,size);
  skip = (**stream+0x18)(stream,len,1).
- ctx+0x288 = depth counter; frame por nível (0x28): ctx+8+depth*0x28 = descriptor,
  +0x10 = message struct, +0x18 = record ptr corrente, +0x28 = misc.
- ctx+0x42b8 = buffer sink (param_5): vector de Ref<Buffer> begin@+8 end@+0x10,
  stride 0x30 (push inline FUN_141c268f0 quando cheio).
- ctx+0x290/0x2a4.. = scratch datetime (swprintf via FUN_14138ef90; 'T' @+0x2a4).
- DESCRIPTOR (param_3): *param_3 = ponteiro p/ primeiro record; *(int*)(param_3+1)
  = +0x08: se 0 → record corrente = NULL (sem campos).
- RECORD = tabela de stride **0x60** (CONFIRMADO contra bytes estáticos; refs do
  decompile: puVar11[k] = byte offset +4k):
  +0x00 kind (u32), +0x08 namePtr (char*), +0x10 offset/id (i64; 0x7fffffff =
  computed via FUN_141c2f4d0(ctx)), +0x18/+0x20/+0x30/+0x38 = 0x7fffffff (limits),
  +0x28 = 0, +0x40 size/maxlen (i64; para strings = max len em unidades de char;
  checagem len > max → erro; segunda checagem utf8 FUN_141c25000), +0x48 nested
  descriptor ptr (kind 0xc), +0x50 = 0, +0x58 flags BYTE: bit0 (0xB0&3==1 na
  leitura original = puVar11[0x16]&3) = campo é ponteiro indireto (deref antes de
  usar), bit1 = campo é Ref<Buffer> inline (resolve buffer do sink).
  CHAIN: o record "next" é avançado PELOS SUB-WALKERS via ctx+0x18 slot
  (LAB_141c30d92 relê o slot) — não é simples record+0x60 no walker pai.
- switch(kind):
  0x15 STRING: read 4 bytes (**stream+8)(stream,&len,4) → ntohl (prefix u32
    BIG-ENDIAN); cap global 0x2000; cap por campo (size@+0x40, size*4 < len → erro);
    campo nulo → skip(len); len 0 → string vazia; senão std::string ctor
    FUN_141ca1730(ptr,len,0), SSO (heap se len>0xf via *(ptr+0xc)), read bytes.
  0x10 DATETIME: parse de TEXTO "%4hu-%2hu-%2hu" + 'T' + "%2hu:%2hu:%2hu" +
    opcional ".%3hu" + offset "+HH:MM"/"-HH:MM"/'Z' (com carry de hora) → 8 ushorts
    (y,m,d,h,mi,s,?,ms) direto na struct; buffer em ctx+0x290; erro -0x7fafffa4.
  0xc NESTED: se bit1 → Ref<Buffer> do sink (push, psVar12 = buffer data) e
    *(campo) = data; recursão FUN_141c2f900(ctx+8, nestedDesc@+0x48, ptr); nulo → erro.
  0x16/0x17 ARRAY: FUN_141c329d0.
  0xe: FUN_141c2fb10. 0x14: FUN_141c30270 (tem corpo 809B mas boundary falso).
  9: FUN_141c33340(ctx, record, flags@+0x58, size@+0x40).
  default (1-8, 0x11, 0x12...): FUN_141c31730 (SCALAR).
- Todos os sub-walkers (FUN_141c2f4d0 computed-offset, 141c2f900 nested, 141c31730
  scalar, 141c329d0 array, 141c2fb10, 141c30270) + ENCODE mirror FUN_141c37e90 são
  FALSAS funções no DB ("bad instruction data") — reader não decompila; boundaries
  errados vêm da análise 6.8 original. Resolver exigiria nova análise dessas
  regiões (não o warm readOnly) OU disassembly manual dos bytes, OU correlação por
  captura runtime.
- Wire facts já confirmados: strings têm prefixo de comprimento u32 network-order;
  datetime é texto ISO; nested pode ser Buffer inline via sink; SSO std::string.

PENDÊNCIA PRÓXIMA (decisão do usuário): para fechar a gramática exata (scalars,
arrays, envelope: nonce 12B + encryption stage + headers HTTP), os caminhos são
(a) captura runtime de um Logon real via MITM (ferramentas já existem do teste
09/11; exige autorização — pass estava estático-only), (b) disassembly manual dos
sub-walkers via read_bytes (trabalhoso mas viável para FUN_141c31730), ou (c)
processo Ghidra próprio sobre uma NOVA cópia para re-analisar só essas funções
(pesado: nova cópia 1.16GB + análise).

## CAPTURE RUN 2026-11-15 (hosts+CA MITM, approved by user)
Harness: fm8-lsp-server certs (CA thumb 3E44359E1CE489ED95792A584DB67659A7448B7B);
capture server = lsp-capture/capture_server.py (derivative of server.py, saves full
bodies + headers). Env reverted after (restore_ca.ps1).
Artifacts: lsp-capture/capture/179471185{1,5}_Logon.bin (896B each) + .headers.txt;
capture_log.jsonl.

FINDINGS:
- Request body = 12B session nonce + ENCRYPTED payload (high entropy; the two bodies
  agree in only 4/896 bytes). Nonce varies per request; body length constant 896.
  => MessagePipelineStageEncryption is ACTIVE on the outgoing path; wire payload is
  NOT plaintext. Key/IV likely derived from the nonce (12B) — static hunt needed in
  the encryption stage family (MessagePipelineStageEncryption ctor FUN_141c4a1a0;
  object 0x70; also stage family 0x141c4a0a0 decryption).
- Full header set on Logon (all confirmed): Authorization: XBL3.0 x=<xuid>;<JWE
  RSA-OAEP/A128CBC-HS256 token>; X-UserId: 2533274958092393; X-Validation: 32-hex
  (4c0d2c53... — likely body/HMAC check); X-IdempotencyId (GUID-like per request);
  X-LanguageCodeId: 22 (pt-BR); X-Platform: 4; X-RequestId (= traceparent trace-id);
  X-Version: 8.25.06.18.8597102.FMBase_LiveHotFix; X-CodeVersion: 0.1;
  X-ContractVersion: 73; UA "Xls Client"; Content-Type: bin/xtsw;
  path /Services/o.xtsw.
- 09/11 evidence re-checked: client ACCEPTED plaintext responses (echo frame
  {0,0,0}) for race methods => response path encryption is a NO-OP for the mock
  (decrypt stage tolerates plaintext). So the mock can respond plaintext; the
  blocker is understanding the REQUEST encryption only for logging purposes
  (mock does not need to decrypt requests to act — X-Method/X-ClassName headers
  carry routing).
- Game behavior in this run: boot showed "SEM CONEXÃO — Motivo: Falha ao baixar o
  conteúdo" (content download gate fires before/alongside Logon); client sent
  Logon 2x (~4s apart this time) then stalled at the dialog.

OPEN QUESTION for the mock: whether Logon_Results must be ENCRYPTED (client decrypt
stage) or plaintext suffices. Prior race-method acceptance suggests plaintext OK;
will be tested empirically by the mock.

- read_bytes needs `const rb = tools.rea.read_bytes; await rb(...)` (direct call
  can fail); returns `.normalized_result.bytes_hex`.
- qword LE decode: `for (let j=7;j>=0;j--) v=v*256+parseInt(h.substr(off*2+j*2,2),16)`
  (CUIDADO: `(off+j)*2` é BUG — desloca os bytes).
- xrefs() works on RIP-relative code refs (init tables found this way: xref on
  runtime table base 0x145b28bb0 → 0x1400e930f → FUN_1400e91b0).
- search_bytes only finds ABSOLUTE pointers (in .data); code refs are RIP-relative.
- FUN_141bf42b0 and several XLS helpers are FALSE functions (bad boundaries, reader).

## CRYPTO PIPELINE (explorer 2026-11-15)

Method note: the `rea` MCP tool surface was NOT available in the explorer subagent
session (only context7/gh_grep/opencode tools were exposed), so every fact below comes
from direct PE mapping + Capstone 5.0.7 over the on-disk exe (table of contents parsed
manually: ImageBase 0x140000000, .text RVA 0x1000 size 0x39f15bc, .rdata RVA 0x39f3000,
.data RVA 0x5a4f000, .pdata RVA 0x669d000 = 235264 RUNTIME_FUNCTION entries, usable as
an exact function/end map for every VA). Scripts: %TEMP%\opencode\{peh,pef,xref,sabs,cls,dmp}.py

### 1) DECISIVE: part of .text is encrypted at rest, function granular (anti-tamper)
A large subset of functions is stored as high-entropy bytes that exactly fill their
.pdata extent, padded on both sides by the usual 0xCC fill. They do not disassemble at
all (e.g. `add bh,byte ptr [rip-0x2cf2e5b9]`, `push 0x54b04e9b`), i.e. this is not a
boundary problem — the bytes are ciphertext (Denuvo-style on-demand decryption). This is
the real cause of the "bad instruction data / FALSE function" entries in the 6.8 DB.
Opaque (encrypted), with extents:
  - 0x141c4a2a0 (0x81)  - slot [5] of BOTH stage vtables (shared base method)
  - 0x141c4ae40 (0x162) - slot [4] of the DEC vtable only  <= DEC-specific transform
  - 0x141c4afb0 (0x19e) - slot [4] of the ENC vtable and [13] of DEC
  - 0x141c09520 (0x12f) - FormatterIncomingStage slot [3] (the incoming "process")
  - 0x141c04870, 0x141c04520-adjacent 0x141c04870/0x141c093d0 - incoming formatter slots
  - 0x141c16f90 (0xa0)  - the pipeline "add stage" helper used by FUN_141c07720
Not encrypted (readable) in the same family: FUN_141c4a0a0/FUN_141c4a1a0 (ctors),
0x141c49c20/0x141c49c60/0x141c49ca0/0x141c49cd0 (dtors), 0x141c4b410, 0x141c4b520,
0x141c4b6c0, 0x141c09650 (FormatterOutgoing process), 0x141c08b50 (timestamp header).
Consequence: `FUN_1417ce7b0` (AES-CBC encrypt wrapper) has ZERO E8 callers in the whole
.text - its caller is one of the opaque bodies. So Q1/Q3/Q4 "process" logic cannot be
recovered from the file; it needs a runtime dump (after loader decrypt) or tracing.

### 2) Crypto engine class - fully readable, layout confirmed
Instance size >= 0x168 (allocation is 0x168+; ctor FUN_1417ce748):
  +0x000 32B AES key (FUN_1417ceaf8 memcpy 2x16B from a peer engine instance)
  +0x020 0x100B AES-256 round-key schedule; ctor memsets it to 0 (FUN_1417b2984 then
         memset(this+0x20,0,0x100) via 0x141b74782)
  +0x0f0 16B CBC IV inside the schedule struct (written by FUN_1417d0e20)
  +0x120 32B random per-instance value, regenerated on every key set (FUN_1417b4a20)
  +0x140 CRITICAL_SECTION (Enter/Leave around every crypto op: 0x1417ce813/0x1417ce842)
  +0x148/+0x158 heap blob + length (dynamic key material copied engine->engine)
API (all real code):
  FUN_1417ce748 ctor: registry init (0x1417b2984 -> FNV-1a 0x811c9dc5 at 0x1417b2a25),
    zero IV/blob, random-key path, memset schedule.
  FUN_1417ce86c random init: 128-bit global state at 0x145d866d0 mixed with
    FUN_1417b10d0 (splitmix-style: `~x<<32 ^ x`, `<<12`, `<<48`) 4x, then
    FUN_1417b4a20(this,0x20,+0x120,0x20). (The 4x global mixing is the RNG, not 4 keys.)
  FUN_1417ceaf8 adopt external 32B key: lock, copy 32B into +0x000, regenerate +0x120,
    copy 0x20 bytes again, unlock. Callers: FUN_1417b32e0/0x1417b3620 (engine
    copy/assign), themselves reached from 0x1416cb1d8 and 0x141789530 thunks.
  FUN_1417ce7b0 message encryptor(ctx, key32, src, len): alloc(len+0x20) through the
    registry allocator (0x1417b29a0, align 8), memcpy (0x141b74776 IAT), lock,
    FUN_1417d0e20(schedule, key32, iv16) -> copies [iv16] into schedule+0xf0,
    FUN_1417d0af0(schedule, buf, len) = AES-256-CBC encrypt in place, unlock, return buf.
    NB the wrapper zeroes its 16B IV stack slot at 0x1417ce7e9, so THIS call site uses
    all-zero IV - the per-message IV is whatever the (opaque) caller passes as key/iv.
  FUN_1417d0af0 AES-256-CBC: MixColumns `imul ecx,eax,0x1b` at 0x1417d0c86, S-box table
    base 0x1447b6d50 (single occurrence in the image), rcon 0x1447b6f51, round loop
    `mov r12b,1 ... cmp r12b,0xe` => 14 rounds = AES-256. IV whitening: `movups
    xmm0,[r13+0xf0]` at 0x1417d0b5a. No ChaCha/other cipher anywhere in the image.

### 3) Stage objects and where the key comes from (builder FUN_141c07720, readable)
  - 0x141c07f4b-0x141c07f67: r12b = `([rbp-0x70] != 0) && ((**(obj)+8))(obj) != 0`
    -> passed as r8b to the ENC ctor at 0x141c08172 (stored at stage+0x60). So the
    encrypt flag is a negotiated/queried capability, not a constant.
  - 0x141c07f67: `call [session+0x38]` (session = rsi) -> pipeline/options.
  - 0x141c08058 `test bl,bl; jne 0x141c081f6` => if bl != 0 the WHOLE timestamp-header
    + encryption block is skipped (pipeline stays plaintext); bl is the builder's own
    flag pair with [rsp+0x30] (= 4th bool arg, stored at 0x141c077c5).
  - 0x141c08060 `cmp [rsp+0x30],bl; jne 0x141c08127` => 4th arg == 0 adds
    LspMessageAddTimestampHeaderStage FUN_141c08b50 (0x141c080ae) to pipeline
    [rbp+0x570].
  - 0x141c0812e-0x141c08172: `mov rax,[rsi]; lea r8,[rsp+0x50]; mov rdx,[rbp+0x570];
    mov rcx,rsi; call [rax+0x48]` -> the SESSION's vtable slot 0x48 fills a 2-qword
    Ref at [rsp+0x50]; refcount++ (lock inc [ctrl+8]); that Ref is moved into the ENC
    ctor (stage+0x08/+0x10). Slot 0x58 is then called with the same out-slot
    (0x141c081df-0x141c081f1) = the incoming/DEC counterpart is registered by the
    session, which is why the DEC ctor is not called from this builder.
  - ENC/DEC ctors store a second vtable at stage+0x18 (0x1446091a8) and the bool at
    +0x60 (ENC only), dword 2 at +0x48, zeros at +0x50/+0x58; stage sizes 0x68 (DEC)
    and 0x70 (ENC).

### 4) Capture evidence contradicts "12B nonce + ciphertext"
Byte-compare of lsp-capture/capture/179471185{1,5}_Logon.bin (896B each): the ONLY
equal offsets are 73, 257, 327, 477 (4 bytes ~ the 3.5 expected by chance for random
data). The whole 896B body is uniformly random - there is NO cleartext prefix, no
repeating header, no visible status/code/length field in the request. Also 896 = 56*16
(block aligned) while 896-12 = 884 is NOT a multiple of 16, so "12B cleartext nonce +
CBC ciphertext" is arithmetically impossible; either the whole body is CBC (56 blocks,
zero-IV + per-call key whiten per 2) or the prefix would have to be 16B (880 = 55*16).
The per-request variance must come from the plaintext (idempotency id / timestamp /
nonce field inside the serialized Logon) and/or a per-request key+IV chosen by the
opaque caller.

### 5) Type names present (semantics, from RTTI/type-name strings)
  .?AVEncryption@Xls@@ / .?AVEncryption@Xls@@V12@@Xls@@ @0x145e736bf
  .?AVDecryption@Xls@@ / V12 / @@@ @0x145e76f70
  .?AVDecryptKey@Xls@@U_BCRYPT_ctx_iRSADOAEP2048@@ @0x145e77d75
  .?AVMessagePipelineStageStsSign@Xls@@V12@@Xls@@ @0x145e72d4b  (Xbox STS signing stage)
  .?AVMessagePipelineStageNewFrame / Formatter / Http / TraceContext / PolicyBlock /
  PolicyBlockRepeatable @0x145d0565d..0x145e72d4b
=> the client does RSA-OAEP-2048 decryption of a session key (BCrypt) and has an
   StsSign stage; key transport is client-private-key based, not a 12B nonce.

### 6) ENVELOPE SYNTHESIS (orchestrator 2026-11-15, late)
- Entire 896B Logon body is uniformly random ciphertext (see section 4). Best split:
  256B (RSA-OAEP-2048 wrapped session key) + 640B (AES-CBC body); both halves look
  random, so the split is a hypothesis, not an observation.
- BCRYPT key-blob magics found: 'RSA1' (public key blob) at .rdata 0x14494af60,
  0x14494b080, .data 0x145a5bcf0; 'RSA2' strings at .rdata 0x1449209a0, 0x144920bd0.
  Server public key likely embedded (candidate: 0x145a5bcf0 in .data).
- Encryption is capability-gated (negotiated via session, not marker bytes) and the
  builder has an explicit plaintext mode (section 3) — consistent with 09/11 where the
  client parsed plaintext responses for race methods; only Logon was refused (empty
  Results).
- Consequence for the mock: request routing by X-Method needs no decryption. Next
  empirical step: respond plaintext Logon_Results; observe acceptance at boot.
- Static-exhausted (encrypted at rest, Denuvo-style, function-granular): DEC/ENC stage
  process methods 0x141c4a2a0/0x141c4ae40/0x141c4afb0, FormatterIncoming process
  0x141c09520, pipeline add-stage helper 0x141c16f90. Runtime dump/trace required for
  envelope internals.
- Pending before mock test: extract userData nested block fields (init fn unknown,
  desc PTR_vftable_145b28300 at UserLogonResponse field id 0x70).

### 7) UserLogonResponse runtime table — COMPLETE (init FUN_1400e91b0, read fully)
Record layout confirmed stride 0x60: {kind, namePtr, id, max, max, 0, max, max,
size, nested, 0, 0}. Table base 0x145b28af0. Field order (= wire order):
| # | id | kind | name | size/notes |
|---|----|------|------|------------|
| 1 | 0x08 | 0x11 | isProfileValid | 1 |
| 2 | 0x10 | 0x10 | permissions | 0x200; nested inline record &DAT_1448ec490 (MethodPermission); desc &PTR_vftable_145b24470 |
| 3 | 0x28 | 4 | featureAreasBanMask | 4 |
| 4 | 0x2c | 4 | userFlags | 4 |
| 5 | 0x30 | 5 | upsellOfferId | 8 (i64) |
| 6 | 0x38 | 0x15 | upsellText | maxlen 300 |
| 7 | 0x58 | 0x16 | vipOfferIds | array, element kind 0x10 (datetime, 16B) |
| 8 | 0x70 | 0xc | userData | nested &PTR_DAT_1448dae80 (UserData), size 0xa8 |
| 9 | 0x118 | 0x12 | SecurityId | 0x10 (blob16) |
| 10 | 0x128 | 1 | notificationNonce | 2 |
| 11 | 0x12c | 3 | notificationPollIntervalSeconds | 4 |
| 12 | 0x130 | 4 | defaultFriendsPollIntervalSeconds | 4 |
| 13 | 0x134 | 4 | maxFriendsPollIntervalSeconds | 4 |
| 14 | 0x138 | 0x16 | notificationCategories | array, nested &DAT_1448db450 (XlsNotificationCategory) |
| 15 | 0x150 | 3 | defaultTimeoutMs | 4 |
| 16 | 0x154 | 3 | defaultContentTimeoutMs | 4 |
| 17 | 0x158 | 3 | defaultInGameTimeoutMs | 4 |
| 18 | 0x160 | 0x16 | makeDiscounts | array, nested &DAT_1448fdc40 (MakeDiscountData), max 100 |
| 19 | 0x178 | 0x16 | carDiscounts | array, nested &DAT_1448f6370 (CarDiscountData), max 100 |
| 20 | 0x1c8 | 0xc | allCarDiscount | nested &PTR_DAT_1448ff730, size 0x38 |
| 21 | 0x1e0 | 0x16 | makePartsDiscounts | array, nested MakePartDiscountData, max 100 |
| 22 | ~0x218 | 0x16 | carPartsDiscounts | array, nested &DAT_1448f6bd0 (CarPartDiscountData), max 100 |
| 23 | 0x1f8? | 0xc | allPartsDiscount | nested &PTR_DAT_1448ff980, size 0x38 (order: after carPartsDiscounts) |
| 24 | 0x230 | 0x16 | featuredUserEntries | array, max 100 |
| 25 | 0x248 | 0x16 | pushNotificationTags | array, nested &DAT_1448f5d20 (PushNotificationTag), max 10 |
| 26 | 0x260 | 0xc | cmsInformation | nested &PTR_DAT_14491a9e0, size 0x90 |
| 27 | 0x2f0 | 0xc | availabilityInformation | nested &PTR_DAT_1448feee0, size 0x30 |
| 28 | 0x320 | 0x15 | FlightRingId | string maxlen 0x40 |
| 29 | 0x340 | 0x10 | systemTimeUTC | datetime TEXT (16B struct) |
| 30 | 0x350 | 0x10 | lastZendeskTicketCreateTime | datetime TEXT |
| 31 | 0x360 | 0x16 | banData | ARRAY of UserBanData (&DAT_144910870), max 20 |
CORRECTIONS vs earlier guesses: SecurityId id = 0x118 (not 0xa8); notificationNonce
id = 0x128; banData is an ARRAY (kind 0x16), not a single nested; systemTimeUTC and
lastZendeskTicketCreateTime are datetime-TEXT (kind 0x10); upsellOfferId is i64 (kind 5).

### 8) UserData nested block — COMPLETE (table 0x145b110f0, fully STATIC in file;
earlier 'runtime-filled' claim was a misread)
| # | id | kind | name | size |
|---|----|------|------|------|
| 1 | 0x08 | 6 | qwXuid | 8 |
| 2 | 0x10 | 0x15 | wzGamerTag | maxlen 0xf |
| 3 | 0x30 | 0 | flags | 1 |
| 4 | 0x34 | 0x12 | clubId | 0x10 (GUID blob) |
| 5 | 0x48 | 0x15 | clubTag | maxlen 4 |
| 6 | 0x68 | 3 | clubTopTierCount | 4 |
| 7 | 0x6c | 4 | roleInClub | 4 |
| 8 | 0x70 | 2 | currentBadgeId | 2 |
| 9 | 0x72 | 2 | currentPlayerTitleId | 2 |
| 10 | 0x74 | 4 | currentCarCollectionScore | 4 |
| 11 | 0x78 | 2 | currentCarCollectionTier | 2 |
| 12 | 0x7c | 4 | currentDriverLevel | 4 |
| 13 | 0x80 | 4 | currentPrestigeRank | 4 |
| 14 | 0x84 | 3 | currentDriverModelId | 4 |
| 15 | 0x88 | 0x16 | customizationSlotsV2 | array |
(Records 2+ verified byte-by-byte at 0x145b111b0..0x145b11690; name pool
0x1448db5e0-0x1448db6e8 confirmed by ASCII dump.)

### 9) KIND semantics — REVISED (from UserData static table + response table)
0 = u8 (1B); 1, 2 = u16 (2B); 3, 4 = u32 (4B); 5 = i64 (8B); 6 = u64/blob8 (8B);
0x12 = 16B blob; 0x15 = string (u32 BIG-ENDIAN length prefix + bytes, SSO in struct);
0x10 = datetime TEXT ("yyyy-mm-ddThh:mm:ss[.mmm][Z|±HH:MM]"); 0xc = nested message;
0x16 = array (count + elements; element kind/size from nested desc or record);
0x11 = bool/u8; 9, 0xe, 0x14 = special sub-walkers (FUN_141c33340/2fb10/30270);
0x17 = array variant. Wire encoding is POSITIONAL (record order); no per-field ids
on the wire. Encoder for mock v1: scalars LE fixed-size; strings u32BE-len; empty
arrays = count 0 (verify count prefix width empirically — likely u32 BE like strings).


## FINAL VERDICT (see mock-lsp/ENVELOPE-SPEC.md 'FINAL VERDICT')
Mock route closed: response signature must be Turn 10's; client-key signature rejected (variant 9 decisive boot, immediate SEM CONEXAO, no retries).

