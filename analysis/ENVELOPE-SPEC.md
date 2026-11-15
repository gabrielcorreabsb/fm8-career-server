# ENVELOPE-SPEC — resposta Xls (`Logon_Results`) que o cliente FM8 aceita

Data: 2026-11-15 · Fonte: **dump de memória em runtime** (`mock-lsp/dump_text.bin`,
imagem `.text`+`.rdata`+`.data` já decifrada pelo loader) + desassembly Capstone 5.0.7.
Nada aqui foi obtido executando o jogo; nenhuma chamada a REA/MCP.

```
file_offset(dump_text.bin) = VA - 0x140001000        (dump cobre 0x140001000..0x145c00000)
base de runtime do módulo  = 0x7ff7d4860000           (dump_extents.json)
r2v(p)  = p - 0x7ff7d4860000 + 0x140000000            (ponteiros/vtables no dump estão RELOCADOS)
```

> **Nota metodológica**: no dump, todos os ponteiros (vtables, `namePtr` dos records,
> ponteiros de field-table) estão com o valor de runtime. Toda leitura de tabela abaixo
> passou por `r2v()`; procurar o VA "absoluto" (0x141c…) no dump **não** acha vtable.
> As field tables de `UserLogonResponse`/`UserData` são estáticas (`.data`), os vtables dos
> stages estão em `.rdata` (0x1449xxxx) — ambos dentro do dump.

---

## 0. TL;DR

1. **O frame de resposta tem 13 bytes, não 12**:
   `[0]=1 byte (não validado)`, `[1..4]=status u32 BIG-ENDIAN`, `[5..8]=code u32 BE`,
   `[9..12]=length u32 BE`, depois o corpo. O leitor exige **exatamente 13 bytes**
   (`FUN_141c093d0`, erro `0x80500043`) e `status` tem de ser **0** (2 = erro).
   *O frame de 12 B usado no mock v2 desloca o corpo em 1 byte → rejeição silenciosa.*
2. **O corpo é o `UserLogonResponse` serializado inline, sem prefixo de tamanho e sem wrapper.**
3. **O mock v2 tem 2 erros de schema que sozinhos já invalidam o corpo**:
   `permissions` é **array (kind 0x16)** de `MethodPermission` — não um bloco nested de
   0x200 bytes zerados; e `userData` tem **17 campos** (não 15: faltam `region` e
   `recentlySeen` no fim). Nested (`kind 0xc`) **nunca** é "zeros do tamanho da struct":
   é a serialização dos campos da tabela dele, em ordem.
4. **Gramática**: scalars **big-endian**, tamanho fixo por kind; string e datetime =
   `u32 BE len` + UTF-8; array = `u32 BE count` + elementos; nested = inline sem prefixo;
   GUID (0x12) = Data1/Data2/Data3 BE + Data4 8 bytes crus.
5. **Key transport**: o cliente embrulha a chave AES de sessão em **RSA-OAEP-2048** com uma
   chave **pública embutida no binário** (`RSA1` blobs @0x14494af60/0x14494b080, e um
   RSA-3072 @0x145a5bcf0). O mock **não tem a privada** ⇒ **se** o stage de decriptação da
   resposta estiver instalado, **não existe caminho de mock possível** (nem cifrado nem em
   claro). Logo: plaintext é a única rota e **precisa ser testada com frame+corpo corretos**;
   se falhar, o fallback é capturar a chave AES em runtime (hook), não RE estática.

---

## 1. Envelope / frame (13 bytes) — cadeia de evidência

### 1.1 Reader (`FormatterIncomingStage`)

`FUN_141c093d0` (file **0x01c083d0**):

```
mov rax,[rdx]                 ; rdx = stream (CMemStream), vtable no 1º qword
mov rcx,rdx                   ; this = stream
lea rdx,[rsp+0x38]            ; dest (13 bytes na pilha)
mov r8d,0xd                   ; <<< 13
lea r9,[rsp+0x20]             ; out: bytes lidos
call [rax+8]                  ; stream->Read(dest,13,&n)
...
mov eax,[rsp+0x20]
sub [rbx],eax                 ; "restante" -= n
cmp eax,0xd
jne  -> 0x80500043            ; ERRO se não leu exatamente 13
lea rcx,[rsp+0x28] ; rdx=&[rsp+0x38]
call 0x141c49770              ; copia 13 B (qword + dword + byte) p/ o objeto
```

`FUN_141c49770` (file 0x01c48770) = cópia crua de 13 bytes (`movsd`+`mov`+`movzx byte`) —
não há conversão de endianness na cópia.

### 1.2 Acessores (provam o layout e o BIG-ENDIAN)

| VA | file | código | significado |
|---|---|---|---|
| `FUN_141c4b7f0` | 0x01c4a7f0 | `mov ecx,[rcx+1]` ; `jmp [0x1439f43c8]` | **status** = ntohl(bytes[1..4]) |
| `FUN_141c4b7e0` | 0x01c4a7e0 | `mov ecx,[rcx+5]` ; `jmp [0x1439f43c8]` | **code** = ntohl(bytes[5..8]) |

`0x1439f43c8` é o slot IAT de **WS2_32 ordinal 14 = `ntohl`**
(`0x1439f4458` = ord 9 = `htons/ntohs`, `0x1439f4478` = ord 8 = `htonl/ntohl`).
Ou seja: os três campos são **network byte order**.

### 1.3 Semântica de status (`FUN_141c093d0` 0x141c09432..0x141c09474)

```
status = ntohl([+1])
status == 0            -> OK (retorna 0; nenhum campo de erro preenchido)
status == 2            -> erro = 0x80510000 | ntohl([+5])
qualquer outro valor   -> erro = 0x8050000e
```
Idêntico à convenção já usada no `server.py` (0 = OK, 2 = falha, `0x8051xxxx`).

### 1.4 Layout final no wire

```
byte 0        : 1 byte  — NÃO é lido por nenhum caminho estático (ver §9); mock usa 0x00
bytes 1..4    : status  (u32 BE)  — 0 = sucesso
bytes 5..8    : code    (u32 BE)  — 0
bytes 9..12   : length  (u32 BE)  — tamanho do corpo (advisory; o stream usa o buffer todo)
bytes 13..    : corpo (= §4/§5)
```

> Por que 13 e não 12: com o frame de 12 B do mock v2 (`00 00 00 00 | 00 00 00 00 | 00 00 04 14`)
> o cliente lê 13 bytes e obtém `status=0` (ok, por sorte), `code=0`, mas o **`length` sai
> `0x000414<1º byte do corpo>`** e o decode começa em **corpo[1]** (1 byte deslocado) →
> erro de parse → retry (~2,5 s). Exatamente o observado em 15/11.

### 1.5 Onde o frame é consumido na pipeline de entrada

```
FUN_141c09520  (FMT_IN.process, file 0x01c08520)
   -> pega Ref<Buffer> do provider (this+0x28)->vtable[0x30]
   -> CMemStream ctor FUN_141c5a810(data,size)
   -> this->vtable[0x40] / [0x48]                ; parse
FUN_141c4ff30  (file 0x01c4ef30)                 ; chamado do parse
   -> call FUN_141c093d0 (lê 13 B)
   -> ctx+0x118 = *status  /  *status = 0
FUN_141c4b6c0  (file 0x01c4a6c0)                 ; propaga status
   status < 0  -> estado 0, notifica nós (vtable[3]) e aborta
   status >= 0 -> estado 5, segue para o decode
FUN_141c481d0  (file 0x01c471d0)
   se ctx+0x118 < 0 -> retorna 0 (sem decode)
   CMemStream sobre o corpo -> vtable[0x40] (decode) -> FUN_141c4fdc0
FUN_141c09390 -> jmp FUN_141c37df0 (file 0x01c36df0) -> FUN_141c30860 (DECODE walker)
```

---

## 2. `FMT_IN process` — `FUN_141c09520` (303 B; file **0x01c08520**)

Não há nenhum parse de header HTTP nem de status aqui: a função

1. pega **dois** `Ref<Buffer>` do provider `[this+0x28]` (vtable `+0x30`),
2. monta `CMemStream {vtable, begin, ptr, size, size}` via `FUN_141c5a810` sobre
   `(data,size)` do buffer,
3. chama `this->vtable[0x40](stream, &out1, &out2)`,
4. se qualquer retorno < 0 → erro; senão `this->vtable[0x48](stream, out1)`.

Consequência prática: **o corpo inteiro é um stream**; o "tamanho" do frame **não** limita o
parse (o decode lê até os records acabarem) → `length` errado **não** quebra o parse por si
só, mas o **deslocamento de 1 byte quebra**.

Frames de erro (o que o cliente faz com eles):

* `0x80500043` leitura do frame != 13 bytes
* `0x8050000e` status fora de {0,2}
* `0x80510000|code` status 2
* `0x80500012` "já existe corpo" (0x141c4fdc0)
* `0x80500054` estado interno ≠ 1 (`FUN_141c24480` — spill em arquivo)

---

## 3. Stages `Decryption` / `Encryption`

### 3.1 `DEC process` — `FUN_141c4ae40` (354 B; file **0x01c49e40**; extents offset 129)

Faz **só plumbing** — nenhuma chamada AES/RSA:

```
rcx = [msg+8]                 ; Ref<Buffer> de entrada (o corpo recebido)
old = [stage+0x20] ; [stage+0x20] = rcx
nova->vtable[1](&stage+0x28)  ; addref
old->vtable[2](&stage+0x28)   ; release
... guardas de escopo (vtable 0x144918f40) ...
new(0x38) -> objeto de resultado {vtable 0x144920370, +8 nome, +0x10 stage,
                                  +0x18 strncpy_s(...,0x20,...) = tag de 32 chars}
-> shared base FUN_141c4a2a0
```
**Não há decrypt inline**: a transformação (se houver) acontece no *provider* que entrega o
`Ref<Buffer>` (o caminho `(*(stage+8))->0xa8`, ver ENC). O DEC **aceita qualquer buffer**,
inclusive plaintext — ele não valida e não decifra. É por isso que "plaintext passa" é uma
hipótese plausível, mas **não** prova nada sobre a etapa anterior (que pode decifrar antes).

### 3.2 `ENC process` — `FUN_141c4afb0` (414 B; file **0x01c49fb0**; extents offset 483)

```
rcx = [msg+8]
if (rcx == 0) { stage+0x48 = 0x80500003; return erro }       ; buffer nulo = erro
adota o buffer em stage+0x20 (addref/release como no DEC)
rax = [stage+8]                 ; contexto/sessão (Ref do ctor)
rcx = [rax+0xa8]                ; << provedor cripto da sessão
rax = [rcx]
rdx = [stage+0x20]              ; o buffer
call [rax+0x30]                 ; (**(sessão+0xa8)+0x30)(buffer)  == CIFRA
```
Portanto: **a cifra do payload não está no stage**, está em `(*(stage+8))->+0xa8`
(`vtable[0x30]` = cifra, `[0x20]` = renegociação/estado, `[0x28]` = gancho de erro).
É a razão do scan de memória não achar instâncias do engine AES auto-implementado no
caminho da mensagem: a chave vive no objeto de sessão/BCrypt handle, não no stage.

### 3.3 Base compartilhada — `FUN_141c4a2a0` (129 B; file **0x01c492a0**; extents offset 0)

```
if ([stage+0x48] >= 0)                        ; sem erro
    (*(stage+0x20))->vtable[0x38]( msg, &Ref{stage+0x50, stage+0x58} )
out = {vtable 0x1446091a8, ptr=stage+0x20 (addref)}
```
= "publica o buffer resultante no próximo nó da pipeline".

### 3.4 Engine cripto (contexto, já conhecido) — reforço

* AES-256-CBC próprio: `FUN_1417d0af0` (S-box @0x1447b6d50, 14 rounds), wrapper
  `FUN_1417ce7b0(ctx,key32,src,len)` (IV zero **naquele** call site).
* RSA-OAEP-2048/3072 via **bcrypt.dll** (IAT 0x1439f4dc8..0x1439f4e48; thunks
  `0x1417ae30e..0x1417ae35c`). `BCryptImportKeyPair` é chamado em **0x141c654ad**,
  `BCryptSignHash`/`VerifySignature` em **0x141c654b3/0x141c654b9** (stage STS).
  Nenhum `BCryptEncrypt/Decrypt` alcançável por E8 → cifra de payload é o engine próprio.

---

## 4. Gramática de **ENCODE** (derivada de `FUN_141c34940`)

Entradas:

| VA | file | papel |
|---|---|---|
| `FUN_141c37e90` | 0x01c36e90 | wrapper: aloca 0x42f8 de pilha, ctx de contagem (vtable `0x14491c150`) e chama `FUN_141c34940` |
| `FUN_141c34940` | 0x01c33940 | **walker de encode** (1119 insns), loop por record |
| `FUN_141c37df0` | 0x01c36df0 | espelho de **decode** (chama `FUN_141c30860`) |
| `FUN_141c36f20` | 0x01c35f20 | arrays (kind 0x16 e 0x17) |
| `FUN_141c376a0` | 0x01c366a0 | string/datetime: `WideCharToMultiByte(CP_UTF8=0xfde9)` + `htonl(len)` + bytes |
| `FUN_141c2f4d0` | 0x01c2e4d0 | "próximo record" (e pop de frames de array) |
| `FUN_141c2f830` | 0x01c2e830 | push de frame de array {elemDesc, dataPtr, count} |

Estado no ctx (mesmos offsets do decode, o que confirma o espelhamento):
`ctx+0x288` = profundidade (limite **0xf**), frame = `ctx+8+depth*0x28`
(`+0 desc, +8 msg, +0x10 ptr do campo, +0x18 record corrente, +0x20 count, +0x24 índice, +0x28 max`),
`ctx+0x42b0` = stream de saída (`vtable+0x10` = write(dst,len)),
`ctx+0x290` = scratch de datetime (wchar).

`write` = `(**stream+0x10)(stream, ptr, len)`; erros: `0x8050000c` (tamanho),
`0x80500004` (ponteiro nulo), `0x8050000f` (profundidade), `0x8050002a` (kind inválido),
`0x80500041` (falha de write).

### 4.1 Tabela de kinds (jump tables `0x141c34f98` e `0x141c34fd4`, file 0x01c33f98 / 0x01c33fd4)

`kind = *(u32*)record`; dispatch primário = `kind-9` (0..0xe: 9..0x17), senão `kind` (0..0x13).

| kind | wire | quem escreve | exemplo |
|---|---|---|---|
| `0` | u8 (1 B) | 0x141c34e10 | `2a` |
| `1` | u16 **BE** | 0x141c34e22 (`htons`) | `00 3c` |
| `2` | u16 **BE** | 0x141c34e3e | `00 3c` |
| `3` | u32 **BE** | 0x141c34e5a (`htonl`) | `00 00 00 3c` |
| `4` | u32 **BE** | 0x141c34e74 | `00 00 00 3c` |
| `7` | u32 **BE** | 0x141c34ea3 | `00 00 00 05` |
| `5`, `6`, `0x13` | u64 **BE** | 0x141c34e8b → `FUN_141c3f2f0` = `bswap64` | `00 09 00 00 09 fe d8 69` |
| `0x11` | 1 B (`cmp byte,0` / `setne`) | 0x141c34eba | `01` |
| `0x12` | **16 B**: Data1 u32BE, Data2 u16BE, Data3 u16BE, Data4[8] cru | 0x141c34eca | `{12345678-..}` → `12 34 56 78 ab cd 00 11 22 33 44 55 66 77 88 99` |
| `0x15` | `u32 BE len` + UTF-8 (len **em bytes**; máx 0x2000; máx do record = nº de *chars* via `FUN_141c25000`) | 0x141c34c3d | `00 00 00 0a 54 65 73 74 44 72 69 76 65 72` |
| `9` | wide string (UTF-16) → mesmo wire do 0x15 | 0x141c34c35 → 0x141c376a0 | idem |
| `0x10` | **datetime como TEXTO**: `u32 BE len` + `"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ"` (formato wide @**0x14491c850**, file 0x0491b850) | 0x141c34d66 → `swprintf` `FUN_1416578a0` → 0x141c376a0 | `00 00 00 18 "2026-11-15T01:02:03.456Z"` |
| `0xc` | **nested inline, sem prefixo**: campos do descriptor do record (`record+0x48`) em ordem, recursivo | 0x141c34b9e | — |
| `0x16` | `u32 BE count` + elementos; `count=0` → só o `00 00 00 00`. Cap 0x2000 (0x500000 se o elemento é `kind 0` = bytes crus) | 0x141c36f20 → 0x141c371af / 0x141c2f830 | `00 00 00 01` + 1 elemento |
| `0x17` | `vector<bool>`: `u32 BE count` + `count` bytes 0/1 (`bt` no bitmap do container) | 0x141c37040 | `00 00 00 03 01 00 01` |
| `0x14` | string "grande" (cap 0x500000) | 0x141c34ce4 | — |
| `8`, `0xa`, `0xb`, `0xd`, `0xf` | **inválido** → `0x8050002a` | — | — |

Detalhes que importam:

* **Array**: o `count` é o número de **elementos** (vem de `container->vtable[0x10]`), não
  bytes — exceto quando o elemento é `kind 0` (aí elemento = 1 byte, coincide).
  Cada elemento é serializado com o descriptor do record `+0x50` (kind/size do elemento);
  a iteração avança o ponteiro em `elemSize` (`FUN_141c2f4d0`: `[r8+0x10] += [elem+0x40]`).
* **String**: sem NUL; `len` = bytes UTF-8 (o mesmo `len` escrito é conferido contra o
  máximo do record em **caracteres**, `FUN_141c25000`).
* **Datetime**: sempre com `.mmm` e `Z` no encoder (o decoder aceita também `±HH:MM`).
* **Nested**: não há "presença", "tamanho" nem id na frente — é posicional puro.
* Não existe prefixo de mensagem (nem tamanho, nem contagem de campos) no topo do corpo.

---

## 5. Schema **verificado** (lido do dump, `r2v` aplicado)

### 5.1 `UserLogonResponse` — descriptor **0x144910420** → tabela **0x145b28af0**,
`count = 31` (file **0x05b27af0**). Ordem da tabela = ordem no wire.

| # | id | kind | nome | size/máx | elemento (record `+0x50`) |
|---|---|---|---|---|---|
| 1 | 0x008 | 0x11 | `isProfileValid` | 1 | — |
| 2 | 0x010 | **0x16** | `permissions` | 512 | `MethodPermission` (0xc, 24 B) |
| 3 | 0x028 | 4 | `featureAreasBanMask` | 4 | — |
| 4 | 0x02c | 4 | `userFlags` | 4 | — |
| 5 | 0x030 | 5 | `upsellOfferId` | 8 | — |
| 6 | 0x038 | 0x15 | `upsellText` | 300 | — |
| 7 | 0x058 | 0x16 | `vipOfferIds` | 16 | `Int64` (kind 5, 8 B) |
| 8 | 0x070 | 0xc | `userData` | 168 | tabela 0x145b110f0 (§5.2) |
| 9 | 0x118 | 0x12 | `SecurityId` | 16 | — |
| 10 | 0x128 | 1 | `notificationNonce` | 2 | — |
| 11 | 0x12c | 3 | `notificationPollIntervalSeconds` | 4 | — |
| 12 | 0x130 | 4 | `defaultFriendsPollIntervalSeconds` | 4 | — |
| 13 | 0x134 | 4 | `maxFriendsPollIntervalSeconds` | 4 | — |
| 14 | 0x138 | 0x16 | `notificationCategories` | 9 | `XlsNotificationCategory` (0xc, 88 B) |
| 15 | 0x150 | 3 | `defaultTimeoutMs` | 4 | — |
| 16 | 0x154 | 3 | `defaultContentTimeoutMs` | 4 | — |
| 17 | 0x158 | 3 | `defaultInGameTimeoutMs` | 4 | — |
| 18 | 0x160 | 0x16 | `makeDiscounts` | 100 | `MakeDiscountData` (0xc, 56 B) |
| 19 | 0x178 | 0x16 | `carDiscounts` | 100 | `CarDiscountData` (0xc, 56 B) |
| 20 | 0x190 | 0xc | `allCarDiscount` | 56 | 5 campos §5.4 |
| 21 | 0x1c8 | 0x16 | `makePartsDiscounts` | 100 | `MakePartDiscountData` (0xc, 56 B) |
| 22 | 0x1e0 | 0x16 | `carPartsDiscounts` | 100 | `CarPartDiscountData` (0xc, 56 B) |
| 23 | 0x1f8 | 0xc | `allPartsDiscount` | 56 | 5 campos §5.4 |
| 24 | 0x230 | 0x16 | `featuredUserEntries` | 10 | `u32` (kind 4) |
| 25 | 0x248 | 0x16 | `pushNotificationTags` | 20 | `PushNotificationTag` (0xc, 40 B) |
| 26 | 0x260 | 0xc | `cmsInformation` | 144 | 5 campos §5.3 |
| 27 | 0x2f0 | 0xc | `availabilityInformation` | 48 | 3 campos §5.5 |
| 28 | 0x320 | 0x15 | `FlightRingId` | 64 | — |
| 29 | 0x340 | 0x10 | `systemTimeUTC` | 16 | — (texto!) |
| 30 | 0x350 | 0x10 | `lastZendeskTicketCreateTime` | 16 | — (texto!) |
| 31 | 0x360 | 0x16 | `banData` | 20 | `UserBanData` (0xc, 152 B) |

### 5.2 `userData` — descriptor **0x1448dae80** → tabela **0x145b110f0**, `count = 17`
(file 0x05b100f0) — **correção** vs notas §8 (que paravam em 15)

| # | id | kind | nome | size |
|---|---|---|---|---|
| 1 | 0x08 | 6 | `qwXuid` | 8 |
| 2 | 0x10 | 0x15 | `wzGamerTag` | 15 |
| 3 | 0x30 | 0 | `flags` | 1 |
| 4 | 0x34 | 0x12 | `clubId` | 16 (GUID) |
| 5 | 0x48 | 0x15 | `clubTag` | 4 |
| 6 | 0x68 | 3 | `clubTopTierCount` | 4 |
| 7 | 0x6c | 4 | `roleInClub` | 4 |
| 8 | 0x70 | 2 | `currentBadgeId` | 2 |
| 9 | 0x72 | 2 | `currentPlayerTitleId` | 2 |
| 10 | 0x74 | 4 | `currentCarCollectionScore` | 4 |
| 11 | 0x78 | 2 | `currentCarCollectionTier` | 2 |
| 12 | 0x7c | 4 | `currentDriverLevel` | 4 |
| 13 | 0x80 | 4 | `currentPrestigeRank` | 4 |
| 14 | 0x84 | 3 | `currentDriverModelId` | 4 |
| 15 | 0x88 | 0x16 | `customizationSlotsV2` | 30 × u32 (kind 4) |
| 16 | 0xa0 | 1 | **`region`** | 2 |
| 17 | 0xa2 | 0x11 | **`recentlySeen`** | 1 |

`size` da struct = 0xa8 = 168 (bate com `userData` no response); campos 16/17 cabem
exatamente depois do container de 0x18 B do array em 0x88 → são parte do `UserData`.

### 5.3 `MethodPermission` — tabela **0x1448ec300**, `count = 4` (13 B no wire)
`{ methodId u32 (0x8), tier u32 (0xc), isEnabled bool (0x10), access u32 (0x14) }`

### 5.4 `allCarDiscount` / `allPartsDiscount` — 5 campos (68 B no wire)
`{ TokenDiscountAmount u32-kind7 (0x8), CreditDiscountAmount u32-kind7 (0xc),
   StartDate datetime (0x10), EndDate datetime (0x20), OfferId u32-kind3 (0x30) }`

### 5.5 `cmsInformation` (5) e `availabilityInformation` (3)
```
cmsInformation : Header 0x15(60) Override 0x15(30) SlotId 0x15(20) SnapId 0x15(20) Version 3(4)
availability   : IsCurrentlyAvailable 0x11(1) NearestWindowOpenTime 0x10 NearestWindowCloseTime 0x10
```
(`XlsNotificationCategory` 88 B, `PushNotificationTag` 40 B, `UserBanData` 152 B e os
discounts por make/car não foram decompostos — para o mock basta **count = 0**.)

### 5.6 Envelope da mensagem
* request (`loginData`): tabela com 2 records — `Response`(id 0, 0xc, {isVip,isUltimateVip
  bools}) e `loginData`(id 0x10, 0xc, 272 B → `UserLogonData`);
* response: tabela com **1 record — `responseData`(id 8, 0xc, 888 B → desc 0x144910420)**;
  logo o corpo do `Logon_Results` = **`UserLogonResponse` cru, sem wrapper**.

---

## 6. Key transport — o que o cliente espera e o que é possível

| fato | evidência |
|---|---|
| Chave de payload = **AES-256-CBC** (engine próprio) ou BCrypt simétrico | `FUN_1417d0af0`, S-box 0x1447b6d50; IAT `BCryptGenerateSymmetricKey` 0x1439f4e30 |
| Chave de sessão viaja **RSA-OAEP** | RTTI `.?AVDecryptKey@Xls@@U_BCRYPT_ctx_iRSADOAEP2048@@` (0x145e77d75) |
| Chave **pública** embutida no binário | `BCRYPT_RSAKEY_BLOB` `"RSA1"` @**0x14494af60** e **0x14494b080** (idênticas, RSA-2048, e=0x10001); e **0x145a5bcf0** (RSA-3072, e=0x10001) |
| Import de key pair / assinatura | `BCryptImportKeyPair` @0x141c654ad, `BCryptSignHash` @0x141c654b3, `BCryptVerifySignature` @0x141c654b9 |
| Renegociação dirigida pelo servidor | header string **`X-Renegotiate`** @0x144920100; `FUN_141c4a830` (file 0x01c49830): HTTP **200..206 → OK**, **418 (0x1a2) → renegociar**, senão `0x8050xxxx` |
| Máquina de estados do `DecryptKey` | `FUN_141c4a600` (nomes) / `FUN_141c4a700` (transições): `Uninitialized, Initialized, Authenticating, Authenticated, RenegotiatedRequired, Renegotiating, FailedRenegotiating, Failed, PermanentFailure`; `[this+0x94]` guarda o estado (5 = autenticado, 6 = renegociando) |
| Header de capacidade | **`X-Encryption`** @0x14494aa58; `FUN_141c59e20` (file 0x01c58e20) monta `std::string("X-Encryption")` + literal `"false"` (0x144a10410) e chama `(obj)->vtable[0x28](&name,&value)` |
| Modo plaintext existe no builder | `FUN_141c07720`: flag de capability (`(**(obj)+8))(obj)`) → `stage+0x60`; e caminho que **pula todo** o bloco timestamp+encryption (`0x141c08058: test bl,bl; jne …`) |

### Veredito

1. **A chave AES do cliente é embrulhada com a pública embutida (RSA-OAEP-2048).**
   O mock **não tem a privada** ⇒ é **impossível** produzir um corpo cifrado que o cliente
   decifre. Não existe "negociar a mesma chave" do lado do servidor.
2. **Se o stage de decriptação estiver instalado no pipeline de entrada, plaintext é a única
   rota — e ela depende do cliente tolerar** (o `DEC process` em si não decifra nem valida:
   ele só adota o buffer; a decifração, se houver, é feita antes, no provider da sessão).
3. O único mecanismo **observável** de "plaintext negociável" no binário é:
   * o `X-Encryption` (o cliente sabe escrever `X-Encryption: false`), e
   * a capability query do builder (o mesmo gate que ligou o ENC no request de 15/11 —
     o corpo veio cifrado, então o gate estava **ligado** ⇒ assume-se que o DEC também).
4. Logo: **o teste de 15/11 foi inválido por dois defeitos independentes** (frame 12 B e
   schema errado). Antes de concluir "precisa cifrar", refazer o teste com §7. Se ainda
   recusar, a rota é **capturar a chave AES em runtime** (hook em `FUN_1417d0af0` /
   `BCryptDecrypt`, ou varredura de heap com verificação de schedule) — não é resolvível
   por análise estática.

---

## 7. Spec concreta do mock (byte-level)

### 7.1 Resposta HTTP

```
200 OK
Content-Type: bin/xtsw
Content-Length: 13 + len(corpo)
(e opcionalmente: X-Encryption: false)
```
Não envie `X-Renegotiate` (dispara renegociação de chaves). Evite status ≠ 200..206.

### 7.2 Corpo

```
corpo = UserLogonResponse (31 campos, §5.1) serializado com §4
frame = 00 | status=00000000 | code=00000000 | length=len(corpo)      (13 B, tudo BE)
resp  = frame + corpo
```

### 7.3 Exemplo mínimo (1 permissão, gamerTag "TestDriver", nível 1) → **469 B de corpo**

```
frame13 : 00 00000000 00000000 000001d5
corpo   : 469 B
   +0x0000     1 B   isProfileValid u8
   +0x0001    17 B   permissions (array, u32BE count=1, 13 B/elem)
   +0x0012     4 B   featureAreasBanMask u32
   +0x0016     4 B   userFlags u32
   +0x001a     8 B   upsellOfferId i64
   +0x0022     4 B   upsellText str
   +0x0026     4 B   vipOfferIds scan
   +0x002a    80 B   userData nested (17 campos)
   +0x007a    16 B   SecurityId guid16
   +0x008a     2 B   notificationNonce u16
   +0x008c     4 B   notificationPollIntervalSeconds u32
   +0x0090     4 B   defaultFriendsPollIntervalSeconds u32
   +0x0094     4 B   maxFriendsPollIntervalSeconds u32
   +0x0098     4 B   notificationCategories count=0
   +0x009c     4 B   defaultTimeoutMs u32
   +0x00a0     4 B   defaultContentTimeoutMs u32
   +0x00a4     4 B   defaultInGameTimeoutMs u32
   +0x00a8     4 B   makeDiscounts count=0
   +0x00ac     4 B   carDiscounts count=0
   +0x00b0    68 B   allCarDiscount nested
   +0x00f4     4 B   makePartsDiscounts count=0
   +0x00f8     4 B   carPartsDiscounts count=0
   +0x00fc    68 B   allPartsDiscount nested
   +0x0140     4 B   featuredUserEntries count=0
   +0x0144     4 B   pushNotificationTags count=0
   +0x0148    20 B   cmsInformation nested
   +0x015c    57 B   availabilityInformation nested
   +0x0195     4 B   FlightRingId str
   +0x0199    28 B   systemTimeUTC datetime
   +0x01b5    28 B   lastZendeskTicketCreateTime datetime
   +0x01d1     4 B   banData count=0
```

Hex do corpo (469 B, exatamente o que o Apêndice A gera):

```
010000000100000001000000000100000000000000000000000000000000000000000000
0000000000000009000009fed8690000000a546573744472697665720000000000000000
000000000000000000000000000000000000000000000000000000000000000000000100
00000000000000000000000000000000000000000000000000000000000000000000003c
0000003c0000003c0000000000000fa00000ea600000ea60000000000000000000000000
0000000000000018313937302d30312d30315430303a30303a30302e3030305a00000018
313937302d30312d30315430303a30303a30302e3030305a000000000000000000000000
000000000000000000000018313937302d30312d30315430303a30303a30302e3030305a
00000018313937302d30312d30315430303a30303a30302e3030305a0000000000000000
0000000000000000000000000000000000000000000000000000000018313937302d3031
2d30315430303a30303a30302e3030305a00000018313937302d30312d30315430303a30
303a30302e3030305a0000000000000018323032362d31312d31355430313a30323a3033
2e3435365a00000018313937302d30312d30315430303a30303a30302e3030305a000000
00
```

### 7.4 Ordem dos experimentos (1 boot por variante; ler o padrão de retry)

| # | variante | sinal de ACEITE |
|---|---|---|
| 1 | frame 13 B + corpo §5 + `permissions` **count=0** | 1× `Logon` e depois `KeepAlive`/`DownloadPlayerProfile`/`UpdatePlayerProfile` |
| 2 | igual, `permissions` = 1 `MethodPermission` (isEnabled=1) | idem |
| 3 | igual a 1 + header `X-Encryption: false` | idem |
| 4 | igual a 1, porém frame 13 B com `byte0 = 0x01` | idem |
| 5 | (controle negativo) frame 12 B — **deve** repetir Logon | prova que o frame é o diferencial |

Se 1..4 recusarem e 5 recusar igual: o bloqueio é cripto (ou um 3º defeito de schema) →
próximo passo é hook de runtime na chave AES, não mais estática.

---

## 8. Divergências vs `XLS-FRAMING-NOTES` / mock v2

| item | notas / mock v2 | dump (verificado) |
|---|---|---|
| frame | 12 B `{status,code,len}` | **13 B**: 1 B + 3×u32 BE; status deve ser 0 |
| `permissions` | kind 0x10, "nested inline 0x200" | **kind 0x16 array** de `MethodPermission` (4 campos, 13 B/elem, máx 512) |
| `userData` | 15 campos | **17** (faltavam `region` u16 + `recentlySeen` bool) |
| nested opaco | "zeros do tamanho declarado" | **nunca**: nested é a serialização dos campos (tabelas recuperadas: cmsInformation 5, availability 3, discounts 5/5, UserData 17, MethodPermission 4) |
| array count | "u32be, provável" | **u32 BE confirmado** (encode `htonl` 0x141c34afc; decode `ntohl` 0x141c32a1e) |
| elemento de array | datetime appendeado cru (README §5.3) | elemento usa o kind do descriptor do elemento (`vipOfferIds` = Int64, não datetime) |
| datetime | texto ISO | confirmado: `u32 BE len` + `%04u-%02u-%02uT%02u:%02u:%02u.%03uZ` |
| GUID (`0x12`) | "16 B blob" | Data1/2/3 em **BE**, Data4 cru (0x141c34eca) |

---

## 9. Riscos residuais (o que ainda pode fazer o Logon falhar)

1. **`byte 0` do frame** — nenhum código estático o lê (o reader valida só a contagem;
   o único acesso ao byte +0xc é a própria cópia de 13 B). Valor 0x00 é o default seguro;
   se a variante 1 falhar e a 4 (0x01) passar, o byte é significativo.
2. **Prefixo de 2 B `{isVip, isUltimateVip}` no início do corpo** — a tabela do *request*
   tem o campo `Response`(id 0) com esse nested; a tabela do *response* que localizei tem
   só `responseData`. Se o cliente usar a mesma tabela para os dois sentidos, o corpo
   correto começa com `00 00`. Teste barato: variante 1 com 2 bytes `00 00` antes de
   `isProfileValid` (corpo +2, `length` +2).
3. **`permissions` vazio** pode fazer o cliente considerar o perfil "sem permissões"
   (`isProfileValid` só diz que o perfil existe). Se a variante 1 parsear mas o fluxo parar,
   preencher `permissions` (methodId/tier/access desconhecidos — copiar de uma captura real).
4. **Nested ainda não decompostos com conteúdo**: `XlsNotificationCategory` (88 B),
   `PushNotificationTag` (40 B), `UserBanData` (152 B), Make/CarPart discounts, e
   `customizationSlotsV2` — manter **count = 0** até precisar.
5. **DEC stage ativo** (§6): se o cliente decifrar o corpo, tudo acima é irrelevante.

---

## Apêndice A — encoder de referência (Python, sem dependências)

```python
import struct
be16=lambda v: struct.pack(">H", v & 0xffff)
be32=lambda v: struct.pack(">I", v & 0xffffffff)
be64=lambda v: struct.pack(">Q", v & 0xffffffffffffffff)
s   =lambda t: (lambda b: be32(len(b))+b)(t.encode("utf-8"))         # kind 0x15 / 9
dt  =lambda t: s(t)                                                  # kind 0x10 (texto)
guid=lambda h: (lambda b: b[0:4][::-1]+b[4:6][::-1]+b[6:8][::-1]+b[8:16])(bytes.fromhex(h))
arr =lambda e: be32(len(e))+b"".join(e)                              # kind 0x16

def method_permission(methodId=0,tier=0,isEnabled=0,access=0):        # 13 B
    return be32(methodId)+be32(tier)+bytes([isEnabled&1])+be32(access)

def user_data(x):                                                     # 17 campos
    return b"".join([
        be64(x.get("qwXuid",0)), s(x.get("wzGamerTag","")), bytes([x.get("flags",0)&0xff]),
        guid(x.get("clubId","00"*16)), s(x.get("clubTag","")),
        be32(x.get("clubTopTierCount",0)), be32(x.get("roleInClub",0)),
        be16(x.get("currentBadgeId",0)), be16(x.get("currentPlayerTitleId",0)),
        be32(x.get("currentCarCollectionScore",0)), be16(x.get("currentCarCollectionTier",0)),
        be32(x.get("currentDriverLevel",1)), be32(x.get("currentPrestigeRank",0)),
        be32(x.get("currentDriverModelId",0)),
        arr([be32(v) for v in x.get("customizationSlotsV2",[])]),
        be16(x.get("region",0)), bytes([x.get("recentlySeen",0)&1]),
    ])

def discount(x):
    return (be32(x.get("TokenDiscountAmount",0))+be32(x.get("CreditDiscountAmount",0))+
            dt(x.get("StartDate","1970-01-01T00:00:00.000Z"))+
            dt(x.get("EndDate","1970-01-01T00:00:00.000Z"))+be32(x.get("OfferId",0)))

def logon_response(c):
    return b"".join([
        bytes([1 if c.get("isProfileValid",True) else 0]),            # 1
        arr([method_permission(**p) for p in c.get("permissions",[])]),# 2
        be32(c.get("featureAreasBanMask",0)), be32(c.get("userFlags",0)),
        be64(c.get("upsellOfferId",0)), s(c.get("upsellText","")),
        arr([be64(v) for v in c.get("vipOfferIds",[])]),
        user_data(c.get("userData",{})),
        guid(c.get("SecurityId","00"*16)),
        be16(c.get("notificationNonce",0)),
        be32(c.get("notificationPollIntervalSeconds",60)),
        be32(c.get("defaultFriendsPollIntervalSeconds",60)),
        be32(c.get("maxFriendsPollIntervalSeconds",60)),
        arr([]),                                                      # notificationCategories
        be32(c.get("defaultTimeoutMs",4000)), be32(c.get("defaultContentTimeoutMs",60000)),
        be32(c.get("defaultInGameTimeoutMs",60000)),
        arr([]), arr([]), discount(c.get("allCarDiscount",{})),
        arr([]), arr([]), discount(c.get("allPartsDiscount",{})),
        arr([be32(v) for v in c.get("featuredUserEntries",[])]),
        arr([]),                                                      # pushNotificationTags
        s("")+s("")+s("")+s("")+be32(0),                              # cmsInformation
        bytes([0])+dt("1970-01-01T00:00:00.000Z")+dt("1970-01-01T00:00:00.000Z"),
        s(c.get("FlightRingId","")),
        dt(c.get("systemTimeUTC","2026-11-15T00:00:00.000Z")),
        dt(c.get("lastZendeskTicketCreateTime","1970-01-01T00:00:00.000Z")),
        arr([]),                                                      # banData
    ])

def frame(body, status=0, code=0, b0=0):
    return bytes([b0]) + be32(status) + be32(code) + be32(len(body))
```

---

## RUNTIME DUMP ANALYSIS (2026-11-15/16)

Análise estática sobre `dump_text.bin` (imagem `.text`+`.rdata`+`.data` **decifrada em
runtime**, 96.464.896 B). `VA = file_offset + 0x140001000`. Ponteiros/vtables no dump estão
**relocados** para a base de runtime `0x7ff7d4860000` → `r2v(p) = p - 0x7ff7d4860000 + 0x140000000`.

Limites do dump: `.text` inteiro (0x140001000-0x1439F25BC) + `.rdata` inteiro
(0x1439F3000-0x1459EEE1C) + só o começo de `.data` (0x145A4F000-0x145C00000 de 0xC4D588).
Logo: vtables/tabelas de `.rdata` estão completas; tabelas construídas em `.data` acima de
0x145C00000 **não** aparecem.

Método de classificação "plaintext vs ciphertext" por função: desmontar as primeiras
instruções; se `cs_disasm` produz `invalid` nos primeiros bytes → a função ainda é
**ciphertext** (Denuvo decifra por função, sob demanda).

### R1. Mapa plaintext/ciphertext do cluster cripto (0x141c50xxx-0x141c590xx)

| VA | file | tamanho | estado | papel |
|---|---|---|---|---|
| `FUN_141c543f0` | 0x01c533f0 | 0x3a1 | **plaintext** | decrypt "2 partes" (entrada de vtable) |
| `FUN_141c53920` | 0x01c52920 | 0x72e | **plaintext** | **RSA-OAEP unwrap do bloco final de 0x100 B** (BCryptDecrypt) |
| `FUN_141c54050` | 0x01c53050 | 0x202 | **plaintext** | **decrypt "buffer único"** (é o que casa com o body de 896 B) |
| `FUN_141c53840` | 0x01c52840 | 0xda | **plaintext** | wrapper de decrypt + validação **PKCS#7** |
| `FUN_141c547a0` | 0x01c537a0 | 0x3d6 | **plaintext** | encrypt "2 partes" (monta IV + chama o cipher) |
| `FUN_141c53040` | 0x01c52040 | 0x1c1 | plaintext | cria o objeto "key blob" (32 B) a partir do material derivado |
| `FUN_141c54ba0` | 0x01c53ba0 | 0x412 | plaintext | **setup das 4 chaves CNG da sessão** + headers |
| `FUN_141c52ad0` / `141c526d0` | 0x01c51ad0 / 0x01c516d0 | 0x1f3 / 0x1fe | plaintext | provider CNG `RSA` + import de **chave privada** (RSAPRIVATEBLOB) |
| `FUN_141c528d0` / `141c52cd0` | 0x01c518d0 / 0x01c51cd0 | 0x1fe / 0x1f3 | plaintext | provider CNG `RSA` + import de **chave pública** (RSAPUBLICBLOB) |
| **`FUN_141c54260`** | 0x01c53260 | 0x182 | **CIPHERTEXT** | córtex AES por parte (CBC) |
| **`FUN_141c535d0`** | 0x01c525d0 | 0x26b | **CIPHERTEXT** | unwrap do bloco 0x100 no caminho "2 partes" |
| **`FUN_141c552f0`** | 0x01c542f0 | 0x204 | **CIPHERTEXT** | pré-processamento do bloco RSA (ver R3.3) |
| **`FUN_141ada800`** | 0x01ad9800 | — | **CIPHERTEXT** | **núcleo AES-CBC decrypt** (recebe key blob em ctx+0x148) |
| `FUN_141c5bf20`+ | — | — | plaintext | helper de hash CNG (SHA) |

Conclusão do mapa: **a estrutura do envelope é 100% recuperável; os 4 primitivos
(AES encrypt/decrypt e os dois passos RSA auxiliares) continuam ciphertext** — eles nunca
executaram nesse boot (o dump é anterior a qualquer Logon enviado *nessa* sessão).

### R2. Q1 — quem chama o cipher real

**AES-256-CBC "engine" (`FUN_1417d0af0` / wrapper `FUN_1417ce798`, file 0x017cd798) NÃO é o
cipher de mensagem.** Cadeia completa:

```
FUN_1417d0af0 (AES-256-CBC encrypt, S-box 0x1447b6d50, inv-S-box 0x1447b6e50, rcon 0x1447b6f50)
  <- E8 0x1417ce834  (FUN_1417ce7b0: alloc len+0x20, memcpy, IV -> schedule+0xf0, cifra, SRWLock)
       <- 0 refs
FUN_1417ce798 (mesmo, mas IV = this+0x120, o "random per-instance")
  <- E8 0x1417b3506, 0x1417b3732, 0x1417b384a, 0x1417b3921
     (todos dentro de FUN_1417b3410 / FUN_1417b32e0 = "ctor/assign de blob a partir de wstring")
```
Ou seja: o engine é o **obfuscador de blobs/strings em memória** (objeto 0x168 B:
key@+0x000, schedule@+0x020, random@+0x120, SRWLock@+0x140, blob cifrado@+0x148/len@+0x158).
Isso explica o scan de memória que não achou nenhum "schedule" válido: **o caminho de mensagem
não usa esse engine**.

**Cipher de mensagem = rotinas próprias do Xls (0x141c5xxxx)**, com hash/AES/RSA via CNG:

| chamada | call sites (E8) |
|---|---|
| `BCryptOpenAlgorithmProvider` (thunk 0x1417ae310, file 0x017ad310) | 0x141c526d0, 0x141c52ad0, 0x141c528d0, 0x141c52cd0 (os 4 ctors de provider), 0x141c5c0bc (hash) |
| `BCryptImportKeyPair` (thunk 0x141c654af, file 0x01c644af) | 0x141c5283c, 0x141c52a3c, 0x141c52c31, 0x141c52e31 (os mesmos 4 ctors) |
| **`BCryptDecrypt`** (thunk 0x1417ae32e) | **0x141c53aa7 e 0x141c53aff** (unwrap RSA-OAEP da resposta) |
| **`BCryptEncrypt`** (thunk 0x1417ae328) | **nenhum** — o encrypt de payload é a rotina própria 0x141c54260 |
| `BCryptCreateHash/HashData/FinishHash` | 0x141c5bfc5 / 0x141c5bfdc / 0x141c5bff3 |
| `BCryptSignHash` / `VerifySignature` (thunks 0x141c654b5/bb) | nenhum call site (usados só pelo stage STS via vtable) |

Strings de tipo de blob: `"RSA"` @0x1449210e8, `"RSAPUBLICBLOB"` @0x1449210f0 (file 0x049200f0),
`"RSAPRIVATEBLOB"` @0x144921110 (file 0x04920110).

### R3. Q2 — provider de sessão, layout do body, condicionalidade

#### R3.1 A classe e os entry points

A classe "transform de mensagem" tem duas sub-vtables em `.rdata`
(base `0x144920fe8` e `0x144921028`), com:

| slot | VA | papel |
|---|---|---|
| +0x00 | `FUN_141c543f0` | decrypt "2 partes" (usado pelo stage DEC) |
| +0x08 | `FUN_141c53920` | RSA-OAEP unwrap do bloco de 0x100 B no fim do buffer |
| +0x10 | `FUN_141c54b80` | getter (`[this+0x10]+0x260`) |
| +0x40 | `FUN_141c547a0` | **encrypt** "2 partes" |
| +0x48 | `FUN_141c54050` | **decrypt "buffer único"** |
| +0x50 | `FUN_141c54b90` | getter |

O stage (família `FUN_141c4a1a0`/`141c4ae40`/`141c4afb0`) só faz plumbing:
`(*(stage+8))->[+0xa8]` → object → `vtable[0x30]` → chega nesta classe. *(O mapeamento
exato stage→slot não foi fechado: a vtable da classe tem stubs em +0x30/+0x38; os 4 entry
points acima são os únicos caminhos de mensagem e todos exigem o bloco RSA final.)*

#### R3.2 Layout do corpo (derivado de `FUN_141c54050`, o caminho que casa com 896 B)

```
FUN_141c54050(ctx, Ref<body>, ...) :
  0x141c54086  cmp size, 0x110 ; jb -> erro 0x80500060     ; mínimo 272 B
  0x141c54136  IV    = body[0..16)                          ; copiado verbatim
  ct    = body[16 .. size-0x100)                           ; AES-CBC, múltiplo de 16
  0x141c539e3 / 0x141c54101  RSA = body[size-0x100 .. size) ; 256 B no FIM
  0x141c54198  call FUN_141c53840(aes_ctx=ctx+0x20, IV, ct, ...)  ; decrypt + PKCS#7
```
No caminho "2 partes" (`FUN_141c53920` + `FUN_141c543f0`) o bloco RSA também está no fim:
`0x141c53982  lea rsi,[rax-0x100]` → `src = body + (size-0x100)`, e o mínimo é `size >= 0x200`.

PKCS#7 confirmado: `FUN_141c53840` (0x141c538c6-0x141c538e0) compara os últimos 16 bytes
(`pad = len-16`, todos iguais ao último byte).

**Para o body de request de 896 B**: `16 (IV) + 624 (ct, 39 blocos) + 256 (RSA) = 896` ✓.

Espelho do lado **encrypt** (`FUN_141c547a0`, file 0x01c537a0) — mostra que o request usa
**um campo extra de 16 B** que o parser de resposta não tem:

```
0x141c548d1  rdi = [this+0x50] (= session+0x238, o IV) ; ebx = 16
0x141c548ec  memcpy(out, IV, 16)                 ; out[0..16) = IV
0x141c54900  rand() x16 -> [rbp-1]               ; (CRT rand, 16 B)
0x141c54921  movups [out+16], xmm0               ; out[16..32) = 16 B aleatórios
0x141c54988  FUN_141c54260(cipher=[this+0x20], iv=&[rbp-1], ...)   ; cifra a partir de 32
0x141c54a8f  FUN_141c550d0(...)                  ; bloco RSA no fim
```
⇒ request: `[IV 16][rand 16][ct][RSA 256]` (896 ⇒ ct = 608 = 38 blocos);
resposta (parser `FUN_141c54050`): `[IV 16][ct][RSA 256]` (sem o campo de 16 B).
Os dois caminhos existem porque requests e responses usam *shapes* diferentes.

#### R3.3 O que a decifração da resposta usa (e a chave)

`FUN_141c53920` (file 0x01c52920) — plaintext, sequência exata:

```
size = body->size ; if (size < 0x200) erro
0x141c5399b  keyA = [[this+0x10]+0x1a8]        ; slot +0x1a0 (chave PÚBLICA do servidor)
0x141c539e3  FUN_141c552f0(keyA, body, size-0x100, body+size-0x100, 0x100)   ; pré-passo (ciphertext)
0x141c53a1c  keyB = [[this+0x10]+0x178]        ; slot +0x170 (chave PRIVADA do cliente)
0x141c53a59  [keyB+0x50] = 0x143d7d668         ; BCRYPT_OAEP_PADDING_INFO.pszAlgId = L"SHA1"
             [keyB+0x58] = 0 (pbLabel) ; [keyB+0x60] = 0 (cbLabel)
0x141c53a87  [rsp+0x48] = 4                    ; BCRYPT_PAD_OAEP
0x141c53aa7  BCryptDecrypt(hKey, blob=body+size-0x100, 0x100, &oaepSHA1, ..., out, 0x100, &outlen, 4)
0x141c53aff  BCryptDecrypt(... 2ª chamada, out=&[rbp+0x90])
0x141c53b43  cmp [rsp+0x50], 0x40 ; jne erro   ; <<< o plaintext OAEP tem de ter EXATAMENTE 64 B
```
Depois dos 64 bytes (`[rbp+0x90..0xd0]`):

```
IVA = pt[0..16)                                     ; 0x141c53b4e-0x141c53b55
KEY[i] = pt[0x10+i] ^ crypto[0x20+i]  (i=0..31)      ; 0x141c53b70..0x141c53d9a (XOR desenrolado)
0x141c53dbb  FUN_141c53040(&[rbp+0x68], 0x20, &ref)  ; cria key blob de 32 B
0x141c53dd9  [session+0x208] = keyRef                ; <<< CHAVE AES-256 da sessão
0x141c53e55  [novo buffer 16 B] = pt[0..16)          ; IV
0x141c53e63  [session+0x238] = ivRef                 ; <<< IV da sessão
```
Ou seja, os 64 bytes do RSA-OAEP são: **IV (16 B, verbatim) + chave AES-256 (32 B, XOR com
32 B do estado do objeto) + 16 B de sobra**.

#### R3.4 Condicionalidade — onde o flag é lido (não há gate por header)

Builder do pipeline `FUN_141c07720`:

```
0x141c07d28  bl = ( *(u32*)0x144918b1c != [rbp-0x80] )     ; um "modo" global (0x141b80f60 = cmp dword/setne)
0x141c07d4f  FUN_141c2e060(...)  -> serializa o body em [rbp-0x70]   (two-pass do encoder)
0x141c07f4b  r12b = ( body->vtable[1]() != 0 )              ; "body não vazio"
0x141c08058  test bl,bl ; jne 0x141c081f6                   ; se bl!=0 PULA todo o bloco timestamp+encryption
0x141c080ae  -> stage TimestampHeader (FUN_141c08b50)
0x141c08140  session->vtable[0x48](...)  -> Ref (objeto de crypto)
0x141c08172  FUN_141c4a1a0(&stage, Ref, r12b)               ; ENC stage: SEMPRE adicionado se bl==0
```
Não existe leitura de `X-Encryption` (nem de nenhum header de resposta) nesse caminho.
`FUN_141c59e20` (o que monta `X-Encryption: "false"`) está em vtables em 0x14494aaa0/0x14494aae0,
mas **nenhuma captura de request teve esse header** e o teste 5 (7 variantes, incluindo
`X-Encryption: false`) falhou igual → esse knob não é honrado pelo cliente nesta build.

Capability que "liga" o ENC: **não vem de config baixada**; é o par
`(modo global != default)` **e** `(body serializado não vazio)`. O que é negociado em runtime
é a **chave**, pela FSM (R5).

### R4. Q3 — de onde vem a chave de sessão e onde ela mora

**Descoberta que muda o veredito anterior (corrige §6/TL;DR.5 desta spec):** o cliente tem
**par RSA-2048 privado embutido no binário**:

* `BCRYPT_RSAPRIVATE_BLOB` (magic `'RSA2'`) @**0x1449209a0** (file 0x0491f9a0) e duplicata
  @**0x144920bd0** — **542 B (0x21e)**: header 24 + e(3) + n(257) + p(129) + q(129); 2048-bit,
  `e=0x00010001`, `n = 00b3854ed10bbb6a996f488d9fed8660...` (257 B, com 0x00 inicial).
* `BCRYPT_RSAPUBLIC_BLOB`/`RSA1` @**0x14494af60** (file 0x04949f60) e @**0x14494b080**
  (duplicatas, mesmo `n = 00d01ec7266b2485b9f0be6bd18ef085...`) = chave **pública do servidor**.

Setup (chamado de 0x141ba596b):

```
FUN_141c54ba0(session, blobPtr, blobLen, ...):
  +0x140  FUN_141c52ad0( RSA2 @0x1449209a0 )  -> provider "RSA" + ImportKeyPair(RSAPRIVATEBLOB)
  +0x170  FUN_141c526d0( RSA2 @0x144920bd0 )  -> provider "RSA" + ImportKeyPair(RSAPRIVATEBLOB)
  +0x1a0  FUN_141c52cd0( RSA1 @0x14494b080 )  -> provider "RSA" + ImportKeyPair(RSAPUBLICBLOB)
  +0x1d0  FUN_141c528d0( RSA1 @0x14494af60 )  -> provider "RSA" + ImportKeyPair(RSAPUBLICBLOB)
```
Cada slot é um objeto 0x30 B: `{vtable, +8 = handle CNG, ...}` → a chave usada em
`BCryptDecrypt` é `[[session+0x170]+8]`.

Direção do tráfego:

* **request**: `FUN_141c550d0` (0x141c54a8f) embrulha com a **pública do servidor**
  (`key = [[ctx+0x8]+0x1a8]`, slot +0x1a0) → bloco de 0x100 B no fim do body.
* **response**: `FUN_141c53920` desembrulha com a **privada do cliente** (slot +0x170) →
  os 64 B de key material (R3.3).

Onde a chave fica em memória (para scan/hook futuro):

| dado | local |
|---|---|
| chave AES-256 da sessão (32 B) | `session+0x208` (Ref<blob>; blob alocado por `FUN_141c53040`) |
| IV da sessão (16 B) | `session+0x238` (Ref<blob>) |
| chave efetiva usada pelo AES | `aes_ctx+0x148` (+len `+0x158`), lock em `aes_ctx+0x288`; `aes_ctx` = `crypto+0x20` |
| handles CNG (não exportáveis) | `session+0x140/+0x170/+0x1a0/+0x1d0` (+8 = handle) |

**Não existe `BCRYPT_KEY_DATA_BLOB` ('KDBM')** nem schedule AES-256 em claro no objeto de
mensagem: as chaves simétricas vivem como blob opaco + handle CNG. Portanto um scan deve
procurar **o objeto de contexto** (ponteiro para objeto 0x2a0 com lock em +0x288 e blob em
+0x148) ou, mais simples, **hookar** `FUN_141c54260` / `FUN_141ada800` / `BCryptDecrypt`
para capturar (key, iv) do tráfego real.

### R5. Q4 — FSM `DecryptKey`

`FUN_141c4a600` (nomes de estado) e `FUN_141c4a700`+ (transições), estado em `[this+0x94]`:

```
0x141c4a980  switch ([this+0x94]) 0..8
0x141c4aaa0  ação "negociar": monta msg (obj 0x38, nome 0x20 via strncpy_s),
             envia por [this+0x18]->vtable[8], guarda resposta em [this+0x60];
             se resposta != 0 -> [this+0x90]=2, estado=4 ; senão estado=1
0x141c4ac80  ação "renegociando" (mesma forma, outra mensagem)
0x141c4a830  checagem de status HTTP:
             eax = (*(hdr))->vtable[0x28]()          ; status HTTP
             se (eax == 0x1a2 /*418*/) OU header "X-Renegotiate" (@0x144920100):
                 se estado == 5: [[this+0x80]]->vtable[0x20]()  ; reset do material de chave
                                 estado = 6 (Renegotiating)
             aceita 200..206; 0xc8..0xce -> sucesso; senão 0x8050xxxx
```
**Não há caminho que force plaintext na resposta.** O servidor só pode (a) responder 418 ou
mandar `X-Renegotiate` para pedir renegociação de chave, ou (b) responder cifrado. O que o
teste 5 viu (418 → pausa de 53 s → retries cifrados) é exatamente: estado 5→6, o cliente
manda a mensagem de negociação, não consegue resposta válida e volta a tentar com a chave
antiga.

### R6. VEREDITO prático

**O mock CONSEGUE responder de forma aceitável — mas não com dados 100% estáticos.**
Diferente da conclusão anterior ("impossível sem a privada"), a privada do **cliente** está
no binário; o que falta é o **mask de 32 B** aplicado ao material de chave, que vive no estado
vivo da sessão (`crypto+0x20..+0x40`).

Receita exata (validável com uma leitura de memória ou com o re-dump descrito abaixo):

```
1. plaintext P = frame13 (00 | 00 00 00 00 | 00 00 00 00 | len BE) || UserLogonResponse (spec §5)
   P = PKCS#7(P)                                  ; múltiplo de 16
2. K   = 32 bytes aleatórios                      ; chave AES-256 da RESPOSTA (o cliente aceita qualquer uma)
   if mask != 0: K = K_escolhida ^ mask           ; <<< mask = 32 B em crypto+0x20 (runtime)
3. ct  = AES-256-CBC(key=K, iv=IV, P)             ; IV = 16 bytes aleatórios
4. W   = RSA-OAEP(SHA1, client_pub, IV || K || 16 bytes)         ; 64 B de plaintext, 256 B de saída
5. body_resposta = IV || ct || W                  ; tamanho = 16 + |ct| + 256
6. frame de transporte? NÃO: o frame13 já vai DENTRO do ciphertext (o cliente decifra e só então lê os 13 B)
```
Para o body de Logon de 469 B (spec §7.3): `P = 13 + 469 = 482` → padding 14 → `ct = 496` →
`body = 16 + 496 + 256 = 768` bytes; `Content-Length: 768`.

**Efeito colateral importante (a favor do mock)**: ao desembrulhar com sucesso, o cliente
**grava a chave e o IV que vieram na resposta** em `session+0x208` / `session+0x238`
(0x141c53dd9 / 0x141c53e63) — e o caminho de *encrypt* lê exatamente esses dois campos
(0x141c547df, 0x141c54813). Ou seja: **a resposta do mock passa a definir a chave de sessão
dos requests seguintes** (rollover). Consequência prática: basta acertar *uma* resposta
(cifrada com uma chave escolhida pelo mock) para que o mock passe a **decifrar todos os
requests seguintes** com a mesma chave/IV — e isso também é o sinal definitivo de aceite.
É coerente com o observado no teste 5: com o unwrap falhando, a chave nunca rotaciona e o
cliente segue com a antiga (por isso os retries continuaram cifrados).

Chave pública do cliente (extraída do blob RSA2, pronta para uso):

```
n = 00b3854ed10bbb6a996f488d9fed8660080d79b44cc1c829ec530a525ead8c4b1bff59ac5a089e601131f96908eea0ecf35aad668595669dcf8051ba1d681a936a76a828afafe6c32c4becda97f6f9abd984334e0dea2b112e0d3c1c5690c6eba6befe5434c27ec12e08b4ecd596c7c80e72f886a3c56224e2b86009de34910f18898a8a340931e07d901652b7081bd6033e6db132b5822ec49b8fdfb977fbbccdb6c747e0636f5956da66d819de3b62c5ebf19c8ea3f19db43a15bac774988ecea751e28381853e72685109bbfc99ab2c191a3af4f78d122b2d4b429e0f2c4ae4567ac2f617873f82211612d9f45b206d507b1daebc94f7610d0e1587903bfeab
e = 0x10001
BCRYPT RSAPUBLICBLOB (276 B) =
  5253413100080000030000000101000001000100b3854e...0bfeab
```
(para `cryptography`: `RSA.construct(n=int(n_hex,16), e=65537)` com `n_hex` sem o `00` inicial.)

O que ainda é incógnita e como fechar em **1 boot**:

1. **`mask`** (`crypto+0x20..+0x3f`, 32 B). Primeiro teste: assumir `mask = 0`. Se o cliente
   recusar com o código de erro certo (ver abaixo), ler os 32 B do processo (ReadProcessMemory,
   como o `dumper.py` já faz) ou hookar `FUN_141c53920` pós-`BCryptDecrypt` (os 64 B estão em
   `[rbp+0x90]`).
2. **`FUN_141c552f0`** (ciphertext) — pré-passo antes do BCryptDecrypt em `0x141c539e3`.
   É chamado também em `FUN_141c54050` (`0x141c54101`) antes do AES. Se ele validar algo do
   bloco RSA (ex.: comparar com a chave pública do servidor em +0x1a0), o mock pode precisar
   satisfazer essa condição (possível: usar o mesmo valor de 0x100 B de um request real).
3. Re-dump **depois** de o cliente ter enviado pelo menos um Logon: `0x141c54260`,
   `0x141c535d0`, `0x141c552f0`, `0x141ada800` estarão **plaintext** e fecham 100% da receita
   (inclusive o algoritmo e o mask).

Sinais de diagnóstico (para não repetir a ambiguidade do teste 5):

| código | origem | significa |
|---|---|---|
| `0x80500060` | 0x141c5422b (em `FUN_141c54050`) | body < 0x110, ou `FUN_141c552f0` falhou |
| `0x80510002` | 0x141c53b13 (`FUN_141c53920`) | OAEP ok mas plaintext != 64 B / BCryptDecrypt falhou |
| `0x80500043` | `FUN_141c093d0` | frame interno (pós-decrypt) != 13 B |
| `0x8050000e` | `FUN_141c093d0` | status do frame != 0/2 |
| `0x80500063` | 0x141c538bb (`FUN_141c53840`) | ct < 16 ou **PKCS#7 inválido** |
| `0x80070057` | 0x141c538e4 | tamanhos inconsistentes no decrypt |
| `0x80500057` | 0x141c54b51 (`FUN_141c547a0`) | (lado encrypt) body/chave nulos |

### R7. Correções que esta análise impõe ao restante da spec

1. **TL;DR.5 / §6 "o mock não tem a privada"** → *desatualizado*. A privada do **cliente** está
   embutida (0x1449209a0 / 0x144920bd0). O mock precisa da **pública do cliente** (acima) para
   embrulhar, e da **mask** de 32 B do estado vivo.
2. **§3.1 "DEC não decifra"** → confirmado no stage, mas o *provider* por trás dele
   (`FUN_141c54050`/`FUN_141c53920`) **decifra incondicionalmente**: IV do corpo + AES-CBC +
   PKCS#7 + RSA-OAEP-SHA1 no fim. Plaintext nunca passa (teste 5 confirmou).
3. **"frame 13 B + body cru"** só vale *depois* de decifrar: o `frame13` vai **dentro** do
   ciphertext, e o body no fio é `IV || ct || RSA256`.
4. **"resposta menor que 272 B"** é impossível para uma resposta cifrada (mínimo do parser).

---

## RUNTIME DUMP ANALYSIS II (dump 2 — extents 2026-11-16)

### D0. Reprodução (comandos e exit codes)

Scripts novos em `%TEMP%\opencode\` (`ext2.py` = loader dos extents + disassembler anotado,
`diag_ext.py`, `diag2.py`, `scan_code.py`, `diff_ext.py`, `cites.py`, `grep20.py`,
`calls_k.py`). Todos rodaram com **exit code 0**:

```
python diag_ext.py    -> exit 0   (entropia, comparação com dump_text, busca byte-a-byte)
python diag2.py       -> exit 0   (procurar prologues/CC-runs, janelas no dump_text)
python scan_code.py   -> exit 0   (varredura "início de stream válido" por offset)
python diff_ext.py    -> exit 0   (segmentação DIFF/SAME por bloco de 16 B + disasm de cada lado)
python cites.py       -> exit 0   (janelas de instruções citadas abaixo)
python grep20.py      -> exit 0   (procura de stores em [reg+0x20]/[reg+0x28] no cluster)
python calls_k.py     -> exit 0   (lista de call/jmp em 0x141c65b90 e 0x141ada800)
```
Não foram modificados `dump_text.bin`, `dump_extents.bin` nem `dumper.py`.

### D1. ACHADO BLOQUEANTE: os 4 extents novos continuam **CIPHERTEXT**

O dump 2 leu 0x600/0x400/0x400/0x800 bytes a partir dos 4 VAs corretos, mas **só as
funções vizinhas (já conhecidas) vieram em claro**. As 4 funções-alvo continuam cifradas:

| extent | alvo (VA) | bytes cifrados (DIFF) | resto = SAME (idêntico ao dump_text) | entropia |
|---|---|---|---|---|
| 1 | `0x141c54260` | **0x141c54260..0x141c543f0 (0x190)** | 0x141c543f0..0x141c54860 | 6.527 |
| 2 | `0x141c535d0` | **0x141c535d0..0x141c53840 (0x270)** | 0x141c53840..0x141c539d0 | 7.410 |
| 3 | `0x141c552f0` | **0x141c552f0..0x141c55500 (0x210)** | 0x141c55500..0x141c556f0 | 7.283 |
| 4 | `0x141ada800` | **0x141ada800..0x141ada9e0 (0x1e0)** | 0x141ada9e0..0x141adb000 | 6.023 |

Três provas independentes de que **não** é erro de mapeamento:

1. Em cada extent, a região "SAME" é **byte-a-byte idêntica** ao `dump_text.bin` no mesmo VA
   (`diag_ext.py`); com `delta`/base errados nada casaria.
2. O limite DIFF→SAME cai **exatamente** no início da próxima função conhecida
   (0x141c543f0 = `push rbp; lea rbp,[rsp-0x18]; sub rsp,0x118`; 0x141c53840 =
   `48 89 5C 24 08`; 0x141c55500; 0x141ada9e0) → unidade de cifra = função (Denuvo, granular
   por extent de `.pdata`), exatamente o padrão de dump 1.
3. No início de cada alvo o Capstone produz **zero instruções válidas** (primeiro byte
   inválido em x64: `d5`/`06`/`37`/`60`(=pushad)) e os bytes **diferem** dos do dump 1 no
   mesmo VA nas mesmas posições (ex.: 0x141c54260 dump1 `d5 69 71 8a…` vs dump2
   `d5 69 43 8b…`) ⇒ cifra **re-chaveada por boot**, não conteúdo novo.

Conclusão: o loader **re-protege** a página quando a função "esfria"; essas 4 só rodam
durante o handshake RSA do `Logon` (e no caminho de resposta). Este dump foi tirado com elas
frias. **Não é possível responder 1–6 por dentro dessas funções**; o que segue é derivado
100% dos *callers* em claro (que são suficientes para quase tudo) e está marcado com o grau
de certeza.

### D2. Q1 — o que é `FUN_141c552f0`

Tem **exatamente 2 call sites**, ambos em claro:

```
; rota A (0x141c54050), 0x141c540a4..0x141c54101
0x141c540a4  mov  rcx, [rbp+8]          ; this (+8 = sessão nesta sub-vtable)
0x141c540b4  mov  rcx, [rcx+0x1a8]      ; <<< key object = slot +0x1a0 (RSA PÚBLICA)
0x141c540c0  mov  byte [rsp+0x68], 0    ; guard de Ref
0x141c540d6  rax = [r15] ; call [rax]   ; ptr = body->data()
0x141c540de  ebx = esi (= size-0x100) ; rbx = ptr + esi
0x141c540ee  mov  dword [rsp+0x20], 0x100
0x141c540f6  mov  r9, rbx               ; dest = body + size - 0x100   (in place)
0x141c540f9  mov  r8d, esi              ; len  = size - 0x100
0x141c540fc  mov  rcx, [rsp+0x60]       ; key object
0x141c54101  call FUN_141c552f0
0x141c54106  test al, al
0x141c54126  test bl, bl ; jne 0x141c5422b   ; -> 0x80500060 : ABORTA

; rota B (0x141c53920), 0x141c5399b..0x141c539e3  — convenção IDÊNTICA
0x141c5399b  rcx = [[this+0x10]+0x1a8]  ; mesma chave pública
0x141c539d1  [rsp+0x20] = 0x100
0x141c539d9  r9  = body + (size-0x100)  ; dest in place
0x141c539dc  r8d = size-0x100           ; len
0x141c539e3  call FUN_141c552f0
```

Assinatura real:

```
bool FUN_141c552f0(keyObj *, const void *body, uint32_t prefixLen,
                   void *tail /* body+prefixLen */, uint32_t tailCap /*0x100*/)
      rcx = keyObj (slot +0x1a0 = BCRYPT "RSAPUBLICBLOB", chave do SERVIDOR)
      rdx = body   r8d = size-0x100   r9 = body+size-0x100   [rsp+0x20] = 0x100
```

Respondendo direto:

* **Não é plumbing.** Lê os `size-0x100` bytes da frente e **escreve 0x100 bytes no fim**
  (dest == tail, in-place). Ou seja: o bloco final é **função de todo o corpo** (MAC /
  assinatura / derivação), não um campo livre.
* **É obrigatório nas duas rotas**: retorno `false` ⇒ `0x80500060` e **o AES nunca roda**
  (é um *gate*: path A 0x141c54106→0x141c5422b; path B 0x141c539e8→0x141c53a0e/0x141c54017).
* **Não comprime e não prefixa header**: o AES continua consumindo
  `ct = body[16 .. size-0x100)` intacto (path A: `esi = size-0x100` em 0x141c5409b e
  `0x141c5414a lea rsi,[rax-0x110]` para o tamanho do ct) e o IV continua sendo
  `body[0..16)` (0x141c54136). Nada é inserido/removido do plaintext.
* **Internos desconhecidos** (corpo cifrado). A convenção (chave **pública**, entrada =
  prefixo inteiro, saída = tail de 0x100, in place) indica operação **pública**
  (verify/derive) e **amarra o tail ao prefixo** — mas veja a contradição em D7.6: na rota B
  o mesmo tail também é desembrulhado com a chave privada.

### D3. Q2 — identidade das outras três

| VA | vtable slot | papel |
|---|---|---|
| `FUN_141c54050` | +0x48 | **Rota A — "whole buffer" (resposta/referência)** |
| `FUN_141c53920` | +0x08 | **Rota B passo 1 — "key roll" (unwrap OAEP + troca de chave)** |
| `FUN_141c543f0` | +0x00 | Rota B passo 2 — decifra as "2 partes" com a chave nova |
| `FUN_141c54260` | — | córtex CBC por parte (`cipher(ctx=[this+0x20], iv, kind, src, len, destOffset, extra, &out)`) |
| `FUN_141ada800` | — | folha **AES-CBC decrypt** (`rcx = keyobj+0x148`, `rdx = IV`, `r8d = len`, `r9 = src`, `[rsp+0x20] = dst`), chamada só por `FUN_141c53840` |
| `FUN_141c535d0` | — | unwrap do tail 0x100 no caminho "2 partes" |
| `FUN_141c53840` | — | wrapper: lock (`keyobj+0x288`), chama AES, **valida PKCS#7** |
| `FUN_141c53040` | — | ctor do key blob da sessão: aloca 0x2c8, exige **len == 0x20** (AES-**256**), expande em `obj+8` via `FUN_141c65b90` (0x140 bytes) |

`FUN_141c65b90` (expansão de chave, 0x141c65b90, **em claro**) não chama nenhum thunk de
`bcrypt` (só `memset`/`memcpy`/0x141c67ad0/0x141c660c0/0x141c661b0) ⇒ a cifra simétrica da
mensagem é **AES próprio** (não CNG); CNG é usado só para RSA (import de chaves,
`BCryptDecrypt` do OAEP) e para hashes.

### D4. Q3 — layout de RESPOSTA vs REQUEST (confirmado e refinado)

**Rota A — parser `FUN_141c54050`** (o caminho "simples", casa com 896 B):

```
0x141c54086  if (size < 0x110) -> 0x80500060        ; mínimo 272 B
0x141c54101  GATE FUN_141c552f0(publicKey, body, size-0x100, body+size-0x100, 0x100)
0x141c54136  IV  = body[0..16)                      ; copiado p/ [rsp+0x88], verbatim
0x141c5414a  ctLen = size - 0x110
0x141c54198  FUN_141c53840(aes=[this+0x20], iv=&[rsp+0x88], dst=alloc(ctLen), ...)
                -> FUN_141ada800(...) -> P K C S # 7
```
⇒ `[IV 16][ct (size-0x110)][RSA 0x100]`; `ct` tem de ser **>= 16** (`0x141c538c6 cmp ebx,0x10`)
e múltiplo de 16; PKCS#7 tem de ser válido (senão `0x80500063`, 0x141c538bb).

**Rota B — `FUN_141c53920`** (mínimo `0x200` = 512, `0x141c5396d`):

```
tail = body + (size-0x100)
0x141c539e3  GATE FUN_141c552f0(publicKey, body, size-0x100, tail, 0x100)
0x141c53a59  OAEP info = {"SHA1", NULL, 0}   @0x143d7d668
0x141c53a87  [rsp+0x48] = 4 (BCRYPT_PAD_OAEP)
0x141c53aa7/0x141c53aff  BCryptDecrypt(PRIVATE key slot +0x170, tail, 0x100, ...)
0x141c53b43  if (plainLen != 0x40) -> 0x80500060      ; <<< 64 B exatos
0x141c53b4e  IV = pt[0..16)
0x141c53b70  K[i] = pt[0x10+i] ^ mask[i]  (i<32)
0x141c53dd9  session+0x208 = keyBlob(32 B)            ; roll da chave AES-256
0x141c53e63  session+0x238 = IV(16 B)
```

**Nuance do caminho "2 partes" (`FUN_141c543f0`, slot +0x00)** — nele o bloco de 0x100 é
lido na **frente**, não no fim:

```
0x141c544d0  rdx = alloc->data()            ; dst
0x141c544d6  [rsp+0x28] = &consumed
0x141c544e0  [rsp+0x20] = &outRef
0x141c544e9  r9  = &iv16
0x141c544ed  r8d = 0x100
0x141c544f3  rcx = this
0x141c544f6  call FUN_141c535d0             ; consome 0x100 B e devolve IV + consumed
0x141c54505  offset = consumed              ; as "partes" começam DEPOIS do bloco
0x141c5456f / 0x141c545fa  FUN_141c54260(...) ; decifra parte 1 e parte 2 no dst
```
⇒ há **dois shapes** na rota B: *mensagem de troca de chave* (`FUN_141c53920`: bloco no FIM,
`body+size-0x100`) e *mensagem de dados* (`FUN_141c543f0`: bloco de 0x100 na FRENTE, seguido
das partes). O mock só precisa do shape que o `Logon_Results` usar — determinável pelo
tamanho mínimo que o cliente aceita (272 vs 512) e pelo fingerprint de erro (D7.4).

**Request (espelho, `FUN_141c547a0`)**: `[IV 16][rand16 16][ct][RSA 0x100]` — 896 ⇒ ct = 608.
O campo `rand16` **não existe** na resposta; um mock que repetir o layout de request na
resposta desloca o ct em 16 B (e o parser da rota A leria o ct errado).

**Coisas que o mock v3 precisa respeitar e não estavam no spec:**

1. **mínimo de tamanho** por rota: 272 (A) / 512 (B). Resposta menor = `0x80500060` antes de
   qualquer tentativa de AES.
2. `ct` **>= 16 e múltiplo de 16**; PKCS#7 **válido** (padding uniforme de 1..16 bytes).
3. O **tail de 0x100 B não é livre**: é resultado da operação pública sobre o prefixo
   (gate). Zeros/lixo/aleatório ⇒ `0x80500060`.
4. `IV` = `body[0..16)` **verbatim** (não é derivado de K nem do tail).
5. O `frame13` continua **dentro** do ciphertext (o parser só o vê depois do AES).

### D5. Q4 — o "XOR mask" de 32 B: onde é lido e o que o preenche

Leitura (rota B, `FUN_141c53920`, em claro):

```
0x141c53b60  lea  rcx,[rbp+0xa0]        ; &pt[0x10]
0x141c53b67  mov  r9, rdi               ; rdi = this (objeto do transform)
0x141c53b6a  sub  r9, rcx               ; r9 = this - &pt[0x10]
0x141c53b70  lea  rax,[rbp+0xa0] ; add rax, rdx
0x141c53b7a  movzx ecx, byte [r9+rax+0x20]   ; ==> this + rdx + 0x20
0x141c53b80  xor  cl, byte [rax]             ; ^ pt[0x10+rdx]
0x141c53b82  mov  byte [rbp+rdx+0x68], cl    ; dst32[rdx]
```
⇒ **mask = 32 bytes em `this+0x20 .. this+0x3f`** (confirmado instrução a instrução).

O que mora ali: na sub-vtable irmã a mesma área é usada como **ponteiro do AES ctx**
(`0x141c54194 mov rcx,[rbp+0x20]` → passado como `aes_ctx` para `FUN_141c53840`). E a busca
por stores de 32 B em `[obj+0x20]` no cluster inteiro (`grep20.py`) **não achou nenhum
inicializador de constante** — só `movups [rbx+0x20],xmm0` (zeragem dos objetos de provider
CNG, 0x141c52724/0x141c52924/0x141c52b24/0x141c52d24, que não são este objeto).

**Veredito parcial (alta confiança)**: a mask **não é constante legível**; ela **aliasa
estado de runtime** do objeto (ponteiro do ctx AES e vizinhos). Portanto:
* `mask = 0` só funciona se esses 32 bytes estiverem zerados no momento — plausível apenas
  **antes de o objeto ter chave instalada** (primeira troca da sessão), e não verificável
  estaticamente. **Vale como primeiro teste** (é grátis), mas não é a aposta principal.
* O caminho robusto é ler os 32 B do processo (ou hookar após `BCryptDecrypt`, onde os 64 B
  em claro estão em `[rbp+0x90]` e a chave derivada em `[rbp+0x68]`), ou re-dumpar quente.

### D6. Q5/Q6 — ordem exata no cliente e o *gate* do RSA

```
HTTP body
  -> FMT_IN (FUN_141c09520) : CMemStream sobre o corpo, this->vtable[0x40]/[0x48]
     -> (rota A) FUN_141c54050
          1. size >= 0x110
          2. FUN_141c552f0(publicKey, ...)      <-- GATE RSA; falhou = 0x80500060, FIM
          3. IV = body[0..16)
          4. FUN_141c53840 -> FUN_141ada800 (AES-CBC)  + PKCS#7
     -> (rota B) FUN_141c53920
          1. size >= 0x200
          2. FUN_141c552f0(publicKey, ...)      <-- GATE RSA; falhou = 0x80500060, FIM
          3. BCryptDecrypt(privada do cliente, OAEP-SHA1, tail 0x100) -> 64 B
          4. K = pt[16..48) ^ mask ; IV = pt[0..16)  -> session+0x208/+0x238 (roll)
     -> (rota B, 2ª fase) FUN_141c543f0 -> FUN_141c54260 por parte
  -> DEC stage / FMT_IN: lê o frame de 13 B **do plaintext** e segue o decode
```

**Resposta a Q5/Q6**: sim — o passo RSA (`0x141c552f0`) roda **antes** do AES nas duas rotas
e é **condição necessária**: se ele retornar `false`, o `ct` **não é sequer tentado**
(`0x80500060` imediato). E o mock precisa "emulá-lo" no sentido de **produzir um tail
consistente** com o prefixo — não é opcional nem ignorável.

### D7. MOCK v3 RECIPE UPDATES

Receita atual (spec §R6): `body = [IV 16][AES-256-CBC/PKCS#7(frame13||UserLogonResponse)][RSA-OAEP-SHA1(pub_cliente, IV||K||16B) 256B]`,
`K = 32B ^ mask`. Correções/adições concretas:

1. **O layout acima é o da ROTA B.** Para a rota A o tail é **função pública do prefixo**
   (gate `FUN_141c552f0`) e **não** aceita o blob OAEP do cliente. Ou seja: **existem duas
   respostas possíveis e o mock precisa saber qual o cliente usa** — a diferença é
   observável pelo código de erro (tabela abaixo), não pelo corpo.
2. **Adicionar checagens de tamanho**: `len(body) >= 272` (A) / `>= 512` (B); `ct % 16 == 0`
   e `ct >= 16`. Com o corpo de Logon de 469 B: A ⇒ `16 + 496 + 256 = 768`; B ⇒ mesmo total
   se a resposta for enviada como **uma** parte (`0x141c543f0` suporta 2 partes, mas o split é
   propriedade da mensagem, não do transporte).
3. **PKCS#7 válido sempre** — qualquer padding inconsistente vira `0x80500063` e mascara o
   diagnóstico.
4. **Ordem de probes (1 boot por variante, agora com fingerprint de erro)**:

   | probe | corpo | erro esperado se tudo estiver certo | leitura |
   |---|---|---|---|
   | a | 469 B + tail = **OAEP-SHA1(pub_cliente, IV‖K‖16)**, mask=0 | (aceita) → 1 Logon e segue | rota B + mask=0 |
   | b | idem, mas tail = **zeros** | `0x80500060` | gate do RSA reprovou (esperado) |
   | c | corpo de 272 B (mínimo A) com tail OAEP | `0x80500060` | se for rota B, o motivo é `size<0x200`; se A, o tail OAEP não serve |
   | d | corpo de 512 B mínimo B, tail OAEP | `0x80500060` ou `0x80510002`/`0x80500063` | discrimina A vs B |
   | e | a + `mask` lida em runtime (`this+0x20`, 32 B) | (aceita) | rota B com mask≠0 |

   Fingerprints (todos de `0x141c5xxxx`, já documentados):

   | código | onde | significa |
   |---|---|---|
   | `0x80500060` | 0x141c54017 (B) / 0x141c5422b (A) | `size` abaixo do mínimo **ou** gate `FUN_141c552f0` reprovado |
   | `0x80510002` | 0x141c53b13 (B) | `BCryptDecrypt` do OAEP falhou, ou plaintext ≠ **64 B** |
   | `0x80500063` | 0x141c538bb (A) | `ct < 16` ou **PKCS#7 inválido** ⇒ **chave errada** (mask) |
   | `0x80070057` | 0x141c538e4 / 0x141c53120 | inconsistência de tamanho / `len != 0x20` no key blob |
   | `0x80500043` | 0x141c093d0 | decifrou, mas o `frame13` interno ≠ 13 B |
   | `0x8050000e` | 0x141c093d0 | `status` do frame ∉ {0,2} |

   Leitura prática: **`0x80500063` = cheguei no AES e a chave estava errada** (mask); 
   **`0x80500060` = nem cheguei no AES** (gate/tamanho).
5. **Roll de chave (bônus, confirmado em D4)**: se a rota B passar, o cliente grava
   `session+0x208 = K` e `session+0x238 = IV`; o caminho de *encrypt* lê exatamente esses
   campos ⇒ **todos os requests seguintes passam a usar a chave do mock** (e o mock pode
   decifrá-los: `[IV][rand16][ct][RSA]`). É também o sinal inequívoco de aceite.
6. **Rota A é provavelmente um beco sem saída para o mock** (confiança **média**, ver nota):
   o tail é operação com a chave **pública do servidor** e a chave AES é a da sessão
   corrente — que o mock não conhece (foi gerada pelo cliente e embrulhada para o servidor).
   Só a rota B dá ao mock controle da chave.
   **Nota/contradição em aberto**: na rota B o *mesmo* tail de 0x100 B passa por
   `FUN_141c552f0` (chave **pública**, slot +0x1a0) **e depois** por `BCryptDecrypt` (chave
   **privada**, slot +0x170). Como um bloco RSA-2048 não pode ser simultaneamente
   "verificável com pública" e "desembrulhável com privada", uma das leituras está errada:
   ou (i) `FUN_141c552f0` **não opina** sobre o tail (apenas o lê/valida forma e escreve
   algo derivado do prefixo), ou (ii) os slots +0x1a0/+0x170 são **o par do próprio
   cliente** (pública+privada dele) e não servidor/cliente. Isso só fecha com o corpo de
   `FUN_141c552f0` (re-dump quente, item 7) — e muda o veredito: em (ii) o mock consegue as
   duas rotas.
7. **Próximo passo decisivo (barato)**: re-dumpar **quente**. As 4 unidades são
   re-protegidas quando esfriam; capture-as *durante* o handshake (dumper rodando enquanto o
   cliente retenta o Logon, ou hook em `FUN_141c54050`/`FUN_141c53920` que copie
   `0x141c552f0..+0x210`, `0x141c54260..+0x190`, `0x141c535d0..+0x270`,
   `0x141ada800..+0x1e0` logo após a decifração). Com isso, Q1–Q4 fecham analiticamente.

### D8. Resumo do que o dump 2 muda no spec

| item | antes (§R6) | agora |
|---|---|---|
| estado dos 4 alvos | "ciphertext no dump 1" | **continuam ciphertext no dump 2** (unidades: 0x190/0x270/0x210/0x1e0) |
| `0x141c552f0` | "pré-passo RSA (ciphertext)" | **gate obrigatório** nas 2 rotas; entrada=prefixo, saída=tail 0x100; chave = slot +0x1a0 (**pública**) |
| rotas de resposta | uma só | **duas**: A (tail público + AES) e B (OAEP-privada + roll + AES) |
| mínimo de body | 272 | **272 (A) / 512 (B)** |
| `rand16` | "só no request" | confirmado: **não** existe na resposta |
| mask | "32 B em crypto+0x20" | confirmado; **aliasa ponteiro do AES ctx** ⇒ estado de runtime, não constante |
| chave simétrica | CNG ou própria (indefinido) | **AES próprio** (`FUN_141c65b90` expande 0x20 B → 0x140 B; nenhum thunk bcrypt) |

---

## REQUEST SHAPE EMPIRICAL (2026-11-15/16)

Esta seção **substitui** o modelo de request das seções §4/§R4/D4 para o caminho real
capturado (Logon, 896 B). Ela é baseada em **4 corpos reais** e em aritmética de chave, não
em inferência de código.

### E0. Evidência usada e comandos

Corpos de 896 B (todos reais, capturados do cliente):

| arquivo | origem | sha256(body)[:16] |
|---|---|---|
| `unwrap/logon_1.bin` | mock run 02:33:38 | `e84b3c9f3a1851fb` |
| `unwrap/logon_2.bin` | mock run 02:36:47 | `f4f09cf8849f868e` |
| `lsp-capture/capture/1794711851_Logon.bin` | capture 00:03 | `dfd8f6275429e3cd` |
| `lsp-capture/capture/1794711855_Logon.bin` | capture 00:03 | `4dc661610ad3a58d` |

Chaves do mock: `keys/client_private.pem` / `client_public.pem` — **conferido**: são
exatamente o par embutido no binário (`BCRYPT_RSAPRIVATE_BLOB` magic `'RSA2'` @
`0x1449209a0`, 542 B; `n = b3854ed10bbb6a99…`, `e = 0x10001`).

```
python difflogon.py       -> exit 0   (diff byte-a-byte + entropia 256B/16B)
python oaep_scan.py       -> exit 0   (OAEP SHA1/SHA256 + PKCS1 em todos os offsets 16)
python calib.py           -> exit 0   (calibração de falso positivo em dados aleatórios)
python raw_rsa_scan.py    -> exit 0   (RSA cru + validação ESTRITA PKCS1/OAEP-SHA1/256/384/512)
python sig_scan.py        -> exit 0   (assinatura do tail: EM/DigestInfo + verify)
python sig_verify_all.py  -> exit 0   (verify nos 4 corpos capturados)
python key_guess.py       -> exit 0   (14 chaves estáticas candidatas x 3 IVs x 3 offsets)
```

### E1. Estatística: o corpo inteiro é uniforme (nenhum campo claro)

`difflogon.py` (logon_1 vs logon_2): **888 de 896 bytes diferem**; **0 blocos de 16 B
idênticos**; entropia por janela de 256 B = 7.12–7.23 (máx. 8.0), e por bloco de 16 B = 3.6–4.00
(máx. 4.0). Os **8 bytes coincidentes** estão em `{199, 257, 466, 491, 625, 650, 769, 868}`
(valores `2b 8d 3c 9c 7e d8 de 36`) — offsets e valores aleatórios, dispersos também dentro da
região da assinatura ⇒ coincidência (esperado ≈3,5 por acaso), **não** um campo fixo. Ou seja:
não existe IV/campo em claro distinguível por entropia; tudo é uniforme.

### E2. Scan exaustivo de RSA: **ZERO** (e a explicação do "sucesso" do teste 6)

`raw_rsa_scan.py` faz `m = c^d mod n` para **todos** os offsets de byte (0..640) de cada corpo
e valida **estruturalmente**:

* PKCS#1 v1.5: `EM[0:2] == 00 02`, `PS >= 8`, separador `00` → conteúdo;
* OAEP: `EM[0] == 0`, `lHash` correto (SHA-1/256/384/512), `00…01` → mensagem.

Resultado: **0 hits** em `logon_1.bin` e `logon_2.bin` (641 offsets cada), para todas as 4
funções de hash.

**Por que o teste 6 "desembrulhou" um tail**: `cryptography`/OpenSSL **não valida** o padding
PKCS#1 v1.5 nesse caminho. `calib.py` mede isso em dados **aleatórios**: **217 de 300** blocos
de 256 B "desembrulham" (72%), com comprimentos de 0..250 B. Portanto qualquer "unwrap" via
PKCS1v15 em corpo cifrado é **ruído**; e `logon_2.bin` offset 0 produzia *exatamente* 64 bytes
— o que pareceu "material de chave de 64 B" e era coincidência. **OAEP dá 0/300 em aleatório**
e 0/1282 aqui: OAEP é o único teste confiável, e ele nunca passa.

### E3. O tail **é uma ASSINATURA** (prova criptográfica)

`sig_scan.py`/`sig_verify_all.py`: para os 4 corpos, `body[640:896]` é uma assinatura
**RSA-2048 PKCS#1 v1.5 + SHA-256** sobre **`body[0:640]`**, verificável com
`client_public.pem`:

```
body[640:896] ^ e mod n  =  00 01 FF×202 00 || 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
                                                 └──── DigestInfo SHA-256 ────┘   └── 32 B ──┘
                          e os 32 B == SHA256(body[0:640])
```
Saída literal (`sig_scan.py`):

```
=== logon_1.bin ===
   off=640 (msg=body[0:640]): EM[0:4]=0001ffff last=6e
      PKCS1v15 SIG structure: PS len=202, T=3031300d0609608648016503040201050004205000369c88
      DigestInfo=sha256  digest_match(body)=True
  *** SIGNATURE MATCH off=640 hash=sha256 over body[0:640]
=== logon_2.bin ===  (idem, digest 7d01c42e…)
```
E `sig_verify_all.py` confirma nos 4 arquivos: `sig-matches: [(640, 'sha256', 'pkcs1')]`
(nenhum outro cutoff/hash/padding casa — inclusive PSS).

### E4. SHAPE CORRIGIDO do request (byte-a-byte)

```
body[0   : 16)   session value  (16 B, vem de session+0x238; opaco, por-sessão)
body[16  : 32)   IV da mensagem (16 B, aleatório por request)   <-- IV do AES-CBC
body[32  : 640)  AES-256-CBC ciphertext (608 B = 38 blocos, PKCS#7)
body[640 : 896)  RSA-2048 PKCS#1v1.5/SHA-256 ASSINATURA sobre body[0:640]  (chave do CLIENTE)
```

Confirmação no assembler `FUN_141c547a0` (dump_text, plaintext) — trecho 0x141c548d1..0x141c54988:

```
0x141c548d1  rdi = [r13+0x50]            ; Ref com o valor de 16 B (session+0x238)
0x141c548d5  ebx = [rdi+8]               ; = 16
0x141c548ec  memcpy(out, [rdi+0x10], 16) ; out[0..16)  = session value
0x141c548f5  esi = [rax+8]               ; = 16  (offset corrente)
0x141c54900  rand() x16 -> [rbp-1]       ; 16 B aleatórios
0x141c54921  movups [out+rsi], xmm0      ; out[16..32) = IV da mensagem
0x141c54925  esi += 0x10                 ; = 32
0x141c54973  [rsp+0x28] = rsi            ; destOffset = 32
0x141c54980  rdx = &[rbp-1]              ; IV passado ao cipher = o rand16
0x141c54984  rcx = [r13+0x20]            ; contexto AES (chave = session+0x208)
0x141c54988  call FUN_141c54260          ; cifra a partir de out[32]
...
0x141c54a8f  call FUN_141c550d0          ; assina o prefixo -> out[640..896)
```
A conta de alocação do próprio assembler também fecha: `alignedA + 0x120 + alignedB`, e
**0x120 = 288 = 16 (session) + 16 (IV) + 256 (assinatura)**.

### E5. O que **não** existe no request: transporte de chave

Consequência dura do E2+E3: **não há bloco RSA cifrado no corpo** — nem para o servidor, nem
para o cliente. O único elemento RSA é a assinatura. Portanto a chave AES da sessão (`K`) **não
viaja no request**. Também não há chave estática óbvia: `key_guess.py` testou 14 candidatas
(`n[0:32]`, `n[-32:]`, `d[0:32]`, `d[-32:]`, `SHA256(n)`, `SHA256(pem)`, `SHA256(blob)`,
`blob[0:32]`, `blob[24:56]`, `blob[27:59]`, `blob[-32:]`, zeros, 2 variantes 16B×2) × 3 IVs
(`body[0:16)`, `body[16:32)`, zeros) × 3 offsets de ct (0/16/32) → **0 hits** (PKCS#7 +
frame como oráculo).

Ou seja: `K` é por-sessão e **não é derivável do corpo** nem de material público do binário.
O mock só a obtém por (a) roll bem-sucedido de uma resposta, ou (b) leitura de runtime.

### E6. Correção do modelo das ROTAS de resposta (A vs B)

Com o achado de que a assinatura usa a chave do **cliente**, o mapeamento fica coerente — e
corrige o spec:

| rota | shape | quem valida o quê |
|---|---|---|
| **A** `FUN_141c54050` | `[IV 16][ct][SIG 0x100]`, mín **0x110** | `FUN_141c552f0` = **verifica a assinatura** do tail (objeto de chave em `this+8`+0x1a8); se falhar → `0x80500060`, **AES não roda** |
| **B** `FUN_141c53920` + `FUN_141c543f0` | `[OAEP 0x100][partes][SIG 0x100]`, mín **0x200** | 1) `FUN_141c552f0` verifica o **tail** (chave em `this+0x10`+0x1a8); 2) `BCryptDecrypt(OAEP-SHA1)` decifra o **FRONT 0x100** (`0x141c539c2: rbx = ptr + 0`, `0x141c53aa0: pbInput = body->data()`, `cbInput = 0x100`) com a chave **privada** do cliente → 64 B → `K`/IV (roll); 3) decifra as partes |

A correção importante é a de B: o bloco OAEP fica **no início** (`body[0:0x100]`) e a
assinatura **no fim** (`body[size-0x100:]`) — não é "um tail RSA só". O nome
`FUN_141c552f0` deixa de ser "pré-passo RSA" e passa a ser **verificação de assinatura**.

Consequência para o mock: **a resposta precisa de uma assinatura que o cliente aceite**. O
cliente verifica com a chave do slot `+0x1a0/+0x1a8` = `RSA1` @0x14494b080/0x14494af60
(`n = d01ec7…`, **diferente** da chave do cliente `b3854e…`). Se esse for mesmo o verificador,
**nenhum mock local pode assinar** (seria necessário a privada da Turn 10). O único teste
offline que ainda discrimina: assinar com `client_private.pem` e ver se o erro muda de
`0x80500060` para outro (ver E8, variante 9).

**Cross-validação do mapa de slots** (isto é novo e importante): o request assina com
`[session+0x148]` e a assinatura **verifica com a pública do cliente** (E3) ⇒ o slot `+0x140`
é de fato a **privada do cliente**. Logo, pela mesma tabela de setup
(`0x141c54ba0`: +0x140/+0x170 = `RSAPRIVATEBLOB` com os blobs `RSA2`; +0x1a0/+0x1d0 =
`RSAPUBLICBLOB` com os blobs `RSA1`), `+0x1a8` é com **alta confiança** a **pública do
servidor** — e o gate da resposta exige assinatura da Turn 10.

### E7. Receita corrigida para `xls_crypto.unwrap_request`

```python
# layout provado (E4); funciona já hoje, sem chave alguma:
def split_request(body):                       # body = 896 B
    assert len(body) == 896
    payload, sig = body[:640], body[640:]
    return dict(session=body[0:16], iv=body[16:32], ct=body[32:640], sig=sig, payload=payload)

# 1) autenticidade (SEM chave simétrica) -- SEMPRE deve passar em request real
def verify_request(body, pub):
    s = split_request(body)
    pub.verify(s["sig"], s["payload"], padding.PKCS1v15(), hashes.SHA256())
    return True            # True nos 4 corpos capturados; False => corpo sintético/corrompido

# 2) decifrar (só quando K é conhecida, ex.: após roll ou leitura de runtime)
def decrypt_request(body, K):
    s = split_request(body)
    pt = AES256CBC(K, s["iv"]).decrypt(s["ct"])       # PKCS#7
    pt = unpad_pkcs7(pt)
    frame, msg = pt[:13], pt[13:]                     # frame = 00|status BE|code BE|len BE
    assert frame[0] == 0 and int.from_bytes(frame[1:5], "big") == 0
    return frame, msg
```

**Oráculo de layout (importante)**: como o cliente pode trocar de shape após um roll, o
`unwrap_request` deve tentar candidatos e aceitar o primeiro que valide **PKCS#7 + frame13
coerente** (`b0=0`, `status=0`, `code=0`, `len ≈ len(msg)`):

| candidato | iv | ct | quando |
|---|---|---|---|
| 1 (provado) | `body[16:32)` | `body[32:640)` | padrão atual |
| 2 | `body[0:16)` | `body[16:640)` | se o "session value" for o IV |
| 3 | zeros | `body[32:640)` | se o IV for fixo |
| 4 | `body[0:16)` | `body[32:640)` | variante de 16 B de padding |

Adicione em `/status`: `requests_signature_verified` (novo, funciona offline) e
`requests_decrypted` (só cresce quando K é conhecida).

### E8. Como o mock chega a `requests_decrypted > 1` (e o que **não** vai funcionar)

1. **Não tente RSA no request.** Não existe bloco OAEP no corpo; qualquer "unwrap" que passe
   com PKCS1v15 é falso positivo (72% em dados aleatórios — E2). Valide sempre com OAEP ou
   com `pub.verify`.
2. **K só aparece por roll ou por runtime.** O request nunca carrega K (E5).
   *Roll*: só a rota B (E6) re-chaveia, e ela exige a assinatura de 0x100 no fim — feita com a
   chave que o cliente verifica (`+0x1a8`). Se essa chave for a do servidor, não há roll
   possível offline; se for a do cliente, o mock assina com `client_private.pem`.
   *Runtime*: ler `session+0x208` → objeto da chave → material expandido em `obj+0x148`
   (0x140 B, lock em `+0x288`), ou hookar `FUN_141ada800` (`rcx = keyobj+0x148`, `rdx = IV`) /
   `FUN_141c54260`. É **uma** leitura por boot e destrava tudo.
3. **Variante 9 (teste decisivo, 1 boot)**: responder o Logon com
   `[OAEP-SHA1(pub_cliente, IV‖K‖16)] [AES-256-CBC(K, IV', frame13‖UserLogonResponse)] [SIG]`,
   onde `SIG = PKCS1v15-SHA256(client_private, prefixo)`. Três leituras possíveis:
   * `0x80500060` → o gate de assinatura rejeitou (verificador ≠ chave do cliente, **ou** o
     gate falhou por estrutura — ver nota abaixo) ⇒ rota offline fecha aqui; só resta
     runtime-read de K **e** o mesmo problema de assinatura;
   * `0x80510002` / `0x80500063` → o gate **passou** e o problema é o OAEP/chave ⇒ caminho
     aberto: basta acertar `K`/`IV` e o padding;
   * aceite (segue para outro método) ⇒ `body[0:16)` do próximo request deve ser **igual ao
     IV** que o mock mandou — é o sinal definitivo de que o roll aconteceu, e a partir daí
     `requests_decrypted` sobe com `K` do mock (layout candidato 1).
   *Nota*: `FUN_141c552f0` **escreve 0x100 B no tail** (dest = `body+size-0x100`), o que é
   compatível tanto com "verificar e deixar o EM recuperado no tail" quanto com
   "recomputar/derivar". Nos dois casos o gate devolve `false` ⇒ `0x80500060`; portanto esse
   código **não distingue** "assinatura inválida" de "chave errada". O discriminador fino é o
   *segundo* código: se o gate passar, o próximo erro vem do OAEP (`0x80510002`) ou do
   PKCS#7 (`0x80500063`).
4. **Critério de aceite que funciona hoje, offline**: `requests_signature_verified > 0` com
   4/4 nos corpos reais (E3). É o melhor sinal disponível sem chave — e prova que o mock está
   falando com o cliente real, não com tráfego sintético.

### E9. Tabela-resumo das correções

| item do spec anterior | estava | correto (evidência) |
|---|---|---|
| tail do request | "RSA-OAEP com a pública do servidor" | **assinatura PKCS#1v1.5/SHA-256 com a privada do CLIENTE sobre body[0:640]** (E3) |
| key transport no request | implícito (OAEP 256 B) | **inexistente** (E2/E5) |
| `[0:16)` do request | "IV" | **session value** (16 B, de `session+0x238`); o IV do CBC é `[16:32)` (E4) |
| `[16:32)` | "rand16 sem papel" | **IV da mensagem**, passado a `FUN_141c54260` (E4) |
| ct | 608 B a partir de 32 | **confirmado** (608 = 38 blocos) |
| rota B | `[..][RSA tail]` | **`[OAEP 0x100][partes][SIG 0x100]`**; OAEP no **início** (E6) |
| `FUN_141c552f0` | "pré-passo RSA" | **verificação de assinatura** (gate) (E6) |
| teste 6 "unwrap OK" | sucesso | **falso positivo** de PKCS#1 não validado (E2) |


## FINAL VERDICT (2026-11-15, variant 9 decisive boot)

Route-B response [OAEP(pub_client,IV2||K||0x10)][AES-256-CBC(K,IV2,PKCS7(frame13||body))][SIG=PKCS1v15-SHA256(client_priv,prefix)] (1008B, self-verified) was delivered to a real Logon (ts 1794722077). Client behavior: NO retries (vs 1.5-3s on parse-failures), no other methods, immediate 'SEM CONEXAO' screen. Conclusion: the response signature gate verifies against the SERVER (Turn 10) public key (embedded RSA1 blobs 0x14494af60/0x14494b080), not the client pair. Without the T10 private key, no local mock can produce an acceptable Logon response. Routes tried and refused: plaintext (all framing variants), encrypted route A (mock K), route B with client-signed. The only remaining path would be tampering with the game client's verification code at runtime, which is out of scope (anti-tamper circumvention). Environment reverted: mock killed (PID 9512), REA session closed; hosts/CA revert via fm8-lsp-server restore_ca.ps1 (user, elevated). All evidence: mock-lsp/ (ENVELOPE-SPEC.md 1459+ lines, unwrap/ logon_1-2.bin, capture_log.jsonl full history, dump_text.bin, key_candidates/hunt/scans, keys/).
