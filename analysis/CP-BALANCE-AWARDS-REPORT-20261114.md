# Forza FM8 — CP balance & awards (static) — final report
Date: 2026-11-14. Tool: REA 6.9.0 reader (existing-project, Ghidra 12.1.4), no auto-analysis.
Target: targets/forza-fm8-20261105/forza_steamworks_release_final.exe
SHA-256 89bc22cde56fe25051ac6928188488433d281e81eac6b6849a7b82415d06e37e (PE x86_64).
Session: reader run 52dbb22a-14b3-4ac2-b73c-fafedd7c263f; closed 2026-11-14 (reader deletes
its private copy on close; 6.8 originals untouched).

## Verdict
HYPOTHESIS CONFIRMED. The online XLS service is the authority for Car Points balances and
awards; the local CMS/DB values are presentation/mirror inputs only.
- Per-car CP, level and XP are service-owned: DownloadPlayerProfile response carries, per
  car: carId(0xd0), purchasePrice(0xd8), acquisitionType(0xe0), carPointsTotal(0xe4),
  earnedCarPoints(0xe8), purchasedCarPoints(0xec), currentLevel(0xf0), experiencePoints(0xf4),
  tiersAchieved(0xf8), unredeemed(0x110). (Builder FUN_1400dbd30, schema table 0x145b136e8+.)
- Purchases are server-confirmed transactions: BuyCarPointsForCar request carries
  carPointAmount + expectedPrice (client-claimed), response returns updatedCar + creditDelta.
  BuyShowroomListing: purchaseDelta / priceCorrected / useCarKey.
- Local DB only mirrors: Garage car table has a CarPoints column; reader FUN_1421c9170
  contains `UPDATE %s SET CarPoints = %u WHERE Id = %u` (str @0x144a092a0) and
  `SELECT CarPoints From %s WHERE Id = %u` (@0x144a22f38); reads Experience=param[0x15e],
  CarPoints=param[0x16b]; invoked from row-wrapper ctor FUN_1421a8b60 (xref 0x1421a8dbd).
- CMS edits change display (vehicle level, price) but not balances/awards — consistent
  with CMS values being presentation/seed inputs (matches 2026-11-09 empirical observations
  in fm8-lsp-server HANDOFF.md).

## Evidence chain
- XLS services: 'Forza.WebServices.<X>, Forza.WebServices' strings .rdata 0x1448d3c48-0x144918570
  (User, UserInventory, PlayerProfile, Rewards, DailyCreditBonus, ...).
- Method registries .data {classPtr, methodPtr}: UserInventory 0x145b147a0-0x145b14810
  (BuyShowroomListing 0x1448e1970, AddDebugCredits 0x1448e1a30, BuyCarPointsForCar 0x1448e1aa8);
  PlayerProfile 0x145b0e280 (DownloadPlayerProfile 0x1448d3d18, PlayerProfileUpdateCount 0x1448d3d30).
- Dispatch: (*param_2+0x18)(param_2, classPtr, methodPtr, payload) + X-ContractVersion '73'
  (all services) + POST; Network::CallTaskWithCallback; Task::WebCall<
  WebCallXlsOperationPolicy<Operation>>::CreateAndCall (WebCall.h:375, fmbase_livehotfix) @FUN_14277b3a0.
- Completion: creator FUN_141b7fe80 builds Operation (vftable 0x1448d3d88,
  Xls::PlayerProfile::DownloadPlayerProfile::Operation) + BufferTypeAdapter<Response> +
  std::function lambda_d85e708a (vtable 0x1448d4020). _Do_call FUN_141b80c50: status<0 ->
  consumer vtable slot2(status); success -> adapter allocates Response, consumer slot1(response).
  Consumer = caller object (shared_ptr param_4), dispatched dynamically.

## Limitations / remaining unknowns
- 6.9 reader mode has NO auto-analysis: unanalyzed regions (success handler 0x144F29C48,
  Operation ctor 0x141b984f0 [1-byte IRETD]) cannot be decompiled; decompilation of those
  requires the 6.8 warm path or a new full analysis.
- ICF caveat: FUN_141b7fe80 has no direct callers (only .pdata refs); byte-search found it
  only as _Copy/_Move slots of an unrelated std::_Binder comparator vtable (0x1446dafb0/b8,
  _Do_call 0x14118E170). Identical-COMDAT folding merges addresses across logical roles, so
  the "creator" identification is not a unique role and consumer resolution via std::function
  dispatch is inference (response->game-state application site unresolved).
- Rewards::RewardCarPoints (0x1449b7808, JSON Reader/Writer, refs FUN_1400fefb0/FUN_1401022d0)
  — server-side award type; exact ingestion path not traced.
- Debug path: UserInventory.AddDebugCredits (creditAmount/delta) exists in the registry.

## Reproduction notes (tooling)
- P0 Ghidra reader has no .rdata string xrefs: use search_bytes with 4-byte LE pointer
  encoding of the string address; xrefs(address) works on code; procedure_callers may be
  empty (call graph not recorded) — rely on xrefs + search_bytes.
- decompile output keyed by 'procedure'; batch_decompile param is 'addresses'.
- Manual LE decode caution: an extra digit produced false 'unmapped/Denuvo' readings
  (0x144F29C48 is valid .data; sections verified via PE header: .text/.rdata/.data/.pdata/
  _RDATA/.xbld/.rsrc/.reloc).
- Rollback to 6.8 (for auto-analysis): restore mcp.servers.rea.command to
  .runtime/rea-persistent/warm-bootstrap.mjs and re-add
  REA_GHIDRA_DISABLED_ANALYZERS='WindowsResourceReference,Decompiler Parameter ID'
  (documented in .runtime/rea-reader-6.9/README.md).
