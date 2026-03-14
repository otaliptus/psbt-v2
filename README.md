## go-psbt-v2

A Go implementation of [BIP-370 (PSBTv2)](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki) with full [BIP-174 (PSBTv0)](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) support, built on [btcd](https://github.com/btcsuite/btcd/tree/master/btcutil/psbt).

```
go get github.com/otaliptus/psbt-v2
```

### Why v2?

PSBTv0 freezes the entire unsigned transaction as a single global blob at creation time. Once you call `New()`, the inputs and outputs are locked — you can't add, remove, or reorder them without starting over. This makes multi-party construction (coinjoins, payjoin, collaborative wallets) awkward at best.

PSBTv2 ([BIP-370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)) fixes this by decomposing the transaction:

- **Per-input fields** (`PreviousTxID`, `OutputIndex`, `Sequence`) replace the monolithic `UnsignedTx`
- **Per-output fields** (`Amount`, `Script`) are first-class rather than buried in a wire blob
- **`TxModifiable` bitfield** explicitly controls whether inputs/outputs can still be added or removed
- **Per-input locktime requirements** (`RequiredTimeLocktime`, `RequiredHeightLocktime`) replace the single global locktime, with a deterministic resolution algorithm

The result: multiple parties can incrementally build a transaction without needing to agree on the full structure upfront.


#### Is this LLM slop?

70% no. I do get (who doesn't) a lot of AI assistance of course (guess what, I don't like `go`) but I also do spend quite a portion my time to make sure that:

- it is not pure slop
- it reflects psbt-v2 BIP + other implementations as much as it can
- it does not go full non-sense against the logic btcd/psbt already had (though architecture-wise it may not be the greatest)

Still feel free to send an issue if you see a problem of course. At the end of the day, this is open-source, and I'm a human who can make mistakes.


### v0 vs v2 — side by side

#### Full lifecycle: Create → Update → Sign → Finalize → Extract

**btcd/psbt (v0)** — everything decided upfront:

```go
// All inputs, outputs, locktime, and sequences must be known at creation.
pkt, _ := psbt.New(inputs, outputs, 2, locktime, sequences)

updater, _ := psbt.NewUpdater(pkt)
updater.AddInWitnessUtxo(utxo, 0)
updater.Sign(0, sig, pubKey, nil, nil)

psbt.MaybeFinalize(pkt, 0)
tx, _ := psbt.Extract(pkt)

// Want to add another input now? You can't. Start over.
```

**go-psbt-v2 (v2)** — inputs and outputs are independent, modifiable fields:

```go
// Create with per-input outpoints and per-output amounts.
// fallbackLocktime and modifiable flags are optional.
modifiable := uint8(0x03) // inputs + outputs modifiable
pkt, _ := psbt.NewV2(2, inputs, outputs, &locktime, &modifiable)

// Constructor: add or remove inputs/outputs incrementally.
ctor, _ := psbt.NewConstructor(pkt)
ctor.AddInput(newTxID, newIndex)    // append a new input
ctor.AddOutput(amount, script)      // append a new output

// Then the same Update → Sign → Finalize → Extract flow.
updater, _ := psbt.NewUpdater(pkt)
updater.AddInWitnessUtxo(utxo, 0)
updater.Sign(0, sig, pubKey, nil, nil)

psbt.MaybeFinalize(pkt, 0)
tx, _ := psbt.Extract(pkt)
```

#### Adding inputs after creation

**v0** — not possible. The unsigned transaction is immutable once created. You would need to rebuild the entire PSBT from scratch.

**v2** — first-class operation via the Constructor role:

```go
ctor, _ := psbt.NewConstructor(pkt)

// Safe: Constructor checks TxModifiable flags and rejects
// if signatures already exist (would be invalidated).
ctor.AddInput(prevTxID, outputIndex)
ctor.AddOutput(50_000, p2wpkhScript)

// Remove works too.
ctor.RemoveInput(2)
ctor.RemoveOutput(0)
```

The Constructor enforces BIP-370's mutation rules:
- Rejects changes when any input has signature material (partial sigs, taproot sigs, finalized scripts)
- Respects the `TxModifiable` bitfield (bit 0 = inputs, bit 1 = outputs)
- Blocks one-sided mutations when `SIGHASH_SINGLE` (bit 2) is set

#### Converting between versions

Entirely new — btcd/psbt has no concept of this:

```go
// v0 → v2: lossless. Decomposes UnsignedTx into per-input/output fields.
v2Pkt, _ := psbt.ConvertToV2(v0Pkt)

// v2 → v0: intentionally lossy. Reconstructs UnsignedTx, drops
// TxModifiable and per-input locktime requirements (no v0 equivalent).
v0Pkt, _ := psbt.ConvertToV0(v2Pkt)

// Both return deep copies — mutating the result won't affect the source.
```

### Status

| BIP-370 Role | Status |
|---|---|
| **Parser / Serializer** | Done — v0 + v2, trailing-byte rejection, allocation caps |
| **Creator** (`NewV2`) | Done — builds v2 packets with defensive copying |
| **Constructor** | Done (partial) — `TxModifiable` bitfield, signature guards |
| **Updater** | Done — v2-aware accessors for prevout/sequence |
| **Signer** | Done — updates `TxModifiable` flags per BIP-370 |
| **Finalizer** | Done — preserves v2 fields, iterates `p.Inputs` |
| **Extractor** | Done — reconstructs tx from v2 per-input/output fields |
| **Conversion** | Done — bidirectional with tested lossless/lossy semantics |

Highlights:

- **Dual v0/v2 support** — single `Packet` struct, version-aware `SanityCheck`
- **45+ official BIP-370 test vectors** for parse/validation
- **Locktime determination** — full BIP-370 algorithm (height vs time, max-across-inputs, fallback)
- **Mutation safety** — Constructor rejects modifications when signatures exist or `SIGHASH_SINGLE` pairing would break
- **Taproot support** — Schnorr signatures, x-only pubkeys, leaf scripts, taproot BIP-32 derivations

Remaining work:
- Strict singleton-key enforcement cleanup
- Merge-gate cleanup (`golangci-lint`, TODO debt)

### Conversion Notes

- `ConvertToV2` is lossless for anything PSBTv0 can express. It decomposes `UnsignedTx` into `TxVersion`, `FallbackLocktime`, per-input prevout/sequence fields, and per-output amount/script fields while preserving shared metadata like UTXOs, scripts, derivations, finalized data, taproot data, xpubs, and unknowns.
- `ConvertToV0` is intentionally lossy because PSBTv0 cannot store certain PSBTv2-only fields directly. The resulting `UnsignedTx` preserves the transaction semantics: `FallbackLocktime`, prevouts, sequences, amounts, and scripts are folded into the wire transaction. The actually unrecoverable v2-only data is `TxModifiable` plus per-input required locktimes.
- Both helpers return deep copies. Mutating a converted packet does not mutate the source packet.

### Commands

```sh
go test -v ./...
golangci-lint run -v --timeout=5m
```

### Acknowledgments

This project is derived from [btcd's psbt package](https://github.com/btcsuite/btcd/tree/master/btcutil/psbt) by the btcsuite developers, originally released under the ISC license. The v0 implementation, type definitions, and role-based architecture originate from that work.

### License

[MIT](LICENSE)
