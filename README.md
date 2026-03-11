## go-psbt-v2

This is an ongoing Go implementation of [BIP-370 (PSBTv2)](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki) + [BIP-174 (PSBTv0)](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki). It uses [btcd](https://github.com/btcsuite/btcd/tree/master/btcutil/psbt) as the base, given it has a lot of cool stuff already. 

### Status

| BIP-370 Role | Status |
|---|---|
| **Parser / Serializer** | Done — v0 + v2, trailing-byte rejection, allocation caps |
| **Creator** (`NewV2`) | Done — builds v2 packets with defensive copying |
| **Constructor** | (kinda) Done — `TxModifiable` bitfield, signature guards |
| **Updater** | Done — v2-aware accessors for prevout/sequence |
| **Signer** | Done — updates `TxModifiable` flags per BIP-370 |
| **Finalizer** | Done — preserves v2 fields, iterates `p.Inputs` |
| **Extractor** | Done — reconstructs tx from v2 per-input/output fields |
| **Conversion** (`ConvertToV2`, `ConvertToV0`) | Done — explicit bidirectional conversion with tested lossless/lossy semantics |

So far it has:

- **Dual v0/v2 support** — single `Packet` struct, version-aware `SanityCheck`
- **45 official BIP-370 test vectors** for parse/validation so far (not fully roundtrip yet)
- **Locktime determination** — implements the full BIP-370 algorithm (height vs time, max-across-inputs, fallback)
- **Mutation safety** — Constructor rejects modifications when signatures exist or SIGHASH_SINGLE pairing would break
- **Explicit conversion helpers** — `ConvertToV2` preserves all v0-defined semantics; `ConvertToV0` rebuilds `UnsignedTx` and drops only v2-only fields that v0 cannot encode

What's left are:
- strict singleton-key enforcement cleanup
- merge-gate cleanup (`golangci-lint`, TODO debt, doc drift)
- checking for overkills & oversimplifications (a cleanup todo)

### Usage

```go
// Create a v2 packet
pkt, err := psbt.NewV2(txVersion, inputs, outputs, fallbackLocktime, txModifiable)

// Wrap in Constructor for safe mutation
ctor, err := psbt.NewConstructor(pkt)
err = ctor.AddInput(prevTxID, outputIndex)
err = ctor.AddOutput(amount, script)

// Convert existing packets explicitly.
v2Pkt, err := psbt.ConvertToV2(v0Pkt) // lossless for v0-defined semantics
v0Pkt, err = psbt.ConvertToV0(v2Pkt)  // lossy for v2-only fields
```

### Conversion Notes

- `ConvertToV2` is lossless for anything PSBTv0 can express. It decomposes `UnsignedTx` into `TxVersion`, `FallbackLocktime`, per-input prevout/sequence fields, and per-output amount/script fields while preserving shared metadata like UTXOs, scripts, derivations, finalized data, taproot data, xpubs, and unknowns.
- `ConvertToV0` is intentionally lossy because PSBTv0 cannot store certain PSBTv2-only fields directly. The resulting `UnsignedTx` preserves the transaction semantics: `FallbackLocktime`, prevouts, sequences, amounts, and scripts are folded into the wire transaction. The actually unrecoverable v2-only data is `TxModifiable` plus per-input required locktimes.
- Both helpers return deep copies. Mutating a converted packet does not mutate the source packet.

### Some simple commands you may find fancy

```sh
go test -v ./...
golangci-lint run -v --timeout=5m
```
