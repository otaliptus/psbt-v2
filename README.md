# psbt-v2

Go PSBT library with:

- full [BIP-174 (PSBTv0)](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) support
- full [BIP-370 (PSBTv2)](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki) support
- [BIP-375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki) field transport in the base package
- a higher-level `sp` package for the [BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki) / BIP-375 silent payment workflow
- a standalone `sp/dleq` package for [BIP-374](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki) proofs

```bash
go get github.com/otaliptus/psbt-v2
```

## Package Layout

| Package | Scope |
| --- | --- |
| `psbt-v2` | PSBTv0/v2 parsing, serialization, conversion, BIP-370 roles, BIP-375 field transport |
| `psbt-v2/sp` | BIP-352/BIP-375 silent payment workflow: analysis, share/proof validation, script materialization, extraction checks |
| `psbt-v2/sp/dleq` | Small BIP-374 proof package |

The root package is still the PSBT library. Silent payments live in `sp` on top of it.

## Why v2?

PSBTv0 freezes the unsigned transaction as a single global blob at creation time. Once you call `New()`, the inputs and outputs are fixed. That makes incremental multi-party construction awkward.

PSBTv2 decomposes the transaction into first-class per-input and per-output fields:

- per-input prevout and sequence fields instead of a monolithic `UnsignedTx`
- per-output amount and script fields
- `TxModifiable` flags for controlled mutation
- per-input locktime requirements with deterministic locktime resolution

That makes packet mutation, conversion, and higher-level workflows much cleaner.

## Is This LLM Slop?

About 60% non-slop.

There is obviously AI assistance in here. I still try to keep it grounded in the BIPs, btcd's original `psbt` package, and real test vectors instead of letting it freestyle nonsense. If something looks off, open an issue.

## Examples

### Basic v2 construction

```go
modifiable := uint8(0x03) // inputs + outputs modifiable
pkt, _ := psbt.NewV2(2, inputs, outputs, &locktime, &modifiable)

ctor, _ := psbt.NewConstructor(pkt)
ctor.AddInput(newTxID, newIndex)
ctor.AddOutput(amount, script)
```

### Silent payment flow

```go
owned := []sp.OwnedInput{
	{Index: 0, Secret: input0Secret},
	{Index: 1, Secret: input1Secret},
}

if err := sp.AddSharesAndProofs(pkt, owned); err != nil {
	return err
}

if err := sp.MaterializeOutputs(pkt); err != nil {
	return err
}

tx, err := sp.Extract(pkt)
if err != nil {
	return err
}
_ = tx
```

## Status

| Area | Status |
| --- | --- |
| PSBTv0 parse / serialize / roles | Done |
| PSBTv2 parse / serialize / roles | Done |
| v0 <-> v2 conversion | Done |
| BIP-375 field transport in base package | Done |
| `sp` silent payment workflow | Done |
| `sp/dleq` BIP-374 proof package | Done |

Current caveats:

- `sp/dleq` proof generation uses btcd's variable-time arbitrary-point scalar multiplication
- there is still some general cleanup debt in validation and linting

## Highlights

- single `Packet` type with version-aware validation
- tested v0 <-> v2 conversion helpers
- BIP-375 output/input/global field support
- vector-backed `sp` tests for materialization, extraction checks, ordering, and invalid cases
- tracked BIP-374 proof vectors in `sp/dleq/testdata`

## Commands

```bash
go test -v ./...
golangci-lint run -v --timeout=5m
```

## Acknowledgments

This project is derived from [btcd's psbt package](https://github.com/btcsuite/btcd/tree/master/btcutil/psbt) by the btcsuite developers. The original v0 implementation and most of the role-based structure started there.

## License

[MIT](LICENSE)
