# psbt-v2

Go PSBT library with:

- full [BIP-174 (PSBTv0)](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) support
- full [BIP-370 (PSBTv2)](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki) support
- [BIP-375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki) field transport (silent payment ECDH shares, DLEQ proofs, SP output info)

The silent payment workflow (`sp/`) and DLEQ proof math (`sp/dleq/`) have been extracted to:
- [`dleq374`](https://github.com/otaliptus/dleq374) — standalone BIP-374 DLEQ proof package
- [`bip375-examples/go/sp`](https://github.com/otaliptus/bip375-examples/tree/go/v0/go/sp) — BIP-352/BIP-375 workflow

```bash
go get github.com/otaliptus/psbt-v2
```

This library handles BIP-375 field transport — parsing, serializing, and validating the six silent payment PSBT fields. It does not perform ECDH or DLEQ math itself.

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

### Silent payment output

```go
ctor, _ := psbt.NewConstructor(pkt)
ctor.AddSilentPaymentOutput(amount, scanKey, spendKey, nil)
```

For the full signing/materialization/extraction workflow, see [`bip375-examples/go/sp`](https://github.com/otaliptus/bip375-examples/tree/go/v0/go/sp).

## Status

| Area | Status |
| --- | --- |
| PSBTv0 parse / serialize / roles | Done |
| PSBTv2 parse / serialize / roles | Done |
| v0 <-> v2 conversion | Done |
| BIP-375 field transport | Done |

## Highlights

- single `Packet` type with version-aware validation
- tested v0 <-> v2 conversion helpers
- BIP-375 output/input/global field support
- BIP-375 test vector coverage for field parsing and round-trip

## Commands

```bash
go test -v ./...
golangci-lint run -v --timeout=5m
```

## Acknowledgments

This project is derived from [btcd's psbt package](https://github.com/btcsuite/btcd/tree/master/btcutil/psbt) by the btcsuite developers. The original v0 implementation and most of the role-based structure started there.

## License

[MIT](LICENSE)
