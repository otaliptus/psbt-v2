# `sp`

Silent payment workflow layer on top of the base `psbt-v2` package.

This package owns the BIP-352 / BIP-375 logic that does not belong in the core
PSBT parser:

- packet analysis for eligible inputs and silent-payment outputs
- share / proof generation for owned inputs
- share / proof verification for existing packet data
- output ordering and `k` assignment
- output script materialization
- extractor-side validation

It does not replace the root package. The base `psbt-v2` package still owns
packet parsing, serialization, conversion, and generic extraction.

`sp/dleq` is the lower-level BIP-374 proof primitive. This package uses it, but
keeps the PSBT-specific workflow here.

## Typical Flow

Signer side:

```go
owned := []sp.OwnedInput{
	{Index: 0, Secret: input0Secret},
	{Index: 1, Secret: input1Secret},
}

if err := sp.AddSharesAndProofs(pkt, owned); err != nil {
	return err
}

if err := sp.ValidateReadyToSign(pkt); err != nil {
	return err
}
```

Coordinator or extractor side:

```go
if err := sp.MaterializeOutputs(pkt); err != nil {
	return err
}

tx, err := sp.Extract(pkt)
if err != nil {
	return err
}
_ = tx
```
