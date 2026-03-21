# `sp/dleq`

Small BIP-374 package.

This package only does DLEQ proofs over secp256k1:

- `GenerateProof(secret, B, auxRand, G, message) (Proof, error)`
- `VerifyProof(A, B, C, proof, G, message) bool`

It does not know anything about PSBT, BIP-375 roles, or silent payment packet
layout. That belongs in the higher-level `sp` package.

## Warning

`GenerateProof` currently uses btcd's scalar multiplication.

That is fine for interop and test vectors. It is not the thing to
use if private-key timing/cache/EM side-channel attackers are in scope.

## Vectors

Reference vectors live in [`testdata/`](testdata):

- `test_vectors_generate_proof.csv`
- `test_vectors_verify_proof.csv`

They are copied from the BIP-374 reference material so `go test ./...` works
from a clean checkout.

## Minimal Use

```go
proof, err := dleq.GenerateProof(secret, B, auxRand, G, message)
if err != nil {
	return err
}

if !dleq.VerifyProof(A, B, C, proof, G, message) {
	return errors.New("invalid proof")
}
```
