package psbt

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// ConvertToV2 converts a PSBTv0 packet into a PSBTv2 packet.
//
// The conversion is lossless with respect to all PSBTv0-defined semantics:
// the v0 unsigned transaction is decomposed into the PSBTv2 global/input/output
// fields while all shared PSBT metadata is preserved. In particular:
//   - UnsignedTx.Version becomes TxVersion.
//   - UnsignedTx.LockTime becomes FallbackLocktime when it is non-zero.
//   - Each TxIn's prevout becomes a per-input v2 field.
//   - Each non-default TxIn sequence becomes an explicit per-input v2 field;
//     the default wire.MaxTxInSequenceNum remains implicit.
//   - Each TxOut's amount and script become per-output v2 fields.
//   - Shared PSBT data such as UTXOs, scripts, derivations, final scripts,
//     taproot data, XPubs, and unknowns are deep-copied and preserved.
//
// The conversion does not invent v2-only semantics that never existed in the
// v0 packet:
//   - TxModifiable is left nil.
//   - RequiredTimeLocktime / RequiredHeightLocktime are left nil.
//
// The returned packet is a deep copy: mutating it will not mutate the source
// packet.
func ConvertToV2(p *Packet) (*Packet, error) {
	if p == nil {
		return nil, fmt.Errorf("packet cannot be nil")
	}
	if p.Version != 0 {
		return nil, fmt.Errorf("packet is not v0")
	}
	if err := p.SanityCheck(); err != nil {
		return nil, err
	}
	if p.UnsignedTx == nil {
		return nil, ErrInvalidPsbtFormat
	}

	result := &Packet{
		Version: 2,
		// v0 stores tx version inside UnsignedTx, so carry it into the
		// dedicated v2 global field.
		TxVersion: p.UnsignedTx.Version,
		Inputs:    make([]PInput, len(p.Inputs)),
		Outputs:   make([]POutput, len(p.Outputs)),
		XPubs:     cloneXPubs(p.XPubs),
		Unknowns:  cloneUnknowns(p.Unknowns),
	}

	// Keep the v2 packet minimal: a zero locktime is represented by an absent
	// fallback locktime, while a non-zero v0 locktime is preserved exactly.
	if p.UnsignedTx.LockTime != 0 {
		locktime := p.UnsignedTx.LockTime
		result.FallbackLocktime = &locktime
	}

	for i := range p.Inputs {
		in := clonePInput(p.Inputs[i])
		txIn := p.UnsignedTx.TxIn[i]

		prevTxID := txIn.PreviousOutPoint.Hash
		outputIndex := txIn.PreviousOutPoint.Index
		in.PreviousTxID = &prevTxID
		in.OutputIndex = &outputIndex
		// Keep v2 minimal: the default nSequence is implicit and recovered by
		// inputSequence() when the field is absent.
		if txIn.Sequence != wire.MaxTxInSequenceNum {
			sequence := txIn.Sequence
			in.Sequence = &sequence
		} else {
			in.Sequence = nil
		}
		// v0 has no per-input locktime requirements.
		in.RequiredTimeLocktime = nil
		in.RequiredHeightLocktime = nil

		result.Inputs[i] = in
	}

	for i := range p.Outputs {
		out := clonePOutput(p.Outputs[i])
		txOut := p.UnsignedTx.TxOut[i]

		amount := txOut.Value
		out.Amount = &amount
		out.Script = cloneBytes(txOut.PkScript)

		result.Outputs[i] = out
	}

	if err := result.SanityCheck(); err != nil {
		return nil, err
	}

	return result, nil
}

// ConvertToV0 converts a PSBTv2 packet into a PSBTv0 packet.
//
// This conversion is intentionally lossy because PSBTv0 has no representation
// for several v2-only concepts. The returned v0 packet preserves all shared
// PSBT metadata, but folds structural v2 fields back into the reconstructed
// unsigned transaction:
//   - TxVersion, prevouts, sequences, amounts, scripts, and the resolved
//     locktime are baked into UnsignedTx.
//   - Shared PSBT data such as UTXOs, scripts, derivations, final scripts,
//     taproot data, XPubs, and unknowns are deep-copied and preserved.
//
// The following v2-only fields are dropped because PSBTv0 has nowhere to store
// them explicitly:
//   - TxModifiable.
//   - FallbackLocktime as a named field (its effect is preserved in
//     UnsignedTx.LockTime via buildUnsignedTx()).
//   - RequiredTimeLocktime / RequiredHeightLocktime.
//   - PreviousTxID / OutputIndex / Sequence as standalone input fields.
//   - Amount / Script as standalone output fields.
//
// If the v2 packet cannot be materialized into a valid unsigned transaction
// (for example because locktime requirements are incompatible), conversion
// fails with an error.
//
// The returned packet is a deep copy: mutating it will not mutate the source
// packet.
func ConvertToV0(p *Packet) (*Packet, error) {
	if p == nil {
		return nil, fmt.Errorf("packet cannot be nil")
	}
	if p.Version != 2 {
		return nil, fmt.Errorf("packet is not v2")
	}
	if err := p.SanityCheck(); err != nil {
		return nil, err
	}

	unsignedTx, err := p.buildUnsignedTx()
	if err != nil {
		return nil, err
	}

	// Build a fresh v0 packet rather than cloning the v2 packet so v2-only
	// global fields such as FallbackLocktime and TxModifiable are naturally
	// absent in the result.
	result := &Packet{
		Version:    0,
		UnsignedTx: unsignedTx,
		Inputs:     make([]PInput, len(p.Inputs)),
		Outputs:    make([]POutput, len(p.Outputs)),
		XPubs:      cloneXPubs(p.XPubs),
		Unknowns:   cloneUnknowns(p.Unknowns),
	}

	for i := range p.Inputs {
		in := clonePInput(p.Inputs[i])
		in.PreviousTxID = nil
		in.OutputIndex = nil
		in.Sequence = nil
		in.RequiredTimeLocktime = nil
		in.RequiredHeightLocktime = nil

		result.Inputs[i] = in
	}

	for i := range p.Outputs {
		out := clonePOutput(p.Outputs[i])
		out.Amount = nil
		out.Script = nil

		result.Outputs[i] = out
	}

	if err := result.SanityCheck(); err != nil {
		return nil, err
	}

	return result, nil
}

func cloneBytes(src []byte) []byte {
	if src == nil {
		return nil
	}

	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func cloneUnknowns(src []*Unknown) []*Unknown {
	if src == nil {
		return nil
	}

	dst := make([]*Unknown, len(src))
	for i, item := range src {
		if item == nil {
			continue
		}
		dst[i] = &Unknown{
			Key:   cloneBytes(item.Key),
			Value: cloneBytes(item.Value),
		}
	}

	return dst
}

func clonePartialSigs(src []*PartialSig) []*PartialSig {
	if src == nil {
		return nil
	}

	dst := make([]*PartialSig, len(src))
	for i, item := range src {
		if item == nil {
			continue
		}
		dst[i] = &PartialSig{
			PubKey:    cloneBytes(item.PubKey),
			Signature: cloneBytes(item.Signature),
		}
	}

	return dst
}

func cloneBip32Derivations(src []*Bip32Derivation) []*Bip32Derivation {
	if src == nil {
		return nil
	}

	dst := make([]*Bip32Derivation, len(src))
	for i, item := range src {
		if item == nil {
			continue
		}
		path := make([]uint32, len(item.Bip32Path))
		copy(path, item.Bip32Path)

		dst[i] = &Bip32Derivation{
			PubKey:               cloneBytes(item.PubKey),
			MasterKeyFingerprint: item.MasterKeyFingerprint,
			Bip32Path:            path,
		}
	}

	return dst
}

func cloneXPubs(src []XPub) []XPub {
	if src == nil {
		return nil
	}

	dst := make([]XPub, len(src))
	for i, item := range src {
		path := make([]uint32, len(item.Bip32Path))
		copy(path, item.Bip32Path)

		dst[i] = XPub{
			ExtendedKey:          cloneBytes(item.ExtendedKey),
			MasterKeyFingerprint: item.MasterKeyFingerprint,
			Bip32Path:            path,
		}
	}

	return dst
}

func cloneTaprootScriptSpendSigs(src []*TaprootScriptSpendSig) []*TaprootScriptSpendSig {
	if src == nil {
		return nil
	}

	dst := make([]*TaprootScriptSpendSig, len(src))
	for i, item := range src {
		if item == nil {
			continue
		}
		dst[i] = &TaprootScriptSpendSig{
			XOnlyPubKey: cloneBytes(item.XOnlyPubKey),
			LeafHash:    cloneBytes(item.LeafHash),
			Signature:   cloneBytes(item.Signature),
			SigHash:     item.SigHash,
		}
	}

	return dst
}

func cloneTaprootLeafScripts(src []*TaprootTapLeafScript) []*TaprootTapLeafScript {
	if src == nil {
		return nil
	}

	dst := make([]*TaprootTapLeafScript, len(src))
	for i, item := range src {
		if item == nil {
			continue
		}
		dst[i] = &TaprootTapLeafScript{
			ControlBlock: cloneBytes(item.ControlBlock),
			Script:       cloneBytes(item.Script),
			LeafVersion:  item.LeafVersion,
		}
	}

	return dst
}

func cloneTaprootBip32Derivations(src []*TaprootBip32Derivation) []*TaprootBip32Derivation {
	if src == nil {
		return nil
	}

	dst := make([]*TaprootBip32Derivation, len(src))
	for i, item := range src {
		if item == nil {
			continue
		}

		leafHashes := make([][]byte, len(item.LeafHashes))
		for j, hash := range item.LeafHashes {
			leafHashes[j] = cloneBytes(hash)
		}

		path := make([]uint32, len(item.Bip32Path))
		copy(path, item.Bip32Path)

		dst[i] = &TaprootBip32Derivation{
			XOnlyPubKey:          cloneBytes(item.XOnlyPubKey),
			LeafHashes:           leafHashes,
			MasterKeyFingerprint: item.MasterKeyFingerprint,
			Bip32Path:            path,
		}
	}

	return dst
}

func cloneHashPtr(src *chainhash.Hash) *chainhash.Hash {
	if src == nil {
		return nil
	}
	hash := *src
	return &hash
}

func cloneUint32Ptr(src *uint32) *uint32 {
	if src == nil {
		return nil
	}
	v := *src
	return &v
}

func cloneInt64Ptr(src *int64) *int64 {
	if src == nil {
		return nil
	}
	v := *src
	return &v
}

func cloneTxOut(src *wire.TxOut) *wire.TxOut {
	if src == nil {
		return nil
	}

	return wire.NewTxOut(src.Value, cloneBytes(src.PkScript))
}

func clonePInput(src PInput) PInput {
	dst := src
	dst.NonWitnessUtxo = nil
	if src.NonWitnessUtxo != nil {
		dst.NonWitnessUtxo = src.NonWitnessUtxo.Copy()
	}
	dst.WitnessUtxo = cloneTxOut(src.WitnessUtxo)
	dst.PartialSigs = clonePartialSigs(src.PartialSigs)
	dst.RedeemScript = cloneBytes(src.RedeemScript)
	dst.WitnessScript = cloneBytes(src.WitnessScript)
	dst.Bip32Derivation = cloneBip32Derivations(src.Bip32Derivation)
	dst.FinalScriptSig = cloneBytes(src.FinalScriptSig)
	dst.FinalScriptWitness = cloneBytes(src.FinalScriptWitness)
	dst.TaprootKeySpendSig = cloneBytes(src.TaprootKeySpendSig)
	dst.TaprootScriptSpendSig = cloneTaprootScriptSpendSigs(
		src.TaprootScriptSpendSig,
	)
	dst.TaprootLeafScript = cloneTaprootLeafScripts(src.TaprootLeafScript)
	dst.TaprootBip32Derivation = cloneTaprootBip32Derivations(
		src.TaprootBip32Derivation,
	)
	dst.TaprootInternalKey = cloneBytes(src.TaprootInternalKey)
	dst.TaprootMerkleRoot = cloneBytes(src.TaprootMerkleRoot)
	dst.Unknowns = cloneUnknowns(src.Unknowns)
	dst.PreviousTxID = cloneHashPtr(src.PreviousTxID)
	dst.OutputIndex = cloneUint32Ptr(src.OutputIndex)
	dst.Sequence = cloneUint32Ptr(src.Sequence)
	dst.RequiredTimeLocktime = cloneUint32Ptr(src.RequiredTimeLocktime)
	dst.RequiredHeightLocktime = cloneUint32Ptr(src.RequiredHeightLocktime)

	return dst
}

func clonePOutput(src POutput) POutput {
	dst := src
	dst.RedeemScript = cloneBytes(src.RedeemScript)
	dst.WitnessScript = cloneBytes(src.WitnessScript)
	dst.Bip32Derivation = cloneBip32Derivations(src.Bip32Derivation)
	dst.TaprootInternalKey = cloneBytes(src.TaprootInternalKey)
	dst.TaprootTapTree = cloneBytes(src.TaprootTapTree)
	dst.TaprootBip32Derivation = cloneTaprootBip32Derivations(
		src.TaprootBip32Derivation,
	)
	dst.Unknowns = cloneUnknowns(src.Unknowns)
	dst.Amount = cloneInt64Ptr(src.Amount)
	dst.Script = cloneBytes(src.Script)

	return dst
}
