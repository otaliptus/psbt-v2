// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psbt

import (
	"github.com/btcsuite/btcd/wire"
)

// MinTxVersion is the lowest transaction version that we'll permit.
const MinTxVersion = 1

// New on provision of an input and output 'skeleton' for the transaction, a
// new partially populated PBST packet. The populated packet will include the
// unsigned transaction, and the set of known inputs and outputs contained
// within the unsigned transaction.  The values of nLockTime, nSequence (per
// input) and transaction version (must be 1 of 2) must be specified here. Note
// that the default nSequence value is wire.MaxTxInSequenceNum.  Referencing
// the PSBT BIP, this function serves the roles of the Creator.
func New(inputs []*wire.OutPoint,
	outputs []*wire.TxOut, version int32, nLockTime uint32,
	nSequences []uint32) (*Packet, error) {

	// Create the new struct; the input and output lists will be empty, the
	// unsignedTx object must be constructed and serialized, and that
	// serialization should be entered as the only entry for the
	// globalKVPairs list.
	//
	// Ensure that the version of the transaction is greater then our
	// minimum allowed transaction version. There must be one sequence
	// number per input.
	if version < MinTxVersion || len(nSequences) != len(inputs) {
		return nil, ErrInvalidPsbtFormat
	}

	unsignedTx := wire.NewMsgTx(version)
	unsignedTx.LockTime = nLockTime
	for i, in := range inputs {
		unsignedTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: *in,
			Sequence:         nSequences[i],
		})
	}
	for _, out := range outputs {
		unsignedTx.AddTxOut(out)
	}

	// The input and output lists are empty, but there is a list of those
	// two lists, and each one must be of length matching the unsigned
	// transaction; the unknown list can be nil.
	pInputs := make([]PInput, len(unsignedTx.TxIn))
	pOutputs := make([]POutput, len(unsignedTx.TxOut))

	// This new Psbt is "raw" and contains no key-value fields, so sanity
	// checking with c.Cpsbt.SanityCheck() is not required.
	return &Packet{
		Version:    0,
		UnsignedTx: unsignedTx,
		Inputs:     pInputs,
		Outputs:    pOutputs,
		Unknowns:   nil,
	}, nil
}

// NewV2 creates a PSBTv2 packet from per-input outpoints and per-output
// amount/script pairs. This implements the BIP-370 Creator role: the returned
// packet contains the required v2 global fields and per-input/per-output
// fields but no signatures, scripts, or derivation data.
//
// fallbackLocktime and txModifiable may be nil if not needed.
func NewV2(
	txVersion int32,
	inputs []wire.OutPoint,
	outputs []*wire.TxOut,
	fallbackLocktime *uint32,
	txModifiable *uint8,
) (*Packet, error) {

	if txVersion < MinTxVersion {
		return nil, ErrInvalidPsbtFormat
	}

	pInputs := make([]PInput, len(inputs))
	for i, op := range inputs {
		txid := op.Hash
		idx := op.Index
		pInputs[i] = PInput{
			PreviousTxID: &txid,
			OutputIndex:  &idx,
		}
	}

	pOutputs := make([]POutput, len(outputs))
	for i, out := range outputs {
		if out == nil {
			return nil, ErrInvalidPsbtFormat
		}

		if out.Value < 0 {
			return nil, ErrInvalidPsbtFormat
		}

		amount := out.Value
		script := make([]byte, len(out.PkScript))
		copy(script, out.PkScript)

		pOutputs[i] = POutput{
			Amount: &amount,
			Script: script,
		}
	}

	// Copy optional pointer args so the caller can't mutate packet state.
	var fl *uint32
	if fallbackLocktime != nil {
		v := *fallbackLocktime
		fl = &v
	}

	var mod *uint8
	if txModifiable != nil {
		v := *txModifiable
		mod = &v
	}

	pkt := &Packet{
		Version:          2,
		TxVersion:        txVersion,
		FallbackLocktime: fl,
		TxModifiable:     mod,
		Inputs:           pInputs,
		Outputs:          pOutputs,
	}

	if err := pkt.SanityCheck(); err != nil {
		return nil, err
	}

	return pkt, nil
}
