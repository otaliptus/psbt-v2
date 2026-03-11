package psbt

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// InPlaceSort modifies the passed packet's inputs and outputs to be sorted
// based on BIP 69. The sorting happens in a way that the packet's partial
// inputs and outputs are also modified to match the sorted order.
//
// For v0, both the wire TxIn/TxOut and the partial Inputs/Outputs are swapped
// together. For v2 (where UnsignedTx is nil), only the partial slices are
// sorted using the per-input/output field accessors.
//
// WARNING: This function must NOT be called with packets that already contain
// (partial) signatures or finalized scripts since sorting changes prevout
// ordering and invalidates any existing signature data.
func InPlaceSort(packet *Packet) error {
	// Sanity check: packet must be non-nil, a recognized version, and
	// structurally valid.
	err := VerifyInputOutputLen(packet, false, false)
	if err != nil {
		return err
	}

	// Reject packets that have any signatures or finalized scripts.
	// Sorting after signing silently invalidates signatures, which is
	// dangerous for both v0 and v2.
	for i, in := range packet.Inputs {
		if len(in.PartialSigs) > 0 || in.FinalScriptSig != nil ||
			in.FinalScriptWitness != nil ||
			in.TaprootKeySpendSig != nil ||
			len(in.TaprootScriptSpendSig) > 0 {

			return fmt.Errorf("input %d has signature data; "+
				"sorting after signing is not safe", i)
		}
	}

	// For v2, verify that all inputs and outputs have the fields that
	// Less() needs. Without this, missing PreviousTxID/OutputIndex or
	// Amount/Script would be silently treated as zero values, producing
	// a non-canonical ordering.
	if packet.Version == 2 {
		for i, in := range packet.Inputs {
			if in.PreviousTxID == nil || in.OutputIndex == nil {
				return fmt.Errorf("v2 input %d missing "+
					"PreviousTxID or OutputIndex", i)
			}
		}
		for i, out := range packet.Outputs {
			if out.Amount == nil || out.Script == nil {
				return fmt.Errorf("v2 output %d missing "+
					"Amount or Script", i)
			}
		}
	}

	sort.Sort(&sortableInputs{p: packet})
	sort.Sort(&sortableOutputs{p: packet})

	return nil
}

// sortableInputs is a simple wrapper around a packet that implements the
// sort.Interface for sorting the wire and partial inputs of a packet.
type sortableInputs struct {
	p *Packet
}

// sortableOutputs is a simple wrapper around a packet that implements the
// sort.Interface for sorting the wire and partial outputs of a packet.
type sortableOutputs struct {
	p *Packet
}

// For sortableInputs and sortableOutputs, three functions are needed to make
// them sortable with sort.Sort() -- Len, Less, and Swap.
// Len and Swap are trivial. Less is BIP 69 specific.
func (s *sortableInputs) Len() int { return len(s.p.Inputs) }
func (s sortableOutputs) Len() int { return len(s.p.Outputs) }

// Swap swaps two inputs. For v0 the wire TxIn is also swapped.
func (s *sortableInputs) Swap(i, j int) {
	if s.p.UnsignedTx != nil {
		tx := s.p.UnsignedTx
		tx.TxIn[i], tx.TxIn[j] = tx.TxIn[j], tx.TxIn[i]
	}
	s.p.Inputs[i], s.p.Inputs[j] = s.p.Inputs[j], s.p.Inputs[i]
}

// Swap swaps two outputs. For v0 the wire TxOut is also swapped.
func (s *sortableOutputs) Swap(i, j int) {
	if s.p.UnsignedTx != nil {
		tx := s.p.UnsignedTx
		tx.TxOut[i], tx.TxOut[j] = tx.TxOut[j], tx.TxOut[i]
	}
	s.p.Outputs[i], s.p.Outputs[j] = s.p.Outputs[j], s.p.Outputs[i]
}

// Less is the input comparison function. First sort based on input hash
// (reversed / rpc-style), then index. BIP 69 semantics are identical
// for v0 (reading from UnsignedTx.TxIn) and v2 (reading from per-input
// PreviousTxID/OutputIndex via inputPrevOutpoint).
func (s *sortableInputs) Less(i, j int) bool {
	// inputPrevOutpoint is version-aware and returns the correct prevout
	// for both v0 and v2.
	iOut, _ := s.p.inputPrevOutpoint(i)
	jOut, _ := s.p.inputPrevOutpoint(j)

	ihash := iOut.Hash
	jhash := jOut.Hash
	if ihash == jhash {
		return iOut.Index < jOut.Index
	}

	// At this point, the hashes are not equal, so reverse them to
	// big-endian and return the result of the comparison.
	const hashSize = chainhash.HashSize
	for b := 0; b < hashSize/2; b++ {
		ihash[b], ihash[hashSize-1-b] = ihash[hashSize-1-b], ihash[b]
		jhash[b], jhash[hashSize-1-b] = jhash[hashSize-1-b], jhash[b]
	}
	return bytes.Compare(ihash[:], jhash[:]) == -1
}

// Less is the output comparison function. First sort based on amount (smallest
// first), then PkScript. Uses version-aware accessors for v2 compatibility.
func (s *sortableOutputs) Less(i, j int) bool {
	// outputAmount and outputScript are version-aware.
	iAmt, _ := s.p.outputAmount(i)
	jAmt, _ := s.p.outputAmount(j)

	if iAmt == jAmt {
		iScript, _ := s.p.outputScript(i)
		jScript, _ := s.p.outputScript(j)
		return bytes.Compare(iScript, jScript) < 0
	}
	return iAmt < jAmt
}
