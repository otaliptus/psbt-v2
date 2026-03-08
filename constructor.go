package psbt

import "github.com/btcsuite/btcd/chaincfg/chainhash"

// Constructor enables incremental modification of a PSBTv2 packet.
// It enforces the PSBT_GLOBAL_TX_MODIFIABLE bitfield: inputs may only be
// added or removed when bit 0 is set, and outputs when bit 1 is set.
//
// Mutation is rejected outright if any input already contains signature
// material (partial sigs, taproot sigs, or final scripts), since modifying
// the transaction structure would silently invalidate those signatures.
//
// When bit 2 (Has SIGHASH_SINGLE) is set, one-sided add/remove operations
// are rejected because they would break the required input↔output index
// pairing. Full paired mutation APIs may be added in a future phase.
//
// This implements the BIP-370 Constructor role.
type Constructor struct {
	Pkt *Packet
}

// NewConstructor wraps a v2 Packet for incremental modification.
// Returns an error if the packet is nil, not version 2, or fails
// SanityCheck.
func NewConstructor(p *Packet) (*Constructor, error) {
	if p == nil || p.Version != 2 {
		return nil, ErrInvalidPsbtFormat
	}

	if err := p.SanityCheck(); err != nil {
		return nil, err
	}

	return &Constructor{Pkt: p}, nil
}

// AddInput appends a new input identified by its previous outpoint.
// Returns ErrInputsNotModifiable if the Inputs Modifiable flag is not set.
func (c *Constructor) AddInput(prevTxID chainhash.Hash, outputIndex uint32) error {
	if !c.inputsModifiable() {
		return ErrInputsNotModifiable
	}

	if err := c.checkMutable(); err != nil {
		return err
	}

	txid := prevTxID
	idx := outputIndex
	c.Pkt.Inputs = append(c.Pkt.Inputs, PInput{
		PreviousTxID: &txid,
		OutputIndex:  &idx,
	})

	return nil
}

// AddOutput appends a new output with the given amount and scriptPubKey.
// Returns ErrOutputsNotModifiable if the Outputs Modifiable flag is not set.
func (c *Constructor) AddOutput(amount int64, script []byte) error {
	if !c.outputsModifiable() {
		return ErrOutputsNotModifiable
	}

	if err := c.checkMutable(); err != nil {
		return err
	}

	if amount < 0 {
		return ErrInvalidPsbtFormat
	}

	a := amount
	s := make([]byte, len(script))
	copy(s, script)

	c.Pkt.Outputs = append(c.Pkt.Outputs, POutput{
		Amount: &a,
		Script: s,
	})

	return nil
}

// RemoveInput removes the input at the given index.
// Returns ErrInputsNotModifiable if the flag is not set, or
// ErrInvalidPsbtFormat if the index is out of range.
func (c *Constructor) RemoveInput(index int) error {
	if !c.inputsModifiable() {
		return ErrInputsNotModifiable
	}

	if err := c.checkMutable(); err != nil {
		return err
	}

	if index < 0 || index >= len(c.Pkt.Inputs) {
		return ErrInvalidPsbtFormat
	}

	c.Pkt.Inputs = append(
		c.Pkt.Inputs[:index], c.Pkt.Inputs[index+1:]...,
	)

	return nil
}

// RemoveOutput removes the output at the given index.
// Returns ErrOutputsNotModifiable if the flag is not set, or
// ErrInvalidPsbtFormat if the index is out of range.
func (c *Constructor) RemoveOutput(index int) error {
	if !c.outputsModifiable() {
		return ErrOutputsNotModifiable
	}

	if err := c.checkMutable(); err != nil {
		return err
	}

	if index < 0 || index >= len(c.Pkt.Outputs) {
		return ErrInvalidPsbtFormat
	}

	c.Pkt.Outputs = append(
		c.Pkt.Outputs[:index], c.Pkt.Outputs[index+1:]...,
	)

	return nil
}

// checkMutable returns an error if the packet must not be mutated.
// Two conditions block mutation:
//   - Any input contains signature material (partial sigs, taproot sigs,
//     or final scripts). Mutating the tx structure would invalidate them.
//   - Bit 2 of TxModifiable (Has SIGHASH_SINGLE) is set, which requires
//     strict input↔output index pairing that one-sided mutations break.
func (c *Constructor) checkMutable() error {
	if c.hasSignatureMaterial() {
		return ErrSignaturesExist
	}

	if c.hasSighashSingleBit() {
		return ErrSighashSinglePairing
	}

	return nil
}

// hasSignatureMaterial returns true if any input in the packet already
// contains partial signatures, taproot signatures, or finalized scripts.
func (c *Constructor) hasSignatureMaterial() bool {
	for _, in := range c.Pkt.Inputs {
		if len(in.PartialSigs) > 0 {
			return true
		}

		if in.TaprootKeySpendSig != nil {
			return true
		}

		if len(in.TaprootScriptSpendSig) > 0 {
			return true
		}

		if in.FinalScriptSig != nil {
			return true
		}

		if in.FinalScriptWitness != nil {
			return true
		}
	}

	return false
}

// hasSighashSingleBit returns true if bit 2 of TxModifiable is set.
func (c *Constructor) hasSighashSingleBit() bool {
	if c.Pkt.TxModifiable == nil {
		return false
	}

	return *c.Pkt.TxModifiable&0x04 != 0
}

// inputsModifiable returns true if bit 0 of TxModifiable is set.
func (c *Constructor) inputsModifiable() bool {
	if c.Pkt.TxModifiable == nil {
		return false
	}

	return *c.Pkt.TxModifiable&0x01 != 0
}

// outputsModifiable returns true if bit 1 of TxModifiable is set.
func (c *Constructor) outputsModifiable() bool {
	if c.Pkt.TxModifiable == nil {
		return false
	}

	return *c.Pkt.TxModifiable&0x02 != 0
}
