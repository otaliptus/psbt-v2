// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package psbt is an implementation of Partially Signed Bitcoin
// Transactions (PSBT). The format is defined in BIP 174:
// https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
package psbt

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
)

// psbtMagicLength is the length of the magic bytes used to signal the start of
// a serialized PSBT packet.
const psbtMagicLength = 5

var (
	// psbtMagic is the separator.
	psbtMagic = [psbtMagicLength]byte{0x70,
		0x73, 0x62, 0x74, 0xff, // = "psbt" + 0xff sep
	}
)

// MaxPsbtValueLength is the size of the largest transaction serialization
// that could be passed in a NonWitnessUtxo field. This is definitely
// less than 4M.
const MaxPsbtValueLength = 4000000

// MaxPsbtKeyLength is the length of the largest key that we'll successfully
// deserialize from the wire. Anything more will return ErrInvalidKeyData.
const MaxPsbtKeyLength = 10000

// MaxPsbtKeyValue is the maximum value of a key type in a PSBT. This maximum
// isn't specified by the BIP but used by bitcoind in various places to limit
// the number of items processed. So we use it to validate the key type in order
// to have a consistent behavior.
const MaxPsbtKeyValue = 0x02000000

var (

	// ErrInvalidPsbtFormat is a generic error for any situation in which a
	// provided Psbt serialization does not conform to the rules of BIP174.
	ErrInvalidPsbtFormat = errors.New("Invalid PSBT serialization format")

	// ErrDuplicateKey indicates that a passed Psbt serialization is invalid
	// due to having the same key repeated in the same key-value pair.
	ErrDuplicateKey = errors.New("Invalid Psbt due to duplicate key")

	// ErrInvalidKeyData indicates that a key-value pair in the PSBT
	// serialization contains data in the key which is not valid.
	ErrInvalidKeyData = errors.New("Invalid key data")

	// ErrInvalidMagicBytes indicates that a passed Psbt serialization is
	// invalid due to having incorrect magic bytes.
	ErrInvalidMagicBytes = errors.New("Invalid Psbt due to incorrect " +
		"magic bytes")

	// ErrInvalidRawTxSigned indicates that the raw serialized transaction
	// in the global section of the passed Psbt serialization is invalid
	// because it contains scriptSigs/witnesses (i.e. is fully or partially
	// signed), which is not allowed by BIP174.
	ErrInvalidRawTxSigned = errors.New("Invalid Psbt, raw transaction " +
		"must be unsigned.")

	// ErrInvalidPrevOutNonWitnessTransaction indicates that the transaction
	// hash (i.e. SHA256^2) of the fully serialized previous transaction
	// provided in the NonWitnessUtxo key-value field doesn't match the
	// prevout hash in the UnsignedTx field in the PSBT itself.
	ErrInvalidPrevOutNonWitnessTransaction = errors.New("Prevout hash " +
		"does not match the provided non-witness utxo serialization")

	// ErrInvalidSignatureForInput indicates that the signature the user is
	// trying to append to the PSBT is invalid, either because it does
	// not correspond to the previous transaction hash, or redeem script,
	// or witness script.
	// NOTE this does not include ECDSA signature checking.
	ErrInvalidSignatureForInput = errors.New("Signature does not " +
		"correspond to this input")

	// ErrInputAlreadyFinalized indicates that the PSBT passed to a
	// Finalizer already contains the finalized scriptSig or witness.
	ErrInputAlreadyFinalized = errors.New("Cannot finalize PSBT, " +
		"finalized scriptSig or scriptWitnes already exists")

	// ErrIncompletePSBT indicates that the Extractor object
	// was unable to successfully extract the passed Psbt struct because
	// it is not complete
	ErrIncompletePSBT = errors.New("PSBT cannot be extracted as it is " +
		"incomplete")

	// ErrNotFinalizable indicates that the PSBT struct does not have
	// sufficient data (e.g. signatures) for finalization
	ErrNotFinalizable = errors.New("PSBT is not finalizable")

	// ErrInvalidSigHashFlags indicates that a signature added to the PSBT
	// uses Sighash flags that are not in accordance with the requirement
	// according to the entry in PsbtInSighashType, or otherwise not the
	// default value (SIGHASH_ALL)
	ErrInvalidSigHashFlags = errors.New("Invalid Sighash Flags")

	// ErrUnsupportedScriptType indicates that the redeem script or
	// script witness given is not supported by this codebase, or is
	// otherwise not valid.
	ErrUnsupportedScriptType = errors.New("Unsupported script type")
)

// Unknown is a struct encapsulating a key-value pair for which the key type is
// unknown by this package; these fields are allowed in both the 'Global' and
// the 'Input' section of a PSBT.
type Unknown struct {
	Key   []byte
	Value []byte
}

// Packet is the actual psbt representation. It is a set of 1 + N + M
// key-value pair lists, 1 global, defining the unsigned transaction structure
// with N inputs and M outputs.  These key-value pairs can contain scripts,
// signatures, key derivations and other transaction-defining data.
type Packet struct {
	// Version is the PSBT version:
	//   0 = BIP-174 (PSBTv0)
	//   2 = BIP-370 (PSBTv2)
	//
	// A zero value defaults to v0 behavior for backward compatibility.
	Version uint32

	// UnsignedTx is the decoded unsigned transaction for this PSBT.
	// It is **required** for v0 and should be **nil** for v2.
	UnsignedTx *wire.MsgTx // Deserialization of unsigned tx

	// PSBTv2 global fields.
	// For v0 packets these remain **zero/nil**.
	TxVersion        int32   // 0x02 (32-bit LE-int per BIP)
	FallbackLocktime *uint32 // 0x03
	TxModifiable     *uint8  // 0x06

	// Inputs contains all the information needed to properly sign this
	// target input within the above transaction.
	Inputs []PInput

	// Outputs contains all information required to spend any outputs
	// produced by this PSBT.
	Outputs []POutput

	// XPubs is a list of extended public keys that can be used to derive
	// public keys used in the inputs and outputs of this transaction. It
	// should be the public key at the highest hardened derivation index so
	// that the unhardened child keys used in the transaction can be
	// derived.
	XPubs []XPub

	// Unknowns are the set of custom types (global only) within this PSBT.
	Unknowns []*Unknown
}

// validateUnsignedTx returns true if the transaction is unsigned.  Note that
// more basic sanity requirements, such as the presence of inputs and outputs,
// is implicitly checked in the call to MsgTx.Deserialize().
func validateUnsignedTX(tx *wire.MsgTx) bool {
	for _, tin := range tx.TxIn {
		if len(tin.SignatureScript) != 0 || len(tin.Witness) != 0 {
			return false
		}
	}

	return true
}

// NewFromUnsignedTx creates a new Psbt struct, without any signatures (i.e.
// only the global section is non-empty) using the passed unsigned transaction.
func NewFromUnsignedTx(tx *wire.MsgTx) (*Packet, error) {
	if !validateUnsignedTX(tx) {
		return nil, ErrInvalidRawTxSigned
	}

	inSlice := make([]PInput, len(tx.TxIn))
	outSlice := make([]POutput, len(tx.TxOut))
	xPubSlice := make([]XPub, 0)
	unknownSlice := make([]*Unknown, 0)

	return &Packet{
		UnsignedTx: tx,
		Inputs:     inSlice,
		Outputs:    outSlice,
		XPubs:      xPubSlice,
		Unknowns:   unknownSlice,
	}, nil
}

// TODO: CHECK
func decodeCompactSizeValue(value []byte) (int, error) {
	reader := bytes.NewReader(value)

	count, err := wire.ReadVarInt(reader, 0)
	if err != nil {
		return 0, ErrInvalidPsbtFormat
	}
	if reader.Len() != 0 {
		return 0, ErrInvalidPsbtFormat
	}

	maxInt := int(^uint(0) >> 1)
	if count > uint64(maxInt) {
		return 0, ErrInvalidPsbtFormat
	}

	return int(count), nil
}

// /////////////////// PSBTv2 ///////////////////
// parseGlobalmap reads the entire global map before any input/output parsing.
// This exists because PSBTv2 cannot be identified by assuming the first global
// key is `PSBT_GLOBAL_UNSIGNED_TX` like PSBTv0.
// It sounds good to collect all global fields first,
// decide whether the packet is v0 or v2, validate the required
// and forbidden globals for that version, and return the input/output counts
// that determine how many maps the rest of NewFromRawBytes should read.
func parseGlobalMap(r io.Reader) (*Packet, int, int, error) {
	var (
		unsignedTx       *wire.MsgTx
		version          *uint32
		txVersion        *int32
		fallbackLocktime *uint32
		inputCount       *int
		outputCount      *int
		txModifiable     *uint8
		xPubSlice        []XPub
		unknownSlice     []*Unknown
	)

	for {
		keyCode, keyData, err := getKey(r)
		if err != nil {
			return nil, 0, 0, err
		}
		if keyCode == -1 {
			break
		}

		value, err := wire.ReadVarBytes(r, 0, MaxPsbtValueLength, "PSBT value")
		if err != nil {
			return nil, 0, 0, err
		}

		switch GlobalType(keyCode) {
		case UnsignedTxType:
			if keyData != nil {
				err := appendUnknownKV(&unknownSlice, keyCode, keyData, value)
				if err != nil {
					return nil, 0, 0, err
				}
				continue
			}
			if unsignedTx != nil {
				return nil, 0, 0, ErrDuplicateKey
			}

			msgTx := wire.NewMsgTx(2)
			err := msgTx.DeserializeNoWitness(bytes.NewReader(value))
			if err != nil {
				return nil, 0, 0, err
			}
			if !validateUnsignedTX(msgTx) {
				return nil, 0, 0, ErrInvalidRawTxSigned
			}

			unsignedTx = msgTx

		case XPubType:
			xPub, err := ReadXPub(keyData, value)
			if err != nil {
				return nil, 0, 0, err
			}

			for _, x := range xPubSlice {
				if bytes.Equal(x.ExtendedKey, keyData) {
					return nil, 0, 0, ErrDuplicateKey
				}
			}

			xPubSlice = append(xPubSlice, *xPub)

		case TxVersionType:
			if keyData != nil {
				err := appendUnknownKV(&unknownSlice, keyCode, keyData, value)
				if err != nil {
					return nil, 0, 0, err
				}
				continue
			}
			if txVersion != nil {
				return nil, 0, 0, ErrDuplicateKey
			}
			if len(value) != 4 {
				return nil, 0, 0, ErrInvalidPsbtFormat
			}

			v := int32(binary.LittleEndian.Uint32(value))
			txVersion = &v

		case FallbackLocktimeType:
			if keyData != nil {
				err := appendUnknownKV(&unknownSlice, keyCode, keyData, value)
				if err != nil {
					return nil, 0, 0, err
				}
				continue
			}
			if fallbackLocktime != nil {
				return nil, 0, 0, ErrDuplicateKey
			}
			if len(value) != 4 {
				return nil, 0, 0, ErrInvalidPsbtFormat
			}

			v := binary.LittleEndian.Uint32(value)
			fallbackLocktime = &v

		case InputCountType:
			if keyData != nil {
				err := appendUnknownKV(&unknownSlice, keyCode, keyData, value)
				if err != nil {
					return nil, 0, 0, err
				}
				continue
			}
			if inputCount != nil {
				return nil, 0, 0, ErrDuplicateKey
			}

			count, err := decodeCompactSizeValue(value)
			if err != nil {
				return nil, 0, 0, err
			}
			inputCount = &count

		case OutputCountType:
			if keyData != nil {
				err := appendUnknownKV(&unknownSlice, keyCode, keyData, value)
				if err != nil {
					return nil, 0, 0, err
				}
				continue
			}
			if outputCount != nil {
				return nil, 0, 0, ErrDuplicateKey
			}

			count, err := decodeCompactSizeValue(value)
			if err != nil {
				return nil, 0, 0, err
			}
			outputCount = &count

		case TxModifiableType:
			if keyData != nil {
				err := appendUnknownKV(&unknownSlice, keyCode, keyData, value)
				if err != nil {
					return nil, 0, 0, err
				}
				continue
			}
			if txModifiable != nil {
				return nil, 0, 0, ErrDuplicateKey
			}
			if len(value) != 1 {
				return nil, 0, 0, ErrInvalidPsbtFormat
			}

			v := value[0]
			txModifiable = &v

		case VersionType:
			if keyData != nil {
				err := appendUnknownKV(&unknownSlice, keyCode, keyData, value)
				if err != nil {
					return nil, 0, 0, err
				}
				continue
			}
			if version != nil {
				return nil, 0, 0, ErrDuplicateKey
			}
			if len(value) != 4 {
				return nil, 0, 0, ErrInvalidPsbtFormat
			}

			v := binary.LittleEndian.Uint32(value)
			version = &v

		// TODO(check): Should this go to unknown?
		case ProprietaryGlobalType:
			err := appendUnknownKV(&unknownSlice, keyCode, keyData, value)
			if err != nil {
				return nil, 0, 0, err
			}

		default:
			err := appendUnknownKV(&unknownSlice, keyCode, keyData, value)
			if err != nil {
				return nil, 0, 0, err
			}
		}
	}

	psbtVersion := uint32(0)

	if version != nil {
		psbtVersion = *version
	}

	switch psbtVersion {
	case 0:
		if unsignedTx == nil {
			// pov: visible confusion ¯\_(ツ)_/¯
			return nil, 0, 0, ErrInvalidPsbtFormat
		}
		if txVersion != nil || fallbackLocktime != nil || inputCount != nil || outputCount != nil || txModifiable != nil {
			return nil, 0, 0, ErrInvalidPsbtFormat
		}
		return &Packet{
			Version:    0,
			UnsignedTx: unsignedTx,
			XPubs:      xPubSlice,
			Unknowns:   unknownSlice,
		}, len(unsignedTx.TxIn), len(unsignedTx.TxOut), nil

	case 2:
		if unsignedTx != nil {
			return nil, 0, 0, ErrInvalidPsbtFormat
		}
		if txVersion == nil || inputCount == nil || outputCount == nil {
			return nil, 0, 0, ErrInvalidPsbtFormat
		}

		return &Packet{
			Version:          2,
			TxVersion:        *txVersion,
			FallbackLocktime: fallbackLocktime,
			TxModifiable:     txModifiable,
			XPubs:            xPubSlice,
			Unknowns:         unknownSlice,
		}, *inputCount, *outputCount, nil
	default:
		return nil, 0, 0, ErrInvalidPsbtFormat
	}
}

// NewFromRawBytes returns a new instance of a Packet struct created by reading
// from a byte slice. If the format is invalid, an error is returned. If the
// argument b64 is true, the passed byte slice is decoded from base64 encoding
// before processing.
//
// NOTE: To create a Packet from one's own data, rather than reading in a
// serialization from a counterparty, one should use a psbt.New.
func NewFromRawBytes(r io.Reader, b64 bool) (*Packet, error) {
	// If the PSBT is base64 encoded, wrap the reader in a streaming decoder
	// before doing any PSBT parsing.
	if b64 {
		based64EncodedReader := r
		r = base64.NewDecoder(base64.StdEncoding, based64EncodedReader)
	}

	// The Packet struct does not store the fixed magic bytes, but they must
	// be present or the serialization must be explicitly rejected.
	var magic [psbtMagicLength]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, err
	}
	if magic != psbtMagic {
		return nil, ErrInvalidMagicBytes
	}

	// Parse the entire global map first. Unlike the old v0-only flow, we
	// cannot assume the first global key is PSBT_GLOBAL_UNSIGNED_TX because
	// PSBTv2 determines packet structure from version-aware global fields.
	pkt, inputCount, outputCount, err := parseGlobalMap(r)
	if err != nil {
		return nil, err
	}

	// With the global map parsed and the packet version decided, we now know
	// exactly how many input maps to read.
	inSlice := make([]PInput, inputCount)
	for i := 0; i < inputCount; i++ {
		input := PInput{}
		err = input.deserialize(r)
		if err != nil {
			return nil, err
		}

		inSlice[i] = input
	}

	// Likewise, the parsed global state tells us how many output maps follow.
	outSlice := make([]POutput, outputCount)
	for i := 0; i < outputCount; i++ {
		output := POutput{}
		err = output.deserialize(r)
		if err != nil {
			return nil, err
		}

		outSlice[i] = output
	}

	// Populate the Packet with the parsed input/output maps.
	pkt.Inputs = inSlice
	pkt.Outputs = outSlice

	// Extended sanity checking is applied here to ensure the parsed packet
	// obeys the rules for its PSBT version.
	if err = pkt.SanityCheck(); err != nil {
		return nil, err
	}

	return pkt, nil
}

// Serialize creates a binary serialization of the referenced Packet struct
// with lexicographical ordering (by key) of the subsections.
func (p *Packet) Serialize(w io.Writer) error {
	// First we write out the precise set of magic bytes that identify a
	// valid PSBT transaction.
	if _, err := w.Write(psbtMagic[:]); err != nil {
		return err
	}

	// Next we prep to write out the unsigned transaction by first
	// serializing it into an intermediate buffer.
	serializedTx := bytes.NewBuffer(
		make([]byte, 0, p.UnsignedTx.SerializeSize()),
	)
	if err := p.UnsignedTx.SerializeNoWitness(serializedTx); err != nil {
		return err
	}

	// Now that we have the serialized transaction, we'll write it out to
	// the proper global type.
	err := serializeKVPairWithType(
		w, uint8(UnsignedTxType), nil, serializedTx.Bytes(),
	)
	if err != nil {
		return err
	}

	// Serialize the global xPubs.
	for _, xPub := range p.XPubs {
		pathBytes := SerializeBIP32Derivation(
			xPub.MasterKeyFingerprint, xPub.Bip32Path,
		)
		err := serializeKVPairWithType(
			w, uint8(XPubType), xPub.ExtendedKey, pathBytes,
		)
		if err != nil {
			return err
		}
	}

	// Unknown is a special case; we don't have a key type, only a key and
	// a value field
	for _, kv := range p.Unknowns {
		err := serializeKVpair(w, kv.Key, kv.Value)
		if err != nil {
			return err
		}
	}

	// With that our global section is done, so we'll write out the
	// separator.
	separator := []byte{0x00}
	if _, err := w.Write(separator); err != nil {
		return err
	}

	for _, pInput := range p.Inputs {
		err := pInput.serialize(w)
		if err != nil {
			return err
		}

		if _, err := w.Write(separator); err != nil {
			return err
		}
	}

	for _, pOutput := range p.Outputs {
		err := pOutput.serialize(w)
		if err != nil {
			return err
		}

		if _, err := w.Write(separator); err != nil {
			return err
		}
	}

	return nil
}

// B64Encode returns the base64 encoding of the serialization of
// the current PSBT, or an error if the encoding fails.
func (p *Packet) B64Encode() (string, error) {
	var b bytes.Buffer
	if err := p.Serialize(&b); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

// IsComplete returns true only if all of the inputs are
// finalized; this is particularly important in that it decides
// whether the final extraction to a network serialized signed
// transaction will be possible.
func (p *Packet) IsComplete() bool {
	for i := 0; i < len(p.UnsignedTx.TxIn); i++ {
		if !isFinalized(p, i) {
			return false
		}
	}
	return true
}

// SanityCheck checks conditions on a PSBT to ensure that it obeys the
// rules of the PSBT version it represents.
func (p *Packet) SanityCheck() error {
	switch p.Version {
	case 0:
		// In PSBTv0 the unsigned transaction is mandatory and remains the
		// source of truth for input/output counts.
		if p.UnsignedTx == nil {
			return ErrInvalidPsbtFormat
		}
		if !validateUnsignedTX(p.UnsignedTx) {
			return ErrInvalidRawTxSigned
		}
		if len(p.Inputs) != len(p.UnsignedTx.TxIn) ||
			len(p.Outputs) != len(p.UnsignedTx.TxOut) {

			return ErrInvalidPsbtFormat
		}

	case 2:
		// In PSBTv2 the unsigned transaction must not be present; transaction
		// structure comes from version-aware global, input, and output fields.
		// p.s. I yolo'ed LLM for this one
		if p.UnsignedTx != nil {
			return ErrInvalidPsbtFormat
		}

		for _, in := range p.Inputs {
			if in.PreviousTxID == nil || in.OutputIndex == nil {
				return ErrInvalidPsbtFormat
			}
			if in.RequiredTimeLocktime != nil &&
				*in.RequiredTimeLocktime < LocktimeThreshold {

				return ErrInvalidPsbtFormat
			}
			if in.RequiredHeightLocktime != nil &&
				(*in.RequiredHeightLocktime == 0 ||
					*in.RequiredHeightLocktime >= LocktimeThreshold) {

				return ErrInvalidPsbtFormat
			}
		}

		for _, out := range p.Outputs {
			if out.Amount == nil || out.Script == nil {
				return ErrInvalidPsbtFormat
			}
		}

	default:
		return ErrInvalidPsbtFormat
	}

	for _, tin := range p.Inputs {
		if !tin.IsSane() {
			return ErrInvalidPsbtFormat
		}
	}

	return nil
}

// GetTxFee returns the transaction fee.  An error is returned if a transaction
// input does not contain any UTXO information.
func (p *Packet) GetTxFee() (btcutil.Amount, error) {
	sumInputs, err := SumUtxoInputValues(p)
	if err != nil {
		return 0, err
	}

	var sumOutputs int64
	for _, txOut := range p.UnsignedTx.TxOut {
		sumOutputs += txOut.Value
	}

	fee := sumInputs - sumOutputs
	return btcutil.Amount(fee), nil
}

// ////////////////////////////////////////
// ////////// PSBTv2 accessors ////////////
// ////////////////////////////////////////
// Following functions will handle internal
// error-returning accessors for critical paths
// such as signing/finalizing/extracting/fee fetch
//
// Should prevent silently treating missing
// v2 fields as zeroes
//
// TL;DR: Handlers for both versions
// ...... to make things less retarded
// ////////////////////////////////////////

// inputPrevOutpoint returns the prevout for the input i
// For PSBTv2, returns error if required fields are missing
func (p *Packet) inputPrevOutpount(i int) (wire.OutPoint, error) {
	if p.Version == 0 {
		return p.UnsignedTx.TxIn[i].PreviousOutPoint, nil
	}

	in := p.Inputs[i]

	if in.PreviousTxID == nil || in.OutputIndex == nil {
		return wire.OutPoint{}, ErrInvalidPsbtFormat
	}

	return wire.OutPoint{Hash: *in.PreviousTxID, Index: *in.OutputIndex}, nil
}

// Returns the sequence number for input i
// For PSBTv2, returns wire.MaxTxInSequenceNum if Sequence is not set
func (p *Packet) inputSequence(i int) uint32 {
	if p.Version == 0 {
		return p.UnsignedTx.TxIn[i].Sequence
	}
	if p.Inputs[i].Sequence != nil {
		return *p.Inputs[i].Sequence
	}
	return wire.MaxTxInSequenceNum
}

// Returns the amount for input i
// For PSBTv2, returns InvalidPSBT if the amount is missing
func (p *Packet) outputAmount(i int) (int64, error) {
	if p.Version == 0 {
		return p.UnsignedTx.TxOut[i].Value, nil
	}
	if p.Outputs[i].Amount == nil {
		return 0, ErrInvalidPsbtFormat
	}
	return *p.Outputs[i].Amount, nil
}

// Returns the pkScript for output i
// For PSBTv2, returns InvalidPSBT if the Script is missing
func (p *Packet) outputScript(i int) ([]byte, error) {
	if p.Version == 0 {
		return p.UnsignedTx.TxOut[i].PkScript, nil
	}
	if p.Outputs[i].Script == nil {
		return nil, ErrInvalidPsbtFormat
	}
	return p.Outputs[i].Script, nil
}

// ComputedLockTime returns the transaction locktime.
// For v0, this is the nLockTime in the unsigned transaction.
// For v2, this follows BIP370's locktime algorithm.
func (p *Packet) ComputedLockTime() (uint32, error) {
	if p.Version != 2 {
		if p.UnsignedTx == nil {
			return 0, ErrInvalidPsbtFormat
		}

		return p.UnsignedTx.LockTime, nil
	}

	// (TODO): I had a thought about here but forgot
	// 		 : Check carefully
	var (
		hasAnyLocktime bool
		heightPossible = true
		timePossible   = true
		maxHeight      uint32
		maxTime        uint32
	)

	for _, in := range p.Inputs {
		hasHeight := in.RequiredHeightLocktime != nil
		hasTime := in.RequiredTimeLocktime != nil

		if !hasHeight && !hasTime {
			continue
		}

		hasAnyLocktime = true

		switch {
		case hasHeight && hasTime:
			if *in.RequiredHeightLocktime > maxHeight {
				maxHeight = *in.RequiredHeightLocktime
			}
			if *in.RequiredTimeLocktime > maxTime {
				maxTime = *in.RequiredTimeLocktime
			}

		case hasHeight:
			timePossible = false
			if *in.RequiredHeightLocktime > maxHeight {
				maxHeight = *in.RequiredHeightLocktime
			}

		case hasTime:
			heightPossible = false
			if *in.RequiredTimeLocktime > maxTime {
				maxTime = *in.RequiredTimeLocktime
			}
		}
	}

	if !hasAnyLocktime {
		if p.FallbackLocktime != nil {
			return *p.FallbackLocktime, nil
		}

		return 0, nil
	}

	if heightPossible {
		return maxHeight, nil
	}
	if timePossible {
		return maxTime, nil
	}

	return 0, ErrInvalidPsbtFormat
}

// GetTxVersion returns the transaction version for both PSBTv0 and PSBTv2.
func (p *Packet) GetTxVersion() int32 {
	if p.Version == 2 {
		return p.TxVersion
	}
	if p.UnsignedTx == nil {
		return 0
	}

	return p.UnsignedTx.Version
}
