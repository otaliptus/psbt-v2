package psbt

// GlobalType is the set of types that are used at the global scope level
// within the PSBT.
type GlobalType uint8

const (
	// UnsignedTxType is the global scope key that houses the unsigned
	// transaction of the PSBT. The value is a transaction in network
	// serialization. The scriptSigs and witnesses for each input must be
	// empty. The transaction must be in the old serialization format
	// (without witnesses). A PSBT must have a transaction, otherwise it is
	// invalid.
	UnsignedTxType GlobalType = 0

	// XPubType houses a global xPub for the entire PSBT packet.
	//
	// The key ({0x01}|{xpub}) is the 78 byte serialized extended public key
	// as defined by BIP-0032. Extended public keys are those that can be
	// used to derive public keys used in the inputs and outputs of this
	// transaction. It should be the public key at the highest hardened
	// derivation index so that the unhardened child keys used in the
	// transaction can be derived.
	//
	// The value is the master key fingerprint as defined by BIP-0032
	// concatenated with the derivation path of the public key. The
	// derivation path is represented as 32-bit little endian unsigned
	// integer indexes concatenated with each other. The number of 32-bit
	// unsigned integer indexes must match the depth provided in the
	// extended public key.
	XPubType GlobalType = 1

	// The following section includes global type changes stated in the BIP-174/370 spec
	// https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#specification
	// https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#specification
	// Question/TODO: BIP-375 Types? ECDHShare & DLEQ?
	// ================================================
	// ============= BIP-370 GLOBAL TYPES =============
	// ================================================
	//

	// TxVersionType is the transaction version for PSBTv2.
	//
	// The key ({0x02}) has no additional key data.
	// The value is a 32-bit little-endian unsigned integer.
	// In PSBTv0 this field was _inside_ the unsigned transaction.
	//
	// **Required** in v2; **invalid** in v0.
	TxVersionType GlobalType = 0x02

	// FallbackLocktimeType is the fallback locktime for PSBTv2.
	//
	// The key ({0x03}) has no additional key data.
	// The value is a 32-bit little-endian unsigned integer.
	// **Optional**; used only when no inputs specify a required locktime.
	FallbackLocktimeType GlobalType = 0x03

	// InputCountType is the number of inputs for a PSBTv2 transaction.
	//
	// The key ({0x04}) has no additional key data.
	// The value is a compact-size (varint) unsigned integer, representing
	// the number of inputs.
	// **Required** in v2; **invalid** in v0.
	InputCountType GlobalType = 0x04

	// OutputCountType is the number of outputs for a PSBTv2 transaction.
	//
	// The key ({0x05}) has no additional key data.
	// The value is a compact-size (varint) unsigned integer, representing
	// the number of outputs.
	// **Required** in v2; **invalid** in v0.
	OutputCountType GlobalType = 0x05

	// TxModifiableType indicates the modifiability flags for PSBTv2.
	//
	// The key ({0x06}) has no additional key data.
	// The value is an 8-bit little endian unsigned integer as a bitfield.
	//
	// Bit 0: Inputs modifiable.
	// Bit 1: Outputs modifiable.
	// Bit 2: Has a SIGHASH_SINGLE sig
	//
	// This type is **optional**.
	TxModifiableType GlobalType = 0x06

	// ================================================
	// =========== BIP-370 GLOBAL TYPES END ===========
	// ================================================

	// VersionType houses the global version number of this PSBT. There is
	// no key (only contains the byte type), then the value if omitted, is
	// assumed to be zero.
	VersionType GlobalType = 0xFB

	// ProprietaryGlobalType is used to house any proper chary global-scope
	// keys within the PSBT.
	//
	// The key is ({0xFC}|<prefix>|{subtype}|{key data}) a variable length
	// identifier prefix, followed by a subtype, followed by the key data
	// itself.
	//
	// The value is any data as defined by the proprietary type user.
	ProprietaryGlobalType = 0xFC
)

// InputType is the set of types that are defined for each input included
// within the PSBT.
type InputType uint32

const (
	// NonWitnessUtxoType has no key ({0x00}) and houses the transaction in
	// network serialization format the current input spends from. This
	// should only be present for inputs which spend non-segwit outputs.
	// However, if it is unknown whether an input spends a segwit output,
	// this type should be used. The entire input transaction is needed in
	// order to be able to verify the values of the input (pre-segwit they
	// aren't in the signature digest).
	NonWitnessUtxoType InputType = 0

	// WitnessUtxoType has no key ({0x01}), and houses the entire
	// transaction output in network serialization which the current input
	// spends from.  This should only be present for inputs which spend
	// segwit outputs, including P2SH embedded ones (value || script).
	WitnessUtxoType InputType = 1

	// PartialSigType is used to include a partial signature with key
	// ({0x02}|{public key}).
	//
	// The value is the signature as would be pushed to the stack from a
	// scriptSig or witness..
	PartialSigType InputType = 2

	// SighashType is an empty key ({0x03}).
	//
	// The value contains the 32-bit unsigned integer specifying the
	// sighash type to be used for this input. Signatures for this input
	// must use the sighash type, finalizers must fail to finalize inputs
	// which have signatures that do not match the specified sighash type.
	// Signers who cannot produce signatures with the sighash type must not
	// provide a signature.
	SighashType InputType = 3

	// RedeemScriptInputType is an empty key ({0x04}).
	//
	// The value is the redeem script of the input if present.
	RedeemScriptInputType InputType = 4

	// WitnessScriptInputType is an empty key ({0x05}).
	//
	// The value is the witness script of this input, if it has one.
	WitnessScriptInputType InputType = 5

	// Bip32DerivationInputType is a type that carries the pubkey along
	// with the key ({0x06}|{public key}).
	//
	// The value is master key fingerprint as defined by BIP 32
	// concatenated with the derivation path of the public key. The
	// derivation path is represented as 32 bit unsigned integer indexes
	// concatenated with each other. Public keys are those that will be
	// needed to sign this input.
	Bip32DerivationInputType InputType = 6

	// FinalScriptSigType is an empty key ({0x07}).
	//
	// The value contains a fully constructed scriptSig with signatures and
	// any other scripts necessary for the input to pass validation.
	FinalScriptSigType InputType = 7

	// FinalScriptWitnessType is an empty key ({0x08}). The value is a
	// fully constructed scriptWitness with signatures and any other
	// scripts necessary for the input to pass validation.
	FinalScriptWitnessType InputType = 8

	// The following section includes input type changes stated in the BIP-174/370 spec
	// Question/TODO: BIP-375 Types? ECDHShare & DLEQ?
	// ================================================
	// ============== BIP-370 INPUT TYPES =============
	// ================================================
	//

	// PreviousTxIDType is the 32-byte txid of the previous output.
	//
	// The key ({0x0E}) has no additional key data. The value is a 32-byte hash.
	// It replaces the unsigned tx's input prevout. Since it's standalone, inputs
	// can be added/removed without re-serializing.
	// Standard byte order, not the displayed one.
	//
	// **Required** in v2; **invalid** in v0.
	PreviousTxIDType InputType = 0x0e

	// OutputIndexType is the index of the output in the previous transaction.
	//
	// The key ({0x0F}) has no additional key data.
	// The value is a 32-bit little-endian unsigned integer.
	// Uniquely identifies the UTXO with PreviousTxID.
	//
	// **Required** in v2; **invalid** in v0.
	OutputIndexType InputType = 0x0f

	// SequenceType is the sequence number for the input.
	//
	// The key ({0x10}) has no additional key data.
	// The value is a 32-bit little-endian unsigned integer for the sequence
	// number of the input.
	//
	// **Optional**; defaults to 0xFFFFFFFF when absent.
	SequenceType InputType = 0x10

	// RequiredTimeLocktimeType is the minimum time-based locktime.
	//
	// The key ({0x11}) has no additional key data.
	// The value is a 32-bit little-endian unsigned integer.
	//
	// Represents the minimum Unix timestamp the input requires to be set
	// as the locktime.
	//
	// Must be >= 500000000.
	RequiredTimeLocktimeType InputType = 0x11

	// RequiredHeightLocktimeType is the minimum height-based locktime.
	//
	// The key ({0x12}) has no additional key data.
	// The value is a 32-bit little-endian unsigned integer.
	//
	// Represents the minimum block height the input requires to be set
	// as the locktime.
	//
	// Must be < 500000000.
	RequiredHeightLocktimeType InputType = 0x12

	// ================================================
	// =========== BIP-370 INPUT TYPES END ============
	// ================================================

	// TaprootKeySpendSignatureType is an empty key ({0x13}). The value is
	// a 64-byte Schnorr signature or a 65-byte Schnorr signature with the
	// one byte sighash type appended to it.
	TaprootKeySpendSignatureType InputType = 0x13

	// TaprootScriptSpendSignatureType is a type that carries the
	// x-only pubkey and leaf hash along with the key
	// ({0x14}|{xonlypubkey}|{leafhash}).
	//
	// The value is a 64-byte Schnorr signature or a 65-byte Schnorr
	// signature with the one byte sighash type appended to it.
	TaprootScriptSpendSignatureType InputType = 0x14

	// TaprootLeafScriptType is a type that carries the control block along
	// with the key ({0x15}|{control block}).
	//
	// The value is a script followed by a one byte unsigned integer that
	// represents the leaf version.
	TaprootLeafScriptType InputType = 0x15

	// TaprootBip32DerivationInputType is a type that carries the x-only
	// pubkey along with the key ({0x16}|{xonlypubkey}).
	//
	// The value is a compact integer denoting the number of hashes,
	// followed by said number of 32-byte leaf hashes. The rest of the value
	// is then identical to the Bip32DerivationInputType value.
	TaprootBip32DerivationInputType InputType = 0x16

	// TaprootInternalKeyInputType is an empty key ({0x17}). The value is
	// an x-only pubkey denoting the internal public key used for
	// constructing a taproot key.
	TaprootInternalKeyInputType InputType = 0x17

	// TaprootMerkleRootType is an empty key ({0x18}). The value is a
	// 32-byte hash denoting the root hash of a merkle tree of scripts.
	TaprootMerkleRootType InputType = 0x18

	// ProprietaryInputType is a custom type for use by devs.
	//
	// The key ({0xFC}|<prefix>|{subtype}|{key data}), is a Variable length
	// identifier prefix, followed by a subtype, followed by the key data
	// itself.
	//
	// The value is any value data as defined by the proprietary type user.
	ProprietaryInputType InputType = 0xFC
)

// OutputType is the set of types defined per output within the PSBT.
type OutputType uint32

const (
	// RedeemScriptOutputType is an empty key ({0x00}>
	//
	// The value is the redeemScript for this output if it has one.
	RedeemScriptOutputType OutputType = 0

	// WitnessScriptOutputType is an empty key ({0x01}).
	//
	// The value is the witness script of this input, if it has one.
	WitnessScriptOutputType OutputType = 1

	// Bip32DerivationOutputType is used to communicate derivation information
	// needed to spend this output. The key is ({0x02}|{public key}).
	//
	// The value is master key fingerprint concatenated with the derivation
	// path of the public key. The derivation path is represented as 32-bit
	// little endian unsigned integer indexes concatenated with each other.
	// Public keys are those needed to spend this output.
	Bip32DerivationOutputType OutputType = 2

	// ================================================
	// ============= BIP-370 OUTPUT TYPES =============
	// ================================================
	//
	// AmountType is the output value in satoshis.
	//
	// The key ({0x03}) has no additional key data.
	// The value is a 64-bit little-endian signed integer.
	//
	// **Required** in v2; **invalid** in v0.
	AmountType OutputType = 3

	// ScriptType is the output scriptPubKey.
	//
	// The key ({0x04}) has no additional key data.
	// The value is the raw scriptPubKey bytes.
	//
	// **Required** in v2; **invalid** in v0.
	ScriptType OutputType = 4

	// ================================================
	// =========== BIP-370 OUTPUT TYPES END ===========
	// ================================================

	// TaprootInternalKeyOutputType is an empty key ({0x05}). The value is
	// an x-only pubkey denoting the internal public key used for
	// constructing a taproot key.
	TaprootInternalKeyOutputType OutputType = 5

	// TaprootTapTreeType is an empty key ({0x06}). The value is a
	// serialized taproot tree.
	TaprootTapTreeType OutputType = 6

	// TaprootBip32DerivationOutputType is a type that carries the x-only
	// pubkey along with the key ({0x07}|{xonlypubkey}).
	//
	// The value is a compact integer denoting the number of hashes,
	// followed by said number of 32-byte leaf hashes. The rest of the value
	// is then identical to the Bip32DerivationInputType value.
	TaprootBip32DerivationOutputType OutputType = 7
)
