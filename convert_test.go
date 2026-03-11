package psbt

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func makeTestXPub(t *testing.T) XPub {
	t.Helper()

	seed := bytes.Repeat([]byte{0x42}, 32)
	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	require.NoError(t, err)

	pub, err := master.Neuter()
	require.NoError(t, err)

	return XPub{
		ExtendedKey:          EncodeExtendedKey(pub),
		MasterKeyFingerprint: 0x01020304,
		Bip32Path:            []uint32{},
	}
}

func makeConvertV0BasicPacket(t *testing.T, locktime uint32) *Packet {
	t.Helper()

	pubKeyHash := bytes.Repeat([]byte{0x11}, 20)
	prevScript := append([]byte{txscript.OP_0, 0x14}, pubKeyHash...)

	fundingTx := wire.NewMsgTx(2)
	fundingTx.AddTxIn(&wire.TxIn{})
	fundingTx.AddTxOut(&wire.TxOut{
		Value:    75_000,
		PkScript: prevScript,
	})

	prevOut := &wire.OutPoint{
		Hash:  fundingTx.TxHash(),
		Index: 0,
	}

	pkt, err := New(
		[]*wire.OutPoint{prevOut},
		[]*wire.TxOut{{
			Value:    50_000,
			PkScript: []byte{txscript.OP_TRUE},
		}},
		2, locktime, []uint32{12345},
	)
	require.NoError(t, err)

	pkt.Inputs[0].NonWitnessUtxo = fundingTx.Copy()
	pkt.Inputs[0].WitnessUtxo = cloneTxOut(fundingTx.TxOut[0])
	pkt.Inputs[0].PartialSigs = []*PartialSig{{
		PubKey:    cloneBytes(testPub1),
		Signature: cloneBytes(testSig1),
	}}
	pkt.Inputs[0].SighashType = txscript.SigHashAll
	pkt.Inputs[0].RedeemScript = []byte{txscript.OP_TRUE}
	pkt.Inputs[0].WitnessScript = []byte{txscript.OP_FALSE}
	pkt.Inputs[0].Bip32Derivation = []*Bip32Derivation{{
		PubKey:               cloneBytes(testPub1),
		MasterKeyFingerprint: 0xaabbccdd,
		Bip32Path:            []uint32{1, 2},
	}}
	pkt.Inputs[0].Unknowns = []*Unknown{{
		Key:   []byte{0xfc, 0x01},
		Value: []byte{0xaa, 0xbb},
	}}

	pkt.Outputs[0].RedeemScript = []byte{0x63}
	pkt.Outputs[0].WitnessScript = []byte{0x64}
	pkt.Outputs[0].Bip32Derivation = []*Bip32Derivation{{
		PubKey:               cloneBytes(testPub1),
		MasterKeyFingerprint: 0x11223344,
		Bip32Path:            []uint32{9},
	}}
	pkt.Outputs[0].Unknowns = []*Unknown{{
		Key:   []byte{0xfc, 0x02},
		Value: []byte{0xcc},
	}}

	pkt.XPubs = []XPub{makeTestXPub(t)}
	pkt.Unknowns = []*Unknown{{
		Key:   []byte{0xfc, 0x03},
		Value: []byte{0xdd},
	}}

	require.NoError(t, pkt.SanityCheck())
	return pkt
}

func makeConvertV0RichPacket(t *testing.T) *Packet {
	t.Helper()

	pkt := makeConvertV0BasicPacket(t, 500)
	pkt.Inputs[0].FinalScriptSig = []byte{0x00, 0x51}
	pkt.Inputs[0].FinalScriptWitness = []byte{0x02, 0x01, 0x00}
	pkt.Inputs[0].TaprootKeySpendSig = bytes.Repeat([]byte{0x01}, schnorrSigMinLength)
	pkt.Inputs[0].TaprootScriptSpendSig = []*TaprootScriptSpendSig{{
		XOnlyPubKey: bytes.Repeat([]byte{0x02}, 32),
		LeafHash:    bytes.Repeat([]byte{0x03}, 32),
		Signature:   bytes.Repeat([]byte{0x04}, schnorrSigMinLength),
		SigHash:     txscript.SigHashDefault,
	}}
	pkt.Inputs[0].TaprootLeafScript = []*TaprootTapLeafScript{{
		ControlBlock: bytes.Repeat([]byte{0x05}, 33),
		Script:       []byte{txscript.OP_TRUE},
		LeafVersion:  0xc0,
	}}
	pkt.Inputs[0].TaprootBip32Derivation = []*TaprootBip32Derivation{{
		XOnlyPubKey:          bytes.Repeat([]byte{0x06}, 32),
		LeafHashes:           [][]byte{bytes.Repeat([]byte{0x07}, 32)},
		MasterKeyFingerprint: 0x55667788,
		Bip32Path:            []uint32{3, 4},
	}}
	pkt.Inputs[0].TaprootInternalKey = bytes.Repeat([]byte{0x08}, 32)
	pkt.Inputs[0].TaprootMerkleRoot = bytes.Repeat([]byte{0x09}, 32)

	pkt.Outputs[0].TaprootInternalKey = bytes.Repeat([]byte{0x0a}, 32)
	pkt.Outputs[0].TaprootTapTree = []byte{0x01, 0x02, 0x03}
	pkt.Outputs[0].TaprootBip32Derivation = []*TaprootBip32Derivation{{
		XOnlyPubKey:          bytes.Repeat([]byte{0x0b}, 32),
		LeafHashes:           [][]byte{bytes.Repeat([]byte{0x0c}, 32)},
		MasterKeyFingerprint: 0x99aabbcc,
		Bip32Path:            []uint32{5},
	}}

	require.NoError(t, pkt.SanityCheck())
	return pkt
}

func makeConvertV2RichPacket(t *testing.T) *Packet {
	t.Helper()

	mod := uint8(0x03)
	pkt := makeV2WithWitnessUtxo(t, &mod)

	fallback := uint32(777)
	sequence := uint32(12345)
	requiredTime := uint32(LocktimeThreshold + 25)

	pkt.FallbackLocktime = &fallback
	pkt.TxModifiable = &mod
	pkt.Inputs[0].Sequence = &sequence
	pkt.Inputs[0].RequiredTimeLocktime = &requiredTime
	pkt.Inputs[0].PartialSigs = []*PartialSig{{
		PubKey:    cloneBytes(testPub1),
		Signature: cloneBytes(testSig1),
	}}
	pkt.Inputs[0].SighashType = txscript.SigHashAll
	pkt.Inputs[0].RedeemScript = []byte{txscript.OP_TRUE}
	pkt.Inputs[0].WitnessScript = []byte{txscript.OP_FALSE}
	pkt.Inputs[0].Bip32Derivation = []*Bip32Derivation{{
		PubKey:               cloneBytes(testPub1),
		MasterKeyFingerprint: 0xdeadbeef,
		Bip32Path:            []uint32{6, 7},
	}}
	pkt.Inputs[0].FinalScriptSig = []byte{0x00, 0x51}
	pkt.Inputs[0].FinalScriptWitness = []byte{0x02, 0x01, 0x00}
	pkt.Inputs[0].TaprootInternalKey = bytes.Repeat([]byte{0x21}, 32)
	pkt.Inputs[0].TaprootMerkleRoot = bytes.Repeat([]byte{0x22}, 32)
	pkt.Inputs[0].Unknowns = []*Unknown{{
		Key:   []byte{0xfc, 0x10},
		Value: []byte{0xaa},
	}}

	pkt.Outputs[0].RedeemScript = []byte{0x63}
	pkt.Outputs[0].WitnessScript = []byte{0x64}
	pkt.Outputs[0].Bip32Derivation = []*Bip32Derivation{{
		PubKey:               cloneBytes(testPub1),
		MasterKeyFingerprint: 0xcafebabe,
		Bip32Path:            []uint32{8},
	}}
	pkt.Outputs[0].TaprootInternalKey = bytes.Repeat([]byte{0x23}, 32)
	pkt.Outputs[0].TaprootTapTree = []byte{0x01, 0x02}
	pkt.Outputs[0].Unknowns = []*Unknown{{
		Key:   []byte{0xfc, 0x11},
		Value: []byte{0xbb},
	}}

	pkt.XPubs = []XPub{makeTestXPub(t)}
	pkt.Unknowns = []*Unknown{{
		Key:   []byte{0xfc, 0x12},
		Value: []byte{0xcc},
	}}

	require.NoError(t, pkt.SanityCheck())
	return pkt
}

func TestConvertToV2Basic(t *testing.T) {
	v0 := makeConvertV0BasicPacket(t, 500)

	v2, err := ConvertToV2(v0)
	require.NoError(t, err)
	require.Equal(t, uint32(2), v2.Version)
	require.Nil(t, v2.UnsignedTx)
	require.Equal(t, v0.UnsignedTx.Version, v2.TxVersion)
	require.NotNil(t, v2.FallbackLocktime)
	require.Equal(t, uint32(500), *v2.FallbackLocktime)

	require.Equal(t,
		v0.UnsignedTx.TxIn[0].PreviousOutPoint.Hash, *v2.Inputs[0].PreviousTxID,
	)
	require.Equal(t,
		v0.UnsignedTx.TxIn[0].PreviousOutPoint.Index, *v2.Inputs[0].OutputIndex,
	)
	require.Equal(t, v0.UnsignedTx.TxIn[0].Sequence, *v2.Inputs[0].Sequence)
	require.Equal(t, v0.UnsignedTx.TxOut[0].Value, *v2.Outputs[0].Amount)
	require.Equal(t, v0.UnsignedTx.TxOut[0].PkScript, v2.Outputs[0].Script)
	require.NoError(t, v2.SanityCheck())
}

func TestConvertToV2OmitsDefaultSequence(t *testing.T) {
	v0 := makeConvertV0BasicPacket(t, 500)
	v0.UnsignedTx.TxIn[0].Sequence = wire.MaxTxInSequenceNum

	v2, err := ConvertToV2(v0)
	require.NoError(t, err)
	require.Nil(t, v2.Inputs[0].Sequence)
	require.Equal(t, wire.MaxTxInSequenceNum, v2.inputSequence(0))
}

func TestConvertToV0Basic(t *testing.T) {
	v2 := makeConvertV2RichPacket(t)

	v0, err := ConvertToV0(v2)
	require.NoError(t, err)
	require.Equal(t, uint32(0), v0.Version)
	require.NotNil(t, v0.UnsignedTx)
	require.Equal(t, v2.TxVersion, v0.UnsignedTx.Version)
	require.Equal(t, *v2.Inputs[0].PreviousTxID, v0.UnsignedTx.TxIn[0].PreviousOutPoint.Hash)
	require.Equal(t, *v2.Inputs[0].OutputIndex, v0.UnsignedTx.TxIn[0].PreviousOutPoint.Index)
	require.Equal(t, *v2.Inputs[0].Sequence, v0.UnsignedTx.TxIn[0].Sequence)
	require.Equal(t, *v2.Outputs[0].Amount, v0.UnsignedTx.TxOut[0].Value)
	require.Equal(t, v2.Outputs[0].Script, v0.UnsignedTx.TxOut[0].PkScript)
	require.Nil(t, v0.Inputs[0].PreviousTxID)
	require.Nil(t, v0.Inputs[0].OutputIndex)
	require.Nil(t, v0.Inputs[0].Sequence)
	require.Nil(t, v0.Outputs[0].Amount)
	require.Nil(t, v0.Outputs[0].Script)
	require.NoError(t, v0.SanityCheck())
}

func TestConvertV0ToV2ToV0RoundTrip(t *testing.T) {
	original := makeConvertV0BasicPacket(t, 500)

	var originalBytes bytes.Buffer
	require.NoError(t, original.Serialize(&originalBytes))

	v2, err := ConvertToV2(original)
	require.NoError(t, err)

	roundTripped, err := ConvertToV0(v2)
	require.NoError(t, err)

	var roundTripBytes bytes.Buffer
	require.NoError(t, roundTripped.Serialize(&roundTripBytes))

	require.Equal(t, originalBytes.Bytes(), roundTripBytes.Bytes())
}

func TestConvertToV2PreservesSharedFields(t *testing.T) {
	original := makeConvertV0RichPacket(t)

	converted, err := ConvertToV2(original)
	require.NoError(t, err)

	require.Equal(t, original.Inputs[0].WitnessUtxo.Value, converted.Inputs[0].WitnessUtxo.Value)
	require.Equal(t, original.Inputs[0].WitnessUtxo.PkScript, converted.Inputs[0].WitnessUtxo.PkScript)
	require.Equal(t, original.Inputs[0].NonWitnessUtxo.TxOut[0].PkScript, converted.Inputs[0].NonWitnessUtxo.TxOut[0].PkScript)
	require.Equal(t, original.Inputs[0].PartialSigs[0].Signature, converted.Inputs[0].PartialSigs[0].Signature)
	require.Equal(t, original.Inputs[0].RedeemScript, converted.Inputs[0].RedeemScript)
	require.Equal(t, original.Inputs[0].WitnessScript, converted.Inputs[0].WitnessScript)
	require.Equal(t, original.Inputs[0].Bip32Derivation[0].Bip32Path, converted.Inputs[0].Bip32Derivation[0].Bip32Path)
	require.Equal(t, original.Inputs[0].FinalScriptSig, converted.Inputs[0].FinalScriptSig)
	require.Equal(t, original.Inputs[0].FinalScriptWitness, converted.Inputs[0].FinalScriptWitness)
	require.Equal(t, original.Inputs[0].TaprootKeySpendSig, converted.Inputs[0].TaprootKeySpendSig)
	require.Equal(t, original.Inputs[0].TaprootLeafScript[0].ControlBlock, converted.Inputs[0].TaprootLeafScript[0].ControlBlock)
	require.Equal(t, original.Inputs[0].TaprootLeafScript[0].Script, converted.Inputs[0].TaprootLeafScript[0].Script)
	require.Equal(t, original.Inputs[0].TaprootScriptSpendSig[0].Signature, converted.Inputs[0].TaprootScriptSpendSig[0].Signature)
	require.Equal(t, original.Inputs[0].TaprootInternalKey, converted.Inputs[0].TaprootInternalKey)
	require.Equal(t, original.Inputs[0].TaprootMerkleRoot, converted.Inputs[0].TaprootMerkleRoot)
	require.Equal(t, original.Outputs[0].RedeemScript, converted.Outputs[0].RedeemScript)
	require.Equal(t, original.Outputs[0].WitnessScript, converted.Outputs[0].WitnessScript)
	require.Equal(t, original.Outputs[0].TaprootInternalKey, converted.Outputs[0].TaprootInternalKey)
	require.Equal(t, original.Outputs[0].TaprootTapTree, converted.Outputs[0].TaprootTapTree)
	require.Equal(t, original.XPubs[0].ExtendedKey, converted.XPubs[0].ExtendedKey)
	require.Equal(t, original.Unknowns[0].Value, converted.Unknowns[0].Value)
	require.Equal(t, original.Inputs[0].Unknowns[0].Value, converted.Inputs[0].Unknowns[0].Value)
	require.Equal(t, original.Outputs[0].Unknowns[0].Value, converted.Outputs[0].Unknowns[0].Value)

	converted.Inputs[0].WitnessUtxo.PkScript[0] ^= 0xff
	converted.Inputs[0].NonWitnessUtxo.TxOut[0].PkScript[0] ^= 0xff
	converted.Inputs[0].Bip32Derivation[0].Bip32Path[0]++
	converted.Outputs[0].Script[0] ^= 0xff
	converted.Unknowns[0].Value[0] ^= 0xff
	converted.XPubs[0].ExtendedKey[0] ^= 0xff

	require.NotEqual(t,
		converted.Inputs[0].WitnessUtxo.PkScript, original.Inputs[0].WitnessUtxo.PkScript,
	)
	require.NotEqual(t,
		converted.Inputs[0].NonWitnessUtxo.TxOut[0].PkScript,
		original.Inputs[0].NonWitnessUtxo.TxOut[0].PkScript,
	)
	require.NotEqual(t,
		converted.Inputs[0].Bip32Derivation[0].Bip32Path,
		original.Inputs[0].Bip32Derivation[0].Bip32Path,
	)
	require.NotEqual(t, converted.Outputs[0].Script, original.UnsignedTx.TxOut[0].PkScript)
	require.NotEqual(t, converted.Unknowns[0].Value, original.Unknowns[0].Value)
	require.NotEqual(t, converted.XPubs[0].ExtendedKey, original.XPubs[0].ExtendedKey)
}

func TestConvertToV0DropsV2OnlyFields(t *testing.T) {
	original := makeConvertV2RichPacket(t)

	converted, err := ConvertToV0(original)
	require.NoError(t, err)

	require.Nil(t, converted.FallbackLocktime)
	require.Nil(t, converted.TxModifiable)
	require.Nil(t, converted.Inputs[0].PreviousTxID)
	require.Nil(t, converted.Inputs[0].OutputIndex)
	require.Nil(t, converted.Inputs[0].Sequence)
	require.Nil(t, converted.Inputs[0].RequiredTimeLocktime)
	require.Nil(t, converted.Inputs[0].RequiredHeightLocktime)
	require.Nil(t, converted.Outputs[0].Amount)
	require.Nil(t, converted.Outputs[0].Script)

	// Shared fields are preserved.
	require.Equal(t, original.Inputs[0].FinalScriptSig, converted.Inputs[0].FinalScriptSig)
	require.Equal(t, original.Inputs[0].FinalScriptWitness, converted.Inputs[0].FinalScriptWitness)
	require.Equal(t, original.Inputs[0].RedeemScript, converted.Inputs[0].RedeemScript)
	require.Equal(t, original.Outputs[0].RedeemScript, converted.Outputs[0].RedeemScript)
	require.Equal(t, original.Unknowns[0].Value, converted.Unknowns[0].Value)
	require.Equal(t, original.XPubs[0].ExtendedKey, converted.XPubs[0].ExtendedKey)

	converted.UnsignedTx.TxOut[0].PkScript[0] ^= 0xff
	converted.Unknowns[0].Value[0] ^= 0xff
	converted.Inputs[0].WitnessUtxo.PkScript[0] ^= 0xff

	require.NotEqual(t, converted.UnsignedTx.TxOut[0].PkScript, original.Outputs[0].Script)
	require.NotEqual(t, converted.Unknowns[0].Value, original.Unknowns[0].Value)
	require.NotEqual(t, converted.Inputs[0].WitnessUtxo.PkScript, original.Inputs[0].WitnessUtxo.PkScript)
}

func TestConvertToV2LocktimePolicy(t *testing.T) {
	t.Run("zero locktime stays absent", func(t *testing.T) {
		v0 := makeConvertV0BasicPacket(t, 0)

		v2, err := ConvertToV2(v0)
		require.NoError(t, err)
		require.Nil(t, v2.FallbackLocktime)
	})

	t.Run("non-zero locktime becomes fallback", func(t *testing.T) {
		v0 := makeConvertV0BasicPacket(t, 500)

		v2, err := ConvertToV2(v0)
		require.NoError(t, err)
		require.NotNil(t, v2.FallbackLocktime)
		require.Equal(t, uint32(500), *v2.FallbackLocktime)
	})
}

func TestConvertToV0WithLocktime(t *testing.T) {
	txid := chainhash.HashH([]byte("convert-locktime"))
	idx := uint32(0)
	amount := int64(10_000)
	requiredHeight := uint32(144)

	pkt := &Packet{
		Version:   2,
		TxVersion: 2,
		Inputs: []PInput{{
			PreviousTxID:           &txid,
			OutputIndex:            &idx,
			RequiredHeightLocktime: &requiredHeight,
		}},
		Outputs: []POutput{{
			Amount: &amount,
			Script: []byte{txscript.OP_TRUE},
		}},
	}
	require.NoError(t, pkt.SanityCheck())

	v0, err := ConvertToV0(pkt)
	require.NoError(t, err)

	locktime, err := pkt.ComputedLockTime()
	require.NoError(t, err)
	require.Equal(t, locktime, v0.UnsignedTx.LockTime)
}

func TestConvertWrongVersionRejected(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
		msg  string
	}{
		{
			name: "ConvertToV2 rejects nil input",
			run: func() error {
				_, err := ConvertToV2(nil)
				return err
			},
			msg: "packet cannot be nil",
		},
		{
			name: "ConvertToV0 rejects nil input",
			run: func() error {
				_, err := ConvertToV0(nil)
				return err
			},
			msg: "packet cannot be nil",
		},
		{
			name: "ConvertToV2 rejects v2 input",
			run: func() error {
				_, err := ConvertToV2(makeV2WithWitnessUtxo(t, nil))
				return err
			},
			msg: "packet is not v0",
		},
		{
			name: "ConvertToV0 rejects v0 input",
			run: func() error {
				_, err := ConvertToV0(makeConvertV0BasicPacket(t, 0))
				return err
			},
			msg: "packet is not v2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.msg)
		})
	}
}

func TestConvertToV0IncompatibleLocktimes(t *testing.T) {
	txid1 := chainhash.HashH([]byte("lock-1"))
	txid2 := chainhash.HashH([]byte("lock-2"))
	idx := uint32(0)
	amount := int64(5_000)
	requiredHeight := uint32(144)
	requiredTime := uint32(LocktimeThreshold + 10)

	// Construct the packet directly and let ConvertToV0 perform its own
	// validation so this test exercises the failing v2 locktime-materialization
	// path rather than a helper that already pre-sanitized the packet.
	pkt := &Packet{
		Version:   2,
		TxVersion: 2,
		Inputs: []PInput{
			{
				PreviousTxID:           &txid1,
				OutputIndex:            &idx,
				RequiredHeightLocktime: &requiredHeight,
			},
			{
				PreviousTxID:         &txid2,
				OutputIndex:          &idx,
				RequiredTimeLocktime: &requiredTime,
			},
		},
		Outputs: []POutput{{
			Amount: &amount,
			Script: []byte{txscript.OP_TRUE},
		}},
	}

	_, err := ConvertToV0(pkt)
	require.Error(t, err)
}
