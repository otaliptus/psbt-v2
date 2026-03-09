package psbt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// /////////////////////////////////////////////////////////////////////////////
// /////////////////////////////////////////////////////////////////////////////
// /////////////////////////////////////////////////////////////////////////////
//
// These tests mirror the BIP370 rust vectors at the level currently supported
// by this codebase: input/output map parsing of v2 keys.
// They're mostly **LLM generated** and then hand-checked.
// I believe they're good enough :)
//
// SOURCE: https://github.com/rust-bitcoin/rust-psbt/blob/efb1e8fc1bf000c810fc012cc237f67aceef1d9e/tests/bip370-parse-valid.rs
//
// TestPSBTV2MirroredFieldParsing checks successful parsing of canonical v2
// per-input/per-output fields that are already implemented in this repo.
func TestPSBTV2MirroredFieldParsing(t *testing.T) {
	// required_fields_only mirrors the minimal v2 shape:
	// input prevout fields and output amount/script fields.
	t.Run("required_fields_only", func(t *testing.T) {
		var in PInput
		var inBuf bytes.Buffer

		txid := bytes.Repeat([]byte{0x11}, 32)
		putKV(t, &inBuf, uint8(PreviousTxIDType), nil, txid)
		putKV(t, &inBuf, uint8(OutputIndexType), nil, u32LE(0))
		endSection(t, &inBuf)

		err := in.deserialize(bytes.NewReader(inBuf.Bytes()))
		require.NoError(t, err)
		require.NotNil(t, in.PreviousTxID)
		require.NotNil(t, in.OutputIndex)
		require.Nil(t, in.Sequence)
		require.Nil(t, in.RequiredTimeLocktime)
		require.Nil(t, in.RequiredHeightLocktime)

		var out POutput
		var outBuf bytes.Buffer
		putKV(t, &outBuf, uint8(AmountType), nil, u64LE(12345))
		putKV(t, &outBuf, uint8(ScriptType), nil, []byte{0x00, 0x14, 0x01, 0x02})
		endSection(t, &outBuf)

		err = out.deserialize(bytes.NewReader(outBuf.Bytes()))
		require.NoError(t, err)
		require.NotNil(t, out.Amount)
		require.NotNil(t, out.Script)
	})

	// sequence_and_all_locktimes mirrors the richer v2 shape:
	// optional sequence plus both required locktime fields.
	t.Run("sequence_and_all_locktimes", func(t *testing.T) {
		var in PInput
		var inBuf bytes.Buffer

		txid := bytes.Repeat([]byte{0x22}, 32)
		putKV(t, &inBuf, uint8(PreviousTxIDType), nil, txid)
		putKV(t, &inBuf, uint8(OutputIndexType), nil, u32LE(1))
		putKV(t, &inBuf, uint8(SequenceType), nil, u32LE(0xfffffffe))
		putKV(t, &inBuf, uint8(RequiredTimeLocktimeType), nil, u32LE(1657048460))
		putKV(t, &inBuf, uint8(RequiredHeightLocktimeType), nil, u32LE(10000))
		endSection(t, &inBuf)

		err := in.deserialize(bytes.NewReader(inBuf.Bytes()))
		require.NoError(t, err)
		require.NotNil(t, in.Sequence)
		require.NotNil(t, in.RequiredTimeLocktime)
		require.NotNil(t, in.RequiredHeightLocktime)
		require.EqualValues(t, 0xfffffffe, *in.Sequence)
		require.EqualValues(t, 1657048460, *in.RequiredTimeLocktime)
		require.EqualValues(t, 10000, *in.RequiredHeightLocktime)
	})
}

// SOURCE: https://github.com/rust-bitcoin/rust-psbt/blob/efb1e8fc1bf000c810fc012cc237f67aceef1d9e/tests/bip370-parse-valid.rs
// TestPSBTV2MirroredInvalidLocktimeBoundaries checks BIP370 boundary rules:
// time locktimes must be >= threshold and height locktimes must be < threshold.
func TestPSBTV2MirroredInvalidLocktimeBoundaries(t *testing.T) {
	// Invalid: time-based locktime below threshold.
	t.Run("required_time_locktime_below_500000000", func(t *testing.T) {
		var in PInput
		var buf bytes.Buffer
		putKV(t, &buf, uint8(RequiredTimeLocktimeType), nil, u32LE(LocktimeThreshold-1))
		endSection(t, &buf)

		err := in.deserialize(bytes.NewReader(buf.Bytes()))
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})

	// Invalid: height-based locktime at/above threshold.
	t.Run("required_height_locktime_at_or_above_500000000", func(t *testing.T) {
		var in PInput
		var buf bytes.Buffer
		putKV(t, &buf, uint8(RequiredHeightLocktimeType), nil, u32LE(LocktimeThreshold))
		endSection(t, &buf)

		err := in.deserialize(bytes.NewReader(buf.Bytes()))
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})
}

// TestPSBTV2GlobalFieldsParseIntoPacket verifies the parser now recognizes
// canonical global v2 fields as first-class Packet fields.
func TestPSBTV2GlobalFieldsParseIntoPacket(t *testing.T) {
	raw := buildRawPSBT(
		t,
		[]testKV{
			{keyType: uint8(VersionType), value: u32LE(2)},
			{keyType: uint8(TxVersionType), value: u32LE(3)},
			{keyType: uint8(FallbackLocktimeType), value: u32LE(500)},
			{keyType: uint8(InputCountType), value: compactSize(t, 1)},
			{keyType: uint8(OutputCountType), value: compactSize(t, 1)},
			{keyType: uint8(TxModifiableType), value: []byte{0x03}},
		},
		[][]testKV{
			{
				{keyType: uint8(PreviousTxIDType), value: bytes.Repeat([]byte{0x11}, 32)},
				{keyType: uint8(OutputIndexType), value: u32LE(1)},
			},
		},
		[][]testKV{
			{
				{keyType: uint8(AmountType), value: u64LE(12345)},
				{keyType: uint8(ScriptType), value: []byte{0x00, 0x14, 0x01, 0x02}},
			},
		},
	)

	parsed, err := NewFromRawBytes(bytes.NewReader(raw), false)
	require.NoError(t, err)
	require.EqualValues(t, 2, parsed.Version)
	require.EqualValues(t, 3, parsed.TxVersion)
	require.NotNil(t, parsed.FallbackLocktime)
	require.EqualValues(t, 500, *parsed.FallbackLocktime)
	require.NotNil(t, parsed.TxModifiable)
	require.EqualValues(t, 0x03, *parsed.TxModifiable)
	require.Nil(t, parsed.UnsignedTx)
	require.Len(t, parsed.Inputs, 1)
	require.Len(t, parsed.Outputs, 1)
	require.Empty(t, parsed.Unknowns)
	require.NotNil(t, parsed.Inputs[0].PreviousTxID)
	require.NotNil(t, parsed.Inputs[0].OutputIndex)
	require.NotNil(t, parsed.Outputs[0].Amount)
	require.NotNil(t, parsed.Outputs[0].Script)
}

// TestParseV2_GlobalOrderIndependence verifies parseGlobalMap does not depend
// on any specific ordering of v2 global keys.
func TestParseV2_GlobalOrderIndependence(t *testing.T) {
	raw := buildRawPSBT(
		t,
		[]testKV{
			{keyType: uint8(TxModifiableType), value: []byte{0x03}},
			{keyType: uint8(OutputCountType), value: compactSize(t, 1)},
			{keyType: uint8(FallbackLocktimeType), value: u32LE(500)},
			{keyType: uint8(TxVersionType), value: u32LE(3)},
			{keyType: uint8(InputCountType), value: compactSize(t, 1)},
			{keyType: uint8(VersionType), value: u32LE(2)},
		},
		[][]testKV{
			{
				{keyType: uint8(PreviousTxIDType), value: bytes.Repeat([]byte{0x33}, 32)},
				{keyType: uint8(OutputIndexType), value: u32LE(2)},
			},
		},
		[][]testKV{
			{
				{keyType: uint8(AmountType), value: u64LE(5000)},
				{keyType: uint8(ScriptType), value: []byte{0x51}},
			},
		},
	)

	parsed, err := NewFromRawBytes(bytes.NewReader(raw), false)
	require.NoError(t, err)
	require.EqualValues(t, 2, parsed.Version)
	require.EqualValues(t, 3, parsed.TxVersion)
	require.NotNil(t, parsed.FallbackLocktime)
	require.EqualValues(t, 500, *parsed.FallbackLocktime)
	require.NotNil(t, parsed.TxModifiable)
	require.EqualValues(t, 0x03, *parsed.TxModifiable)
	require.Len(t, parsed.Inputs, 1)
	require.Len(t, parsed.Outputs, 1)
	require.Nil(t, parsed.UnsignedTx)
}

// TestPSBTV2GlobalFieldKeyDataFallbackToUnknown ensures forward-compat
// behavior for recognized global v2 types with non-empty keydata.
func TestPSBTV2GlobalFieldKeyDataFallbackToUnknown(t *testing.T) {
	raw := buildRawPSBT(
		t,
		[]testKV{
			{keyType: uint8(VersionType), value: u32LE(2)},
			{keyType: uint8(TxVersionType), keyData: []byte{0x01}, value: u32LE(99)},
			{keyType: uint8(TxVersionType), value: u32LE(2)},
			{keyType: uint8(InputCountType), value: compactSize(t, 1)},
			{keyType: uint8(OutputCountType), value: compactSize(t, 1)},
		},
		[][]testKV{
			{
				{keyType: uint8(PreviousTxIDType), value: bytes.Repeat([]byte{0x22}, 32)},
				{keyType: uint8(OutputIndexType), value: u32LE(0)},
			},
		},
		[][]testKV{
			{
				{keyType: uint8(AmountType), value: u64LE(1)},
				{keyType: uint8(ScriptType), value: []byte{0x51}},
			},
		},
	)

	parsed, err := NewFromRawBytes(bytes.NewReader(raw), false)
	require.NoError(t, err)
	require.EqualValues(t, 2, parsed.TxVersion)
	require.True(t, hasUnknownWithKey(parsed.Unknowns, []byte{byte(TxVersionType), 0x01}))
}

// TestPSBTV2InvalidGlobalFieldsRejected verifies required and forbidden global
// field combinations are enforced for packet-level v2 parsing.
func TestPSBTV2InvalidGlobalFieldsRejected(t *testing.T) {
	t.Run("implicit_v0_rejects_v2_globals", func(t *testing.T) {
		raw := buildRawPSBT(
			t,
			[]testKV{
				{keyType: uint8(UnsignedTxType), value: minimalUnsignedTxBytes(t)},
				{keyType: uint8(TxVersionType), value: u32LE(2)},
			},
			[][]testKV{{}},
			[][]testKV{{}},
		)

		_, err := NewFromRawBytes(bytes.NewReader(raw), false)
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})

	t.Run("explicit_v0_rejects_v2_globals", func(t *testing.T) {
		raw := buildRawPSBT(
			t,
			[]testKV{
				{keyType: uint8(UnsignedTxType), value: minimalUnsignedTxBytes(t)},
				{keyType: uint8(VersionType), value: u32LE(0)},
				{keyType: uint8(OutputCountType), value: compactSize(t, 1)},
			},
			[][]testKV{{}},
			[][]testKV{{}},
		)

		_, err := NewFromRawBytes(bytes.NewReader(raw), false)
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})

	t.Run("missing_tx_version", func(t *testing.T) {
		raw := buildRawPSBT(
			t,
			[]testKV{
				{keyType: uint8(VersionType), value: u32LE(2)},
				{keyType: uint8(InputCountType), value: compactSize(t, 1)},
				{keyType: uint8(OutputCountType), value: compactSize(t, 1)},
			},
			[][]testKV{
				{
					{keyType: uint8(PreviousTxIDType), value: bytes.Repeat([]byte{0x11}, 32)},
					{keyType: uint8(OutputIndexType), value: u32LE(0)},
				},
			},
			[][]testKV{
				{
					{keyType: uint8(AmountType), value: u64LE(1)},
					{keyType: uint8(ScriptType), value: []byte{0x51}},
				},
			},
		)

		_, err := NewFromRawBytes(bytes.NewReader(raw), false)
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})

	t.Run("missing_input_count", func(t *testing.T) {
		raw := buildRawPSBT(
			t,
			[]testKV{
				{keyType: uint8(VersionType), value: u32LE(2)},
				{keyType: uint8(TxVersionType), value: u32LE(2)},
				{keyType: uint8(OutputCountType), value: compactSize(t, 1)},
			},
			[][]testKV{
				{
					{keyType: uint8(PreviousTxIDType), value: bytes.Repeat([]byte{0x11}, 32)},
					{keyType: uint8(OutputIndexType), value: u32LE(0)},
				},
			},
			[][]testKV{
				{
					{keyType: uint8(AmountType), value: u64LE(1)},
					{keyType: uint8(ScriptType), value: []byte{0x51}},
				},
			},
		)

		_, err := NewFromRawBytes(bytes.NewReader(raw), false)
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})

	t.Run("missing_output_count", func(t *testing.T) {
		raw := buildRawPSBT(
			t,
			[]testKV{
				{keyType: uint8(VersionType), value: u32LE(2)},
				{keyType: uint8(TxVersionType), value: u32LE(2)},
				{keyType: uint8(InputCountType), value: compactSize(t, 1)},
			},
			[][]testKV{
				{
					{keyType: uint8(PreviousTxIDType), value: bytes.Repeat([]byte{0x11}, 32)},
					{keyType: uint8(OutputIndexType), value: u32LE(0)},
				},
			},
			[][]testKV{
				{
					{keyType: uint8(AmountType), value: u64LE(1)},
					{keyType: uint8(ScriptType), value: []byte{0x51}},
				},
			},
		)

		_, err := NewFromRawBytes(bytes.NewReader(raw), false)
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})

	t.Run("unsigned_tx_forbidden_in_v2", func(t *testing.T) {
		unsignedTx := wire.NewMsgTx(2)
		var txBuf bytes.Buffer
		require.NoError(t, unsignedTx.SerializeNoWitness(&txBuf))

		raw := buildRawPSBT(
			t,
			[]testKV{
				{keyType: uint8(UnsignedTxType), value: txBuf.Bytes()},
				{keyType: uint8(VersionType), value: u32LE(2)},
				{keyType: uint8(TxVersionType), value: u32LE(2)},
				{keyType: uint8(InputCountType), value: compactSize(t, 0)},
				{keyType: uint8(OutputCountType), value: compactSize(t, 0)},
			},
			nil,
			nil,
		)

		_, err := NewFromRawBytes(bytes.NewReader(raw), false)
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})

	t.Run("missing_required_v2_input_fields", func(t *testing.T) {
		raw := buildRawPSBT(
			t,
			[]testKV{
				{keyType: uint8(VersionType), value: u32LE(2)},
				{keyType: uint8(TxVersionType), value: u32LE(2)},
				{keyType: uint8(InputCountType), value: compactSize(t, 1)},
				{keyType: uint8(OutputCountType), value: compactSize(t, 1)},
			},
			[][]testKV{
				{
					{keyType: uint8(PreviousTxIDType), value: bytes.Repeat([]byte{0x11}, 32)},
				},
			},
			[][]testKV{
				{
					{keyType: uint8(AmountType), value: u64LE(1)},
					{keyType: uint8(ScriptType), value: []byte{0x51}},
				},
			},
		)

		_, err := NewFromRawBytes(bytes.NewReader(raw), false)
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})

	t.Run("missing_required_v2_output_fields", func(t *testing.T) {
		raw := buildRawPSBT(
			t,
			[]testKV{
				{keyType: uint8(VersionType), value: u32LE(2)},
				{keyType: uint8(TxVersionType), value: u32LE(2)},
				{keyType: uint8(InputCountType), value: compactSize(t, 1)},
				{keyType: uint8(OutputCountType), value: compactSize(t, 1)},
			},
			[][]testKV{
				{
					{keyType: uint8(PreviousTxIDType), value: bytes.Repeat([]byte{0x11}, 32)},
					{keyType: uint8(OutputIndexType), value: u32LE(0)},
				},
			},
			[][]testKV{
				{
					{keyType: uint8(AmountType), value: u64LE(1)},
				},
			},
		)

		_, err := NewFromRawBytes(bytes.NewReader(raw), false)
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})

	t.Run("incompatible_v2_locktime_constraints", func(t *testing.T) {
		raw := buildRawPSBT(
			t,
			[]testKV{
				{keyType: uint8(VersionType), value: u32LE(2)},
				{keyType: uint8(TxVersionType), value: u32LE(2)},
				{keyType: uint8(InputCountType), value: compactSize(t, 2)},
				{keyType: uint8(OutputCountType), value: compactSize(t, 1)},
			},
			[][]testKV{
				{
					{keyType: uint8(PreviousTxIDType), value: bytes.Repeat([]byte{0x11}, 32)},
					{keyType: uint8(OutputIndexType), value: u32LE(0)},
					{keyType: uint8(RequiredHeightLocktimeType), value: u32LE(10000)},
				},
				{
					{keyType: uint8(PreviousTxIDType), value: bytes.Repeat([]byte{0x22}, 32)},
					{keyType: uint8(OutputIndexType), value: u32LE(1)},
					{keyType: uint8(RequiredTimeLocktimeType), value: u32LE(1657048460)},
				},
			},
			[][]testKV{
				{
					{keyType: uint8(AmountType), value: u64LE(1)},
					{keyType: uint8(ScriptType), value: []byte{0x51}},
				},
			},
		)

		_, err := NewFromRawBytes(bytes.NewReader(raw), false)
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})
}

// TestPSBTV0RejectsV2InputOutputFields verifies v0 packets reject v2-only
// per-input/per-output fields from BIP370's invalid matrix.
func TestPSBTV0RejectsV2InputOutputFields(t *testing.T) {
	tests := []struct {
		name    string
		inputs  [][]testKV
		outputs [][]testKV
	}{
		{
			name: "v0_rejects_previous_txid",
			inputs: [][]testKV{
				{
					{keyType: uint8(PreviousTxIDType), value: bytes.Repeat([]byte{0x11}, 32)},
				},
			},
			outputs: [][]testKV{{}},
		},
		{
			name: "v0_rejects_output_index",
			inputs: [][]testKV{
				{
					{keyType: uint8(OutputIndexType), value: u32LE(0)},
				},
			},
			outputs: [][]testKV{{}},
		},
		{
			name: "v0_rejects_sequence",
			inputs: [][]testKV{
				{
					{keyType: uint8(SequenceType), value: u32LE(0xfffffffe)},
				},
			},
			outputs: [][]testKV{{}},
		},
		{
			name: "v0_rejects_required_time_locktime",
			inputs: [][]testKV{
				{
					{keyType: uint8(RequiredTimeLocktimeType), value: u32LE(LocktimeThreshold)},
				},
			},
			outputs: [][]testKV{{}},
		},
		{
			name: "v0_rejects_required_height_locktime",
			inputs: [][]testKV{
				{
					{keyType: uint8(RequiredHeightLocktimeType), value: u32LE(1)},
				},
			},
			outputs: [][]testKV{{}},
		},
		{
			name:   "v0_rejects_output_amount",
			inputs: [][]testKV{{}},
			outputs: [][]testKV{
				{
					{keyType: uint8(AmountType), value: u64LE(1)},
				},
			},
		},
		{
			name:   "v0_rejects_output_script",
			inputs: [][]testKV{{}},
			outputs: [][]testKV{
				{
					{keyType: uint8(ScriptType), value: []byte{0x51}},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := buildRawPSBT(
				t,
				[]testKV{
					{keyType: uint8(UnsignedTxType), value: minimalUnsignedTxBytes(t)},
					{keyType: uint8(VersionType), value: u32LE(0)},
				},
				test.inputs,
				test.outputs,
			)

			_, err := NewFromRawBytes(bytes.NewReader(raw), false)
			require.ErrorIs(t, err, ErrInvalidPsbtFormat)
		})
	}
}

// TestSerializeV0RejectsV2InputOutputFields verifies the serializer refuses to
// emit v0 packets containing v2-only per-input/per-output fields.
func TestSerializeV0RejectsV2InputOutputFields(t *testing.T) {
	t.Run("reject_v2_input_fields_in_v0", func(t *testing.T) {
		packet := &Packet{
			Version:    0,
			UnsignedTx: &wire.MsgTx{TxIn: []*wire.TxIn{{}}, TxOut: []*wire.TxOut{{Value: 1}}},
			Inputs: []PInput{
				{
					PreviousTxID: hashPtr(0x11),
					OutputIndex:  u32Ptr(0),
				},
			},
			Outputs: []POutput{{}},
		}

		var serialized bytes.Buffer
		err := packet.Serialize(&serialized)
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})

	t.Run("reject_v2_output_fields_in_v0", func(t *testing.T) {
		amount := int64(1)

		packet := &Packet{
			Version:    0,
			UnsignedTx: &wire.MsgTx{TxIn: []*wire.TxIn{{}}, TxOut: []*wire.TxOut{{Value: 1}}},
			Inputs:     []PInput{{}},
			Outputs: []POutput{
				{
					Amount: &amount,
					Script: []byte{0x51},
				},
			},
		}

		var serialized bytes.Buffer
		err := packet.Serialize(&serialized)
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})
}

// //////////////////////////////////////////////////////////////////////////
// BIP-370 official test vectors
// Source: https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#test-vectors
// //////////////////////////////////////////////////////////////////////////

// TestBIP370InvalidV0WithV2Fields tests all 13 cases where a v0 PSBT
// contains fields that are only valid in v2.
func TestBIP370InvalidV0WithV2Fields(t *testing.T) {
	vectors := []struct {
		name   string
		vector string
	}{
		{"v0_with_global_version_2", "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAECBAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA=="},
		{"v0_with_tx_version", "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAECBAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA=="},
		{"v0_with_fallback_locktime", "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAEDBAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA=="},
		{"v0_with_input_count", "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAEEAQIAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA=="},
		{"v0_with_output_count", "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAEFAQIAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA=="},
		{"v0_with_tx_modifiable", "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAEGAQAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA=="},
		{"v0_with_previous_txid", "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gAIgIC1gH4SEamdV93a+AOPZ3o+xCsyTX7g8RfsBYtTK1at5IY9p2HPlQAAIABAACAAAAAgAAAAAAqAAAAACICA27+LCVWIZhlU7qdZcPdxkFlyhQ24FqjWkxusCRRz3ltGPadhz5UAACAAQAAgAAAAIABAAAAYgAAAAA="},
		{"v0_with_output_index", "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA=="},
		{"v0_with_sequence", "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonARAE/////wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA=="},
		{"v0_with_required_time_locktime", "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonAREEjI3EYgAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA=="},
		{"v0_with_required_height_locktime", "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonARIEECcAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA=="},
		{"v0_with_out_amount", "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonACICAtYB+EhGpnVfd2vgDj2d6PsQrMk1+4PEX7AWLUytWreSGPadhz5UAACAAQAAgAAAAIAAAAAAKgAAAAEDCAAIry8AAAAAACICA27+LCVWIZhlU7qdZcPdxkFlyhQ24FqjWkxusCRRz3ltGPadhz5UAACAAQAAgAAAAIABAAAAYgAAAAA="},
		{"v0_with_out_script", "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonACICAtYB+EhGpnVfd2vgDj2d6PsQrMk1+4PEX7AWLUytWreSGPadhz5UAACAAQAAgAAAAIAAAAAAKgAAAAEEFgAUoH2sirbKlC03nteV+DW6ccnMaIUAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA=="},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			_, err := NewFromRawBytes(strings.NewReader(v.vector), true)
			require.ErrorIs(t, err, ErrInvalidPsbtFormat)
		})
	}
}

// TestBIP370InvalidV2MissingRequired tests v2 packets that are missing
// required global or per-input/per-output fields.
func TestBIP370InvalidV2MissingRequired(t *testing.T) {
	vectors := []struct {
		name   string
		vector string
	}{
		{"missing_input_count", "cHNidP8BAgQCAAAAAQMEAAAAAAEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARAE/v///wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA=="},
		{"missing_output_count", "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARAE/v///wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA=="},
		{"missing_previous_txid", "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEPBAAAAAABEAT+////ACICAtYB+EhGpnVfd2vgDj2d6PsQrMk1+4PEX7AWLUytWreSGPadhz5UAACAAQAAgAAAAIAAAAAAKgAAAAEDCAAIry8AAAAAAQQWABTEMPZMR1baMQ29GghVcu8pmSYnLAAiAgLjb7/1PdU0Bwz4/TlmFGgPNXqbhdtzQL8c+nRdKtezQBj2nYc+VAAAgAEAAIAAAACAAQAAAGQAAAABAwiLvesLAAAAAAEEFgAUTdGTrJZKVqwbnhzKhFT+L0dPhRMA"},
		{"missing_output_index", "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IARAE/v///wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA=="},
		{"missing_out_amount", "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAEQBP7///8AIgIC1gH4SEamdV93a+AOPZ3o+xCsyTX7g8RfsBYtTK1at5IY9p2HPlQAAIABAACAAAAAgAAAAAAqAAAAAQQWABTEMPZMR1baMQ29GghVcu8pmSYnLAAiAgLjb7/1PdU0Bwz4/TlmFGgPNXqbhdtzQL8c+nRdKtezQBj2nYc+VAAAgAEAAIAAAACAAQAAAGQAAAABAwiLvesLAAAAAAEEFgAUTdGTrJZKVqwbnhzKhFT+L0dPhRMA"},
		{"missing_out_script", "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAEQBP7///8AIgIC1gH4SEamdV93a+AOPZ3o+xCsyTX7g8RfsBYtTK1at5IY9p2HPlQAAIABAACAAAAAgAAAAAAqAAAAAQMIAAivLwAAAAAAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA=="},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			_, err := NewFromRawBytes(strings.NewReader(v.vector), true)
			require.ErrorIs(t, err, ErrInvalidPsbtFormat)
		})
	}
}

// TestBIP370InvalidV2LocktimeBoundary tests locktime boundary violations.
func TestBIP370InvalidV2LocktimeBoundary(t *testing.T) {
	vectors := []struct {
		name   string
		vector string
	}{
		{"time_locktime_below_threshold", "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAAREE/2TNHQAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA=="},
		{"height_locktime_at_threshold", "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARIEAGXNHQAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA=="},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			_, err := NewFromRawBytes(strings.NewReader(v.vector), true)
			require.ErrorIs(t, err, ErrInvalidPsbtFormat)
		})
	}
}

// TestBIP370ValidV2 tests all valid v2 vectors from the BIP-370 spec.
func TestBIP370ValidV2(t *testing.T) {
	vectors := []struct {
		name         string
		vector       string
		numInputs    int
		numOutputs   int
		txModifiable *uint8 // nil means field absent
	}{
		{"required_fields_only", "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==", 1, 2, nil},
		{"updated", "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAACICAtYB+EhGpnVfd2vgDj2d6PsQrMk1+4PEX7AWLUytWreSGPadhz5UAACAAQAAgAAAAIAAAAAAKgAAAAEDCAAIry8AAAAAAQQWABTEMPZMR1baMQ29GghVcu8pmSYnLAAiAgLjb7/1PdU0Bwz4/TlmFGgPNXqbhdtzQL8c+nRdKtezQBj2nYc+VAAAgAEAAIAAAACAAQAAAGQAAAABAwiLvesLAAAAAAEEFgAUTdGTrJZKVqwbnhzKhFT+L0dPhRMA", 1, 2, nil},
		{"with_sequence", "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARAE/v///wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==", 1, 2, nil},
		{"all_locktime_fields", "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAEQBP7///8BEQSMjcRiARIEECcAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==", 1, 2, nil},
		{"inputs_modifiable", "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEBAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==", 1, 2, ptrU8(0x01)},
		{"outputs_modifiable", "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==", 1, 2, ptrU8(0x02)},
		{"sighash_single_flag", "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEEAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==", 1, 2, ptrU8(0x04)},
		{"undefined_flag_bit3", "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEIAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==", 1, 2, ptrU8(0x08)},
		{"inputs_and_outputs_modifiable", "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEDAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==", 1, 2, ptrU8(0x03)},
		{"inputs_and_sighash_single", "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEFAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==", 1, 2, ptrU8(0x05)},
		{"outputs_and_sighash_single", "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEGAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==", 1, 2, ptrU8(0x06)},
		{"all_defined_flags", "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEHAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==", 1, 2, ptrU8(0x07)},
		{"all_flags_0xff", "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgH/AfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==", 1, 2, ptrU8(0xff)},
		{"all_v2_fields", "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAQYBBwH7BAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BDiALCtkhQZwchxlzXXLcc5+eqeBjjR/kwe7w+ZRAhIFfyAEPBAAAAAABEAT+////AREEjI3EYgESBBAnAAAAIgIC1gH4SEamdV93a+AOPZ3o+xCsyTX7g8RfsBYtTK1at5IY9p2HPlQAAIABAACAAAAAgAAAAAAqAAAAAQMIAAivLwAAAAABBBYAFMQw9kxHVtoxDb0aCFVy7ymZJicsACICAuNvv/U91TQHDPj9OWYUaA81epuF23NAvxz6dF0q17NAGPadhz5UAACAAQAAgAAAAIABAAAAZAAAAAEDCIu96wsAAAAAAQQWABRN0ZOslkpWrBueHMqEVP4vR0+FEwA=", 1, 2, ptrU8(0x07)},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			p, err := NewFromRawBytes(strings.NewReader(v.vector), true)
			require.NoError(t, err)
			require.EqualValues(t, 2, p.Version)
			require.Nil(t, p.UnsignedTx)
			require.Len(t, p.Inputs, v.numInputs)
			require.Len(t, p.Outputs, v.numOutputs)

			// Verify TxModifiable byte preservation.
			if v.txModifiable == nil {
				require.Nil(t, p.TxModifiable,
					"expected TxModifiable to be nil")
			} else {
				require.NotNil(t, p.TxModifiable,
					"expected TxModifiable to be set")
				require.Equal(t, *v.txModifiable, *p.TxModifiable,
					"TxModifiable byte mismatch")
			}

			// Roundtrip: serialize → re-parse → compare TxModifiable.
			var buf bytes.Buffer
			require.NoError(t, p.Serialize(&buf))
			p2, err := NewFromRawBytes(&buf, false)
			require.NoError(t, err)
			if v.txModifiable == nil {
				require.Nil(t, p2.TxModifiable)
			} else {
				require.NotNil(t, p2.TxModifiable)
				require.Equal(t, *v.txModifiable, *p2.TxModifiable,
					"TxModifiable not preserved after roundtrip")
			}
		})
	}
}

// TestBIP370LocktimeDetermination tests the locktime computation algorithm
// using official BIP-370 base64 vectors.
func TestBIP370LocktimeDetermination(t *testing.T) {
	validVectors := []struct {
		name     string
		vector   string
		locktime uint32
	}{
		{"no_locktimes", "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==", 0},
		{"fallback_locktime_zero", "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAAAAQ4gOhs7PIN9ZInqejHY5sfdUDwAG+8+BpWOdXSAjWjKeKUBDwQAAAAAAAEDCE+TNXcAAAAAAQQWABQLE1LKzQPPaqG388jWOIZxs0peEQA=", 0},
		{"height_10000_other_none", "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAABAwhPkzV3AAAAAAEEFgAUCxNSys0Dz2qht/PI1jiGcbNKXhEA", 10000},
		{"height_10000_vs_9000", "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAESBCgjAAAAAQMIT5M1dwAAAAABBBYAFAsTUsrNA89qobfzyNY4hnGzSl4RAA==", 10000},
		{"height_10000_vs_height_9000_time_1657048460", "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAERBIyNxGIBEgQoIwAAAAEDCE+TNXcAAAAAAQQWABQLE1LKzQPPaqG388jWOIZxs0peEQA=", 10000},
		{"both_have_both_height_wins", "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEQSLjcRiARIEECcAAAABDiA6Gzs8g31kiep6Mdjmx91QPAAb7z4GlY51dICNaMp4pQEPBAAAAAABEQSMjcRiARIEKCMAAAABAwhPkzV3AAAAAAEEFgAUCxNSys0Dz2qht/PI1jiGcbNKXhEA", 10000},
		{"time_only_vs_height_and_time", "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEQSLjcRiAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAERBIyNxGIBEgQoIwAAAAEDCE+TNXcAAAAAAQQWABQLE1LKzQPPaqG388jWOIZxs0peEQA=", 1657048460},
		{"height_and_time_vs_time_only", "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEQSLjcRiARIEECcAAAABDiA6Gzs8g31kiep6Mdjmx91QPAAb7z4GlY51dICNaMp4pQEPBAAAAAABEQSMjcRiAAEDCE+TNXcAAAAAAQQWABQLE1LKzQPPaqG388jWOIZxs0peEQA=", 1657048460},
		{"both_time_only", "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAAAAQ4gOhs7PIN9ZInqejHY5sfdUDwAG+8+BpWOdXSAjWjKeKUBDwQAAAAAAREEjI3EYgABAwhPkzV3AAAAAAEEFgAUCxNSys0Dz2qht/PI1jiGcbNKXhEA", 1657048460},
	}

	for _, v := range validVectors {
		t.Run(v.name, func(t *testing.T) {
			p, err := NewFromRawBytes(strings.NewReader(v.vector), true)
			require.NoError(t, err)

			locktime, err := p.ComputedLockTime()
			require.NoError(t, err)
			require.EqualValues(t, v.locktime, locktime)
		})
	}

	// The indeterminate case: height-only vs time-only.
	t.Run("indeterminate_height_vs_time", func(t *testing.T) {
		const vector = "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAERBIyNxGIAAQMIT5M1dwAAAAABBBYAFAsTUsrNA89qobfzyNY4hnGzSl4RAA=="

		// This vector should fail to parse because SanityCheck calls
		// ComputedLockTime which returns an error for incompatible types.
		_, err := NewFromRawBytes(strings.NewReader(vector), true)
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})
}

// TestV2RejectsTrailingGarbage ensures the parser rejects packets with extra
// bytes after all declared maps have been consumed.
func TestV2RejectsTrailingGarbage(t *testing.T) {
	raw := buildRawPSBT(
		t,
		[]testKV{
			{keyType: uint8(VersionType), value: u32LE(2)},
			{keyType: uint8(TxVersionType), value: u32LE(2)},
			{keyType: uint8(InputCountType), value: compactSize(t, 1)},
			{keyType: uint8(OutputCountType), value: compactSize(t, 1)},
		},
		[][]testKV{{
			{keyType: uint8(PreviousTxIDType), value: bytes.Repeat([]byte{0xaa}, 32)},
			{keyType: uint8(OutputIndexType), value: u32LE(0)},
		}},
		[][]testKV{{
			{keyType: uint8(AmountType), value: u64LE(1000)},
			{keyType: uint8(ScriptType), value: []byte{0x51}},
		}},
	)

	// Append trailing garbage after the valid packet.
	raw = append(raw, 0xDE, 0xAD, 0xBE, 0xEF)

	_, err := NewFromRawBytes(bytes.NewReader(raw), false)
	require.ErrorIs(t, err, ErrInvalidPsbtFormat)
}

// TestV2RejectsExtraInputMapPastDeclaredCount ensures the parser rejects a
// packet whose INPUT_COUNT is smaller than the actual number of input maps.
func TestV2RejectsExtraInputMapPastDeclaredCount(t *testing.T) {
	// Build globals declaring 1 input, 1 output.
	var buf bytes.Buffer
	_, err := buf.Write(psbtMagic[:])
	require.NoError(t, err)

	// Global map.
	putKV(t, &buf, uint8(VersionType), nil, u32LE(2))
	putKV(t, &buf, uint8(TxVersionType), nil, u32LE(2))
	putKV(t, &buf, uint8(InputCountType), nil, compactSize(t, 1))
	putKV(t, &buf, uint8(OutputCountType), nil, compactSize(t, 1))
	endSection(t, &buf)

	// Input map #1 (declared).
	putKV(t, &buf, uint8(PreviousTxIDType), nil, bytes.Repeat([]byte{0x11}, 32))
	putKV(t, &buf, uint8(OutputIndexType), nil, u32LE(0))
	endSection(t, &buf)

	// Output map #1 (declared).
	putKV(t, &buf, uint8(AmountType), nil, u64LE(1000))
	putKV(t, &buf, uint8(ScriptType), nil, []byte{0x51})
	endSection(t, &buf)

	// Extra undeclared input map — should cause rejection.
	putKV(t, &buf, uint8(PreviousTxIDType), nil, bytes.Repeat([]byte{0x22}, 32))
	putKV(t, &buf, uint8(OutputIndexType), nil, u32LE(1))
	endSection(t, &buf)

	_, err = NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
	require.ErrorIs(t, err, ErrInvalidPsbtFormat)
}

// TestV2RejectsExtraOutputMapPastDeclaredCount ensures the parser rejects a
// packet whose OUTPUT_COUNT is smaller than the actual number of output maps.
func TestV2RejectsExtraOutputMapPastDeclaredCount(t *testing.T) {
	var buf bytes.Buffer
	_, err := buf.Write(psbtMagic[:])
	require.NoError(t, err)

	// Global map.
	putKV(t, &buf, uint8(VersionType), nil, u32LE(2))
	putKV(t, &buf, uint8(TxVersionType), nil, u32LE(2))
	putKV(t, &buf, uint8(InputCountType), nil, compactSize(t, 1))
	putKV(t, &buf, uint8(OutputCountType), nil, compactSize(t, 1))
	endSection(t, &buf)

	// Input map #1 (declared).
	putKV(t, &buf, uint8(PreviousTxIDType), nil, bytes.Repeat([]byte{0x11}, 32))
	putKV(t, &buf, uint8(OutputIndexType), nil, u32LE(0))
	endSection(t, &buf)

	// Output map #1 (declared).
	putKV(t, &buf, uint8(AmountType), nil, u64LE(1000))
	putKV(t, &buf, uint8(ScriptType), nil, []byte{0x51})
	endSection(t, &buf)

	// Extra undeclared output map — should cause rejection.
	putKV(t, &buf, uint8(AmountType), nil, u64LE(2000))
	putKV(t, &buf, uint8(ScriptType), nil, []byte{0x51})
	endSection(t, &buf)

	_, err = NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
	require.ErrorIs(t, err, ErrInvalidPsbtFormat)
}

// TestHugeInputCountRejected ensures that a packet declaring an absurdly large
// INPUT_COUNT is rejected before allocation.
func TestHugeInputCountRejected(t *testing.T) {
	raw := buildRawPSBT(
		t,
		[]testKV{
			{keyType: uint8(VersionType), value: u32LE(2)},
			{keyType: uint8(TxVersionType), value: u32LE(2)},
			{keyType: uint8(InputCountType), value: compactSize(t, 1_000_000)},
			{keyType: uint8(OutputCountType), value: compactSize(t, 1)},
		},
		nil, // no actual input maps
		nil, // no actual output maps
	)

	_, err := NewFromRawBytes(bytes.NewReader(raw), false)
	require.Error(t, err)
}

// TestHugeOutputCountRejected ensures that a packet declaring an absurdly large
// OUTPUT_COUNT is rejected before allocation.
func TestHugeOutputCountRejected(t *testing.T) {
	raw := buildRawPSBT(
		t,
		[]testKV{
			{keyType: uint8(VersionType), value: u32LE(2)},
			{keyType: uint8(TxVersionType), value: u32LE(2)},
			{keyType: uint8(InputCountType), value: compactSize(t, 1)},
			{keyType: uint8(OutputCountType), value: compactSize(t, 1_000_000)},
		},
		nil,
		nil,
	)

	_, err := NewFromRawBytes(bytes.NewReader(raw), false)
	require.Error(t, err)
}

// TestPSBTV2FieldKeyDataFallbackToUnknown ensures forward-compat behavior:
// known v2 type bytes with non-empty keydata are treated as Unknown entries.
func TestPSBTV2FieldKeyDataFallbackToUnknown(t *testing.T) {
	// Input case: PreviousTxIDType with keydata falls back to Unknowns.
	t.Run("input_previous_txid_with_keydata", func(t *testing.T) {
		var in PInput
		var buf bytes.Buffer

		val := bytes.Repeat([]byte{0x11}, 32)
		putKV(t, &buf, uint8(PreviousTxIDType), []byte{0x01}, val)
		endSection(t, &buf)

		err := in.deserialize(bytes.NewReader(buf.Bytes()))
		require.NoError(t, err)
		require.Nil(t, in.PreviousTxID)
		require.Len(t, in.Unknowns, 1)
		require.Equal(t, []byte{byte(PreviousTxIDType), 0x01}, in.Unknowns[0].Key)
		require.Equal(t, val, in.Unknowns[0].Value)
	})

	// Output case: AmountType with keydata falls back to Unknowns.
	t.Run("output_amount_with_keydata", func(t *testing.T) {
		var out POutput
		var buf bytes.Buffer

		val := u64LE(1)
		putKV(t, &buf, uint8(AmountType), []byte{0x01}, val)
		endSection(t, &buf)

		err := out.deserialize(bytes.NewReader(buf.Bytes()))
		require.NoError(t, err)
		require.Nil(t, out.Amount)
		require.Len(t, out.Unknowns, 1)
		require.Equal(t, []byte{byte(AmountType), 0x01}, out.Unknowns[0].Key)
		require.Equal(t, val, out.Unknowns[0].Value)
	})
}

// TestPSBTV2DuplicateKnownFieldsRejected verifies duplicate singleton v2 keys
// are rejected with ErrDuplicateKey.
func TestPSBTV2DuplicateKnownFieldsRejected(t *testing.T) {
	// Input case: duplicate PreviousTxIDType is invalid.
	t.Run("duplicate_input_previous_txid", func(t *testing.T) {
		var in PInput
		var buf bytes.Buffer

		putKV(t, &buf, uint8(PreviousTxIDType), nil, bytes.Repeat([]byte{0x11}, 32))
		putKV(t, &buf, uint8(PreviousTxIDType), nil, bytes.Repeat([]byte{0x22}, 32))
		endSection(t, &buf)

		err := in.deserialize(bytes.NewReader(buf.Bytes()))
		require.ErrorIs(t, err, ErrDuplicateKey)
	})

	// Output case: duplicate AmountType is invalid.
	t.Run("duplicate_output_amount", func(t *testing.T) {
		var out POutput
		var buf bytes.Buffer

		putKV(t, &buf, uint8(AmountType), nil, u64LE(1))
		putKV(t, &buf, uint8(AmountType), nil, u64LE(2))
		endSection(t, &buf)

		err := out.deserialize(bytes.NewReader(buf.Bytes()))
		require.ErrorIs(t, err, ErrDuplicateKey)
	})
}

// TestPacketGetTxVersion verifies the version accessor hides the v0/v2 split.
func TestPacketGetTxVersion(t *testing.T) {
	t.Run("v0_reads_unsigned_tx_version", func(t *testing.T) {
		packet := &Packet{
			UnsignedTx: wire.NewMsgTx(3),
		}

		require.EqualValues(t, 3, packet.GetTxVersion())
	})

	t.Run("v2_reads_global_tx_version", func(t *testing.T) {
		packet := &Packet{
			Version:   2,
			TxVersion: 4,
		}

		require.EqualValues(t, 4, packet.GetTxVersion())
	})
}

// TestPacketIsCompleteV2 verifies v2 completeness checks do not depend on
// UnsignedTx and therefore do not panic when it is nil.
func TestPacketIsCompleteV2(t *testing.T) {
	t.Run("incomplete_v2_packet", func(t *testing.T) {
		packet := &Packet{
			Version: 2,
			Inputs:  []PInput{{}},
		}

		require.NotPanics(t, func() {
			require.False(t, packet.IsComplete())
		})
	})

	t.Run("complete_v2_packet", func(t *testing.T) {
		packet := &Packet{
			Version: 2,
			Inputs: []PInput{
				{FinalScriptSig: []byte{0x51}},
				{FinalScriptWitness: []byte{0x00}},
			},
		}

		require.NotPanics(t, func() {
			require.True(t, packet.IsComplete())
		})
	})
}

// TestPSBTV2SerializeRoundTrip ensures packet-level v2 serialization emits a
// parseable PSBTv2 global map instead of dereferencing UnsignedTx.
func TestPSBTV2SerializeRoundTrip(t *testing.T) {
	txModifiable := uint8(0x03)
	amount := int64(12345)

	packet := &Packet{
		Version:          2,
		TxVersion:        3,
		FallbackLocktime: u32Ptr(500),
		TxModifiable:     &txModifiable,
		Inputs: []PInput{
			{
				PreviousTxID: hashPtr(0x11),
				OutputIndex:  u32Ptr(1),
				Sequence:     u32Ptr(0xfffffffe),
			},
		},
		Outputs: []POutput{
			{
				Amount: &amount,
				Script: []byte{0x00, 0x14, 0x01, 0x02},
			},
		},
		Unknowns: []*Unknown{
			{
				Key:   []byte{byte(TxVersionType), 0x01},
				Value: u32LE(99),
			},
		},
	}

	var serialized bytes.Buffer
	err := packet.Serialize(&serialized)
	require.NoError(t, err)

	parsed, err := NewFromRawBytes(bytes.NewReader(serialized.Bytes()), false)
	require.NoError(t, err)
	require.EqualValues(t, 2, parsed.Version)
	require.Nil(t, parsed.UnsignedTx)
	require.EqualValues(t, 3, parsed.TxVersion)
	require.NotNil(t, parsed.FallbackLocktime)
	require.EqualValues(t, 500, *parsed.FallbackLocktime)
	require.NotNil(t, parsed.TxModifiable)
	require.EqualValues(t, 0x03, *parsed.TxModifiable)
	require.Len(t, parsed.Inputs, 1)
	require.Len(t, parsed.Outputs, 1)
	require.NotNil(t, parsed.Inputs[0].PreviousTxID)
	require.NotNil(t, parsed.Inputs[0].OutputIndex)
	require.NotNil(t, parsed.Inputs[0].Sequence)
	require.NotNil(t, parsed.Outputs[0].Amount)
	require.EqualValues(t, 12345, *parsed.Outputs[0].Amount)
	require.Equal(t, []byte{0x00, 0x14, 0x01, 0x02}, parsed.Outputs[0].Script)
	require.True(t, hasUnknownWithKey(parsed.Unknowns, []byte{byte(TxVersionType), 0x01}))
}

// TestPSBTV2B64EncodeRoundTrip ensures the base64 helper remains a thin,
// working wrapper once v2 serialization is enabled.
func TestPSBTV2B64EncodeRoundTrip(t *testing.T) {
	amount := int64(1)

	packet := &Packet{
		Version:   2,
		TxVersion: 2,
		Inputs: []PInput{
			{
				PreviousTxID: hashPtr(0x22),
				OutputIndex:  u32Ptr(0),
			},
		},
		Outputs: []POutput{
			{
				Amount: &amount,
				Script: []byte{0x51},
			},
		},
	}

	encoded, err := packet.B64Encode()
	require.NoError(t, err)

	parsed, err := NewFromRawBytes(strings.NewReader(encoded), true)
	require.NoError(t, err)
	require.EqualValues(t, 2, parsed.Version)
	require.Nil(t, parsed.UnsignedTx)
	require.EqualValues(t, 2, parsed.TxVersion)
	require.Len(t, parsed.Inputs, 1)
	require.Len(t, parsed.Outputs, 1)
	require.NotNil(t, parsed.Inputs[0].PreviousTxID)
	require.NotNil(t, parsed.Inputs[0].OutputIndex)
	require.NotNil(t, parsed.Outputs[0].Amount)
	require.EqualValues(t, 1, *parsed.Outputs[0].Amount)
	require.Equal(t, []byte{0x51}, parsed.Outputs[0].Script)
}

// TestBuildUnsignedTxV2 verifies buildUnsignedTx reconstructs a correct
// wire.MsgTx from v2 per-input/per-output fields without UnsignedTx.
func TestBuildUnsignedTxV2(t *testing.T) {
	t.Run("basic_reconstruction", func(t *testing.T) {
		amount1 := int64(5000)
		amount2 := int64(3000)

		packet := &Packet{
			Version:   2,
			TxVersion: 2,
			Inputs: []PInput{
				{
					PreviousTxID: hashPtr(0xaa),
					OutputIndex:  u32Ptr(0),
					Sequence:     u32Ptr(0xfffffffe),
				},
				{
					PreviousTxID: hashPtr(0xbb),
					OutputIndex:  u32Ptr(3),
					// Sequence omitted — should default to MaxTxInSequenceNum.
				},
			},
			Outputs: []POutput{
				{Amount: &amount1, Script: []byte{0x00, 0x14, 0x01}},
				{Amount: &amount2, Script: []byte{0x51}},
			},
		}

		tx, err := packet.buildUnsignedTx()
		require.NoError(t, err)

		// Transaction-level fields.
		require.EqualValues(t, 2, tx.Version)
		require.EqualValues(t, 0, tx.LockTime)

		// Inputs.
		require.Len(t, tx.TxIn, 2)
		require.Equal(t, *hashPtr(0xaa), tx.TxIn[0].PreviousOutPoint.Hash)
		require.EqualValues(t, 0, tx.TxIn[0].PreviousOutPoint.Index)
		require.EqualValues(t, 0xfffffffe, tx.TxIn[0].Sequence)
		require.Equal(t, *hashPtr(0xbb), tx.TxIn[1].PreviousOutPoint.Hash)
		require.EqualValues(t, 3, tx.TxIn[1].PreviousOutPoint.Index)
		require.EqualValues(t, wire.MaxTxInSequenceNum, tx.TxIn[1].Sequence)

		// Outputs.
		require.Len(t, tx.TxOut, 2)
		require.EqualValues(t, 5000, tx.TxOut[0].Value)
		require.Equal(t, []byte{0x00, 0x14, 0x01}, tx.TxOut[0].PkScript)
		require.EqualValues(t, 3000, tx.TxOut[1].Value)
		require.Equal(t, []byte{0x51}, tx.TxOut[1].PkScript)
	})

	t.Run("with_locktime", func(t *testing.T) {
		amount := int64(1)

		packet := &Packet{
			Version:          2,
			TxVersion:        2,
			FallbackLocktime: u32Ptr(800000),
			Inputs: []PInput{
				{
					PreviousTxID: hashPtr(0xcc),
					OutputIndex:  u32Ptr(0),
				},
			},
			Outputs: []POutput{
				{Amount: &amount, Script: []byte{0x51}},
			},
		}

		tx, err := packet.buildUnsignedTx()
		require.NoError(t, err)
		require.EqualValues(t, 800000, tx.LockTime)
	})

	t.Run("missing_prevout_returns_error", func(t *testing.T) {
		amount := int64(1)

		packet := &Packet{
			Version:   2,
			TxVersion: 2,
			Inputs:    []PInput{{}},
			Outputs: []POutput{
				{Amount: &amount, Script: []byte{0x51}},
			},
		}

		_, err := packet.buildUnsignedTx()
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})

	t.Run("missing_output_script_returns_error", func(t *testing.T) {
		amount := int64(1)

		packet := &Packet{
			Version:   2,
			TxVersion: 2,
			Inputs: []PInput{
				{
					PreviousTxID: hashPtr(0xdd),
					OutputIndex:  u32Ptr(0),
				},
			},
			Outputs: []POutput{
				{Amount: &amount},
			},
		}

		_, err := packet.buildUnsignedTx()
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})

	t.Run("v0_returns_copy", func(t *testing.T) {
		orig := wire.NewMsgTx(1)
		orig.LockTime = 42
		orig.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: *hashPtr(0xff), Index: 0},
			Sequence:         wire.MaxTxInSequenceNum,
		})
		orig.AddTxOut(&wire.TxOut{Value: 100, PkScript: []byte{0x51}})

		packet := &Packet{
			Version:    0,
			UnsignedTx: orig,
			Inputs:     []PInput{{}},
			Outputs:    []POutput{{}},
		}

		tx, err := packet.buildUnsignedTx()
		require.NoError(t, err)

		// Should be equal but not the same pointer.
		require.EqualValues(t, orig.LockTime, tx.LockTime)
		require.Len(t, tx.TxIn, 1)
		require.Len(t, tx.TxOut, 1)

		// Mutating the copy should not affect the original.
		tx.LockTime = 999
		require.EqualValues(t, 42, orig.LockTime)
	})
}

// //////////////////////////////////////////////////////////////////////////
// PSBTv2 - Creator & Constructor tests
// //////////////////////////////////////////////////////////////////////////

// TestNewV2CreatesRequiredFields verifies that NewV2 populates v2-required
// per-input and per-output fields and passes SanityCheck.
func TestNewV2CreatesRequiredFields(t *testing.T) {
	inputs := []wire.OutPoint{
		{Hash: *hashPtr(0xaa), Index: 0},
		{Hash: *hashPtr(0xbb), Index: 3},
	}
	outputs := []*wire.TxOut{
		{Value: 5000, PkScript: []byte{0x00, 0x14, 0x01}},
		{Value: 3000, PkScript: []byte{0x51}},
	}

	pkt, err := NewV2(2, inputs, outputs, nil, nil)
	require.NoError(t, err)

	// Packet-level fields.
	require.EqualValues(t, 2, pkt.Version)
	require.Nil(t, pkt.UnsignedTx)
	require.EqualValues(t, 2, pkt.TxVersion)
	require.Nil(t, pkt.FallbackLocktime)
	require.Nil(t, pkt.TxModifiable)

	// Per-input fields.
	require.Len(t, pkt.Inputs, 2)
	require.Equal(t, hashPtr(0xaa), pkt.Inputs[0].PreviousTxID)
	require.EqualValues(t, 0, *pkt.Inputs[0].OutputIndex)
	require.Equal(t, hashPtr(0xbb), pkt.Inputs[1].PreviousTxID)
	require.EqualValues(t, 3, *pkt.Inputs[1].OutputIndex)

	// Per-output fields.
	require.Len(t, pkt.Outputs, 2)
	require.EqualValues(t, 5000, *pkt.Outputs[0].Amount)
	require.Equal(t, []byte{0x00, 0x14, 0x01}, pkt.Outputs[0].Script)
	require.EqualValues(t, 3000, *pkt.Outputs[1].Amount)
	require.Equal(t, []byte{0x51}, pkt.Outputs[1].Script)

	// Must pass its own SanityCheck.
	require.NoError(t, pkt.SanityCheck())
}

// TestNewV2WithOptionalFields verifies fallbackLocktime and txModifiable
// are properly set when provided.
func TestNewV2WithOptionalFields(t *testing.T) {
	fl := uint32(800_000)
	mod := uint8(0x03) // inputs + outputs modifiable

	pkt, err := NewV2(
		2,
		[]wire.OutPoint{{Hash: *hashPtr(0x11), Index: 0}},
		[]*wire.TxOut{{Value: 1000, PkScript: []byte{0x51}}},
		&fl, &mod,
	)
	require.NoError(t, err)
	require.NotNil(t, pkt.FallbackLocktime)
	require.EqualValues(t, 800_000, *pkt.FallbackLocktime)
	require.NotNil(t, pkt.TxModifiable)
	require.EqualValues(t, 0x03, *pkt.TxModifiable)
}

// TestNewV2RejectsInvalidTxVersion ensures bad transaction versions fail.
func TestNewV2RejectsInvalidTxVersion(t *testing.T) {
	_, err := NewV2(
		0, // below MinTxVersion
		[]wire.OutPoint{{Hash: *hashPtr(0x11), Index: 0}},
		[]*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}},
		nil, nil,
	)
	require.ErrorIs(t, err, ErrInvalidPsbtFormat)
}

// TestNewV2SerializeRoundTrip verifies a created v2 packet survives
// serialization and re-parsing.
func TestNewV2SerializeRoundTrip(t *testing.T) {
	fl := uint32(500)
	pkt, err := NewV2(
		2,
		[]wire.OutPoint{
			{Hash: *hashPtr(0xaa), Index: 0},
		},
		[]*wire.TxOut{
			{Value: 9000, PkScript: []byte{0x00, 0x14, 0x02}},
		},
		&fl, nil,
	)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, pkt.Serialize(&buf))

	parsed, err := NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
	require.NoError(t, err)
	require.EqualValues(t, 2, parsed.Version)
	require.EqualValues(t, 2, parsed.TxVersion)
	require.NotNil(t, parsed.FallbackLocktime)
	require.EqualValues(t, 500, *parsed.FallbackLocktime)
	require.Len(t, parsed.Inputs, 1)
	require.Len(t, parsed.Outputs, 1)
	require.Equal(t, hashPtr(0xaa), parsed.Inputs[0].PreviousTxID)
	require.EqualValues(t, 0, *parsed.Inputs[0].OutputIndex)
	require.EqualValues(t, 9000, *parsed.Outputs[0].Amount)
	require.Equal(t, []byte{0x00, 0x14, 0x02}, parsed.Outputs[0].Script)
}

// TestNewV2DoesNotAlias ensures NewV2 copies input data so the caller
// can't mutate the packet through the original slices.
func TestNewV2DoesNotAlias(t *testing.T) {
	script := []byte{0x51, 0x52}
	outputs := []*wire.TxOut{{Value: 100, PkScript: script}}

	pkt, err := NewV2(
		2,
		[]wire.OutPoint{{Hash: *hashPtr(0x11), Index: 0}},
		outputs, nil, nil,
	)
	require.NoError(t, err)

	// Mutate the original — packet should be unaffected.
	script[0] = 0xff
	require.EqualValues(t, 0x51, pkt.Outputs[0].Script[0])
}

// TestConstructorRejectsV0 ensures NewConstructor only accepts v2 packets.
func TestConstructorRejectsV0(t *testing.T) {
	pkt := &Packet{
		Version:    0,
		UnsignedTx: &wire.MsgTx{},
	}

	_, err := NewConstructor(pkt)
	require.ErrorIs(t, err, ErrInvalidPsbtFormat)
}

// TestConstructorAddInputOutput verifies inputs/outputs can be added when
// the corresponding TxModifiable bits are set.
func TestConstructorAddInputOutput(t *testing.T) {
	mod := uint8(0x03) // both modifiable
	pkt, err := NewV2(
		2,
		[]wire.OutPoint{{Hash: *hashPtr(0x11), Index: 0}},
		[]*wire.TxOut{{Value: 1000, PkScript: []byte{0x51}}},
		nil, &mod,
	)
	require.NoError(t, err)

	c, err := NewConstructor(pkt)
	require.NoError(t, err)

	// Add an input.
	require.NoError(t, c.AddInput(*hashPtr(0x22), 1))
	require.Len(t, pkt.Inputs, 2)
	require.Equal(t, hashPtr(0x22), pkt.Inputs[1].PreviousTxID)
	require.EqualValues(t, 1, *pkt.Inputs[1].OutputIndex)

	// Add an output.
	require.NoError(t, c.AddOutput(2000, []byte{0x00, 0x14, 0x03}))
	require.Len(t, pkt.Outputs, 2)
	require.EqualValues(t, 2000, *pkt.Outputs[1].Amount)
	require.Equal(t, []byte{0x00, 0x14, 0x03}, pkt.Outputs[1].Script)
}

// TestConstructorRejectsWhenNotModifiable verifies that add/remove operations
// fail when TxModifiable is nil or the relevant bit is cleared.
func TestConstructorRejectsWhenNotModifiable(t *testing.T) {
	t.Run("nil_tx_modifiable", func(t *testing.T) {
		pkt := &Packet{
			Version:   2,
			TxVersion: 2,
			Inputs: []PInput{{
				PreviousTxID: hashPtr(0x11),
				OutputIndex:  u32Ptr(0),
			}},
			Outputs: []POutput{{
				Amount: func() *int64 { a := int64(1); return &a }(),
				Script: []byte{0x51},
			}},
		}

		c, err := NewConstructor(pkt)
		require.NoError(t, err)

		require.ErrorIs(t, c.AddInput(*hashPtr(0x22), 0), ErrInputsNotModifiable)
		require.ErrorIs(t, c.AddOutput(1, []byte{0x51}), ErrOutputsNotModifiable)
		require.ErrorIs(t, c.RemoveInput(0), ErrInputsNotModifiable)
		require.ErrorIs(t, c.RemoveOutput(0), ErrOutputsNotModifiable)
	})

	t.Run("inputs_only_modifiable", func(t *testing.T) {
		mod := uint8(0x01) // only inputs
		pkt := &Packet{
			Version:      2,
			TxVersion:    2,
			TxModifiable: &mod,
			Inputs: []PInput{{
				PreviousTxID: hashPtr(0x11),
				OutputIndex:  u32Ptr(0),
			}},
			Outputs: []POutput{{
				Amount: func() *int64 { a := int64(1); return &a }(),
				Script: []byte{0x51},
			}},
		}

		c, err := NewConstructor(pkt)
		require.NoError(t, err)

		require.NoError(t, c.AddInput(*hashPtr(0x33), 0))
		require.ErrorIs(t, c.AddOutput(1, []byte{0x51}), ErrOutputsNotModifiable)
	})

	t.Run("outputs_only_modifiable", func(t *testing.T) {
		mod := uint8(0x02) // only outputs
		pkt := &Packet{
			Version:      2,
			TxVersion:    2,
			TxModifiable: &mod,
			Inputs: []PInput{{
				PreviousTxID: hashPtr(0x11),
				OutputIndex:  u32Ptr(0),
			}},
			Outputs: []POutput{{
				Amount: func() *int64 { a := int64(1); return &a }(),
				Script: []byte{0x51},
			}},
		}

		c, err := NewConstructor(pkt)
		require.NoError(t, err)

		require.ErrorIs(t, c.AddInput(*hashPtr(0x33), 0), ErrInputsNotModifiable)
		require.NoError(t, c.AddOutput(2000, []byte{0x51}))
	})
}

// TestConstructorRemoveInputOutput verifies removal by index.
func TestConstructorRemoveInputOutput(t *testing.T) {
	mod := uint8(0x03)
	pkt, err := NewV2(
		2,
		[]wire.OutPoint{
			{Hash: *hashPtr(0xaa), Index: 0},
			{Hash: *hashPtr(0xbb), Index: 1},
			{Hash: *hashPtr(0xcc), Index: 2},
		},
		[]*wire.TxOut{
			{Value: 100, PkScript: []byte{0x51}},
			{Value: 200, PkScript: []byte{0x52}},
		},
		nil, &mod,
	)
	require.NoError(t, err)

	c, err := NewConstructor(pkt)
	require.NoError(t, err)

	// Remove middle input.
	require.NoError(t, c.RemoveInput(1))
	require.Len(t, pkt.Inputs, 2)
	require.Equal(t, hashPtr(0xaa), pkt.Inputs[0].PreviousTxID)
	require.Equal(t, hashPtr(0xcc), pkt.Inputs[1].PreviousTxID)

	// Remove first output.
	require.NoError(t, c.RemoveOutput(0))
	require.Len(t, pkt.Outputs, 1)
	require.EqualValues(t, 200, *pkt.Outputs[0].Amount)

	// Out-of-range removal.
	require.ErrorIs(t, c.RemoveInput(5), ErrInvalidPsbtFormat)
	require.ErrorIs(t, c.RemoveOutput(-1), ErrInvalidPsbtFormat)
}

// TestConstructorAddOutputDoesNotAlias ensures the Constructor copies
// the script so the caller can't mutate the packet afterward.
func TestConstructorAddOutputDoesNotAlias(t *testing.T) {
	mod := uint8(0x02)
	pkt := &Packet{
		Version:      2,
		TxVersion:    2,
		TxModifiable: &mod,
		Inputs: []PInput{{
			PreviousTxID: hashPtr(0x11),
			OutputIndex:  u32Ptr(0),
		}},
		Outputs: []POutput{{
			Amount: func() *int64 { a := int64(1); return &a }(),
			Script: []byte{0x51},
		}},
	}

	c, err := NewConstructor(pkt)
	require.NoError(t, err)

	script := []byte{0xaa, 0xbb}
	require.NoError(t, c.AddOutput(500, script))

	// Mutate caller's slice — packet should be unaffected.
	script[0] = 0xff
	require.EqualValues(t, 0xaa, pkt.Outputs[1].Script[0])
}

// TestConstructorRejectsWhenSignaturesExist verifies that mutation is blocked
// once any input contains signature material.
func TestConstructorRejectsWhenSignaturesExist(t *testing.T) {
	makePacket := func(inputs []PInput) *Packet {
		mod := uint8(0x03)
		return &Packet{
			Version:      2,
			TxVersion:    2,
			TxModifiable: &mod,
			Inputs:       inputs,
			Outputs: []POutput{{
				Amount: func() *int64 { a := int64(1); return &a }(),
				Script: []byte{0x51},
			}},
		}
	}

	tests := []struct {
		name  string
		input PInput
	}{
		{
			name: "partial_sig",
			input: PInput{
				PreviousTxID: hashPtr(0x11),
				OutputIndex:  u32Ptr(0),
				PartialSigs: []*PartialSig{{
					PubKey:    make([]byte, 33),
					Signature: make([]byte, 64),
				}},
			},
		},
		{
			name: "taproot_key_spend_sig",
			input: PInput{
				PreviousTxID:       hashPtr(0x11),
				OutputIndex:        u32Ptr(0),
				TaprootKeySpendSig: make([]byte, 64),
			},
		},
		{
			name: "taproot_script_spend_sig",
			input: PInput{
				PreviousTxID: hashPtr(0x11),
				OutputIndex:  u32Ptr(0),
				TaprootScriptSpendSig: []*TaprootScriptSpendSig{{
					XOnlyPubKey: make([]byte, 32),
					LeafHash:    make([]byte, 32),
					Signature:   make([]byte, 64),
				}},
			},
		},
		{
			name: "final_script_sig",
			input: PInput{
				PreviousTxID:   hashPtr(0x11),
				OutputIndex:    u32Ptr(0),
				FinalScriptSig: []byte{0x51},
			},
		},
		{
			name: "final_script_witness",
			input: PInput{
				PreviousTxID:       hashPtr(0x11),
				OutputIndex:        u32Ptr(0),
				FinalScriptWitness: []byte{0x00},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkt := makePacket([]PInput{test.input})
			c, err := NewConstructor(pkt)
			require.NoError(t, err)

			require.ErrorIs(t,
				c.AddInput(*hashPtr(0x22), 0),
				ErrSignaturesExist,
			)
			require.ErrorIs(t,
				c.AddOutput(1, []byte{0x51}),
				ErrSignaturesExist,
			)
			require.ErrorIs(t,
				c.RemoveInput(0),
				ErrSignaturesExist,
			)
			require.ErrorIs(t,
				c.RemoveOutput(0),
				ErrSignaturesExist,
			)
		})
	}
}

// TestConstructorAllowsMutationWithoutSignatures confirms that mutation
// succeeds when no signature material is present (sanity counterpart).
func TestConstructorAllowsMutationWithoutSignatures(t *testing.T) {
	mod := uint8(0x03)
	pkt, err := NewV2(
		2,
		[]wire.OutPoint{{Hash: *hashPtr(0x11), Index: 0}},
		[]*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}},
		nil, &mod,
	)
	require.NoError(t, err)

	c, err := NewConstructor(pkt)
	require.NoError(t, err)

	require.NoError(t, c.AddInput(*hashPtr(0x22), 0))
	require.NoError(t, c.AddOutput(2, []byte{0x52}))
}

// TestConstructorRejectsSighashSingleOneSided verifies that when bit 2
// (Has SIGHASH_SINGLE) is set, all one-sided mutations are rejected.
func TestConstructorRejectsSighashSingleOneSided(t *testing.T) {
	mod := uint8(0x07) // inputs + outputs + sighash_single
	pkt, err := NewV2(
		2,
		[]wire.OutPoint{{Hash: *hashPtr(0x11), Index: 0}},
		[]*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}},
		nil, &mod,
	)
	require.NoError(t, err)

	c, err := NewConstructor(pkt)
	require.NoError(t, err)

	require.ErrorIs(t,
		c.AddInput(*hashPtr(0x22), 0),
		ErrSighashSinglePairing,
	)
	require.ErrorIs(t,
		c.AddOutput(2, []byte{0x52}),
		ErrSighashSinglePairing,
	)
	require.ErrorIs(t,
		c.RemoveInput(0),
		ErrSighashSinglePairing,
	)
	require.ErrorIs(t,
		c.RemoveOutput(0),
		ErrSighashSinglePairing,
	)
}

// TestConstructorAllowsMutationWithoutSighashSingle confirms that mutation
// succeeds when bit 2 is NOT set (sanity counterpart).
func TestConstructorAllowsMutationWithoutSighashSingle(t *testing.T) {
	mod := uint8(0x03) // inputs + outputs, no sighash_single
	pkt, err := NewV2(
		2,
		[]wire.OutPoint{{Hash: *hashPtr(0x11), Index: 0}},
		[]*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}},
		nil, &mod,
	)
	require.NoError(t, err)

	c, err := NewConstructor(pkt)
	require.NoError(t, err)

	require.NoError(t, c.AddInput(*hashPtr(0x22), 0))
	require.NoError(t, c.AddOutput(2, []byte{0x52}))
}

// TestNewConstructorNil ensures NewConstructor returns an error on nil input.
func TestNewConstructorNil(t *testing.T) {
	_, err := NewConstructor(nil)
	require.ErrorIs(t, err, ErrInvalidPsbtFormat)
}

// TestNewV2NilOutputElement ensures NewV2 returns an error when an output
// element is nil rather than panicking.
func TestNewV2NilOutputElement(t *testing.T) {
	_, err := NewV2(
		2,
		[]wire.OutPoint{{Hash: *hashPtr(0x11), Index: 0}},
		[]*wire.TxOut{nil},
		nil, nil,
	)
	require.ErrorIs(t, err, ErrInvalidPsbtFormat)
}

// TestNewV2RejectsNegativeAmount ensures NewV2 rejects outputs with
// negative values.
func TestNewV2RejectsNegativeAmount(t *testing.T) {
	_, err := NewV2(
		2,
		[]wire.OutPoint{{Hash: *hashPtr(0x11), Index: 0}},
		[]*wire.TxOut{{Value: -1, PkScript: []byte{0x51}}},
		nil, nil,
	)
	require.ErrorIs(t, err, ErrInvalidPsbtFormat)
}

// TestConstructorRejectsNegativeAmount ensures AddOutput rejects negative
// amounts.
func TestConstructorRejectsNegativeAmount(t *testing.T) {
	mod := uint8(0x02)
	pkt, err := NewV2(
		2,
		[]wire.OutPoint{{Hash: *hashPtr(0x11), Index: 0}},
		[]*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}},
		nil, &mod,
	)
	require.NoError(t, err)

	c, err := NewConstructor(pkt)
	require.NoError(t, err)

	require.ErrorIs(t, c.AddOutput(-1, []byte{0x51}), ErrInvalidPsbtFormat)
}

// TestNewV2DoesNotAliasGlobalPointers ensures caller can't mutate packet
// globals through the original pointer args.
func TestNewV2DoesNotAliasGlobalPointers(t *testing.T) {
	fl := uint32(100)
	mod := uint8(0x03)

	pkt, err := NewV2(
		2,
		[]wire.OutPoint{{Hash: *hashPtr(0x11), Index: 0}},
		[]*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}},
		&fl, &mod,
	)
	require.NoError(t, err)

	// Mutate caller's values — packet should be unaffected.
	fl = 999
	mod = 0x00

	require.EqualValues(t, 100, *pkt.FallbackLocktime)
	require.EqualValues(t, 0x03, *pkt.TxModifiable)
}

// TestPacketComputedLockTimeV0 verifies the legacy passthrough behavior.
func TestPacketComputedLockTimeV0(t *testing.T) {
	packet := &Packet{
		UnsignedTx: &wire.MsgTx{LockTime: 12345},
	}

	locktime, err := packet.ComputedLockTime()
	require.NoError(t, err)
	require.EqualValues(t, 12345, locktime)
}

// TestPacketGetTxFeeV2 verifies fee calculation on v2 packets is version-aware
// and does not depend on UnsignedTx being present.
func TestPacketGetTxFeeV2(t *testing.T) {
	t.Run("mixed_witness_and_nonwitness_utxo", func(t *testing.T) {
		amount := int64(1000)
		nonWitness := wire.NewMsgTx(2)
		nonWitness.AddTxOut(&wire.TxOut{Value: 123, PkScript: []byte{0x51}})
		nonWitness.AddTxOut(&wire.TxOut{Value: 500, PkScript: []byte{0x51}})

		packet := &Packet{
			Version:   2,
			TxVersion: 2,
			Inputs: []PInput{
				{
					PreviousTxID: hashPtr(0x11),
					OutputIndex:  u32Ptr(0),
					WitnessUtxo:  &wire.TxOut{Value: 700, PkScript: []byte{0x51}},
				},
				{
					PreviousTxID:   hashPtr(0x22),
					OutputIndex:    u32Ptr(1),
					NonWitnessUtxo: nonWitness,
				},
			},
			Outputs: []POutput{
				{
					Amount: &amount,
					Script: []byte{0x51},
				},
			},
		}

		fee, err := packet.GetTxFee()
		require.NoError(t, err)
		require.EqualValues(t, 200, fee)
	})

	t.Run("missing_utxo_info_returns_error", func(t *testing.T) {
		amount := int64(1)
		packet := &Packet{
			Version:   2,
			TxVersion: 2,
			Inputs: []PInput{
				{
					PreviousTxID: hashPtr(0x33),
					OutputIndex:  u32Ptr(0),
				},
			},
			Outputs: []POutput{
				{
					Amount: &amount,
					Script: []byte{0x51},
				},
			},
		}

		require.NotPanics(t, func() {
			_, err := packet.GetTxFee()
			require.Error(t, err)
		})
	})
}

// SOURCE:
// https://github.com/rust-bitcoin/rust-psbt/blob/efb1e8fc1bf000c810fc012cc237f67aceef1d9e/tests/bip370-determine-lock-time.rs
//
// TestPSBTV2MirroredComputedLockTime mirrors the BIP370 locktime determination
// cases from rust-psbt at the Packet helper level currently supported here.
func TestPSBTV2MirroredComputedLockTime(t *testing.T) {
	tests := []struct {
		name   string
		packet *Packet
		want   uint32
	}{
		{
			name: "no_locktimes_specified",
			packet: &Packet{
				Version: 2,
				Inputs:  []PInput{{}, {}},
			},
			want: 0,
		},
		{
			name: "fallback_locktime_of_zero",
			packet: &Packet{
				Version:          2,
				FallbackLocktime: u32Ptr(0),
				Inputs:           []PInput{{}, {}},
			},
			want: 0,
		},
		{
			name: "height_10000_and_other_input_without_locktime",
			packet: &Packet{
				Version: 2,
				Inputs: []PInput{
					{RequiredHeightLocktime: u32Ptr(10000)},
					{},
				},
			},
			want: 10000,
		},
		{
			name: "height_10000_and_height_9000",
			packet: &Packet{
				Version: 2,
				Inputs: []PInput{
					{RequiredHeightLocktime: u32Ptr(10000)},
					{RequiredHeightLocktime: u32Ptr(9000)},
				},
			},
			want: 10000,
		},
		{
			name: "height_10000_and_other_input_with_height_9000_and_time_1657048460",
			packet: &Packet{
				Version: 2,
				Inputs: []PInput{
					{RequiredHeightLocktime: u32Ptr(10000)},
					{
						RequiredHeightLocktime: u32Ptr(9000),
						RequiredTimeLocktime:   u32Ptr(1657048460),
					},
				},
			},
			want: 10000,
		},
		{
			name: "both_inputs_support_both_and_height_wins_tie",
			packet: &Packet{
				Version: 2,
				Inputs: []PInput{
					{
						RequiredHeightLocktime: u32Ptr(10000),
						RequiredTimeLocktime:   u32Ptr(1657048459),
					},
					{
						RequiredHeightLocktime: u32Ptr(9000),
						RequiredTimeLocktime:   u32Ptr(1657048460),
					},
				},
			},
			want: 10000,
		},
		{
			name: "time_1657048459_and_other_input_with_height_9000_and_time_1657048460",
			packet: &Packet{
				Version: 2,
				Inputs: []PInput{
					{RequiredTimeLocktime: u32Ptr(1657048459)},
					{
						RequiredHeightLocktime: u32Ptr(9000),
						RequiredTimeLocktime:   u32Ptr(1657048460),
					},
				},
			},
			want: 1657048460,
		},
		{
			name: "height_10000_and_time_1657048459_then_other_input_time_1657048460",
			packet: &Packet{
				Version: 2,
				Inputs: []PInput{
					{
						RequiredHeightLocktime: u32Ptr(10000),
						RequiredTimeLocktime:   u32Ptr(1657048459),
					},
					{RequiredTimeLocktime: u32Ptr(1657048460)},
				},
			},
			want: 1657048460,
		},
		{
			name: "other_input_without_locktimes_then_time_1657048460",
			packet: &Packet{
				Version: 2,
				Inputs: []PInput{
					{},
					{RequiredTimeLocktime: u32Ptr(1657048460)},
				},
			},
			want: 1657048460,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			locktime, err := test.packet.ComputedLockTime()
			require.NoError(t, err)
			require.EqualValues(t, test.want, locktime)
		})
	}
}

// SOURCE:
// https://github.com/rust-bitcoin/rust-psbt/blob/efb1e8fc1bf000c810fc012cc237f67aceef1d9e/tests/bip370-determine-lock-time.rs
//
// TestPSBTV2MirroredComputedLockTimeIndeterminate mirrors the incompatible
// locktime-type case from rust-psbt.
func TestPSBTV2MirroredComputedLockTimeIndeterminate(t *testing.T) {
	packet := &Packet{
		Version: 2,
		Inputs: []PInput{
			{RequiredHeightLocktime: u32Ptr(10000)},
			{RequiredTimeLocktime: u32Ptr(1657048460)},
		},
	}

	_, err := packet.ComputedLockTime()
	require.ErrorIs(t, err, ErrInvalidPsbtFormat)
}

// /////////////////////////////////////////////////////////////////////////////

func putKV(t *testing.T, w *bytes.Buffer, kt uint8, keyData, value []byte) {
	t.Helper()
	require.NoError(t, serializeKVPairWithType(w, kt, keyData, value))
}

func endSection(t *testing.T, w *bytes.Buffer) {
	t.Helper()
	require.NoError(t, w.WriteByte(0x00))
}

func u32LE(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

func u64LE(v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return b[:]
}

// Go moment (or I don't understand this lang well still...)
func u32Ptr(v uint32) *uint32 {
	return &v
}

type testKV struct {
	keyType uint8
	keyData []byte
	value   []byte
}

// buildRawPSBT assembles a raw PSBT packet from explicit global/input/output
// test maps so packet-level parser cases can be written directly in bytes.
func buildRawPSBT(t *testing.T, globals []testKV, inputs [][]testKV, outputs [][]testKV) []byte {
	t.Helper()

	var buf bytes.Buffer
	_, err := buf.Write(psbtMagic[:])
	require.NoError(t, err)

	writeTestMap(t, &buf, globals)
	for _, inputMap := range inputs {
		writeTestMap(t, &buf, inputMap)
	}
	for _, outputMap := range outputs {
		writeTestMap(t, &buf, outputMap)
	}

	return buf.Bytes()
}

// writeTestMap serializes one PSBT map and appends its terminator byte.
func writeTestMap(t *testing.T, w *bytes.Buffer, kvs []testKV) {
	t.Helper()

	for _, kv := range kvs {
		putKV(t, w, kv.keyType, kv.keyData, kv.value)
	}
	endSection(t, w)
}

// compactSize encodes a uint64 using Bitcoin's compact-size format for use in
// INPUT_COUNT/OUTPUT_COUNT test values.
func compactSize(t *testing.T, v uint64) []byte {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, wire.WriteVarInt(&buf, 0, v))
	return buf.Bytes()
}

// hasUnknownWithKey reports whether a parsed unknown entry preserved the exact
// serialized key bytes we expect.
func hasUnknownWithKey(unknowns []*Unknown, key []byte) bool {
	for _, u := range unknowns {
		if bytes.Equal(u.Key, key) {
			return true
		}
	}

	return false
}

// hashPtr creates a stable *chainhash.Hash from a repeated fill byte for
// compact v2 prevout fixtures.
func hashPtr(fill byte) *chainhash.Hash {
	var h chainhash.Hash
	copy(h[:], bytes.Repeat([]byte{fill}, len(h)))
	return &h
}

// minimalUnsignedTxBytes builds a minimal valid unsigned v0 transaction for
// raw parser tests that need a PSBT_GLOBAL_UNSIGNED_TX payload.
func minimalUnsignedTxBytes(t *testing.T) []byte {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	tx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})

	var buf bytes.Buffer
	require.NoError(t, tx.SerializeNoWitness(&buf))

	return buf.Bytes()
}

// /////////////////////////////////////////////////////////////////////////////
// PSBTv2: lifecycle tests (updater → signer → finalizer)
// /////////////////////////////////////////////////////////////////////////////

// testSig1 and testPub1 are format-valid DER sig + compressed pubkey borrowed
// from Core's regtest for use in v2 lifecycle tests.
//
// The sig is NOT cryptographically valid
// for any particular input, but passes the format
// checks in addPartialSignature.
var (
	testSig1, _ = hex.DecodeString(
		"304402200da03ac9890f5d724c42c83c2a62844c08425a274f1a5bca50dcde41" +
			"26eb20dd02205278897b65cb8e390a0868c9582133c7157b2ad3e81c1c70d8" +
			"fbd65f51a5658b01",
	)
	testPub1, _ = hex.DecodeString(
		"024d6b24f372dd4551277c8df4ecc0655101e11c22894c8e05a3468409c865a72c",
	)
)

// makeV2WithWitnessUtxo builds a minimal v2 Packet with a single P2WPKH input
// that has a WitnessUtxo attached, suitable for testing the sign/finalize path.
func makeV2WithWitnessUtxo(t *testing.T, mod *uint8) *Packet {
	t.Helper()

	txid := chainhash.HashH([]byte("test-prevout"))
	idx := uint32(0)
	amt := int64(50_000)
	// P2WPKH scriptPubKey: OP_0 <HASH160(pubkey)>
	pubKeyHash := btcutil.Hash160(testPub1)
	scriptPubKey, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(pubKeyHash).
		Script()
	require.NoError(t, err)

	outAmt := int64(40_000)
	outScript := []byte{0x51} // OP_TRUE

	pkt := &Packet{
		Version:      2,
		TxVersion:    2,
		TxModifiable: mod,
		Inputs: []PInput{{
			PreviousTxID: &txid,
			OutputIndex:  &idx,
			WitnessUtxo: &wire.TxOut{
				Value:    amt,
				PkScript: scriptPubKey,
			},
			PartialSigs:     []*PartialSig{},
			Bip32Derivation: []*Bip32Derivation{},
		}},
		Outputs: []POutput{{
			Amount: &outAmt,
			Script: outScript,
		}},
	}
	require.NoError(t, pkt.SanityCheck())
	return pkt
}

// TestV2UpdaterSignDoesNotPanic verifies that the Updater.Sign path works on
// a v2 packet where UnsignedTx is nil, exercising the accessor migration.
func TestV2UpdaterSignDoesNotPanic(t *testing.T) {
	pkt := makeV2WithWitnessUtxo(t, nil)
	require.Nil(t, pkt.UnsignedTx) // v2 has no UnsignedTx

	u, err := NewUpdater(pkt)
	require.NoError(t, err)

	res, err := u.Sign(0, testSig1, testPub1, nil, nil)
	require.NoError(t, err)
	require.Equal(t, SignOutcome(SignSuccesful), res)
	require.Len(t, pkt.Inputs[0].PartialSigs, 1)
}

// TestV2SignerUpdatesTxModifiable verifies that after signing a v2 packet,
// the TxModifiable flags are updated per BIP-370 sighash rules.
func TestV2SignerUpdatesTxModifiable(t *testing.T) {
	tests := []struct {
		name         string
		sighashType  txscript.SigHashType
		initialFlags uint8
		expectedMask uint8 // expected flags after signing
	}{
		{
			// SIGHASH_ALL (default): clear bits 0 and 1.
			name:         "sighash_all_clears_inputs_outputs",
			sighashType:  txscript.SigHashAll,
			initialFlags: 0x03, // inputs + outputs modifiable
			expectedMask: 0x00,
		},
		{
			// SIGHASH_NONE: clear bit 0, keep bit 1.
			name:         "sighash_none_clears_inputs_only",
			sighashType:  txscript.SigHashNone,
			initialFlags: 0x03,
			expectedMask: 0x02,
		},
		{
			// SIGHASH_SINGLE: clear bit 0, clear bit 1, set bit 2.
			name:         "sighash_single_sets_bit2",
			sighashType:  txscript.SigHashSingle,
			initialFlags: 0x03,
			expectedMask: 0x04,
		},
		{
			// SIGHASH_ALL|ANYONECANPAY: keep bit 0, clear bit 1.
			name:         "sighash_all_acp_clears_outputs_only",
			sighashType:  txscript.SigHashAll | txscript.SigHashAnyOneCanPay,
			initialFlags: 0x03,
			expectedMask: 0x01,
		},
		{
			// SIGHASH_NONE|ANYONECANPAY: keep bits 0 and 1.
			name:         "sighash_none_acp_clears_nothing",
			sighashType:  txscript.SigHashNone | txscript.SigHashAnyOneCanPay,
			initialFlags: 0x03,
			expectedMask: 0x03,
		},
		{
			// SIGHASH_SINGLE|ANYONECANPAY: keep bit 0, clear bit 1, set bit 2.
			name:         "sighash_single_acp_sets_bit2_keeps_inputs",
			sighashType:  txscript.SigHashSingle | txscript.SigHashAnyOneCanPay,
			initialFlags: 0x03,
			expectedMask: 0x05, // bit 0 + bit 2
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flags := tc.initialFlags
			pkt := makeV2WithWitnessUtxo(t, &flags)

			// Set the sighash type on the input.
			pkt.Inputs[0].SighashType = tc.sighashType

			// Build a signature with the matching trailing sighash byte.
			sig := make([]byte, len(testSig1))
			copy(sig, testSig1)
			sig[len(sig)-1] = byte(tc.sighashType)

			u, err := NewUpdater(pkt)
			require.NoError(t, err)

			res, err := u.Sign(0, sig, testPub1, nil, nil)
			require.NoError(t, err)
			require.Equal(t, SignOutcome(SignSuccesful), res)

			require.NotNil(t, pkt.TxModifiable)
			require.Equal(t, tc.expectedMask, *pkt.TxModifiable,
				"TxModifiable flags mismatch after signing")
		})
	}
}

// TestV2SignerNoFlagUpdateForV0 confirms that signing a v0 packet does NOT
// touch TxModifiable (which doesn't exist in v0).
func TestV2SignerNoFlagUpdateForV0(t *testing.T) {
	// Use an existing v0 PSBT from the Core test vectors.
	imported := "cHNidP8BAJwCAAAAAjaoF6eKeGsPiDQxxqqhFDfHWjBtZzRqmaZmvyCVWZ5JAQAAAAD/////RhypNiFfnQSMNpo0SGsgIvDOyMQFAYEHZXD5jp4kCrUAAAAAAP////8CgCcSjAAAAAAXqRQFWy8ScSkkhlGMwfOnx15YwRzApofwX5MDAAAAABepFAt4TyLfGnL9QY6GLYHbpSQj+QclhwAAAAAAAAAAAA=="
	pkt, err := NewFromRawBytes(strings.NewReader(imported), true)
	require.NoError(t, err)
	require.Nil(t, pkt.TxModifiable)

	// Add witness UTXO and sign.
	fundingTxHex := "02000000014f2cbac7d7691fafca30313097d79be9e78aa6670752fcb1fc15508e77586efb000000004847304402201b5568d7cab977ae0892840b779d84e36d62e42fd93b95e648aaebeacd2577d602201d2ebda2b0cddfa0c1a71d3cbcb602e7c9c860a41ed8b4d18d40c92ccbe92aed01feffffff028c636f91000000001600147447b6d7e6193499565779c8eb5184fcfdfee6ef00879303000000001600149e88f2828a074ebf64af23c2168d1816258311d72d010000"
	fundBytes, err := hex.DecodeString(fundingTxHex)
	require.NoError(t, err)
	txFund := wire.NewMsgTx(2)
	require.NoError(t, txFund.Deserialize(bytes.NewReader(fundBytes)))

	u := &Updater{Upsbt: pkt}
	require.NoError(t, u.AddInWitnessUtxo(txFund.TxOut[1], 0))

	res, err := u.Sign(0, testSig1, testPub1, nil, nil)
	require.NoError(t, err)
	require.Equal(t, SignOutcome(SignSuccesful), res)

	// v0 must not have TxModifiable set.
	require.Nil(t, pkt.TxModifiable)
}

// TestV2MaybeFinalizeAllDoesNotPanic verifies MaybeFinalizeAll iterates
// over p.Inputs (not p.UnsignedTx.TxIn) for v2 packets.
func TestV2MaybeFinalizeAllDoesNotPanic(t *testing.T) {
	pkt := makeV2WithWitnessUtxo(t, nil)
	require.Nil(t, pkt.UnsignedTx)

	// MaybeFinalizeAll should not panic. It will return an error because
	// the input has no signatures, but the point is it doesn't panic.
	err := MaybeFinalizeAll(pkt)
	require.Error(t, err)
}

// TestV2AddPartialSigPrevOutValidation verifies that the NonWitnessUtxo
// validation in addPartialSignature uses the v2-safe accessor.
func TestV2AddPartialSigPrevOutValidation(t *testing.T) {
	// Build a v2 packet with a NonWitnessUtxo instead of WitnessUtxo.
	idx := uint32(1)
	outAmt := int64(40_000)
	outScript := []byte{0x51}

	// Create a funding tx that the NonWitnessUtxo will point to.
	fundTx := wire.NewMsgTx(2)
	fundTx.AddTxIn(&wire.TxIn{})
	fundTx.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: []byte{0x76}})

	// P2PKH output at index 1.
	pubKeyHash := make([]byte, 20)
	copy(pubKeyHash, testPub1[1:21])
	p2pkhScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_DUP).
		AddOp(txscript.OP_HASH160).
		AddData(pubKeyHash).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)
	fundTx.AddTxOut(&wire.TxOut{Value: 50_000, PkScript: p2pkhScript})

	// The PreviousTxID must match the funding tx hash.
	txid := fundTx.TxHash()

	pkt := &Packet{
		Version:   2,
		TxVersion: 2,
		Inputs: []PInput{{
			PreviousTxID:    &txid,
			OutputIndex:     &idx,
			NonWitnessUtxo:  fundTx,
			PartialSigs:     []*PartialSig{},
			Bip32Derivation: []*Bip32Derivation{},
		}},
		Outputs: []POutput{{
			Amount: &outAmt,
			Script: outScript,
		}},
	}
	require.NoError(t, pkt.SanityCheck())
	require.Nil(t, pkt.UnsignedTx)

	u, err := NewUpdater(pkt)
	require.NoError(t, err)

	// Sign should work — the accessor resolves the prevout from v2 fields.
	res, err := u.Sign(0, testSig1, testPub1, nil, nil)
	require.NoError(t, err)
	require.Equal(t, SignOutcome(SignSuccesful), res)

	// Now verify with a mismatched txid — should fail validation.
	wrongTxid := chainhash.HashH([]byte("wrong-txid"))
	pkt2 := &Packet{
		Version:   2,
		TxVersion: 2,
		Inputs: []PInput{{
			PreviousTxID:    &wrongTxid,
			OutputIndex:     &idx,
			NonWitnessUtxo:  fundTx,
			PartialSigs:     []*PartialSig{},
			Bip32Derivation: []*Bip32Derivation{},
		}},
		Outputs: []POutput{{
			Amount: &outAmt,
			Script: outScript,
		}},
	}
	require.NoError(t, pkt2.SanityCheck())

	u2, err := NewUpdater(pkt2)
	require.NoError(t, err)

	_, err = u2.Sign(0, testSig1, testPub1, nil, nil)
	require.ErrorIs(t, err, ErrInvalidSignatureForInput)
}

// TestV2ExtractReconstructsTx verifies that Extract on a finalized v2 packet
// reconstructs the transaction from per-input/output fields and applies the
// final sigScript/witness data.
func TestV2ExtractReconstructsTx(t *testing.T) {
	pkt := makeV2WithWitnessUtxo(t, nil)
	require.Nil(t, pkt.UnsignedTx)

	// Sign the single input.
	u, err := NewUpdater(pkt)
	require.NoError(t, err)

	res, err := u.Sign(0, testSig1, testPub1, nil, nil)
	require.NoError(t, err)
	require.Equal(t, SignOutcome(SignSuccesful), res)

	// Finalize.
	err = MaybeFinalizeAll(pkt)
	require.NoError(t, err)
	require.True(t, pkt.IsComplete())

	// Extract.
	tx, err := Extract(pkt)
	require.NoError(t, err)
	require.NotNil(t, tx)

	// The extracted tx should have correct structure.
	require.Len(t, tx.TxIn, 1)
	require.Len(t, tx.TxOut, 1)
	require.Equal(t, int32(2), tx.Version)

	// Input should reference the prevout we set up.
	txid := chainhash.HashH([]byte("test-prevout"))
	require.Equal(t, txid, tx.TxIn[0].PreviousOutPoint.Hash)
	require.Equal(t, uint32(0), tx.TxIn[0].PreviousOutPoint.Index)

	// Output amount and script should match.
	require.Equal(t, int64(40_000), tx.TxOut[0].Value)
	require.Equal(t, []byte{0x51}, tx.TxOut[0].PkScript)

	// Witness should be populated (P2WPKH: [sig, pubkey]).
	require.NotNil(t, tx.TxIn[0].Witness)
	require.Len(t, tx.TxIn[0].Witness, 2)
}

// TestV2ExtractIncompleteReturnsError verifies Extract rejects a v2 packet
// that is not fully finalized.
func TestV2ExtractIncompleteReturnsError(t *testing.T) {
	pkt := makeV2WithWitnessUtxo(t, nil)
	require.Nil(t, pkt.UnsignedTx)

	// Don't sign or finalize — should fail.
	_, err := Extract(pkt)
	require.ErrorIs(t, err, ErrIncompletePSBT)
}

// TestV2ExtractWithLocktime verifies that Extract applies the computed
// locktime from v2 per-input locktime fields.
func TestV2ExtractWithLocktime(t *testing.T) {
	txid := chainhash.HashH([]byte("locktime-test"))
	idx := uint32(0)
	amt := int64(50_000)
	height := uint32(800_000)

	pubKeyHash := btcutil.Hash160(testPub1)
	scriptPubKey, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(pubKeyHash).
		Script()
	require.NoError(t, err)

	outAmt := int64(40_000)
	outScript := []byte{0x51}

	pkt := &Packet{
		Version:   2,
		TxVersion: 2,
		Inputs: []PInput{{
			PreviousTxID:          &txid,
			OutputIndex:           &idx,
			RequiredHeightLocktime: &height,
			WitnessUtxo: &wire.TxOut{
				Value:    amt,
				PkScript: scriptPubKey,
			},
			PartialSigs:     []*PartialSig{},
			Bip32Derivation: []*Bip32Derivation{},
		}},
		Outputs: []POutput{{
			Amount: &outAmt,
			Script: outScript,
		}},
	}
	require.NoError(t, pkt.SanityCheck())

	u, err := NewUpdater(pkt)
	require.NoError(t, err)

	res, err := u.Sign(0, testSig1, testPub1, nil, nil)
	require.NoError(t, err)
	require.Equal(t, SignOutcome(SignSuccesful), res)

	err = MaybeFinalizeAll(pkt)
	require.NoError(t, err)

	tx, err := Extract(pkt)
	require.NoError(t, err)
	require.Equal(t, uint32(800_000), tx.LockTime)
}

// TestV2ExtractMultipleInputsOutputs verifies Extract works with multiple
// inputs and outputs on a v2 packet.
func TestV2ExtractMultipleInputsOutputs(t *testing.T) {
	pubKeyHash := btcutil.Hash160(testPub1)
	scriptPubKey, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(pubKeyHash).
		Script()
	require.NoError(t, err)

	txid1 := chainhash.HashH([]byte("multi-in-1"))
	txid2 := chainhash.HashH([]byte("multi-in-2"))
	idx0 := uint32(0)
	idx1 := uint32(1)
	outAmt1 := int64(30_000)
	outAmt2 := int64(15_000)
	outScript := []byte{0x51}

	pkt := &Packet{
		Version:   2,
		TxVersion: 2,
		Inputs: []PInput{
			{
				PreviousTxID: &txid1,
				OutputIndex:  &idx0,
				WitnessUtxo: &wire.TxOut{
					Value:    50_000,
					PkScript: scriptPubKey,
				},
				PartialSigs:     []*PartialSig{},
				Bip32Derivation: []*Bip32Derivation{},
			},
			{
				PreviousTxID: &txid2,
				OutputIndex:  &idx1,
				WitnessUtxo: &wire.TxOut{
					Value:    25_000,
					PkScript: scriptPubKey,
				},
				PartialSigs:     []*PartialSig{},
				Bip32Derivation: []*Bip32Derivation{},
			},
		},
		Outputs: []POutput{
			{Amount: &outAmt1, Script: outScript},
			{Amount: &outAmt2, Script: outScript},
		},
	}
	require.NoError(t, pkt.SanityCheck())

	u, err := NewUpdater(pkt)
	require.NoError(t, err)

	// Sign both inputs.
	for i := 0; i < 2; i++ {
		res, err := u.Sign(i, testSig1, testPub1, nil, nil)
		require.NoError(t, err)
		require.Equal(t, SignOutcome(SignSuccesful), res)
	}

	err = MaybeFinalizeAll(pkt)
	require.NoError(t, err)

	tx, err := Extract(pkt)
	require.NoError(t, err)
	require.Len(t, tx.TxIn, 2)
	require.Len(t, tx.TxOut, 2)

	// Verify prevout references.
	require.Equal(t, txid1, tx.TxIn[0].PreviousOutPoint.Hash)
	require.Equal(t, txid2, tx.TxIn[1].PreviousOutPoint.Hash)

	// Verify output amounts.
	require.Equal(t, int64(30_000), tx.TxOut[0].Value)
	require.Equal(t, int64(15_000), tx.TxOut[1].Value)

	// Both witnesses populated.
	for i := 0; i < 2; i++ {
		require.NotNil(t, tx.TxIn[i].Witness)
		require.Len(t, tx.TxIn[i].Witness, 2)
	}
}

// TestBoundsCheckSign verifies that Sign returns an error (not a panic)
// for negative and out-of-range input indexes.
func TestBoundsCheckSign(t *testing.T) {
	pkt := makeV2WithWitnessUtxo(t, nil)
	u, err := NewUpdater(pkt)
	require.NoError(t, err)

	for _, idx := range []int{-1, 1, 100} {
		res, err := u.Sign(idx, testSig1, testPub1, nil, nil)
		require.ErrorIs(t, err, ErrInputIndexOutOfBounds, "index %d", idx)
		require.Equal(t, SignOutcome(SignInvalid), res, "index %d", idx)
	}
}

// TestBoundsCheckFinalize verifies that Finalize and MaybeFinalize return
// errors for invalid indexes instead of panicking.
func TestBoundsCheckFinalize(t *testing.T) {
	pkt := makeV2WithWitnessUtxo(t, nil)

	for _, idx := range []int{-1, 1, 100} {
		err := Finalize(pkt, idx)
		require.ErrorIs(t, err, ErrInputIndexOutOfBounds, "Finalize index %d", idx)

		_, err = MaybeFinalize(pkt, idx)
		require.ErrorIs(t, err, ErrInputIndexOutOfBounds, "MaybeFinalize index %d", idx)
	}
}

// TestBoundsCheckUpdater verifies that Updater methods return errors for
// invalid indexes instead of panicking.
func TestBoundsCheckUpdater(t *testing.T) {
	pkt := makeV2WithWitnessUtxo(t, nil)
	u, err := NewUpdater(pkt)
	require.NoError(t, err)

	for _, idx := range []int{-1, 1} {
		require.ErrorIs(t,
			u.AddInNonWitnessUtxo(nil, idx),
			ErrInputIndexOutOfBounds,
		)
		require.ErrorIs(t,
			u.AddInWitnessUtxo(nil, idx),
			ErrInputIndexOutOfBounds,
		)
		require.ErrorIs(t,
			u.AddInSighashType(0, idx),
			ErrInputIndexOutOfBounds,
		)
		require.ErrorIs(t,
			u.AddInRedeemScript(nil, idx),
			ErrInputIndexOutOfBounds,
		)
		require.ErrorIs(t,
			u.AddInWitnessScript(nil, idx),
			ErrInputIndexOutOfBounds,
		)
		require.ErrorIs(t,
			u.AddInBip32Derivation(0, nil, nil, idx),
			ErrInputIndexOutOfBounds,
		)
	}

	// Output index bounds.
	for _, idx := range []int{-1, 1} {
		require.ErrorIs(t,
			u.AddOutBip32Derivation(0, nil, nil, idx),
			ErrOutputIndexOutOfBounds,
		)
		require.ErrorIs(t,
			u.AddOutRedeemScript(nil, idx),
			ErrOutputIndexOutOfBounds,
		)
		require.ErrorIs(t,
			u.AddOutWitnessScript(nil, idx),
			ErrOutputIndexOutOfBounds,
		)
	}
}

// ptrU8 returns a pointer to the given uint8 value.
func ptrU8(v uint8) *uint8 { return &v }
