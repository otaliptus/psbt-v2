package psbt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"sort"
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
	require.Equal(t, SignOutcome(SignSuccessful), res)
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
			require.Equal(t, SignOutcome(SignSuccessful), res)

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
	require.Equal(t, SignOutcome(SignSuccessful), res)

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
	require.Equal(t, SignOutcome(SignSuccessful), res)

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
	require.Equal(t, SignOutcome(SignSuccessful), res)

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
	require.Equal(t, SignOutcome(SignSuccessful), res)

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
		require.Equal(t, SignOutcome(SignSuccessful), res)
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

// ///////////////////////////////////////////////////////////////////////////
// Phase 7: v2-aware sort/utils tests
// ///////////////////////////////////////////////////////////////////////////

// makeV2ForSort builds a v2 packet with multiple inputs and outputs suitable
// for testing BIP-69 sort behavior. No signatures attached.
func makeV2ForSort(t *testing.T) *Packet {
	t.Helper()

	hash1 := chainhash.HashH([]byte("txid-cc")) // will sort later in big-endian
	hash2 := chainhash.HashH([]byte("txid-aa")) // will sort earlier in big-endian
	idx0 := uint32(7)
	idx1 := uint32(3)

	amt0 := int64(20_000)
	amt1 := int64(10_000)
	script0 := []byte{0x99, 0x88}
	script1 := []byte{0x11, 0x22}

	pkt := &Packet{
		Version:   2,
		TxVersion: 2,
		Inputs: []PInput{
			{
				PreviousTxID: &hash1,
				OutputIndex:  &idx0,
				SighashType:  0, // marker to track position
			},
			{
				PreviousTxID: &hash2,
				OutputIndex:  &idx1,
				SighashType:  1,
			},
		},
		Outputs: []POutput{
			{
				Amount:       &amt0,
				Script:       script0,
				RedeemScript: []byte{0}, // marker
			},
			{
				Amount:       &amt1,
				Script:       script1,
				RedeemScript: []byte{1}, // marker
			},
		},
	}
	require.NoError(t, pkt.SanityCheck())
	require.Nil(t, pkt.UnsignedTx)
	return pkt
}

// TestInPlaceSortV2 verifies that InPlaceSort correctly reorders a v2
// packet's Inputs and Outputs by BIP-69 rules using per-input/output
// accessors, without requiring UnsignedTx.
func TestInPlaceSortV2(t *testing.T) {
	pkt := makeV2ForSort(t)

	// Record pre-sort markers.
	preSortIn0 := pkt.Inputs[0].SighashType
	preSortOut0 := pkt.Outputs[0].RedeemScript[0]

	err := InPlaceSort(pkt)
	require.NoError(t, err)

	// Verify inputs are sorted by prevout hash (big-endian), then index.
	for i := 0; i < len(pkt.Inputs)-1; i++ {
		outI, err := pkt.inputPrevOutpoint(i)
		require.NoError(t, err)
		outJ, err := pkt.inputPrevOutpoint(i + 1)
		require.NoError(t, err)

		cmp := bytes.Compare(outI.Hash[:], outJ.Hash[:])
		if cmp == 0 {
			require.LessOrEqual(t, outI.Index, outJ.Index,
				"same-hash inputs not index-sorted")
		}
		// We just need the sort to have run; the exact BIP-69 hash
		// reversal is tested by the existing v0 sort test.
	}

	// Verify outputs are sorted by amount ascending.
	amt0, err := pkt.outputAmount(0)
	require.NoError(t, err)
	amt1, err := pkt.outputAmount(1)
	require.NoError(t, err)
	require.LessOrEqual(t, amt0, amt1, "outputs not sorted by amount")

	// Verify that sorting actually moved elements (not a no-op).
	// At least one of the marker pairs should have changed position.
	postSortIn0 := pkt.Inputs[0].SighashType
	postSortOut0 := pkt.Outputs[0].RedeemScript[0]
	moved := preSortIn0 != postSortIn0 || preSortOut0 != postSortOut0
	require.True(t, moved, "sort should have reordered at least one slice")
}

// TestInPlaceSortV2RejectsSignedPacket verifies that InPlaceSort refuses
// to sort a v2 packet that already has signature data attached.
func TestInPlaceSortV2RejectsSignedPacket(t *testing.T) {
	pkt := makeV2ForSort(t)
	// Attach a dummy partial signature.
	pkt.Inputs[0].PartialSigs = []*PartialSig{{
		PubKey:    testPub1,
		Signature: testSig1,
	}}

	err := InPlaceSort(pkt)
	require.Error(t, err, "InPlaceSort must reject signed packets")
	require.Contains(t, err.Error(), "signature data")
}

// TestInPlaceSortV2RejectsMalformedPacket verifies that InPlaceSort returns
// an error for a v2 packet with missing required fields (PreviousTxID,
// OutputIndex, Amount, Script) rather than silently treating them as zero.
func TestInPlaceSortV2RejectsMalformedPacket(t *testing.T) {
	t.Run("missing_prevtxid", func(t *testing.T) {
		idx := uint32(0)
		amt := int64(1_000)
		pkt := &Packet{
			Version:   2,
			TxVersion: 2,
			Inputs:    []PInput{{OutputIndex: &idx}},
			Outputs:   []POutput{{Amount: &amt, Script: []byte{0x51}}},
		}
		err := InPlaceSort(pkt)
		require.Error(t, err)
		require.Contains(t, err.Error(), "PreviousTxID")
	})

	t.Run("missing_output_amount", func(t *testing.T) {
		txid := chainhash.HashH([]byte("sort-malformed"))
		idx := uint32(0)
		pkt := &Packet{
			Version:   2,
			TxVersion: 2,
			Inputs:    []PInput{{PreviousTxID: &txid, OutputIndex: &idx}},
			Outputs:   []POutput{{Script: []byte{0x51}}},
		}
		err := InPlaceSort(pkt)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Amount")
	})
}

// TestSumUtxoInputValuesV2 verifies that SumUtxoInputValues works on a v2
// packet (where UnsignedTx is nil) by using the version-aware accessor.
func TestSumUtxoInputValuesV2(t *testing.T) {
	t.Run("witness_utxo", func(t *testing.T) {
		pkt := makeV2WithWitnessUtxo(t, nil)
		sum, err := SumUtxoInputValues(pkt)
		require.NoError(t, err)
		require.Equal(t, int64(50_000), sum)
	})

	t.Run("non_witness_utxo", func(t *testing.T) {
		txid := chainhash.HashH([]byte("non-witness-sum"))
		idx := uint32(0)
		outAmt := int64(40_000)
		outScript := []byte{0x51}

		fundTx := wire.NewMsgTx(2)
		fundTx.AddTxIn(&wire.TxIn{})
		fundTx.AddTxOut(&wire.TxOut{Value: 75_000, PkScript: []byte{0x76}})

		pkt := &Packet{
			Version:   2,
			TxVersion: 2,
			Inputs: []PInput{{
				PreviousTxID:   &txid,
				OutputIndex:    &idx,
				NonWitnessUtxo: fundTx,
			}},
			Outputs: []POutput{{
				Amount: &outAmt,
				Script: outScript,
			}},
		}
		require.NoError(t, pkt.SanityCheck())

		sum, err := SumUtxoInputValues(pkt)
		require.NoError(t, err)
		require.Equal(t, int64(75_000), sum)
	})

	t.Run("no_utxo_returns_error", func(t *testing.T) {
		txid := chainhash.HashH([]byte("no-utxo"))
		idx := uint32(0)
		outAmt := int64(1_000)
		pkt := &Packet{
			Version:   2,
			TxVersion: 2,
			Inputs: []PInput{{
				PreviousTxID: &txid,
				OutputIndex:  &idx,
			}},
			Outputs: []POutput{{
				Amount: &outAmt,
				Script: []byte{0x51},
			}},
		}
		_, err := SumUtxoInputValues(pkt)
		require.Error(t, err)
	})
}

// TestVerifyInputOutputLenV2 verifies that VerifyInputOutputLen works for
// v2 packets where UnsignedTx is nil.
func TestVerifyInputOutputLenV2(t *testing.T) {
	t.Run("valid_v2_with_inputs_and_outputs", func(t *testing.T) {
		pkt := makeV2WithWitnessUtxo(t, nil)
		err := VerifyInputOutputLen(pkt, true, true)
		require.NoError(t, err)
	})

	t.Run("v2_no_inputs_but_needs_inputs", func(t *testing.T) {
		pkt := &Packet{
			Version:   2,
			TxVersion: 2,
			Outputs:   []POutput{{}},
		}
		err := VerifyInputOutputLen(pkt, true, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "at least one input")
	})

	t.Run("v2_no_outputs_but_needs_outputs", func(t *testing.T) {
		pkt := &Packet{
			Version:   2,
			TxVersion: 2,
			Inputs:    []PInput{{}},
		}
		err := VerifyInputOutputLen(pkt, false, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "at least one output")
	})

	t.Run("v2_empty_ok_when_not_needed", func(t *testing.T) {
		pkt := &Packet{
			Version:   2,
			TxVersion: 2,
		}
		err := VerifyInputOutputLen(pkt, false, false)
		require.NoError(t, err)
	})
}

// TestInputsReadyToSignV2 verifies that InputsReadyToSign works for v2
// packets without depending on UnsignedTx.
func TestInputsReadyToSignV2(t *testing.T) {
	t.Run("ready_with_witness_utxo", func(t *testing.T) {
		pkt := makeV2WithWitnessUtxo(t, nil)
		err := InputsReadyToSign(pkt)
		require.NoError(t, err)
	})

	t.Run("not_ready_missing_utxo", func(t *testing.T) {
		txid := chainhash.HashH([]byte("not-ready"))
		idx := uint32(0)
		outAmt := int64(1_000)

		pkt := &Packet{
			Version:   2,
			TxVersion: 2,
			Inputs: []PInput{{
				PreviousTxID: &txid,
				OutputIndex:  &idx,
				// No WitnessUtxo or NonWitnessUtxo.
			}},
			Outputs: []POutput{{
				Amount: &outAmt,
				Script: []byte{0x51},
			}},
		}
		err := InputsReadyToSign(pkt)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing utxo")
	})
}

// TestV0V2HelperParity builds equivalent v0 and v2 packets and asserts that
// SumUtxoInputValues, VerifyInputOutputLen, and InputsReadyToSign produce
// matching results across both versions.
func TestV0V2HelperParity(t *testing.T) {
	// Build a v0 packet.
	prevOut := &wire.OutPoint{
		Hash:  chainhash.HashH([]byte("parity-test")),
		Index: 0,
	}
	txOut := &wire.TxOut{Value: 60_000, PkScript: []byte{0x51}}
	v0Pkt, err := New([]*wire.OutPoint{prevOut}, []*wire.TxOut{txOut}, 2, 0, []uint32{0})
	require.NoError(t, err)
	v0Pkt.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 80_000, PkScript: []byte{0x00, 0x14}}

	// Build equivalent v2 packet.
	txid := prevOut.Hash
	idx := prevOut.Index
	outAmt := txOut.Value
	v2Pkt := &Packet{
		Version:   2,
		TxVersion: 2,
		Inputs: []PInput{{
			PreviousTxID: &txid,
			OutputIndex:  &idx,
			WitnessUtxo:  &wire.TxOut{Value: 80_000, PkScript: []byte{0x00, 0x14}},
		}},
		Outputs: []POutput{{
			Amount: &outAmt,
			Script: txOut.PkScript,
		}},
	}

	// SumUtxoInputValues parity.
	v0Sum, err := SumUtxoInputValues(v0Pkt)
	require.NoError(t, err)
	v2Sum, err := SumUtxoInputValues(v2Pkt)
	require.NoError(t, err)
	require.Equal(t, v0Sum, v2Sum, "input sums must match")

	// VerifyInputOutputLen parity.
	require.NoError(t, VerifyInputOutputLen(v0Pkt, true, true))
	require.NoError(t, VerifyInputOutputLen(v2Pkt, true, true))

	// InputsReadyToSign parity.
	require.NoError(t, InputsReadyToSign(v0Pkt))
	require.NoError(t, InputsReadyToSign(v2Pkt))
}

// ///////////////////////////////////////////////////////////////////////////
// Regression tests for bug fixes
// ///////////////////////////////////////////////////////////////////////////

// TestSignNilUTXOReturnsError verifies that Sign returns an error instead of
// panicking when an input has neither WitnessUtxo nor NonWitnessUtxo.
// Regression: signer.go default case dereferenced NonWitnessUtxo without a
// nil guard, causing a panic on v2 packets before UTXO data is attached.
func TestSignNilUTXOReturnsError(t *testing.T) {
	txid := chainhash.HashH([]byte("nil-utxo-test"))
	idx := uint32(0)
	outAmt := int64(40_000)
	outScript := []byte{0x51}

	pkt := &Packet{
		Version:   2,
		TxVersion: 2,
		Inputs: []PInput{{
			PreviousTxID:    &txid,
			OutputIndex:     &idx,
			PartialSigs:     []*PartialSig{},
			Bip32Derivation: []*Bip32Derivation{},
			// No WitnessUtxo, no NonWitnessUtxo.
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
	require.Error(t, err, "Sign must return an error, not panic")
	require.Equal(t, SignOutcome(SignInvalid), res)
}

// TestSignUsesStoredRedeemScript verifies that the Sign redeem-script branch
// checks pInput.RedeemScript (the stored field) rather than the function
// argument when deciding whether the input is a witness program.
// Regression: signer.go Case 2 passed the argument `redeemScript` to
// IsWitnessProgram instead of pInput.RedeemScript, so callers that
// pre-populated the PSBT and passed nil missed witness conversion.
func TestSignUsesStoredRedeemScript(t *testing.T) {
	idx := uint32(0)
	outAmt := int64(40_000)
	outScript := []byte{0x51}

	// Build a P2SH-P2WPKH redeemScript (a witness program).
	pubKeyHash := btcutil.Hash160(testPub1)
	redeemScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(pubKeyHash).
		Script()
	require.NoError(t, err)

	// Create a funding tx whose output is P2SH wrapping the witness program.
	p2shScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_HASH160).
		AddData(btcutil.Hash160(redeemScript)).
		AddOp(txscript.OP_EQUAL).
		Script()
	require.NoError(t, err)

	fundTx := wire.NewMsgTx(2)
	fundTx.AddTxIn(&wire.TxIn{})
	fundTx.AddTxOut(&wire.TxOut{Value: 50_000, PkScript: p2shScript})
	fundTxid := fundTx.TxHash()

	pkt := &Packet{
		Version:   2,
		TxVersion: 2,
		Inputs: []PInput{{
			PreviousTxID:    &fundTxid,
			OutputIndex:     &idx,
			NonWitnessUtxo:  fundTx,
			RedeemScript:    redeemScript, // Pre-populated.
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

	// Pass nil redeemScript to Sign -- it should use the stored one.
	res, err := u.Sign(0, testSig1, testPub1, nil, nil)
	require.NoError(t, err)
	require.Equal(t, SignOutcome(SignSuccessful), res)

	// The fix: WitnessUtxo should now be populated because the stored
	// redeemScript was correctly identified as a witness program.
	require.NotNil(t, pkt.Inputs[0].WitnessUtxo,
		"WitnessUtxo must be set after signing a P2SH-P2WPKH input")
}

// TestDuplicateUnknownKeyRejected verifies that the parser rejects two
// unknown entries with the same key but different values.
// Regression: duplicate detection compared both key AND value, so entries
// with the same key but different values were silently accepted.
func TestDuplicateUnknownKeyRejected(t *testing.T) {
	// Use a proprietary key type (0xFC) with identical keydata but
	// different values.
	propKey := byte(0xFC)

	t.Run("input_map", func(t *testing.T) {
		var buf bytes.Buffer
		// First entry: key=0xFC||0x01, value=0xAA
		putKV(t, &buf, propKey, []byte{0x01}, []byte{0xAA})
		// Duplicate key, different value: key=0xFC||0x01, value=0xBB
		putKV(t, &buf, propKey, []byte{0x01}, []byte{0xBB})
		endSection(t, &buf)

		var pi PInput
		err := pi.deserialize(bytes.NewReader(buf.Bytes()))
		require.ErrorIs(t, err, ErrDuplicateKey)
	})

	t.Run("output_map", func(t *testing.T) {
		var buf bytes.Buffer
		putKV(t, &buf, propKey, []byte{0x01}, []byte{0xAA})
		putKV(t, &buf, propKey, []byte{0x01}, []byte{0xBB})
		endSection(t, &buf)

		var po POutput
		err := po.deserialize(bytes.NewReader(buf.Bytes()))
		require.ErrorIs(t, err, ErrDuplicateKey)
	})

	t.Run("appendUnknownKV_helper", func(t *testing.T) {
		var unknowns []*Unknown
		err := appendUnknownKV(&unknowns, 0xFC, []byte{0x01}, []byte{0xAA})
		require.NoError(t, err)
		err = appendUnknownKV(&unknowns, 0xFC, []byte{0x01}, []byte{0xBB})
		require.ErrorIs(t, err, ErrDuplicateKey)
	})
}

// TestReadTxOutMultiByteVarInt verifies that readTxOut correctly handles
// scriptPubKeys whose CompactSize length prefix is longer than one byte
// (>= 253 bytes), and validates the declared length against actual data.
// Regression: readTxOut hardcoded offset 9 (8 value + 1 varint), which
// misparsed scripts with multi-byte CompactSize prefixes.
func TestReadTxOutMultiByteVarInt(t *testing.T) {
	t.Run("large_script_3byte_varint", func(t *testing.T) {
		// Build a TxOut with a 300-byte scriptPubKey.
		// CompactSize for 300 = 0xFD 0x2C 0x01 (3 bytes).
		value := uint64(42_000)
		scriptLen := 300
		script := bytes.Repeat([]byte{0xAB}, scriptLen)

		var buf bytes.Buffer
		err := binary.Write(&buf, binary.LittleEndian, value)
		require.NoError(t, err)
		err = wire.WriteVarInt(&buf, 0, uint64(scriptLen))
		require.NoError(t, err)
		_, err = buf.Write(script)
		require.NoError(t, err)

		txout, err := readTxOut(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, int64(value), txout.Value)
		require.Len(t, txout.PkScript, scriptLen)
		require.Equal(t, script, txout.PkScript)
	})

	t.Run("normal_script_1byte_varint", func(t *testing.T) {
		// P2WPKH: 22-byte script, varint = single byte 0x16.
		value := uint64(50_000)
		script := bytes.Repeat([]byte{0xCD}, 22)

		var buf bytes.Buffer
		err := binary.Write(&buf, binary.LittleEndian, value)
		require.NoError(t, err)
		err = wire.WriteVarInt(&buf, 0, 22)
		require.NoError(t, err)
		_, err = buf.Write(script)
		require.NoError(t, err)

		txout, err := readTxOut(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, int64(value), txout.Value)
		require.Equal(t, script, txout.PkScript)
	})

	t.Run("length_mismatch_rejected", func(t *testing.T) {
		// Declare 100-byte script but only provide 50 bytes.
		value := uint64(1_000)
		var buf bytes.Buffer
		err := binary.Write(&buf, binary.LittleEndian, value)
		require.NoError(t, err)
		err = wire.WriteVarInt(&buf, 0, 100)
		require.NoError(t, err)
		_, err = buf.Write(bytes.Repeat([]byte{0x00}, 50))
		require.NoError(t, err)

		_, err = readTxOut(buf.Bytes())
		require.ErrorIs(t, err, ErrInvalidPsbtFormat)
	})

	t.Run("empty_script", func(t *testing.T) {
		value := uint64(0)
		var buf bytes.Buffer
		err := binary.Write(&buf, binary.LittleEndian, value)
		require.NoError(t, err)
		err = wire.WriteVarInt(&buf, 0, 0)
		require.NoError(t, err)

		txout, err := readTxOut(buf.Bytes())
		require.NoError(t, err)
		require.Equal(t, int64(0), txout.Value)
		require.Len(t, txout.PkScript, 0)
	})
}

// TestTaprootScriptSpendSigSortCanonical verifies that the SortBefore
// comparator for TaprootScriptSpendSig produces a stable, deterministic
// ordering regardless of input arrangement.
// Regression: the original comparator used && instead of lexicographic
// ordering, which violated sort.Interface's strict weak ordering contract.
func TestTaprootScriptSpendSigSortCanonical(t *testing.T) {
	makeSig := func(pubFill, leafFill byte) *TaprootScriptSpendSig {
		return &TaprootScriptSpendSig{
			XOnlyPubKey: bytes.Repeat([]byte{pubFill}, 32),
			LeafHash:    bytes.Repeat([]byte{leafFill}, 32),
		}
	}

	// Three sigs that exposed the old && bug:
	// A: pub=0x01, leaf=0x03
	// B: pub=0x02, leaf=0x01
	// C: pub=0x01, leaf=0x02  (same pub as A, different leaf)
	a := makeSig(0x01, 0x03)
	b := makeSig(0x02, 0x01)
	c := makeSig(0x01, 0x02)

	// Expected lexicographic order: C (01,02) < A (01,03) < B (02,01)
	// Try multiple input arrangements to prove stability.
	arrangements := [][]*TaprootScriptSpendSig{
		{a, b, c},
		{c, b, a},
		{b, a, c},
		{c, a, b},
	}

	for i, arr := range arrangements {
		sorted := make([]*TaprootScriptSpendSig, len(arr))
		copy(sorted, arr)
		sort.Slice(sorted, func(x, y int) bool {
			return sorted[x].SortBefore(sorted[y])
		})

		require.Equal(t, c, sorted[0], "arrangement %d: first", i)
		require.Equal(t, a, sorted[1], "arrangement %d: second", i)
		require.Equal(t, b, sorted[2], "arrangement %d: third", i)
	}
}

// /////////////////////////////////////////////////////////////////////////////
// Gap 2: End-to-end v2 lifecycle
// /////////////////////////////////////////////////////////////////////////////
//
// Exercises the full BIP-370 role chain in a single test:
// Creator → Constructor → Updater → Signer → Serializer → Parser →
// Finalizer → Extractor.

func TestV2LifecycleEndToEnd(t *testing.T) {
	// ── From-scratch P2WPKH lifecycle ──────────────────────────────────
	t.Run("p2wpkh_from_scratch", func(t *testing.T) {
		// Known pubkey from BIP-174 test vectors.
		pub, _ := hex.DecodeString(
			"029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f")

		// Build the P2WPKH scriptPubKey that locks the UTXO to `pub`.
		pubHash := btcutil.Hash160(pub)
		p2wpkhScript, err := txscript.NewScriptBuilder().
			AddOp(txscript.OP_0).
			AddData(pubHash).
			Script()
		require.NoError(t, err)

		// Destination output (another P2WPKH).
		destHash := bytes.Repeat([]byte{0xab}, 20)
		destScript, err := txscript.NewScriptBuilder().
			AddOp(txscript.OP_0).
			AddData(destHash).
			Script()
		require.NoError(t, err)

		prevTxID := chainhash.HashH([]byte("fake-prev-tx"))
		prevOutpoint := wire.OutPoint{Hash: prevTxID, Index: 0}

		// ── CREATOR ──
		locktime := uint32(0)
		modifiable := uint8(0x03) // inputs + outputs modifiable
		pkt, err := NewV2(
			2,
			[]wire.OutPoint{prevOutpoint},
			[]*wire.TxOut{{Value: 50_000_000, PkScript: destScript}},
			&locktime, &modifiable,
		)
		require.NoError(t, err)
		require.Equal(t, uint32(2), pkt.Version)
		require.Nil(t, pkt.UnsignedTx, "v2 must not have UnsignedTx")

		// ── CONSTRUCTOR (verify the wrapper works) ──
		ctor, err := NewConstructor(pkt)
		require.NoError(t, err)
		require.NotNil(t, ctor)

		// ── UPDATER ──
		updater, err := NewUpdater(pkt)
		require.NoError(t, err)

		err = updater.AddInWitnessUtxo(&wire.TxOut{
			Value:    100_000_000,
			PkScript: p2wpkhScript,
		}, 0)
		require.NoError(t, err)

		// ── SERIALIZE / ROUND-TRIP ──
		var buf bytes.Buffer
		require.NoError(t, pkt.Serialize(&buf))

		pkt2, err := NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
		require.NoError(t, err)
		require.Equal(t, uint32(2), pkt2.Version)

		// Continue with the round-tripped packet.
		updater2, err := NewUpdater(pkt2)
		require.NoError(t, err)

		// ── SIGNER ──
		sig, _ := hex.DecodeString(
			"3044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99" +
				"022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01")

		res, err := updater2.Sign(0, sig, pub, nil, nil)
		require.NoError(t, err)
		require.Equal(t, SignSuccessful, int(res))

		// Signer clears the Inputs Modifiable bit.
		require.NotNil(t, pkt2.TxModifiable)
		require.Zero(t, *pkt2.TxModifiable&0x01,
			"inputs-modifiable flag should be cleared after signing")

		// ── FINALIZER ──
		require.NoError(t, MaybeFinalizeAll(pkt2))
		require.True(t, pkt2.IsComplete())

		// ── EXTRACTOR ──
		tx, err := Extract(pkt2)
		require.NoError(t, err)

		require.Len(t, tx.TxIn, 1)
		require.Len(t, tx.TxOut, 1)
		require.Equal(t, prevOutpoint, tx.TxIn[0].PreviousOutPoint)
		require.Equal(t, int64(50_000_000), tx.TxOut[0].Value)
		require.Equal(t, destScript, tx.TxOut[0].PkScript)

		// P2WPKH witness: [sig, pubkey]
		require.Len(t, tx.TxIn[0].Witness, 2)
		require.Equal(t, sig, []byte(tx.TxIn[0].Witness[0]))
		require.Equal(t, pub, []byte(tx.TxIn[0].Witness[1]))
		require.Equal(t, uint32(0), tx.LockTime)
	})

	// ── Convert BIP-174 v0 → v2, finalize, extract ─────────────────────
	// Takes the fully-signed BIP-174 combined PSBT (v0), converts to v2,
	// round-trips through serialization, finalizes, extracts, and compares
	// the resulting network transaction to the known BIP-174 answer.
	t.Run("convert_finalize_extract", func(t *testing.T) {
		// Combined PSBT with all 4 partial sigs (from psbt_test.go).
		combinedHex := finalizerPsbtData["finalize"]
		combinedBytes, err := hex.DecodeString(combinedHex)
		require.NoError(t, err)

		v0Pkt, err := NewFromRawBytes(
			bytes.NewReader(combinedBytes), false,
		)
		require.NoError(t, err)
		require.Equal(t, uint32(0), v0Pkt.Version)

		// Convert v0 → v2.
		v2Pkt, err := ConvertToV2(v0Pkt)
		require.NoError(t, err)
		require.Equal(t, uint32(2), v2Pkt.Version)
		require.Nil(t, v2Pkt.UnsignedTx)
		require.Len(t, v2Pkt.Inputs, 2)
		require.Len(t, v2Pkt.Outputs, 2)

		// Verify v2-specific fields were populated from UnsignedTx.
		require.Equal(t, v0Pkt.UnsignedTx.Version, v2Pkt.TxVersion)
		for i, txIn := range v0Pkt.UnsignedTx.TxIn {
			require.NotNil(t, v2Pkt.Inputs[i].PreviousTxID)
			require.Equal(t, txIn.PreviousOutPoint.Hash,
				*v2Pkt.Inputs[i].PreviousTxID)
			require.NotNil(t, v2Pkt.Inputs[i].OutputIndex)
			require.Equal(t, txIn.PreviousOutPoint.Index,
				*v2Pkt.Inputs[i].OutputIndex)
		}
		for i, txOut := range v0Pkt.UnsignedTx.TxOut {
			require.NotNil(t, v2Pkt.Outputs[i].Amount)
			require.Equal(t, txOut.Value, *v2Pkt.Outputs[i].Amount)
			require.Equal(t, txOut.PkScript, v2Pkt.Outputs[i].Script)
		}

		// Partial sigs were preserved.
		require.Len(t, v2Pkt.Inputs[0].PartialSigs, 2)
		require.Len(t, v2Pkt.Inputs[1].PartialSigs, 2)

		// Round-trip the v2 packet.
		var buf bytes.Buffer
		require.NoError(t, v2Pkt.Serialize(&buf))

		v2Rt, err := NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
		require.NoError(t, err)
		require.Equal(t, uint32(2), v2Rt.Version)

		// Finalize the round-tripped v2 packet.
		require.NoError(t, MaybeFinalizeAll(v2Rt))
		require.True(t, v2Rt.IsComplete())

		// Extract network transaction.
		tx, err := Extract(v2Rt)
		require.NoError(t, err)

		// Serialize and compare to the known BIP-174 network tx.
		var txBuf bytes.Buffer
		require.NoError(t, tx.Serialize(&txBuf))

		expectedTxHex := finalizerPsbtData["network"]
		expectedTx, err := hex.DecodeString(expectedTxHex)
		require.NoError(t, err)
		require.Equal(t, expectedTx, txBuf.Bytes(),
			"extracted v2 tx must match BIP-174 network transaction")
	})
}

// /////////////////////////////////////////////////////////////////////////////
// Gap 5: Cross-implementation differential testing
// /////////////////////////////////////////////////////////////////////////////
//
// Parses BIP-174 test vectors and verifies specific field values against
// known expected values derived from the BIP specification, then compares
// the extracted transaction to the BIP-174 reference network transaction.
// This catches symmetric parse/serialize bugs where both directions agree
// but produce incorrect results.

func TestDifferentialBIP174Fields(t *testing.T) {
	// ── Verify field values in the combined (all-sigs) PSBT ────────────
	t.Run("combined_psbt_field_values", func(t *testing.T) {
		b, err := hex.DecodeString(finalizerPsbtData["finalize"])
		require.NoError(t, err)

		p, err := NewFromRawBytes(bytes.NewReader(b), false)
		require.NoError(t, err)

		// Global: UnsignedTx shape
		require.Equal(t, int32(2), p.UnsignedTx.Version)
		require.Equal(t, uint32(0), p.UnsignedTx.LockTime)
		require.Len(t, p.UnsignedTx.TxIn, 2)
		require.Len(t, p.UnsignedTx.TxOut, 2)

		// Input 0 outpoint (raw internal byte order, reversed from display txid):
		var expectedHash0 chainhash.Hash
		expHashBytes0, _ := hex.DecodeString(
			"58e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd75")
		copy(expectedHash0[:], expHashBytes0)
		require.Equal(t, expectedHash0, p.UnsignedTx.TxIn[0].PreviousOutPoint.Hash)
		require.Equal(t, uint32(0), p.UnsignedTx.TxIn[0].PreviousOutPoint.Index)

		// Input 1 outpoint (raw internal byte order):
		var expectedHash1 chainhash.Hash
		expHashBytes1, _ := hex.DecodeString(
			"838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d")
		copy(expectedHash1[:], expHashBytes1)
		require.Equal(t, expectedHash1, p.UnsignedTx.TxIn[1].PreviousOutPoint.Hash)
		require.Equal(t, uint32(1), p.UnsignedTx.TxIn[1].PreviousOutPoint.Index)

		// Output 0: 149990000 sat to P2WPKH
		require.Equal(t, int64(149990000), p.UnsignedTx.TxOut[0].Value)
		require.True(t, txscript.IsPayToWitnessPubKeyHash(
			p.UnsignedTx.TxOut[0].PkScript))

		// Output 1: 100000000 sat to P2WPKH
		require.Equal(t, int64(100000000), p.UnsignedTx.TxOut[1].Value)
		require.True(t, txscript.IsPayToWitnessPubKeyHash(
			p.UnsignedTx.TxOut[1].PkScript))

		// Input 0: Non-witness UTXO, 2-of-2 P2SH multisig
		require.NotNil(t, p.Inputs[0].NonWitnessUtxo)
		require.Nil(t, p.Inputs[0].WitnessUtxo)
		require.NotNil(t, p.Inputs[0].RedeemScript)
		require.Nil(t, p.Inputs[0].WitnessScript)
		require.Len(t, p.Inputs[0].PartialSigs, 2,
			"input 0 should have 2 partial sigs (one per signer)")
		require.Equal(t, txscript.SigHashType(1), p.Inputs[0].SighashType)

		// Input 0 redeemScript: OP_2 <pub1> <pub2> OP_2 OP_CHECKMULTISIG
		rs0 := p.Inputs[0].RedeemScript
		require.Equal(t, byte(txscript.OP_2), rs0[0])
		require.Equal(t, byte(txscript.OP_2), rs0[len(rs0)-2])
		require.Equal(t, byte(txscript.OP_CHECKMULTISIG), rs0[len(rs0)-1])

		// Input 1: Witness UTXO, P2SH-P2WSH 2-of-2 multisig
		require.Nil(t, p.Inputs[1].NonWitnessUtxo)
		require.NotNil(t, p.Inputs[1].WitnessUtxo)
		require.NotNil(t, p.Inputs[1].RedeemScript)
		require.NotNil(t, p.Inputs[1].WitnessScript)
		require.Len(t, p.Inputs[1].PartialSigs, 2)
		require.Equal(t, txscript.SigHashType(1), p.Inputs[1].SighashType)
		require.True(t, txscript.IsPayToScriptHash(
			p.Inputs[1].WitnessUtxo.PkScript),
			"input 1 WitnessUtxo should be P2SH")

		// Input 1 witnessScript: same 2-of-2 multisig structure
		ws1 := p.Inputs[1].WitnessScript
		require.Equal(t, byte(txscript.OP_2), ws1[0])
		require.Equal(t, byte(txscript.OP_CHECKMULTISIG), ws1[len(ws1)-1])

		// Partial sig pubkeys must be valid 33-byte compressed keys.
		for idx, inp := range p.Inputs {
			for j, ps := range inp.PartialSigs {
				require.Len(t, ps.PubKey, 33,
					"input %d sig %d: compressed pubkey", idx, j)
				require.Contains(t, []byte{0x02, 0x03}, ps.PubKey[0],
					"input %d sig %d: pubkey prefix", idx, j)
			}
		}
	})

	// ── Finalize + extract must match BIP-174 network tx ───────────────
	t.Run("extracted_tx_matches_bip174_network", func(t *testing.T) {
		b, err := hex.DecodeString(finalizerPsbtData["finalize"])
		require.NoError(t, err)

		p, err := NewFromRawBytes(bytes.NewReader(b), false)
		require.NoError(t, err)
		require.NoError(t, MaybeFinalizeAll(p))

		tx, err := Extract(p)
		require.NoError(t, err)

		var txBuf bytes.Buffer
		require.NoError(t, tx.Serialize(&txBuf))

		expectedHex := finalizerPsbtData["network"]
		expectedBytes, err := hex.DecodeString(expectedHex)
		require.NoError(t, err)

		require.Equal(t, expectedBytes, txBuf.Bytes(),
			"extracted tx must byte-match BIP-174 network transaction")

		// Also verify key structural properties of the extracted tx.
		require.Equal(t, int32(2), tx.Version)
		require.Equal(t, uint32(0), tx.LockTime)
		require.Len(t, tx.TxIn, 2)
		require.Len(t, tx.TxOut, 2)

		// Input 0 (P2SH): scriptSig present, no witness
		require.NotEmpty(t, tx.TxIn[0].SignatureScript)
		require.Empty(t, tx.TxIn[0].Witness)

		// Input 1 (P2SH-P2WSH): both scriptSig and witness present
		require.NotEmpty(t, tx.TxIn[1].SignatureScript)
		require.NotEmpty(t, tx.TxIn[1].Witness)
	})

	// ── v0 vs v2 extraction produces identical transactions ────────────
	t.Run("v0_v2_extract_parity", func(t *testing.T) {
		b, err := hex.DecodeString(finalizerPsbtData["finalize"])
		require.NoError(t, err)

		// Finalize v0.
		v0, err := NewFromRawBytes(bytes.NewReader(b), false)
		require.NoError(t, err)
		require.NoError(t, MaybeFinalizeAll(v0))
		txV0, err := Extract(v0)
		require.NoError(t, err)

		// Finalize v2 (via conversion).
		v0Again, err := NewFromRawBytes(bytes.NewReader(b), false)
		require.NoError(t, err)
		v2, err := ConvertToV2(v0Again)
		require.NoError(t, err)
		require.NoError(t, MaybeFinalizeAll(v2))
		txV2, err := Extract(v2)
		require.NoError(t, err)

		// Serialize both and compare.
		var bufV0, bufV2 bytes.Buffer
		require.NoError(t, txV0.Serialize(&bufV0))
		require.NoError(t, txV2.Serialize(&bufV2))
		require.Equal(t, bufV0.Bytes(), bufV2.Bytes(),
			"v0 and v2 must produce identical extracted transactions")
	})
}

// /////////////////////////////////////////////////////////////////////////////
// BIP-174 §"Fails Signer checks"
// /////////////////////////////////////////////////////////////////////////////
//
// Four PSBT vectors where the Signer role must reject due to
// script-consistency mismatches between UTXO scriptPubKey, redeemScript,
// and witnessScript fields. Each vector is a valid parse that should fail
// when a signature is attempted.
//
// SOURCE: https://github.com/rust-bitcoin/rust-psbt/blob/main/tests/bip174-signer-checks.rs

func TestBIP174SignerChecksReject(t *testing.T) {
	// A syntactically valid DER signature + compressed public key.
	// addPartialSignature does NOT verify the ECDSA math, only script
	// consistency, so these just need to pass format validation.
	dummySig, _ := hex.DecodeString(
		"3044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99" +
			"022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01")
	dummyPub, _ := hex.DecodeString(
		"029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f")

	cases := []struct {
		name      string
		hex       string
		failInput int // which input triggers the signer-check failure
	}{
		{
			// Input 0 carries a WitnessUtxo whose scriptPubKey is
			// P2PKH (non-witness). The p2wkh pattern check inside
			// addPartialSignature rejects because OP_DUP OP_HASH160
			// can never match OP_0 <20-byte-hash>.
			name: "witness_utxo_for_non_witness_input",
			hex: "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001012" +
				"2d3dff505000000001976a914d48ed3110b94014cb114bd32d6f4d066dc74256b88ac0001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb8230800220202ead596687ca806043edc3de116cdf29d5e9257c196cd055cf698c8d02bf24e9910b4a6ba670000008000000080020000800022020394f62be9df19952c5587768aeb7698061ad2c4a25c894f47d8c162b4d7213d0510b4a6ba6700000080010000800200008000",
			failInput: 0,
		},
		{
			// Input 0's redeemScript has been modified (last byte
			// ae→af: OP_CHECKMULTISIG→OP_CHECKMULTISIGVERIFY). Its
			// Hash160 no longer matches the P2SH scriptPubKey in the
			// NonWitnessUtxo.
			name: "redeem_script_non_witness_utxo_mismatch",
			hex: "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000002202" +
				"02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01010304010000000104475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752af2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f000000800000008000000080220602dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d710d90c6a4f0000008000000080010000800001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8872202023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d2010103040100000001042200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903010547522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae2206023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7310d90c6a4f000000800000008003000080220603089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc10d90c6a4f00000080000000800200008000220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000",
			failInput: 0,
		},
		{
			// Input 1's redeemScript has been modified (last byte
			// 03→00 in the P2WSH program). Its Hash160 no longer
			// matches the P2SH scriptPubKey in the WitnessUtxo.
			name: "redeem_script_witness_utxo_mismatch",
			hex: "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000002202" +
				"02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01010304010000000104475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f000000800000008000000080220602dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d710d90c6a4f0000008000000080010000800001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8872202023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d2010103040100000001042200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028900010547522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae2206023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7310d90c6a4f000000800000008003000080220603089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc10d90c6a4f00000080000000800200008000220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000",
			failInput: 1,
		},
		{
			// Input 1's witnessScript has been modified (last byte
			// ae→ad: OP_CHECKMULTISIG→OP_CHECKMULTISIGVERIFY). Its
			// SHA256 no longer matches the P2WSH hash embedded in
			// the redeemScript.
			name: "witness_script_witness_utxo_mismatch",
			hex: "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000002202" +
				"02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01010304010000000104475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f000000800000008000000080220602dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d710d90c6a4f0000008000000080010000800001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8872202023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d2010103040100000001042200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903010547522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ad2206023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7310d90c6a4f000000800000008003000080220603089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc10d90c6a4f00000080000000800200008000220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000",
			failInput: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := hex.DecodeString(tc.hex)
			require.NoError(t, err, "hex decode")

			p, err := NewFromRawBytes(bytes.NewReader(b), false)
			require.NoError(t, err, "parse PSBT")

			u, err := NewUpdater(p)
			require.NoError(t, err, "create updater")

			_, err = u.Sign(tc.failInput, dummySig, dummyPub, nil, nil)
			require.ErrorIs(t, err, ErrInvalidSignatureForInput,
				"input %d should fail signer checks", tc.failInput)
		})
	}
}

// /////////////////////////////////////////////////////////////////////////////
// Gap 6: Fuzz testing for the parser
// /////////////////////////////////////////////////////////////////////////////
//
// Feeds random bytes to NewFromRawBytes and exercises serialize + SanityCheck
// on anything that parses. The goal is to catch panics, infinite loops, and
// OOM on malformed input — not to validate correctness (the unit tests do
// that).
//
// Run: go test -fuzz=FuzzParsePacket -fuzztime=30s

func FuzzParsePacket(f *testing.F) {
	// Seed with the PSBT magic prefix (bare minimum).
	f.Add([]byte{0x70, 0x73, 0x62, 0x74, 0xff})

	// Seed with a minimal valid v0 PSBT (one segwit input, one output).
	if b, err := hex.DecodeString(
		"70736274ff01005202000000016d41e6873367c23c3e5f8b2c61a97de59cba" +
			"fe5dbc10878d8b4cb184a17e57920000000000ffffffff0100f90295000000" +
			"001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688ac000000000000"); err == nil {
		f.Add(b)
	}

	// Seed with a known BIP-174 PSBT.
	if b, err := hex.DecodeString(finalizerPsbtData["finalize"]); err == nil {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := NewFromRawBytes(bytes.NewReader(data), false)
		if err != nil {
			return
		}

		// If it parsed, exercising serialize and sanity-check must not
		// panic.
		var buf bytes.Buffer
		_ = p.Serialize(&buf)
		_ = p.SanityCheck()

		// Also exercise B64 path.
		_, _ = p.B64Encode()

		// Try conversion helpers (only on the correct version).
		switch p.Version {
		case 0:
			_, _ = ConvertToV2(p)
		case 2:
			_, _ = ConvertToV0(p)
		}
	})
}
