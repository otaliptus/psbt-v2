package psbt

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
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

// TestPacketComputedLockTimeV0 verifies the legacy passthrough behavior.
func TestPacketComputedLockTimeV0(t *testing.T) {
	packet := &Packet{
		UnsignedTx: &wire.MsgTx{LockTime: 12345},
	}

	locktime, err := packet.ComputedLockTime()
	require.NoError(t, err)
	require.EqualValues(t, 12345, locktime)
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

func writeTestMap(t *testing.T, w *bytes.Buffer, kvs []testKV) {
	t.Helper()

	for _, kv := range kvs {
		putKV(t, w, kv.keyType, kv.keyData, kv.value)
	}
	endSection(t, w)
}

func compactSize(t *testing.T, v uint64) []byte {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, wire.WriteVarInt(&buf, 0, v))
	return buf.Bytes()
}

func hasUnknownWithKey(unknowns []*Unknown, key []byte) bool {
	for _, u := range unknowns {
		if bytes.Equal(u.Key, key) {
			return true
		}
	}

	return false
}

func hashPtr(fill byte) *chainhash.Hash {
	var h chainhash.Hash
	copy(h[:], bytes.Repeat([]byte{fill}, len(h)))
	return &h
}

func minimalUnsignedTxBytes(t *testing.T) []byte {
	t.Helper()

	// minimalUnsignedTxBytes builds a minimal valid unsigned v0 transaction for
	// raw parser tests that need a PSBT_GLOBAL_UNSIGNED_TX payload.
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
