package psbt

import (
	"bytes"
	"encoding/binary"
	"testing"

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

// TestPSBTV2CurrentGlobalV2FieldsRoundTripAsUnknown documents current behavior:
// global v2 keys are preserved as Unknowns until global-v2 parsing is added.
func TestPSBTV2CurrentGlobalV2FieldsRoundTripAsUnknown(t *testing.T) {
	packet, err := New(nil, nil, 2, 0, nil)
	require.NoError(t, err)

	packet.Unknowns = []*Unknown{
		{Key: []byte{byte(TxVersionType)}, Value: u32LE(2)},
		{Key: []byte{byte(InputCountType)}, Value: []byte{0x00}},
		{Key: []byte{byte(OutputCountType)}, Value: []byte{0x00}},
		{Key: []byte{byte(VersionType)}, Value: u32LE(2)},
	}

	var buf bytes.Buffer
	require.NoError(t, packet.Serialize(&buf))

	parsed, err := NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
	require.NoError(t, err)
	require.True(t, hasSingletonGlobalUnknown(parsed.Unknowns, TxVersionType))
	require.True(t, hasSingletonGlobalUnknown(parsed.Unknowns, InputCountType))
	require.True(t, hasSingletonGlobalUnknown(parsed.Unknowns, OutputCountType))
	require.True(t, hasSingletonGlobalUnknown(parsed.Unknowns, VersionType))
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

func hasSingletonGlobalUnknown(unknowns []*Unknown, t GlobalType) bool {
	for _, u := range unknowns {
		if len(u.Key) == 1 && u.Key[0] == byte(t) {
			return true
		}
	}

	return false
}
