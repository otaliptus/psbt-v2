package psbt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type bip375TestVectors struct {
	Version string `json:"version"`
	Invalid []struct {
		Description string `json:"description"`
		PSBT        string `json:"psbt"`
	} `json:"invalid"`
	Valid []struct {
		Description string `json:"description"`
		PSBT        string `json:"psbt"`
	} `json:"valid"`
}

func loadBIP375Vectors(t *testing.T) bip375TestVectors {
	t.Helper()

	data, err := os.ReadFile("testdata/bip375_test_vectors.json")
	if err != nil {
		t.Fatalf("test vectors not available: %v", err)
	}

	var vectors bip375TestVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to parse test vectors: %v", err)
	}

	if vectors.Version != "1.2" {
		t.Fatalf("unexpected vector version %q", vectors.Version)
	}

	return vectors
}

func decodeVectorPSBT(t *testing.T, b64 string) []byte {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("bad base64: %v", err)
	}

	return raw
}

var structuralVectors = map[string]bool{
	"psbt structure: missing PSBT_OUT_SP_V0_INFO with PSBT_OUT_SP_V0_LABEL set": true,
	"psbt structure: PSBT_OUT_SP_V0_INFO field with incorrect size":             true,
	"psbt structure: PSBT_IN_SP_ECDH_SHARE field with incorrect size":           true,
	"psbt structure: PSBT_IN_SP_DLEQ field with incorrect size":                 true,
	"psbt structure: P2WPKH output missing PSBT_OUT_SCRIPT":                     true,
}

func TestBIP375StructuralInvalid(t *testing.T) {
	vectors := loadBIP375Vectors(t)

	tested := 0
	for _, v := range vectors.Invalid {
		if !structuralVectors[v.Description] {
			continue
		}

		tested++
		t.Run(v.Description, func(t *testing.T) {
			raw := decodeVectorPSBT(t, v.PSBT)

			_, err := NewFromRawBytes(bytes.NewReader(raw), false)
			if err == nil {
				t.Fatalf("expected parse/sanity error for structural invalid vector")
			}
		})
	}

	if tested != len(structuralVectors) {
		t.Fatalf("expected to test %d structural invalid vectors, got %d",
			len(structuralVectors), tested)
	}
}

func TestBIP375ValidRoundTrip(t *testing.T) {
	vectors := loadBIP375Vectors(t)

	tested := 0
	for _, v := range vectors.Valid {
		tested++
		t.Run(v.Description, func(t *testing.T) {
			raw := decodeVectorPSBT(t, v.PSBT)

			pkt, err := NewFromRawBytes(bytes.NewReader(raw), false)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}

			var buf bytes.Buffer
			if err := pkt.Serialize(&buf); err != nil {
				t.Fatalf("serialize failed: %v", err)
			}

			pkt2, err := NewFromRawBytes(bytes.NewReader(buf.Bytes()), false)
			if err != nil {
				t.Fatalf("re-parse failed: %v", err)
			}

			var buf2 bytes.Buffer
			if err := pkt2.Serialize(&buf2); err != nil {
				t.Fatalf("re-serialize failed: %v", err)
			}

			if !bytes.Equal(buf.Bytes(), buf2.Bytes()) {
				t.Fatalf("round-trip serialization mismatch")
			}
		})
	}

	if tested != 18 {
		t.Fatalf("expected 18 valid vectors, got %d", tested)
	}
}

func TestBIP375FieldPresence(t *testing.T) {
	vectors := loadBIP375Vectors(t)

	tested := 0
	for _, v := range vectors.Valid {
		if !strings.HasPrefix(v.Description, "can finalize:") {
			continue
		}

		tested++
		t.Run(v.Description, func(t *testing.T) {
			raw := decodeVectorPSBT(t, v.PSBT)

			pkt, err := NewFromRawBytes(bytes.NewReader(raw), false)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}

			hasSPOutput := false
			for _, out := range pkt.Outputs {
				if out.SPV0Info == nil {
					continue
				}

				hasSPOutput = true
				if len(out.SPV0Info.ScanKey) != 33 {
					t.Fatalf("SPV0Info.ScanKey len = %d, want 33",
						len(out.SPV0Info.ScanKey))
				}
				if len(out.SPV0Info.SpendKey) != 33 {
					t.Fatalf("SPV0Info.SpendKey len = %d, want 33",
						len(out.SPV0Info.SpendKey))
				}
			}
			if !hasSPOutput {
				t.Fatalf("expected at least one output with SPV0Info")
			}

			hasShares := len(pkt.GlobalSPECDHShares) > 0
			for _, in := range pkt.Inputs {
				if len(in.SPECDHShares) > 0 {
					hasShares = true
					break
				}
			}
			if !hasShares {
				t.Fatalf("expected global or per-input ECDH shares")
			}
		})
	}

	if tested != 12 {
		t.Fatalf("expected 12 'can finalize' vectors, got %d", tested)
	}
}
