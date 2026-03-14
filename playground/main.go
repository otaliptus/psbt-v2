//go:build js && wasm

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	psbt "github.com/otaliptus/psbt-v2"
)

// ---------------------------------------------------------------------------
// Test keys — three deterministic P2WPKH key pairs.
// ---------------------------------------------------------------------------

type testKey struct {
	PrivKey *btcec.PrivateKey
	PubKey  []byte // 33-byte compressed
	Script  []byte // P2WPKH scriptPubKey (OP_0 <20-byte-hash>)
}

var testKeys [3]testKey

func initTestKeys() {
	seeds := [3][]byte{
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
	}
	for i, seed := range seeds {
		priv, pub := btcec.PrivKeyFromBytes(seed)
		compressed := pub.SerializeCompressed()
		h160 := btcutil.Hash160(compressed)

		// OP_0 <20-byte-hash>
		script, err := txscript.NewScriptBuilder().
			AddOp(txscript.OP_0).
			AddData(h160).
			Script()
		if err != nil {
			panic(fmt.Sprintf("initTestKeys: %v", err))
		}

		testKeys[i] = testKey{
			PrivKey: priv,
			PubKey:  compressed,
			Script:  script,
		}
	}
}

// ---------------------------------------------------------------------------
// JSON types for the packet representation sent to the UI.
// ---------------------------------------------------------------------------

type jsonUTXO struct {
	Value  int64  `json:"value"`
	Script string `json:"script"`
}

type jsonInput struct {
	PreviousTxID           string    `json:"previousTxID"`
	OutputIndex            uint32    `json:"outputIndex"`
	Sequence               uint32    `json:"sequence"`
	WitnessUtxo            *jsonUTXO `json:"witnessUtxo,omitempty"`
	PartialSigsCount       int       `json:"partialSigsCount"`
	Status                 string    `json:"status"` // "unsigned", "signed", "finalized"
	ScriptType             string    `json:"scriptType"`
	RequiredTimeLocktime   *uint32   `json:"requiredTimeLocktime,omitempty"`
	RequiredHeightLocktime *uint32   `json:"requiredHeightLocktime,omitempty"`
	SighashType            uint32    `json:"sighashType"`
	HasRedeemScript        bool      `json:"hasRedeemScript"`
	HasWitnessScript       bool      `json:"hasWitnessScript"`
	Bip32DerivationsCount  int       `json:"bip32DerivationsCount"`
	TaprootInternalKey     string    `json:"taprootInternalKey,omitempty"`
	Finalized              bool      `json:"finalized"`
}

type jsonOutput struct {
	Amount     int64  `json:"amount"`
	Script     string `json:"script"`
	ScriptType string `json:"scriptType"`
}

type jsonPacket struct {
	Version          uint32       `json:"version"`
	TxVersion        int32        `json:"txVersion"`
	FallbackLocktime *uint32      `json:"fallbackLocktime,omitempty"`
	TxModifiable     *uint8       `json:"txModifiable,omitempty"`
	ComputedLocktime *uint32      `json:"computedLocktime,omitempty"`
	Fee              *int64       `json:"fee,omitempty"`
	Inputs           []jsonInput  `json:"inputs"`
	Outputs          []jsonOutput `json:"outputs"`
}

// ---------------------------------------------------------------------------
// Script classification
// ---------------------------------------------------------------------------

func classifyScript(script []byte) string {
	switch {
	case txscript.IsPayToWitnessPubKeyHash(script):
		return "P2WPKH"
	case txscript.IsPayToWitnessScriptHash(script):
		return "P2WSH"
	case txscript.IsPayToScriptHash(script):
		return "P2SH"
	case txscript.IsPayToPubKeyHash(script):
		return "P2PKH"
	case txscript.IsPayToPubKey(script):
		return "P2PK"
	case len(script) == 34 && script[0] == 0x51 && script[1] == 0x20:
		return "P2TR"
	default:
		return "unknown"
	}
}

// ---------------------------------------------------------------------------
// Marshal helpers
// ---------------------------------------------------------------------------

func hexToPacket(hexStr string) (*psbt.Packet, error) {
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	pkt, err := psbt.NewFromRawBytes(bytes.NewReader(raw), false)
	if err != nil {
		return nil, fmt.Errorf("parse PSBT: %w", err)
	}
	return pkt, nil
}

func packetToHex(p *psbt.Packet) (string, error) {
	var buf bytes.Buffer
	if err := p.Serialize(&buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

func packetToJSON(p *psbt.Packet) (string, error) {
	jp := jsonPacket{
		Version:   p.Version,
		TxVersion: p.GetTxVersion(),
	}

	if p.FallbackLocktime != nil {
		v := *p.FallbackLocktime
		jp.FallbackLocktime = &v
	}
	if p.TxModifiable != nil {
		v := *p.TxModifiable
		jp.TxModifiable = &v
	}

	// Computed locktime (both v0 and v2).
	if lt, err := p.ComputedLockTime(); err == nil {
		jp.ComputedLocktime = &lt
	}

	// Fee — only if all inputs have UTXO information.
	if fee, err := p.GetTxFee(); err == nil {
		feeInt := int64(fee)
		jp.Fee = &feeInt
	}

	// Inputs.
	jp.Inputs = make([]jsonInput, len(p.Inputs))
	for i := range p.Inputs {
		in := &p.Inputs[i]
		ji := jsonInput{
			Sequence:              p.InputSequence(i),
			PartialSigsCount:      len(in.PartialSigs),
			SighashType:           uint32(in.SighashType),
			HasRedeemScript:       in.RedeemScript != nil,
			HasWitnessScript:      in.WitnessScript != nil,
			Bip32DerivationsCount: len(in.Bip32Derivation),
		}

		// Previous outpoint: v2 uses per-input fields, v0 uses UnsignedTx.
		if in.PreviousTxID != nil {
			ji.PreviousTxID = in.PreviousTxID.String()
		} else if p.UnsignedTx != nil && i < len(p.UnsignedTx.TxIn) {
			ji.PreviousTxID = p.UnsignedTx.TxIn[i].PreviousOutPoint.Hash.String()
		}
		if in.OutputIndex != nil {
			ji.OutputIndex = *in.OutputIndex
		} else if p.UnsignedTx != nil && i < len(p.UnsignedTx.TxIn) {
			ji.OutputIndex = p.UnsignedTx.TxIn[i].PreviousOutPoint.Index
		}

		// WitnessUtxo.
		if in.WitnessUtxo != nil {
			ji.WitnessUtxo = &jsonUTXO{
				Value:  in.WitnessUtxo.Value,
				Script: hex.EncodeToString(in.WitnessUtxo.PkScript),
			}
			ji.ScriptType = classifyScript(in.WitnessUtxo.PkScript)
		}

		// Status: finalized > signed > unsigned.
		if in.FinalScriptSig != nil || in.FinalScriptWitness != nil {
			ji.Status = "finalized"
			ji.Finalized = true
		} else if len(in.PartialSigs) > 0 || in.TaprootKeySpendSig != nil || len(in.TaprootScriptSpendSig) > 0 {
			ji.Status = "signed"
		} else {
			ji.Status = "unsigned"
		}

		// Locktime requirements.
		ji.RequiredTimeLocktime = in.RequiredTimeLocktime
		ji.RequiredHeightLocktime = in.RequiredHeightLocktime

		// Taproot internal key.
		if in.TaprootInternalKey != nil {
			ji.TaprootInternalKey = hex.EncodeToString(in.TaprootInternalKey)
		}

		jp.Inputs[i] = ji
	}

	// Outputs.
	jp.Outputs = make([]jsonOutput, len(p.Outputs))
	for i := range p.Outputs {
		out := &p.Outputs[i]
		jo := jsonOutput{}

		// Amount: v2 stores in POutput.Amount, v0 in UnsignedTx.
		if out.Amount != nil {
			jo.Amount = *out.Amount
		} else if p.UnsignedTx != nil && i < len(p.UnsignedTx.TxOut) {
			jo.Amount = p.UnsignedTx.TxOut[i].Value
		}

		// Script: v2 stores in POutput.Script, v0 in UnsignedTx.
		var script []byte
		if out.Script != nil {
			script = out.Script
		} else if p.UnsignedTx != nil && i < len(p.UnsignedTx.TxOut) {
			script = p.UnsignedTx.TxOut[i].PkScript
		}
		if script != nil {
			jo.Script = hex.EncodeToString(script)
			jo.ScriptType = classifyScript(script)
		}

		jp.Outputs[i] = jo
	}

	data, err := json.Marshal(jp)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func okResult(p *psbt.Packet) string {
	pktJSON, err := packetToJSON(p)
	if err != nil {
		return errResult(fmt.Sprintf("json marshal: %v", err))
	}
	hexStr, err := packetToHex(p)
	if err != nil {
		return errResult(fmt.Sprintf("hex encode: %v", err))
	}
	return fmt.Sprintf(`{"ok":true,"packet":%s,"hex":"%s"}`, pktJSON, hexStr)
}

func errResult(msg string) string {
	data, _ := json.Marshal(msg)
	return fmt.Sprintf(`{"ok":false,"error":%s}`, string(data))
}

// ---------------------------------------------------------------------------
// Registered WASM functions
// ---------------------------------------------------------------------------

// psbtParse(hexOrB64 string) -> JSON
func jsPsbtParse(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return errResult("psbtParse: missing argument")
	}
	input := args[0].String()

	// Try hex first.
	raw, err := hex.DecodeString(input)
	if err != nil {
		// Fall back to base64.
		raw, err = base64.StdEncoding.DecodeString(input)
		if err != nil {
			return errResult("psbtParse: input is neither valid hex nor base64")
		}
	}

	pkt, err := psbt.NewFromRawBytes(bytes.NewReader(raw), false)
	if err != nil {
		return errResult(fmt.Sprintf("psbtParse: %v", err))
	}
	return okResult(pkt)
}

// psbtNewV2(txVersion int, inputsJSON string, outputsJSON string, locktime int, modifiable int) -> JSON
func jsPsbtNewV2(_ js.Value, args []js.Value) any {
	if len(args) < 5 {
		return errResult("psbtNewV2: need 5 args (txVersion, inputsJSON, outputsJSON, locktime, modifiable)")
	}

	txVersion := int32(args[0].Int())

	// Parse inputs: [{"txid":"hex","index":N}, ...]
	type jsInput struct {
		Txid  string `json:"txid"`
		Index uint32 `json:"index"`
	}
	var jsInputs []jsInput
	if err := json.Unmarshal([]byte(args[1].String()), &jsInputs); err != nil {
		return errResult(fmt.Sprintf("psbtNewV2: parse inputs: %v", err))
	}

	inputs := make([]wire.OutPoint, len(jsInputs))
	for i, ji := range jsInputs {
		txidBytes, err := hex.DecodeString(ji.Txid)
		if err != nil || len(txidBytes) != 32 {
			return errResult(fmt.Sprintf("psbtNewV2: invalid txid at index %d", i))
		}
		var hash chainhash.Hash
		copy(hash[:], txidBytes)
		inputs[i] = wire.OutPoint{Hash: hash, Index: ji.Index}
	}

	// Parse outputs: [{"amount":N,"script":"hex"}, ...]
	type jsOutput struct {
		Amount int64  `json:"amount"`
		Script string `json:"script"`
	}
	var jsOutputs []jsOutput
	if err := json.Unmarshal([]byte(args[2].String()), &jsOutputs); err != nil {
		return errResult(fmt.Sprintf("psbtNewV2: parse outputs: %v", err))
	}

	outputs := make([]*wire.TxOut, len(jsOutputs))
	for i, jo := range jsOutputs {
		scriptBytes, err := hex.DecodeString(jo.Script)
		if err != nil {
			return errResult(fmt.Sprintf("psbtNewV2: invalid script at output %d", i))
		}
		outputs[i] = wire.NewTxOut(jo.Amount, scriptBytes)
	}

	// Locktime.
	var fallbackLocktime *uint32
	lt := args[3].Int()
	if lt > 0 {
		v := uint32(lt)
		fallbackLocktime = &v
	}

	// Modifiable flags.
	var txModifiable *uint8
	mod := args[4].Int()
	if mod >= 0 {
		v := uint8(mod)
		txModifiable = &v
	}

	pkt, err := psbt.NewV2(txVersion, inputs, outputs, fallbackLocktime, txModifiable)
	if err != nil {
		return errResult(fmt.Sprintf("psbtNewV2: %v", err))
	}
	return okResult(pkt)
}

// psbtAddInput(hex string, txid string, index int) -> JSON
func jsPsbtAddInput(_ js.Value, args []js.Value) any {
	if len(args) < 3 {
		return errResult("psbtAddInput: need 3 args (hex, txid, index)")
	}

	pkt, err := hexToPacket(args[0].String())
	if err != nil {
		return errResult(fmt.Sprintf("psbtAddInput: %v", err))
	}

	txidBytes, err := hex.DecodeString(args[1].String())
	if err != nil || len(txidBytes) != 32 {
		return errResult("psbtAddInput: invalid txid")
	}
	var hash chainhash.Hash
	copy(hash[:], txidBytes)

	idx := uint32(args[2].Int())

	c, err := psbt.NewConstructor(pkt)
	if err != nil {
		return errResult(fmt.Sprintf("psbtAddInput: constructor: %v", err))
	}
	if err := c.AddInput(hash, idx); err != nil {
		return errResult(fmt.Sprintf("psbtAddInput: %v", err))
	}
	return okResult(c.Pkt)
}

// psbtAddOutput(hex string, amount int, scriptHex string) -> JSON
func jsPsbtAddOutput(_ js.Value, args []js.Value) any {
	if len(args) < 3 {
		return errResult("psbtAddOutput: need 3 args (hex, amount, scriptHex)")
	}

	pkt, err := hexToPacket(args[0].String())
	if err != nil {
		return errResult(fmt.Sprintf("psbtAddOutput: %v", err))
	}

	amount := int64(args[1].Int())
	scriptBytes, err := hex.DecodeString(args[2].String())
	if err != nil {
		return errResult(fmt.Sprintf("psbtAddOutput: invalid script hex: %v", err))
	}

	c, err := psbt.NewConstructor(pkt)
	if err != nil {
		return errResult(fmt.Sprintf("psbtAddOutput: constructor: %v", err))
	}
	if err := c.AddOutput(amount, scriptBytes); err != nil {
		return errResult(fmt.Sprintf("psbtAddOutput: %v", err))
	}
	return okResult(c.Pkt)
}

// psbtRemoveInput(hex string, index int) -> JSON
func jsPsbtRemoveInput(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return errResult("psbtRemoveInput: need 2 args (hex, index)")
	}

	pkt, err := hexToPacket(args[0].String())
	if err != nil {
		return errResult(fmt.Sprintf("psbtRemoveInput: %v", err))
	}

	idx := args[1].Int()

	c, err := psbt.NewConstructor(pkt)
	if err != nil {
		return errResult(fmt.Sprintf("psbtRemoveInput: constructor: %v", err))
	}
	if err := c.RemoveInput(idx); err != nil {
		return errResult(fmt.Sprintf("psbtRemoveInput: %v", err))
	}
	return okResult(c.Pkt)
}

// psbtRemoveOutput(hex string, index int) -> JSON
func jsPsbtRemoveOutput(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return errResult("psbtRemoveOutput: need 2 args (hex, index)")
	}

	pkt, err := hexToPacket(args[0].String())
	if err != nil {
		return errResult(fmt.Sprintf("psbtRemoveOutput: %v", err))
	}

	idx := args[1].Int()

	c, err := psbt.NewConstructor(pkt)
	if err != nil {
		return errResult(fmt.Sprintf("psbtRemoveOutput: constructor: %v", err))
	}
	if err := c.RemoveOutput(idx); err != nil {
		return errResult(fmt.Sprintf("psbtRemoveOutput: %v", err))
	}
	return okResult(c.Pkt)
}

// psbtUpdate(hex string, inputIndex int, value int, scriptHex string) -> JSON
func jsPsbtUpdate(_ js.Value, args []js.Value) any {
	if len(args) < 4 {
		return errResult("psbtUpdate: need 4 args (hex, inputIndex, value, scriptHex)")
	}

	pkt, err := hexToPacket(args[0].String())
	if err != nil {
		return errResult(fmt.Sprintf("psbtUpdate: %v", err))
	}

	inIdx := args[1].Int()
	value := int64(args[2].Int())
	scriptBytes, err := hex.DecodeString(args[3].String())
	if err != nil {
		return errResult(fmt.Sprintf("psbtUpdate: invalid script hex: %v", err))
	}

	txout := wire.NewTxOut(value, scriptBytes)

	u, err := psbt.NewUpdater(pkt)
	if err != nil {
		return errResult(fmt.Sprintf("psbtUpdate: updater: %v", err))
	}
	if err := u.AddInWitnessUtxo(txout, inIdx); err != nil {
		return errResult(fmt.Sprintf("psbtUpdate: %v", err))
	}
	return okResult(u.Upsbt)
}

// psbtSign(hex string, inputIndex int, testKeyIndex int) -> JSON
func jsPsbtSign(_ js.Value, args []js.Value) any {
	if len(args) < 3 {
		return errResult("psbtSign: need 3 args (hex, inputIndex, testKeyIndex)")
	}

	pkt, err := hexToPacket(args[0].String())
	if err != nil {
		return errResult(fmt.Sprintf("psbtSign: %v", err))
	}

	inIdx := args[1].Int()
	keyIdx := args[2].Int()

	if keyIdx < 0 || keyIdx > 2 {
		return errResult("psbtSign: testKeyIndex must be 0-2")
	}
	if inIdx < 0 || inIdx >= len(pkt.Inputs) {
		return errResult("psbtSign: inputIndex out of range")
	}

	tk := testKeys[keyIdx]

	// WitnessUtxo must be present.
	if pkt.Inputs[inIdx].WitnessUtxo == nil {
		return errResult("psbtSign: input has no WitnessUtxo — update it first")
	}

	witnessUtxo := pkt.Inputs[inIdx].WitnessUtxo

	// Build the unsigned transaction for sighash computation.
	unsignedTx, err := pkt.BuildUnsignedTx()
	if err != nil {
		return errResult(fmt.Sprintf("psbtSign: BuildUnsignedTx: %v", err))
	}

	// Build a PrevOutputFetcher that knows about all inputs with WitnessUtxo.
	prevOuts := make(map[wire.OutPoint]*wire.TxOut)
	for i := range pkt.Inputs {
		if pkt.Inputs[i].WitnessUtxo != nil && i < len(unsignedTx.TxIn) {
			prevOuts[unsignedTx.TxIn[i].PreviousOutPoint] = pkt.Inputs[i].WitnessUtxo
		}
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)

	sigHashes := txscript.NewTxSigHashes(unsignedTx, fetcher)

	sig, err := txscript.RawTxInWitnessSignature(
		unsignedTx, sigHashes, inIdx,
		witnessUtxo.Value, witnessUtxo.PkScript,
		txscript.SigHashAll, tk.PrivKey,
	)
	if err != nil {
		return errResult(fmt.Sprintf("psbtSign: sign: %v", err))
	}

	u, err := psbt.NewUpdater(pkt)
	if err != nil {
		return errResult(fmt.Sprintf("psbtSign: updater: %v", err))
	}
	_, err = u.Sign(inIdx, sig, tk.PubKey, nil, nil)
	if err != nil {
		return errResult(fmt.Sprintf("psbtSign: Sign: %v", err))
	}

	return okResult(u.Upsbt)
}

// psbtFinalize(hex string) -> JSON
func jsPsbtFinalize(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return errResult("psbtFinalize: missing hex argument")
	}

	pkt, err := hexToPacket(args[0].String())
	if err != nil {
		return errResult(fmt.Sprintf("psbtFinalize: %v", err))
	}

	if err := psbt.MaybeFinalizeAll(pkt); err != nil {
		return errResult(fmt.Sprintf("psbtFinalize: %v", err))
	}

	return okResult(pkt)
}

// psbtExtract(hex string) -> JSON with rawTx
func jsPsbtExtract(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return errResult("psbtExtract: missing hex argument")
	}

	pkt, err := hexToPacket(args[0].String())
	if err != nil {
		return errResult(fmt.Sprintf("psbtExtract: %v", err))
	}

	tx, err := psbt.Extract(pkt)
	if err != nil {
		return errResult(fmt.Sprintf("psbtExtract: %v", err))
	}

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return errResult(fmt.Sprintf("psbtExtract: serialize: %v", err))
	}

	rawHex := hex.EncodeToString(buf.Bytes())
	return fmt.Sprintf(`{"ok":true,"rawTx":"%s"}`, rawHex)
}

// psbtConvertToV2(hex string) -> JSON
func jsPsbtConvertToV2(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return errResult("psbtConvertToV2: missing hex argument")
	}

	pkt, err := hexToPacket(args[0].String())
	if err != nil {
		return errResult(fmt.Sprintf("psbtConvertToV2: %v", err))
	}

	v2, err := psbt.ConvertToV2(pkt)
	if err != nil {
		return errResult(fmt.Sprintf("psbtConvertToV2: %v", err))
	}

	return okResult(v2)
}

// psbtConvertToV0(hex string) -> JSON
func jsPsbtConvertToV0(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return errResult("psbtConvertToV0: missing hex argument")
	}

	pkt, err := hexToPacket(args[0].String())
	if err != nil {
		return errResult(fmt.Sprintf("psbtConvertToV0: %v", err))
	}

	v0, err := psbt.ConvertToV0(pkt)
	if err != nil {
		return errResult(fmt.Sprintf("psbtConvertToV0: %v", err))
	}

	return okResult(v0)
}

// psbtSerialize(hex string, format string) -> JSON with data
func jsPsbtSerialize(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return errResult("psbtSerialize: need 2 args (hex, format)")
	}

	pkt, err := hexToPacket(args[0].String())
	if err != nil {
		return errResult(fmt.Sprintf("psbtSerialize: %v", err))
	}

	format := args[1].String()
	switch format {
	case "hex":
		h, err := packetToHex(pkt)
		if err != nil {
			return errResult(fmt.Sprintf("psbtSerialize: %v", err))
		}
		return fmt.Sprintf(`{"ok":true,"data":"%s"}`, h)

	case "base64":
		b64, err := pkt.B64Encode()
		if err != nil {
			return errResult(fmt.Sprintf("psbtSerialize: %v", err))
		}
		return fmt.Sprintf(`{"ok":true,"data":"%s"}`, b64)

	default:
		return errResult(fmt.Sprintf("psbtSerialize: unknown format %q (use \"hex\" or \"base64\")", format))
	}
}

// psbtNewV2Preset() -> JSON — creates a ready-to-sign v2 packet with test keys.
func jsPsbtNewV2Preset(_ js.Value, _ []js.Value) any {
	// Two fake outpoints.
	outpoint0 := wire.OutPoint{
		Hash:  chainhash.Hash{0xaa, 0xbb, 0xcc, 0xdd},
		Index: 0,
	}
	outpoint1 := wire.OutPoint{
		Hash:  chainhash.Hash{0xee, 0xff, 0x00, 0x11},
		Index: 1,
	}

	inputs := []wire.OutPoint{outpoint0, outpoint1}

	// Two outputs: one to testKey[2], one change to testKey[0].
	outputs := []*wire.TxOut{
		wire.NewTxOut(50000, testKeys[2].Script),
		wire.NewTxOut(40000, testKeys[0].Script),
	}

	// modifiable = 0x03 (inputs + outputs modifiable).
	mod := uint8(0x03)

	pkt, err := psbt.NewV2(2, inputs, outputs, nil, &mod)
	if err != nil {
		return errResult(fmt.Sprintf("psbtNewV2Preset: NewV2: %v", err))
	}

	// Attach WitnessUtxo to both inputs so they're ready to sign.
	u, err := psbt.NewUpdater(pkt)
	if err != nil {
		return errResult(fmt.Sprintf("psbtNewV2Preset: updater: %v", err))
	}

	// Input 0 spends a 50000 sat output belonging to testKey[0].
	if err := u.AddInWitnessUtxo(wire.NewTxOut(50000, testKeys[0].Script), 0); err != nil {
		return errResult(fmt.Sprintf("psbtNewV2Preset: AddInWitnessUtxo(0): %v", err))
	}

	// Input 1 spends a 50000 sat output belonging to testKey[1].
	if err := u.AddInWitnessUtxo(wire.NewTxOut(50000, testKeys[1].Script), 1); err != nil {
		return errResult(fmt.Sprintf("psbtNewV2Preset: AddInWitnessUtxo(1): %v", err))
	}

	return okResult(u.Upsbt)
}

// ---------------------------------------------------------------------------
// main — register all functions and block forever.
// ---------------------------------------------------------------------------

func main() {
	initTestKeys()

	fmt.Println("PSBT Playground WASM loaded")

	g := js.Global()

	// Ping (keep for health check).
	g.Set("psbtPing", js.FuncOf(func(_ js.Value, _ []js.Value) any {
		return `{"ok":true,"message":"pong"}`
	}))

	// Core functions.
	g.Set("psbtParse", js.FuncOf(jsPsbtParse))
	g.Set("psbtNewV2", js.FuncOf(jsPsbtNewV2))
	g.Set("psbtAddInput", js.FuncOf(jsPsbtAddInput))
	g.Set("psbtAddOutput", js.FuncOf(jsPsbtAddOutput))
	g.Set("psbtRemoveInput", js.FuncOf(jsPsbtRemoveInput))
	g.Set("psbtRemoveOutput", js.FuncOf(jsPsbtRemoveOutput))
	g.Set("psbtUpdate", js.FuncOf(jsPsbtUpdate))
	g.Set("psbtSign", js.FuncOf(jsPsbtSign))
	g.Set("psbtFinalize", js.FuncOf(jsPsbtFinalize))
	g.Set("psbtExtract", js.FuncOf(jsPsbtExtract))
	g.Set("psbtConvertToV2", js.FuncOf(jsPsbtConvertToV2))
	g.Set("psbtConvertToV0", js.FuncOf(jsPsbtConvertToV0))
	g.Set("psbtSerialize", js.FuncOf(jsPsbtSerialize))
	g.Set("psbtNewV2Preset", js.FuncOf(jsPsbtNewV2Preset))

	// Expose test key info for the UI.
	keyInfo := make([]any, 3)
	for i, tk := range testKeys {
		keyInfo[i] = map[string]any{
			"index":  i,
			"pubKey": hex.EncodeToString(tk.PubKey),
			"script": hex.EncodeToString(tk.Script),
		}
	}
	g.Set("psbtTestKeys", js.ValueOf(keyInfo))

	// Block forever.
	select {}
}
