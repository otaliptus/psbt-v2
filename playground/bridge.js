// bridge.js — Thin synchronous wrapper around the Go WASM functions.
// Each method calls the global WASM function, JSON.parses the result,
// and returns the parsed object.

var PSBT = {
  parse: function(input) {
    return JSON.parse(psbtParse(input));
  },

  newV2: function(txVersion, inputs, outputs, locktime, modifiable) {
    return JSON.parse(psbtNewV2(
      txVersion,
      JSON.stringify(inputs),
      JSON.stringify(outputs),
      locktime,
      modifiable
    ));
  },

  newV2Preset: function() {
    return JSON.parse(psbtNewV2Preset());
  },

  addInput: function(hex, txid, index) {
    return JSON.parse(psbtAddInput(hex, txid, index));
  },

  addOutput: function(hex, amount, scriptHex) {
    return JSON.parse(psbtAddOutput(hex, amount, scriptHex));
  },

  removeInput: function(hex, index) {
    return JSON.parse(psbtRemoveInput(hex, index));
  },

  removeOutput: function(hex, index) {
    return JSON.parse(psbtRemoveOutput(hex, index));
  },

  update: function(hex, inputIndex, value, scriptHex) {
    return JSON.parse(psbtUpdate(hex, inputIndex, value, scriptHex));
  },

  sign: function(hex, inputIndex, testKeyIndex) {
    return JSON.parse(psbtSign(hex, inputIndex, testKeyIndex));
  },

  finalize: function(hex) {
    return JSON.parse(psbtFinalize(hex));
  },

  extract: function(hex) {
    return JSON.parse(psbtExtract(hex));
  },

  serialize: function(hex, format) {
    return JSON.parse(psbtSerialize(hex, format));
  },

  convertToV2: function(hex) {
    return JSON.parse(psbtConvertToV2(hex));
  },

  convertToV0: function(hex) {
    return JSON.parse(psbtConvertToV0(hex));
  }
};
