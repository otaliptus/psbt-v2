// app.js — State management and rendering for PSBT Playground.
// Uses safe DOM methods (createElement, textContent, appendChild, replaceChildren).
// No innerHTML with parsed data.

var state = { packet: null, hex: null, error: null, exportData: null };

// ---------------------------------------------------------------------------
// Example PSBTs from BIP-174 and BIP-370 test vectors
// ---------------------------------------------------------------------------

var EXAMPLES = [
  {
    name: "v0 -- P2PKH (BIP-174)",
    description: "Single P2PKH input, unsigned. The simplest v0 PSBT.",
    data: "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab300000000000000"
  },
  {
    name: "v0 -- P2SH-P2WSH Multisig (BIP-174)",
    description: "2-of-2 P2SH-P2WSH multisig with witness script and BIP-32 derivations.",
    data: "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000"
  },
  {
    name: "v2 -- Minimal (BIP-370)",
    description: "Minimal v2 PSBT with only required fields. 1 input, 2 P2WPKH outputs.",
    data: "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA=="
  },
  {
    name: "v2 -- With Locktimes (BIP-370)",
    description: "v2 PSBT with fallback locktime, per-input required height and time locktimes, and explicit sequence.",
    data: "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAEQBP7///8BEQSMjcRiARIEECcAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA=="
  },
  {
    name: "v2 -- Inputs+Outputs Modifiable (BIP-370)",
    description: "v2 PSBT with TxModifiable = 0x03 (inputs and outputs can be added/removed). Try the Constructor.",
    data: "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEDAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA=="
  },
  {
    name: "v2 -- All Fields (BIP-370)",
    description: "Comprehensive v2 PSBT with all supported field types: locktimes, modifiable flags, UTXO data, BIP-32 derivations.",
    data: "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAQYBBwH7BAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BDiALCtkhQZwchxlzXXLcc5+eqeBjjR/kwe7w+ZRAhIFfyAEPBAAAAAABEAT+////AREEjI3EYgESBBAnAAAAIgIC1gH4SEamdV93a+AOPZ3o+xCsyTX7g8RfsBYtTK1at5IY9p2HPlQAAIABAACAAAAAgAAAAAAqAAAAAQMIAAivLwAAAAABBBYAFMQw9kxHVtoxDb0aCFVy7ymZJicsACICAuNvv/U91TQHDPj9OWYUaA81epuF23NAvxz6dF0q17NAGPadhz5UAACAAQAAgAAAAIABAAAAZAAAAAEDCIu96wsAAAAAAQQWABRN0ZOslkpWrBueHMqEVP4vR0+FEwA="
  }
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function truncate(s, len) {
  if (!s || s.length <= len) return s || "";
  return s.substring(0, len) + "...";
}

function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function createChip(label, value, cls) {
  var chip = el("span", "chip" + (cls ? " " + cls : ""));
  chip.appendChild(el("span", "chip-label", label));
  chip.appendChild(el("span", "chip-value", value));
  return chip;
}

function modFlagsText(flags) {
  if (flags === null || flags === undefined) return null;
  var parts = [];
  if (flags & 0x01) parts.push("inputs");
  if (flags & 0x02) parts.push("outputs");
  if (parts.length === 0) return "none";
  return parts.join("+");
}

// ---------------------------------------------------------------------------
// Input card
// ---------------------------------------------------------------------------

function createInputCard(input, index) {
  var card = el("div", "input-card " + input.status);

  // Header
  var header = el("div", "input-header");
  var headerLeft = el("div", "input-header-left");
  headerLeft.appendChild(el("span", "idx-badge", String(index)));
  headerLeft.appendChild(el("span", "status-badge " + input.status, input.status));
  if (input.scriptType) {
    headerLeft.appendChild(el("span", "script-badge", input.scriptType));
  }
  header.appendChild(headerLeft);

  var removeBtn = el("button", "btn-remove", "Remove");
  removeBtn.onclick = function() { handleRemoveInput(index); };
  header.appendChild(removeBtn);
  card.appendChild(header);

  // Fields
  var fields = el("div", "input-fields");
  if (input.previousTxID) {
    var txidLine = el("div");
    txidLine.appendChild(document.createTextNode("txid: " + truncate(input.previousTxID, 24)));
    fields.appendChild(txidLine);
  }
  var voutLine = el("div");
  voutLine.appendChild(document.createTextNode("vout: " + input.outputIndex + "  seq: 0x" + (input.sequence >>> 0).toString(16)));
  fields.appendChild(voutLine);
  card.appendChild(fields);

  // UTXO row
  if (input.witnessUtxo) {
    var utxo = el("div", "utxo-row");
    utxo.appendChild(document.createTextNode("UTXO: " + input.witnessUtxo.value + " sats"));
    card.appendChild(utxo);
  }

  // Signature progress
  var sigCount = input.partialSigsCount || 0;
  if (input.status !== "finalized") {
    var progress = el("div", "sig-progress");
    var bar = el("div", "sig-progress-bar");
    bar.style.width = sigCount > 0 ? "100%" : "0%";
    progress.appendChild(bar);
    card.appendChild(progress);
    var sigLabel = el("div");
    sigLabel.style.fontSize = "11px";
    sigLabel.style.color = "var(--text-muted)";
    sigLabel.textContent = "Sigs: " + sigCount;
    card.appendChild(sigLabel);
  }

  // Details
  var details = el("details", "input-details");
  var summary = el("summary", null, "More details");
  details.appendChild(summary);
  var body = el("div", "input-details-body");
  body.appendChild(el("div", null, "sighashType: " + input.sighashType));
  body.appendChild(el("div", null, "redeemScript: " + (input.hasRedeemScript ? "yes" : "no")));
  body.appendChild(el("div", null, "witnessScript: " + (input.hasWitnessScript ? "yes" : "no")));
  body.appendChild(el("div", null, "bip32Derivations: " + input.bip32DerivationsCount));
  if (input.taprootInternalKey) {
    body.appendChild(el("div", null, "taprootKey: " + truncate(input.taprootInternalKey, 16)));
  }
  if (input.requiredTimeLocktime !== null && input.requiredTimeLocktime !== undefined) {
    body.appendChild(el("div", null, "reqTimeLock: " + input.requiredTimeLocktime));
  }
  if (input.requiredHeightLocktime !== null && input.requiredHeightLocktime !== undefined) {
    body.appendChild(el("div", null, "reqHeightLock: " + input.requiredHeightLocktime));
  }
  details.appendChild(body);
  card.appendChild(details);

  return card;
}

// ---------------------------------------------------------------------------
// Output card
// ---------------------------------------------------------------------------

function createOutputCard(output, index) {
  var card = el("div", "output-card");

  // Header
  var header = el("div", "output-header");
  var headerLeft = el("div", "input-header-left");
  headerLeft.appendChild(el("span", "idx-badge", String(index)));
  var amountSpan = el("span", "output-amount");
  amountSpan.appendChild(document.createTextNode(String(output.amount)));
  var satsSpan = el("span", "output-sats", " sats");
  amountSpan.appendChild(satsSpan);
  headerLeft.appendChild(amountSpan);
  if (output.scriptType) {
    headerLeft.appendChild(el("span", "script-badge", output.scriptType));
  }
  header.appendChild(headerLeft);

  var removeBtn = el("button", "btn-remove", "Remove");
  removeBtn.onclick = function() { handleRemoveOutput(index); };
  header.appendChild(removeBtn);
  card.appendChild(header);

  // Script
  if (output.script) {
    var scriptDiv = el("div", "output-script", truncate(output.script, 64));
    card.appendChild(scriptDiv);
  }

  return card;
}

// ---------------------------------------------------------------------------
// Event handlers
// ---------------------------------------------------------------------------

function renderExamples() {
  var container = document.getElementById("examples-list");
  if (!container) return;
  container.replaceChildren();
  EXAMPLES.forEach(function(ex, i) {
    var card = el("div", "example-card");
    card.appendChild(el("div", "example-name", ex.name));
    card.appendChild(el("div", "example-desc", ex.description));
    card.addEventListener("click", function() { loadExample(i); });
    container.appendChild(card);
  });
}

function loadExample(index) {
  var ex = EXAMPLES[index];
  if (!ex) return;
  var result = PSBT.parse(ex.data);
  if (result.ok) {
    state = { packet: result.packet, hex: result.hex, error: null, exportData: null };
  } else {
    state.error = result.error;
  }
  render();
}

function handleParse() {
  var input = document.getElementById("input-psbt").value.trim();
  if (!input) return;
  var result = PSBT.parse(input);
  if (result.ok) {
    state = { packet: result.packet, hex: result.hex, error: null, exportData: null };
  } else {
    state.error = result.error;
  }
  render();
}

function handleNewV2() {
  var result = PSBT.newV2Preset();
  if (result.ok) {
    state = { packet: result.packet, hex: result.hex, error: null, exportData: null };
  } else {
    state.error = result.error;
  }
  render();
}

function handleConvertToV2() {
  if (!state.hex) return;
  var result = PSBT.convertToV2(state.hex);
  if (result.ok) {
    state = { packet: result.packet, hex: result.hex, error: null, exportData: null };
  } else {
    state.error = result.error;
  }
  render();
}

function handleConvertToV0() {
  if (!state.hex) return;
  var result = PSBT.convertToV0(state.hex);
  if (result.ok) {
    state = { packet: result.packet, hex: result.hex, error: null, exportData: null };
  } else {
    state.error = result.error;
  }
  render();
}

function handleAddInput() {
  if (!state.hex) return;
  // Zero txid for demo
  var zeroTxid = "";
  for (var i = 0; i < 32; i++) zeroTxid += "00";
  var result = PSBT.addInput(state.hex, zeroTxid, 0);
  if (result.ok) {
    state = { packet: result.packet, hex: result.hex, error: null, exportData: null };
  } else {
    state.error = result.error;
  }
  render();
}

function handleAddOutput() {
  if (!state.hex) return;
  // Dummy P2WPKH: OP_0 <20-byte-hash>
  var dummyScript = "0014";
  for (var i = 0; i < 20; i++) dummyScript += "00";
  var result = PSBT.addOutput(state.hex, 10000, dummyScript);
  if (result.ok) {
    state = { packet: result.packet, hex: result.hex, error: null, exportData: null };
  } else {
    state.error = result.error;
  }
  render();
}

function handleRemoveInput(index) {
  if (!state.hex) return;
  var result = PSBT.removeInput(state.hex, index);
  if (result.ok) {
    state = { packet: result.packet, hex: result.hex, error: null, exportData: null };
  } else {
    state.error = result.error;
  }
  render();
}

function handleRemoveOutput(index) {
  if (!state.hex) return;
  var result = PSBT.removeOutput(state.hex, index);
  if (result.ok) {
    state = { packet: result.packet, hex: result.hex, error: null, exportData: null };
  } else {
    state.error = result.error;
  }
  render();
}

function handleSign() {
  if (!state.hex) return;
  var inputIdx = parseInt(document.getElementById("sign-input-select").value, 10);
  var keyIdx = parseInt(document.getElementById("sign-key-select").value, 10);
  var result = PSBT.sign(state.hex, inputIdx, keyIdx);
  if (result.ok) {
    state = { packet: result.packet, hex: result.hex, error: null, exportData: null };
  } else {
    state.error = result.error;
  }
  render();
}

function handleFinalize() {
  if (!state.hex) return;
  var result = PSBT.finalize(state.hex);
  if (result.ok) {
    state = { packet: result.packet, hex: result.hex, error: null, exportData: null };
  } else {
    state.error = result.error;
  }
  render();
}

function handleExtract() {
  if (!state.hex) return;
  var result = PSBT.extract(state.hex);
  if (result.ok) {
    state.exportData = result.rawTx;
    state.error = null;
  } else {
    state.error = result.error;
  }
  render();
}

function handleExport(format) {
  if (!state.hex) return;
  var result = PSBT.serialize(state.hex, format);
  if (result.ok) {
    state.exportData = result.data;
    state.error = null;
  } else {
    state.error = result.error;
  }
  render();
}

function handleCopy() {
  var data = document.getElementById("export-data").textContent;
  if (!data) return;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(data);
  }
}

function dismissError() {
  state.error = null;
  render();
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

function render() {
  var pkt = state.packet;

  // Error banner
  var errorBanner = document.getElementById("error-banner");
  var errorMsg = errorBanner.querySelector(".error-msg");
  if (state.error) {
    errorMsg.textContent = state.error;
    errorBanner.style.display = "flex";
  } else {
    errorBanner.style.display = "none";
    errorMsg.textContent = "";
  }

  // Empty state / packet view / lifecycle zone
  var emptyState = document.getElementById("empty-state");
  var packetView = document.getElementById("packet-view");
  var lifecycleZone = document.getElementById("lifecycle-zone");

  if (!pkt) {
    emptyState.style.display = "block";
    packetView.style.display = "none";
    lifecycleZone.style.display = "none";
    renderExamples();
    return;
  }

  emptyState.style.display = "none";
  packetView.style.display = "block";
  lifecycleZone.style.display = "block";

  // Version badge
  var versionBadge = document.getElementById("version-badge");
  versionBadge.textContent = "PSBTv" + pkt.version;

  // Convert buttons — disable converting to same version
  var btnConvertV0 = document.getElementById("btn-convert-v0");
  var btnConvertV2 = document.getElementById("btn-convert-v2");
  btnConvertV0.disabled = (pkt.version === 0);
  btnConvertV2.disabled = (pkt.version === 2);

  // Global fields
  var globalFields = document.getElementById("global-fields");
  var chips = [];
  chips.push(createChip("Version", String(pkt.version)));
  chips.push(createChip("Tx Version", String(pkt.txVersion)));
  if (pkt.fallbackLocktime !== null && pkt.fallbackLocktime !== undefined) {
    chips.push(createChip("Locktime", String(pkt.fallbackLocktime)));
  }
  if (pkt.computedLocktime !== null && pkt.computedLocktime !== undefined) {
    chips.push(createChip("Computed Lock", String(pkt.computedLocktime)));
  }
  if (pkt.fee !== null && pkt.fee !== undefined) {
    chips.push(createChip("Fee", pkt.fee + " sats"));
  }
  if (pkt.txModifiable !== null && pkt.txModifiable !== undefined) {
    var modChip = el("span", "mod-badge", "Modifiable: " + modFlagsText(pkt.txModifiable));
    chips.push(modChip);
  }
  chips.push(createChip("Inputs", String(pkt.inputs.length)));
  chips.push(createChip("Outputs", String(pkt.outputs.length)));
  globalFields.replaceChildren.apply(globalFields, chips);

  // Input count
  document.getElementById("input-count").textContent = String(pkt.inputs.length);

  // Input cards
  var inputsContainer = document.getElementById("inputs-container");
  var inputCards = [];
  for (var i = 0; i < pkt.inputs.length; i++) {
    inputCards.push(createInputCard(pkt.inputs[i], i));
  }
  inputsContainer.replaceChildren.apply(inputsContainer, inputCards);

  // Output count
  document.getElementById("output-count").textContent = String(pkt.outputs.length);

  // Output cards
  var outputsContainer = document.getElementById("outputs-container");
  var outputCards = [];
  for (var j = 0; j < pkt.outputs.length; j++) {
    outputCards.push(createOutputCard(pkt.outputs[j], j));
  }
  outputsContainer.replaceChildren.apply(outputsContainer, outputCards);

  // Add input/output buttons — enable only if modifiable
  var canModifyInputs = pkt.txModifiable !== null && pkt.txModifiable !== undefined && (pkt.txModifiable & 0x01);
  var canModifyOutputs = pkt.txModifiable !== null && pkt.txModifiable !== undefined && (pkt.txModifiable & 0x02);
  document.getElementById("btn-add-input").disabled = !canModifyInputs;
  document.getElementById("btn-add-output").disabled = !canModifyOutputs;

  // Sign input select
  var signSelect = document.getElementById("sign-input-select");
  var currentVal = signSelect.value;
  var options = [];
  for (var k = 0; k < pkt.inputs.length; k++) {
    var opt = el("option", null, "Input " + k);
    opt.value = String(k);
    options.push(opt);
  }
  signSelect.replaceChildren.apply(signSelect, options);
  // Restore selection if still valid
  if (currentVal && parseInt(currentVal, 10) < pkt.inputs.length) {
    signSelect.value = currentVal;
  }

  // Export data
  var exportBlock = document.getElementById("export-data");
  exportBlock.textContent = state.exportData || "";
}

// ---------------------------------------------------------------------------
// Init — wire up event listeners
// ---------------------------------------------------------------------------

function init() {
  document.getElementById("btn-parse").addEventListener("click", handleParse);
  document.getElementById("btn-new-v2").addEventListener("click", handleNewV2);
  document.getElementById("btn-convert-v0").addEventListener("click", handleConvertToV0);
  document.getElementById("btn-convert-v2").addEventListener("click", handleConvertToV2);
  document.getElementById("btn-add-input").addEventListener("click", handleAddInput);
  document.getElementById("btn-add-output").addEventListener("click", handleAddOutput);
  document.getElementById("btn-sign").addEventListener("click", handleSign);
  document.getElementById("btn-finalize").addEventListener("click", handleFinalize);
  document.getElementById("btn-extract").addEventListener("click", handleExtract);
  document.getElementById("btn-export-hex").addEventListener("click", function() { handleExport("hex"); });
  document.getElementById("btn-export-b64").addEventListener("click", function() { handleExport("base64"); });
  document.getElementById("btn-copy").addEventListener("click", handleCopy);
  document.getElementById("btn-dismiss-error").addEventListener("click", dismissError);

  // Allow pressing Enter in textarea to parse
  document.getElementById("input-psbt").addEventListener("keydown", function(e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleParse();
    }
  });

  render();
}
