// app.js — State management and rendering for PSBT Playground.
// Uses safe DOM methods (createElement, textContent, appendChild, replaceChildren).
// No innerHTML with parsed data.

var state = { packet: null, hex: null, error: null, exportData: null };

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
