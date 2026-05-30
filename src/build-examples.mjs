// build-examples.mjs — Builds the canonical hash-chained example stream.
// Continental Grid Operator (CGO) × VendorE GridSense v6.x —
// a 7-event grid-operations trajectory that exercises HIGH/MEDIUM/LOW BES
// categorization, both OT and IT sides of the air gap, and the CIP-008
// reportable-incident pathway.

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = resolve(HERE, "../examples/cgo-gridsense-2026q4");
const OUT_STREAM = resolve(HERE, "../examples/cgo-gridsense-2026q4-stream.ndjson");
const ZERO_HASH = "0".repeat(64);

function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(value[k])).join(",") + "}";
}
const sha256 = (s) => createHash("sha256").update(s, "utf8").digest("hex");

const AGENT_BASE = {
  ai_tool_card_url:     "https://vendore-gridsense.example/.well-known/ai-tool-cards/gridsense-6.x.json",
  ai_decision_card_url: "https://cgo.example/.well-known/decisions/CGO-DEC-2026-GRID-0117.json"
};
const DECISION_CARD = AGENT_BASE.ai_decision_card_url;

let prevHash = ZERO_HASH;

function buildEvent(partial) {
  const event = { ...partial, prev_hash: prevHash };
  const { hash: _h, ...body } = event;
  const eventHash = sha256(canonicalize(body));
  event.hash = eventHash;
  prevHash = eventHash;
  return event;
}

const events = [
  // 1. IT-side load forecast for a control area — LOW-impact, advisory-only
  buildEvent({
    event_id: "0190et-0001",
    timestamp: "2026-10-15T08:00:00Z",
    kind: "energytech.grid.load-forecast-produced",
    source: "cgo-forecasting-prod",
    asset_ref: { scheme: "control-area-id-tokenized", value: "tok_ca_CGO_north" },
    resource: { type: "load-forecast-record", id_tokenized: "tok_res_lf_a1", bes_cyber_system_categorization: "NONE-APPLICABLE", ot_it_boundary: "IT" },
    action: "recommend",
    outcome: { status: "success", recommendation: "advisory-only" },
    agent: AGENT_BASE,
    regulatory_basis: ["ferc-rule-715-real-time-info", "iso-rto-tariff-and-business-practice-manual"],
    decision_card_ref: DECISION_CARD,
    redaction_applied: [{ field: "control-area-name", action: "tokenize" }]
  }),

  // 2. Outage detected on a MEDIUM-impact substation — OT-side, operator-confirmation-required
  buildEvent({
    event_id: "0190et-0002",
    timestamp: "2026-10-15T14:23:00Z",
    kind: "energytech.grid.outage-detected",
    source: "cgo-ems-prod",
    asset_ref: { scheme: "substation-id-tokenized", value: "tok_sub_CGO_sub_47" },
    resource: { type: "ems-state-estimator-output", id_tokenized: "tok_res_ems_b2", bes_cyber_system_categorization: "MEDIUM-IMPACT", ot_it_boundary: "OT" },
    action: "recommend",
    outcome: { status: "success", recommendation: "operator-confirmation-required" },
    agent: { ...AGENT_BASE, human_operator_session_id_tokenized: "tok_op_session_7e2" },
    regulatory_basis: ["nerc-cip-005-electronic-security-perimeter", "nerc-operating-procedures"],
    decision_card_ref: DECISION_CARD
  }),

  // 3. Outage restoration prioritization — HIGH-impact (affects HIGH-impact transmission), requires human-operator-in-loop
  buildEvent({
    event_id: "0190et-0003",
    timestamp: "2026-10-15T14:25:00Z",
    kind: "energytech.grid.outage-restoration-prioritized",
    source: "cgo-oms-prod",
    asset_ref: { scheme: "transmission-line-id-tokenized", value: "tok_tx_CGO_line_138kv_north" },
    resource: { type: "outage-management-record", id_tokenized: "tok_res_oms_c3", bes_cyber_system_categorization: "HIGH-IMPACT", ot_it_boundary: "OT" },
    action: "recommend",
    outcome: { status: "success", recommendation: "operator-confirmation-required" },
    agent: { ...AGENT_BASE, human_operator_session_id_tokenized: "tok_op_session_7e2", human_operator_nerc_certification_id_tokenized: "tok_nerc_cert_9a01" },
    regulatory_basis: ["nerc-cip-002-bes-categorization", "nerc-operating-procedures"],
    decision_card_ref: DECISION_CARD
  }),

  // 4. Transmission switching recommended on HIGH-impact line — requires NERC-certified human operator
  buildEvent({
    event_id: "0190et-0004",
    timestamp: "2026-10-15T14:30:00Z",
    kind: "energytech.grid.transmission-switching-recommended",
    source: "cgo-ems-prod",
    asset_ref: { scheme: "transmission-line-id-tokenized", value: "tok_tx_CGO_line_138kv_north" },
    resource: { type: "transmission-switching-order", id_tokenized: "tok_res_tx_d4", bes_cyber_system_categorization: "HIGH-IMPACT", ot_it_boundary: "OT" },
    action: "recommend",
    outcome: { status: "success", recommendation: "operator-confirmation-required" },
    agent: { ...AGENT_BASE, human_operator_session_id_tokenized: "tok_op_session_7e2", human_operator_nerc_certification_id_tokenized: "tok_nerc_cert_9a01" },
    regulatory_basis: ["nerc-cip-002-bes-categorization", "nerc-cip-007-system-security-management", "nerc-operating-procedures"],
    decision_card_ref: DECISION_CARD
  }),

  // 5. Cyber-security anomaly detected on the BES — flagged as reportable, triggers invariant #3
  buildEvent({
    event_id: "0190et-0005",
    timestamp: "2026-10-15T15:02:00Z",
    kind: "energytech.cybersecurity.cip-008-reportable-incident-flagged",
    source: "cgo-soc-prod",
    asset_ref: { scheme: "substation-id-tokenized", value: "tok_sub_CGO_sub_47" },
    resource: { type: "cyber-security-event-log", id_tokenized: "tok_res_sec_e5", bes_cyber_system_categorization: "MEDIUM-IMPACT", ot_it_boundary: "OT-IT-CROSSING" },
    action: "stamp",
    outcome: { status: "success", recommendation: "halt-and-escalate" },
    agent: { ...AGENT_BASE, human_operator_session_id_tokenized: "tok_op_session_7e2" },
    regulatory_basis: ["nerc-cip-008-incident-reporting", "nerc-cip-005-electronic-security-perimeter"],
    cip_008_incident_report_ref: {
      report_id: "CGO-CIP-008-2026-0023",
      filed_at: "2026-10-15T15:55:00Z",
      e_isac_url: "https://e-isac.example/reports/CGO-CIP-008-2026-0023"
    },
    decision_card_ref: DECISION_CARD
  }),

  // 6. Pipeline pressure anomaly — triggers TSA disclosure (invariant #2)
  buildEvent({
    event_id: "0190et-0006",
    timestamp: "2026-10-15T17:18:00Z",
    kind: "energytech.pipeline.scada-anomaly-detected",
    source: "cgo-pipeline-scada-prod",
    asset_ref: { scheme: "pipeline-segment-id-tokenized", value: "tok_pipe_CGO_seg_22" },
    resource: { type: "pipeline-pressure-reading", id_tokenized: "tok_res_pp_f6", bes_cyber_system_categorization: "NONE-APPLICABLE", ot_it_boundary: "OT" },
    action: "stamp",
    outcome: { status: "success", recommendation: "halt-and-escalate" },
    agent: { ...AGENT_BASE, human_operator_session_id_tokenized: "tok_op_session_9c4" },
    regulatory_basis: ["tsa-sd-2021-02c-revised-pipeline", "doe-eo-14028-implementation"],
    tsa_pipeline_disclosure_ref: {
      filed_at: "2026-10-15T17:42:00Z",
      tsa_form_id: "TSA-PIPE-2026-1140"
    },
    decision_card_ref: DECISION_CARD
  }),

  // 7. Rate-class design recommendation — IT-only, NONE-APPLICABLE, advisory only
  buildEvent({
    event_id: "0190et-0007",
    timestamp: "2026-10-16T09:00:00Z",
    kind: "energytech.tariff.rate-class-recommendation-produced",
    source: "cgo-tariff-analytics-prod",
    asset_ref: { scheme: "load-zone-id-tokenized", value: "tok_lz_CGO_zone_north" },
    resource: { type: "rate-class-design-record", id_tokenized: "tok_res_rate_g7", bes_cyber_system_categorization: "NONE-APPLICABLE", ot_it_boundary: "IT" },
    action: "recommend",
    outcome: { status: "success", recommendation: "advisory-only" },
    agent: AGENT_BASE,
    regulatory_basis: ["state-puc-tariff-authority", "state-puc-prudency-review"],
    decision_card_ref: DECISION_CARD
  })
];

mkdirSync(OUT_DIR, { recursive: true });
mkdirSync(dirname(OUT_STREAM), { recursive: true });
for (const event of events) {
  writeFileSync(resolve(OUT_DIR, `${event.event_id}.json`), JSON.stringify(event, null, 2) + "\n", "utf8");
}
writeFileSync(OUT_STREAM, events.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf8");
console.log(`built ${events.length} events → ${OUT_STREAM}`);
