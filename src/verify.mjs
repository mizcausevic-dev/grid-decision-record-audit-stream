#!/usr/bin/env node
// verify.mjs — Grid Decision Record Audit Stream verifier.
//
// Verifies:
//   1. Schema validation against schema/grid-decision-event.schema.json
//   2. Hash chain integrity (canonical-JSON SHA-256, prev_hash chained)
//   3. **Human-operator-in-loop invariant**: every event with action
//      affecting a HIGH-IMPACT BES Cyber System on the OT or OT-IT-CROSSING
//      side MUST include agent.human_operator_session_id_tokenized;
//      transmission-switching events additionally require the operator's
//      NERC certification id. (NERC CIP-002 + operating procedures.)
//   4. **TSA pipeline disclosure invariant**: any kind starting with
//      'energytech.pipeline.' MUST include tsa_pipeline_disclosure_ref
//      with filed_at + tsa_form_id. (TSA SD-2021-02 / SD-2021-02C.)
//   5. **CIP-008 incident reporting invariant**: any kind=cip-008-reportable-
//      incident-flagged event MUST include cip_008_incident_report_ref with
//      report_id + filed_at + e_isac_url, AND filed_at must be within 1 hour
//      of the event timestamp (the CIP-008 1-hour notification window).
//
// Exit codes:
//   0 — all events valid
//   1 — schema failed
//   2 — chain failed
//   3 — human-operator-in-loop invariant violated
//   4 — TSA pipeline disclosure invariant violated
//   5 — CIP-008 incident reporting invariant violated
//   6 — usage / IO error

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Ajv2020 } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const ZERO_HASH = "0".repeat(64);
const ONE_HOUR_MS = 60 * 60 * 1000;

const TRANSMISSION_SWITCHING_KINDS = new Set([
  "energytech.grid.transmission-switching-recommended",
  "energytech.grid.transmission-switching-executed"
]);

function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(value[k])).join(",") + "}";
}
const sha256 = (s) => createHash("sha256").update(s, "utf8").digest("hex");

function loadStream(path) {
  return readFileSync(path, "utf8").trim().split("\n").map((line, i) => {
    try { return JSON.parse(line); } catch (e) {
      throw new Error(`line ${i + 1}: invalid JSON — ${e.message}`);
    }
  });
}

function main() {
  const path = process.argv[2];
  if (!path) { console.error("usage: verify.mjs <stream.ndjson>"); process.exit(6); }

  let events;
  try { events = loadStream(path); }
  catch (e) { console.error(`load error: ${e.message}`); process.exit(6); }

  const schemaPath = new URL("../schema/grid-decision-event.schema.json", import.meta.url);
  const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  addFormats(ajv);
  const validate = ajv.compile(schema);

  // Schema
  for (const [i, event] of events.entries()) {
    if (!validate(event)) {
      console.error(`event[${i}] (${event.event_id}) schema fail:`);
      for (const e of validate.errors || []) console.error(`  ${e.instancePath} ${e.message}`);
      process.exit(1);
    }
  }

  // Chain
  let prev = ZERO_HASH;
  for (const [i, event] of events.entries()) {
    if (event.prev_hash !== prev) {
      console.error(`event[${i}] (${event.event_id}) chain: prev_hash=${event.prev_hash} expected=${prev}`);
      process.exit(2);
    }
    const { hash, ...body } = event;
    const expected = sha256(canonicalize(body));
    if (hash !== expected) {
      console.error(`event[${i}] (${event.event_id}) chain: hash=${hash} recomputed=${expected}`);
      process.exit(2);
    }
    prev = event.hash;
  }

  // Invariant 3: human-operator-in-loop on HIGH-IMPACT + OT (or OT-IT-CROSSING)
  for (const [i, event] of events.entries()) {
    const isHighOt =
      event.resource?.bes_cyber_system_categorization === "HIGH-IMPACT" &&
      (event.resource?.ot_it_boundary === "OT" || event.resource?.ot_it_boundary === "OT-IT-CROSSING");
    if (isHighOt) {
      if (!event.agent?.human_operator_session_id_tokenized) {
        console.error(`event[${i}] (${event.event_id}) human-operator-in-loop: HIGH-IMPACT + OT requires agent.human_operator_session_id_tokenized`);
        process.exit(3);
      }
      if (TRANSMISSION_SWITCHING_KINDS.has(event.kind) && !event.agent?.human_operator_nerc_certification_id_tokenized) {
        console.error(`event[${i}] (${event.event_id}) human-operator-in-loop: ${event.kind} requires NERC-certified operator (agent.human_operator_nerc_certification_id_tokenized)`);
        process.exit(3);
      }
    }
  }

  // Invariant 4: TSA pipeline disclosure
  for (const [i, event] of events.entries()) {
    if (event.kind.startsWith("energytech.pipeline.")) {
      if (!event.tsa_pipeline_disclosure_ref?.filed_at || !event.tsa_pipeline_disclosure_ref?.tsa_form_id) {
        console.error(`event[${i}] (${event.event_id}) tsa-pipeline-disclosure: ${event.kind} requires tsa_pipeline_disclosure_ref with filed_at + tsa_form_id`);
        process.exit(4);
      }
    }
  }

  // Invariant 5: CIP-008 reportable incident — 1-hour notification window
  for (const [i, event] of events.entries()) {
    if (event.kind === "energytech.cybersecurity.cip-008-reportable-incident-flagged") {
      const ref = event.cip_008_incident_report_ref;
      if (!ref?.report_id || !ref?.filed_at || !ref?.e_isac_url) {
        console.error(`event[${i}] (${event.event_id}) cip-008-reporting: requires cip_008_incident_report_ref with report_id + filed_at + e_isac_url`);
        process.exit(5);
      }
      const eventAt = Date.parse(event.timestamp);
      const filedAt = Date.parse(ref.filed_at);
      if (!Number.isFinite(eventAt) || !Number.isFinite(filedAt)) {
        console.error(`event[${i}] (${event.event_id}) cip-008-reporting: unparseable timestamp(s)`);
        process.exit(5);
      }
      if (filedAt - eventAt > ONE_HOUR_MS) {
        console.error(`event[${i}] (${event.event_id}) cip-008-reporting: filed_at ${ref.filed_at} is more than 1h after event timestamp ${event.timestamp} (CIP-008 window)`);
        process.exit(5);
      }
    }
  }

  console.log(`OK · ${events.length} events · schema ✓ · chain ✓ · human-operator-in-loop ✓ · tsa-pipeline-disclosure ✓ · cip-008-reporting ✓`);
}

main();
