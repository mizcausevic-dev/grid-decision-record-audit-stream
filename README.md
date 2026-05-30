# grid-decision-record-audit-stream

> **EnergyTech audit-stream Operator (Spec #1 of the EnergyTech 6-pack).** Hash-chained append-only ledger of which AI tool produced which grid-operations decision — load forecasting, outage detection / restoration, demand response, market-clearing, transmission switching, pipeline operations — when, under which NERC CIP standard + FERC rule + TSA Security Directive + state PUC + DOE/EPA basis. **EVERY event carries explicit `bes_cyber_system_categorization` + `ot_it_boundary`** — the EnergyTech vertical's design innovation versus sibling-vertical audit-streams.

Part of the [Kinetic Gain Protocol Suite](https://suite.kineticgain.com).

> Status: v0.1 draft. Schema at [`schema/grid-decision-event.schema.json`](./schema/grid-decision-event.schema.json), canonical 7-event chain at [`examples/cgo-gridsense-2026q4-stream.ndjson`](./examples/cgo-gridsense-2026q4-stream.ndjson), verifier at [`src/verify.mjs`](./src/verify.mjs).

## Regulatory floor

- **NERC CIP-002 through CIP-014** — Critical Infrastructure Protection (BES categorization, electronic security perimeters, system security, incident reporting, information protection, supply-chain risk, physical security)
- **NERC operating procedures + System Operator certification** — control-room conduct rules
- **FERC Orders + Rules** — Order 2222 (aggregated DER), Rule 715 (real-time info), Form 715
- **TSA Security Directives SD-2021-02 + SD-2021-02C** — pipeline cybersecurity (post-Colonial Pipeline)
- **DOE EO 14028 implementation** — federal cybersecurity baseline for energy sector
- **EPA Clean Air Act Section 114** — information request authority
- **State PUC tariff + prudency review** — state-level utility regulation
- **ISO/RTO tariffs + Business Practice Manuals** — wholesale market participation

## Canonical example

- **Buyer:** Continental Grid Operator (CGO) — regional transmission organization in the MISO/PJM/ERCOT shape
- **Vendor / AI system:** VendorE GridSense v6.x — predictive load forecasting + outage detection + market analytics

## Three invariants enforced by the verifier

1. **Human-operator-in-loop on HIGH-IMPACT + OT** — every event affecting a HIGH-impact BES Cyber System on the OT (or OT-IT-CROSSING) side MUST include `agent.human_operator_session_id_tokenized`. Transmission-switching events additionally require `agent.human_operator_nerc_certification_id_tokenized` (NERC certification of the operator on the line).

2. **TSA pipeline disclosure** — any `energytech.pipeline.*` kind MUST include `tsa_pipeline_disclosure_ref` with `filed_at` + `tsa_form_id`. TSA SD-2021-02 / SD-2021-02C disclosure obligation.

3. **CIP-008 incident-reporting clock** — any `energytech.cybersecurity.cip-008-reportable-incident-flagged` event MUST include `cip_008_incident_report_ref` with `report_id` + `filed_at` + `e_isac_url`, AND `filed_at` must be within **1 hour** of the event timestamp. This is the first Suite audit-stream invariant that enforces a wall-clock regulatory deadline numerically, not just structurally.

## Key design innovations vs sibling-vertical audit-streams

| Innovation | Why it's EnergyTech-specific |
| --- | --- |
| `resource.bes_cyber_system_categorization` REQUIRED on every event | CIP-002 categorization (HIGH/MEDIUM/LOW/NONE/PHYSICAL-SECURITY-PERIMETER-ONLY) drives every downstream rule. No other vertical's audit-stream carries critical-infrastructure tier as a first-class field. |
| `resource.ot_it_boundary` REQUIRED on every event | OT (operational technology) and IT (information technology) sides of the air gap carry different regulatory weight — even the same asset. OT-IT-CROSSING requires separately-attested data-diode controls. |
| `outcome.recommendation` value `auto-execute-within-envelope` | Permitted ONLY for LOW-impact + IT-only events. HIGH-impact never permits auto-execute. Encodes a control-room safety norm at the audit-event layer. |
| `outcome.status` block values `blocked-by-bes-category` / `blocked-by-ot-it-boundary` / `blocked-by-human-operator-veto` | Infrastructure-protection blocks as first-class outcomes. These are real-world physical-system safety blocks, not just legal-posture blocks. |
| CIP-008 1-hour wall-clock invariant in the verifier | First time a Suite audit-stream verifier checks regulatory time-arithmetic, not just regulatory shape. |

## Verify

```bash
npm install
npm run build:examples   # builds the canonical 7-event chain
npm run verify           # validates schema + chain + 3 invariants
```

## Composes with

- [`grid-asset-data-vault-contract-profile`](https://github.com/mizcausevic-dev/grid-asset-data-vault-contract-profile) — Decision Card vault contract for grid asset data
- [`nerc-cip-readiness-evidence-bundle`](https://github.com/mizcausevic-dev/nerc-cip-readiness-evidence-bundle) — readiness evidence bundle this stream supplies events to
- [`grid-operations-incident-card-profile`](https://github.com/mizcausevic-dev/grid-operations-incident-card-profile) — where any verifier failure (`status: "blocked-by-bes-category"` / CIP-008 missed window) becomes a published Incident Card
- [`state-puc-ai-disclosure-tracker`](https://github.com/mizcausevic-dev/state-puc-ai-disclosure-tracker) — state PUC + federal regulatory lifecycle context
- [`grid-operator-bias-coverage-lab`](https://github.com/mizcausevic-dev/grid-operator-bias-coverage-lab) — bias in load shed allocation / outage restoration priority / rate-class treatment / EV charging deployment
- [`matter-decision-record-audit-stream`](https://github.com/mizcausevic-dev/matter-decision-record-audit-stream) — sibling-vertical audit-stream (LegalTech)
- [Kinetic Gain Protocol Suite](https://suite.kineticgain.com) — umbrella

## Compliance posture

Audit-stream **readiness scaffolding** for AI tools touching bulk electric system operations, pipeline operations, or rate-design. A grid operator signing a Decision Card for a vendor's AI tool gets a portable, CIP-categorized, hash-chained record of access + recommendations. This does **not** constitute NERC CIP compliance, FERC pre-approval, TSA Security Directive certification, or substitute for the grid operator's own cybersecurity program — per the standing public-language guardrail across the Suite.

## License

Spec text + JSON schemas + example documents + reference verifier: MIT.
