# Changelog

## 1.0.0-prod — 2026-05-31

- Hardened to v1.0-prod per squad doctrine; member of the EnergyTech vertical 6-pack.
- Spec-component repo (no Pages deploy required); AGPL-3.0-or-later, synthetic example data only.
- Pulse universe entry not applicable (no custom subdomain).



## [0.1] — 2026-05-30

### Added

- Initial schema + verifier + canonical example.
- 17-kind enum covering: load-forecast, outage-detected / restoration-prioritized, load-shed (recommended / executed), demand-response-dispatched, market-clearing-recommended, transmission-switching (recommended / executed), protective-relay-action-recommended, pipeline (operations-recommendation / scada-anomaly), cybersecurity (BES-anomaly-detected / cip-008-reportable-incident-flagged), tariff (rate-class-recommendation), EV-charging-deployment-recommendation, deletion-requested.
- **5-value `bes_cyber_system_categorization` taxonomy**: HIGH-IMPACT · MEDIUM-IMPACT · LOW-IMPACT · NONE-APPLICABLE · PHYSICAL-SECURITY-PERIMETER-ONLY. Per NERC CIP-002-5.1a.
- **3-value `ot_it_boundary` taxonomy**: OT · IT · OT-IT-CROSSING. OT-IT-CROSSING requires separately-attested data-diode controls.
- 20-value `regulatory_basis` enum spanning NERC CIP-002/005/007/008/011/013/014, NERC operating procedures, FERC Orders 2222 + 715 + Form 715, TSA SD-2021-02 / SD-2021-02C, DOE EO 14028, EPA Section 114, state PUC tariff + prudency review, ISO/RTO BPMs, engagement-letter binding.
- 9-scheme `asset_ref` taxonomy: bus / substation / generator / transmission line / pipeline segment / distribution feeder / control area / balancing authority / load zone — all tokenized; raw NERC GADS / OASIS / EIA-861 / pipeline-system-IDs MUST NOT appear.
- 16-type `resource.type` enum spanning SCADA data, EMS state-estimator output, load forecast, OMS record, market bid + clearing, AMI meter, DR event, protective relay, transmission switching order, pipeline pressure + control, rate class design, EV charging site, cyber security event log, physical security event log.
- 3 invariants enforced by `src/verify.mjs`:
  - **#1: human-operator-in-loop** on HIGH-IMPACT + OT (or OT-IT-CROSSING) events; transmission-switching additionally requires NERC-certified operator.
  - **#2: TSA pipeline disclosure** on any `energytech.pipeline.*` kind.
  - **#3: CIP-008 incident reporting 1-hour clock** — first Suite verifier invariant that enforces regulatory wall-clock numerically.
- Canonical example: Continental Grid Operator (CGO) × VendorE GridSense v6.x — 7-event trajectory exercising HIGH/MEDIUM/LOW BES categorization, both OT and IT sides, CIP-008 reportable incident pathway, and TSA pipeline disclosure pathway.
- CI workflow.

### Not yet

- Generator dispatch event examples (kinds covered, no example fixture yet).
- Multi-balancing-authority cross-event-stream join example.
- Real-time (millisecond-granularity) protective-relay action example.
- ed25519 `signature` field example.